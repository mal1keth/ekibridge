//! Key store: the handle behind `eki_ks`, the logic every backend shares, and the backend
//! interface.
//!
//! The design has three layers, the same as in the C++ library:
//!
//! 1. [`Handle`] is the object an `eki_ks *` points to. It owns a mutex around the [`Store`],
//!    which holds the backend and the last-error text. One lock serialises every operation on a
//!    handle.
//! 2. [`Store`] is the logic shared by all backends. Each method is one `eki_ks_*` function and
//!    runs the per-function sequence of the ABI contract (plan 4.2): selector and format checks,
//!    then the store-state checks in their fixed order, and only then the backend operation. It
//!    decides every status that follows from caller input or store state (`INVALID_ARGUMENT`,
//!    `KEY_NOT_FOUND`, `WRONG_KEY_TYPE`, `KEY_EXISTS`) and records a non-empty message for every
//!    backend failure.
//! 3. [`Backend`] is what differs per backend: find a key's algorithm and label, create, public
//!    key, sign, HMAC, wrap, unwrap-and-store, destroy. A backend reports only success, a
//!    failure with text, an integrity failure (unwrap only) or a broken internal invariant. No
//!    method returns key bytes, because a token may refuse to export them: wrap and unwrap are
//!    backend operations.
//!
//! Nothing here touches a C pointer. `ffi.rs` checks and converts the C arguments and calls the
//! methods of [`Store`] with Rust values and slices.

use core::ffi::c_char;
use std::sync::{Mutex, MutexGuard, PoisonError};

use ekicore_abi::{
    EKI_HMAC_SHA256_LEN, EKI_KEY_AES_256, EKI_KEY_ECDSA_P256, EKI_KEY_HMAC_SHA256, EKI_KEY_ID_LEN,
    EKI_KS_PKCS11, EKI_KS_SOFTWARE, EKI_LABEL_MAX_LEN, EKI_P256_PUBLIC_KEY_LEN,
    EKI_P256_SIGNATURE_LEN, EKI_WRAPPED_KEY_LEN, eki_key_alg, eki_key_id, eki_key_info,
    eki_ks_backend,
};

use crate::error::Error;

pub mod software;

#[cfg(feature = "pkcs11")]
pub mod pkcs11;

// --- Types the layers share ----------------------------------------------------------------------

/// The id of a stored key: 16 bytes, random for a generated key, chosen by the caller for an
/// unwrapped one. Ids are not secret, so they are compared and ordered in variable time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId(pub [u8; EKI_KEY_ID_LEN]);

impl From<eki_key_id> for KeyId {
    fn from(id: eki_key_id) -> Self {
        Self(id.bytes)
    }
}

impl From<KeyId> for eki_key_id {
    fn from(id: KeyId) -> Self {
        Self { bytes: id.0 }
    }
}

/// The algorithm of a stored key. Unlike the `eki_key_alg` selector, every value is valid, so a
/// backend never sees an unknown algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAlg {
    /// A 32-byte AES-256 key; usable as a key-encryption key; wrappable.
    Aes256,
    /// A 32-byte HMAC-SHA256 key; wrappable.
    HmacSha256,
    /// An ECDSA P-256 key pair; not wrappable.
    EcdsaP256,
}

impl KeyAlg {
    /// The algorithm a selector names, or `None` for any other value.
    pub fn parse(alg: eki_key_alg) -> Option<Self> {
        match alg {
            EKI_KEY_AES_256 => Some(Self::Aes256),
            EKI_KEY_HMAC_SHA256 => Some(Self::HmacSha256),
            EKI_KEY_ECDSA_P256 => Some(Self::EcdsaP256),
            _ => None,
        }
    }

    /// The selector value of the algorithm.
    pub fn to_abi(self) -> eki_key_alg {
        match self {
            Self::Aes256 => EKI_KEY_AES_256,
            Self::HmacSha256 => EKI_KEY_HMAC_SHA256,
            Self::EcdsaP256 => EKI_KEY_ECDSA_P256,
        }
    }

    /// Whether a key of this algorithm can be wrapped: the 32-byte secrets can, a key pair cannot.
    pub fn is_wrappable(self) -> bool {
        match self {
            Self::Aes256 | Self::HmacSha256 => true,
            Self::EcdsaP256 => false,
        }
    }
}

/// A key label that satisfies the contract: 1 to 64 bytes, each in `0x20..=0x7E`.
///
/// The only constructor is [`Label::parse`], so a backend never sees an invalid label. The text
/// is stored inline and zero-padded, so the type is `Copy` and a copy never allocates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Label {
    bytes: [u8; EKI_LABEL_MAX_LEN],
    len: usize,
}

impl Label {
    /// The label whose text is `text`, or `None` if `text` is empty, longer than 64 bytes, or
    /// holds a byte outside `0x20..=0x7E`.
    ///
    /// `text` is the label without its NUL. A C label with no NUL among its first 65 bytes
    /// reaches this function as those 65 bytes and is rejected by length.
    pub fn parse(text: &[u8]) -> Option<Self> {
        let printable = text.iter().all(|byte| (0x20..=0x7E).contains(byte));
        if text.is_empty() || !printable {
            return None;
        }
        let mut bytes = [0; EKI_LABEL_MAX_LEN];
        // `get_mut` is `None` for a text longer than 64 bytes, which rejects it.
        bytes.get_mut(..text.len())?.copy_from_slice(text);
        Some(Self {
            bytes,
            len: text.len(),
        })
    }

    /// The text of the label, without a NUL.
    pub fn as_bytes(&self) -> &[u8] {
        // In bounds: `parse`, the only constructor, sets `len` to at most 64.
        &self.bytes[..self.len]
    }
}

/// The algorithm and label of a stored key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyInfo {
    /// The algorithm.
    pub alg: KeyAlg,
    /// The label.
    pub label: Label,
}

impl KeyInfo {
    /// The C form: the selector value and the label NUL-padded through byte 64.
    pub fn to_abi(&self) -> eki_key_info {
        let mut label: [c_char; EKI_LABEL_MAX_LEN + 1] = [0; EKI_LABEL_MAX_LEN + 1];
        for (dst, &src) in label.iter_mut().zip(self.label.as_bytes()) {
            // Label bytes are `0x20..=0x7E`, so the value is the same whether `c_char` is signed
            // or not.
            *dst = src as c_char;
        }
        eki_key_info {
            alg: self.alg.to_abi(),
            label,
        }
    }
}

/// What carries an id, when something does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Found {
    /// A key this library can describe.
    Key(KeyInfo),
    /// An object that carries the id but is not a key this library can describe: a PKCS#11
    /// object of another shape, or one whose label is not a valid label (plan 4.3). It counts as
    /// existing (`KEY_EXISTS` on unwrap, destroyable); an operation that needs its algorithm or
    /// label fails as a backend failure. The software backend never reports it.
    Foreign,
}

/// How a backend operation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackendError {
    /// The backend itself failed (an RNG, a crypto crate, the PKCS#11 module): `EKI_ERR_BACKEND`.
    /// The text becomes the handle's last-error message; it names the operation and the cause.
    Failed(String),
    /// The wrapped key failed the RFC 3394 integrity check: `EKI_ERR_AUTH_FAILED`. Only
    /// [`Backend::unwrap`] reports it.
    AuthFailed,
    /// A precondition stated on the method did not hold: `EKI_ERR_INTERNAL`.
    Internal(&'static str),
}

/// The result of a backend operation.
pub type BackendResult<T> = Result<T, BackendError>;

// --- Layer 3: the backend interface -------------------------------------------------------------

/// Where keys live.
///
/// [`Store`] calls these methods only with the handle's lock held, so a backend sees one call at
/// a time; the methods take `&mut self` because a backend may hold mutable session state, and
/// `Send` lets the handle be shared across threads behind its mutex. Every status that follows
/// from caller input or store state is decided by the store before it calls the backend: the
/// preconditions below hold whenever the store calls a method, and a backend reports a violated
/// one as [`BackendError::Internal`].
///
/// Panics: a method may panic (the FFI barrier turns that into `EKI_ERR_INTERNAL`), but at every
/// point where it can panic the backend must be as it was before the call or as a completed call
/// leaves it, because the handle recovers its lock after a panic and goes on using the backend
/// (see [`Handle::lock`]).
///
/// Dropping the backend wipes the secrets it holds in memory (software) or closes its session
/// (PKCS#11), and must not panic.
pub trait Backend: Send {
    /// What carries `id`: `None` when no object of any class does.
    fn find(&mut self, id: &KeyId) -> BackendResult<Option<Found>>;

    /// Creates a new key of `alg` labelled `label` under `id`.
    ///
    /// Precondition: nothing carries `id`. On failure nothing is created and existing keys are
    /// unchanged.
    fn create(&mut self, alg: KeyAlg, label: &Label, id: &KeyId) -> BackendResult<()>;

    /// The SEC1 uncompressed public key (`0x04 || X || Y`) of the key pair `id`.
    ///
    /// Precondition: `id` names an ECDSA P-256 key.
    fn public_key(&mut self, id: &KeyId) -> BackendResult<[u8; EKI_P256_PUBLIC_KEY_LEN]>;

    /// The ECDSA signature of SHA-256(`msg`) under the key pair `id`, as `r || s`, 32 bytes each.
    /// `msg` may be empty.
    ///
    /// Precondition: `id` names an ECDSA P-256 key.
    fn sign(&mut self, id: &KeyId, msg: &[u8]) -> BackendResult<[u8; EKI_P256_SIGNATURE_LEN]>;

    /// HMAC-SHA256 of `msg` under the key `id`. `msg` may be empty.
    ///
    /// Precondition: `id` names an HMAC-SHA256 key.
    fn hmac_sha256(&mut self, id: &KeyId, msg: &[u8]) -> BackendResult<[u8; EKI_HMAC_SHA256_LEN]>;

    /// The RFC 3394 AES Key Wrap of the secret key `key` under `kek`. `kek` and `key` may be the
    /// same id.
    ///
    /// Precondition: `kek` names an AES-256 key, `key` an AES-256 or HMAC-SHA256 key.
    fn wrap(&mut self, kek: &KeyId, key: &KeyId) -> BackendResult<[u8; EKI_WRAPPED_KEY_LEN]>;

    /// Unwraps `blob` under `kek` and stores the 32-byte result as a new key of `alg` labelled
    /// `label` under `id`. [`BackendError::AuthFailed`] when the blob fails the integrity check.
    ///
    /// Precondition: `kek` names an AES-256 key; `alg` is AES-256 or HMAC-SHA256; nothing carries
    /// `id`. On any failure nothing is created and existing keys are unchanged.
    fn unwrap(
        &mut self,
        kek: &KeyId,
        blob: &[u8; EKI_WRAPPED_KEY_LEN],
        alg: KeyAlg,
        label: &Label,
        id: &KeyId,
    ) -> BackendResult<()>;

    /// Removes every object that carries `id`; the software backend wipes the key material.
    ///
    /// Precondition: something carries `id`.
    fn destroy(&mut self, id: &KeyId) -> BackendResult<()>;
}

// --- Layer 1: the handle ------------------------------------------------------------------------

/// The object an `eki_ks *` points to: the store behind a mutex.
///
/// `eki_ks_open` boxes one and hands the caller the raw pointer; `eki_ks_close` takes the box
/// back and drops it, which drops the backend and with it every key.
pub struct Handle {
    store: Mutex<Store>,
}

impl Handle {
    /// A handle over `backend`, with an empty last-error message.
    pub fn new(backend: Box<dyn Backend>) -> Self {
        Self {
            store: Mutex::new(Store {
                backend,
                last_error: String::new(),
            }),
        }
    }

    /// Starts an operation on the handle: takes the lock and resets the last-error message to
    /// `""`, as every store call except `last_error_message` and `close` does on entry (plan 4.2,
    /// "Last error"). The guard keeps the handle locked until the operation ends.
    pub fn begin(&self) -> MutexGuard<'_, Store> {
        let mut store = self.lock();
        store.last_error.clear();
        store
    }

    /// Takes the lock without starting an operation, for reading the last-error message.
    ///
    /// A panic while the lock is held poisons the mutex. The lock is recovered instead of the
    /// poison being propagated (plan 4.2, step 7), and that is sound because no panic can leave
    /// the store inconsistent:
    ///
    /// - `last_error` only ever changes by `clear` or by a move of a finished `String`, neither
    ///   of which can panic midway, so it holds `""` or a complete message. The next operation
    ///   resets it on entry anyway.
    /// - The store logic changes nothing else. All other state is in the backend.
    /// - The [`Backend`] contract requires each method to leave the backend unchanged or
    ///   completely changed at every point where it can panic. The software backend meets it:
    ///   key generation, signing, HMAC, wrap and unwrap work on locals and on borrowed keys, and
    ///   its only mutations are a single `BTreeMap` insertion (after everything that can fail)
    ///   and a single removal. Neither can stop halfway: the key comparisons are the derived
    ///   `Ord` of a 16-byte array and the values are moved, so nothing in them can panic, and an
    ///   allocation failure aborts the process instead of unwinding.
    /// - The PKCS#11 backend meets it too. Its own state, the session and the module reference,
    ///   is never changed by an operation. Each change to the token is one PKCS#11 call
    ///   (generate, generate pair, unwrap, destroy object), which the token completes or
    ///   rejects whole, and keys are looked up again on every call, so nothing cached can go
    ///   stale. An object search is finished by the drop of the search iterator, which also
    ///   runs during unwinding, so a panic cannot leave the session in the middle of a search.
    ///
    /// The caller of the panicking operation receives `EKI_ERR_INTERNAL`; the next call finds the
    /// store as the last completed operation left it.
    pub fn lock(&self) -> MutexGuard<'_, Store> {
        self.store.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The backend a configuration selects, once validation step 2 of `eki_ks_open` has passed.
///
/// `eki_ks_open` selects first and reads the PKCS#11 fields of the configuration only for
/// [`Selected::Pkcs11`]: the software backend never reads them, and a backend that is not
/// compiled in answers before any field is looked at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selected {
    /// `EKI_KS_SOFTWARE`.
    Software,
    /// `EKI_KS_PKCS11`, in a library built with the `pkcs11` feature.
    Pkcs11,
}

/// Validation step 2 of `eki_ks_open`: an unknown selector is `INVALID_ARGUMENT`, the PKCS#11
/// selector is `UNSUPPORTED` when the backend is not compiled in.
pub fn select(backend: eki_ks_backend) -> Result<Selected, Error> {
    match backend {
        EKI_KS_SOFTWARE => Ok(Selected::Software),
        EKI_KS_PKCS11 if cfg!(feature = "pkcs11") => Ok(Selected::Pkcs11),
        EKI_KS_PKCS11 => Err(Error::Unsupported),
        _ => Err(Error::InvalidArgument),
    }
}

/// Opens a software store: an empty in-memory map.
pub fn open_software() -> Handle {
    Handle::new(Box::new(software::Software::new()))
}

/// Longest PKCS#11 token label, in bytes: the size of `CK_TOKEN_INFO.label`.
/// cbindgen:ignore
pub const PKCS11_TOKEN_LABEL_MAX_LEN: usize = 32;

/// Longest PKCS#11 user PIN, in bytes.
/// cbindgen:ignore
pub const PKCS11_USER_PIN_MAX_LEN: usize = 255;

/// The PKCS#11 fields of an `eki_ks_config`, after step 1 for them: each is the text before the
/// field's NUL, read by `ffi.rs`. The token label and the PIN were read with a bound one byte
/// past their maximum, so a text without a NUL within that bound arrives one byte too long and
/// fails its format check.
#[derive(Clone, Copy, Debug)]
pub struct Pkcs11Fields<'a> {
    /// The path of the PKCS#11 module to load.
    pub module_path: &'a [u8],
    /// The label of the token to open: 1 to 32 printable bytes.
    pub token_label: &'a [u8],
    /// The user PIN: 1 to 255 bytes.
    pub user_pin: &'a [u8],
}

/// Opens a PKCS#11 store: validation step 3 for the token label and the PIN, in field order
/// (`INVALID_ARGUMENT`), then load, initialise, slot, session and login, where every failure is
/// `EKI_ERR_BACKEND`. There is no handle yet to carry a message, so the reason is dropped and
/// only the status is reported (plan 4.2, "Last error").
///
/// Called only after [`select`] answered [`Selected::Pkcs11`], which it does only when the
/// backend is compiled in.
pub fn open_pkcs11(fields: &Pkcs11Fields<'_>) -> Result<Handle, Error> {
    #[cfg(feature = "pkcs11")]
    {
        let config = pkcs11::Config::parse(fields)?;
        match pkcs11::Pkcs11Backend::open(config) {
            Ok(backend) => Ok(Handle::new(Box::new(backend))),
            Err(BackendError::Internal(_)) => Err(Error::Internal),
            Err(BackendError::Failed(_) | BackendError::AuthFailed) => Err(Error::Backend),
        }
    }
    #[cfg(not(feature = "pkcs11"))]
    {
        let _ = fields;
        Err(Error::Unsupported)
    }
}

/// Copies `text` into `buf` with the snprintf convention of `eki_ks_last_error_message`: at most
/// `buf.len() - 1` bytes of the text followed by a NUL, nothing when `buf` is empty. Returns the
/// full length of `text`, which may exceed what was written.
pub fn copy_message(text: &[u8], buf: &mut [u8]) -> usize {
    if let Some(room) = buf.len().checked_sub(1) {
        let written = text.len().min(room);
        buf.iter_mut()
            .zip(text)
            .take(written)
            .for_each(|(dst, src)| *dst = *src);
        if let Some(nul) = buf.get_mut(written) {
            *nul = 0;
        }
    }
    text.len()
}

// --- Layer 2: the store logic -------------------------------------------------------------------

/// Message for a backend failure that came without text; a BACKEND failure always leaves text.
/// cbindgen:ignore
const NO_REASON: &str = "the key store backend failed without giving a reason";

/// Message for an object that carries an id but is not a key this library can describe.
/// cbindgen:ignore
const FOREIGN_OBJECT: &str =
    "the object with this id is not a key this library can describe (unknown shape or label)";

/// The state behind a handle's lock: the backend and the last-error message, and the logic every
/// backend shares.
///
/// The methods run with the lock held, inside an operation started by [`Handle::begin`]. Each
/// one follows its sequence in plan 4.2 from top to bottom; the first failing step decides the
/// error.
pub struct Store {
    backend: Box<dyn Backend>,
    last_error: String,
}

impl Store {
    /// The message of the most recent operation on the handle: `""` after a success, non-empty
    /// after a backend failure.
    pub fn last_error(&self) -> &str {
        &self.last_error
    }

    /// `eki_ks_generate`: a new key of `alg` labelled `label`, under a fresh random id.
    pub fn generate(&mut self, alg: eki_key_alg, label: &[u8]) -> Result<KeyId, Error> {
        let alg = KeyAlg::parse(alg).ok_or(Error::InvalidArgument)?;
        let label = Label::parse(label).ok_or(Error::InvalidArgument)?;
        let id = self.fresh_id()?;
        self.call(|backend| backend.create(alg, &label, &id))?;
        Ok(id)
    }

    /// `eki_ks_get_info`: the algorithm and label of a key of any type.
    pub fn get_info(&mut self, id: &KeyId) -> Result<KeyInfo, Error> {
        self.key_info(id)
    }

    /// `eki_ks_get_public_key`: missing → `KEY_NOT_FOUND`, not ECDSA → `WRONG_KEY_TYPE`.
    pub fn public_key(&mut self, id: &KeyId) -> Result<[u8; EKI_P256_PUBLIC_KEY_LEN], Error> {
        self.require(id, KeyAlg::EcdsaP256)?;
        self.call(|backend| backend.public_key(id))
    }

    /// `eki_ks_sign`: missing → `KEY_NOT_FOUND`, not ECDSA → `WRONG_KEY_TYPE`.
    pub fn sign(&mut self, id: &KeyId, msg: &[u8]) -> Result<[u8; EKI_P256_SIGNATURE_LEN], Error> {
        self.require(id, KeyAlg::EcdsaP256)?;
        self.call(|backend| backend.sign(id, msg))
    }

    /// `eki_ks_hmac_sha256`: missing → `KEY_NOT_FOUND`, not HMAC → `WRONG_KEY_TYPE`.
    pub fn hmac_sha256(
        &mut self,
        id: &KeyId,
        msg: &[u8],
    ) -> Result<[u8; EKI_HMAC_SHA256_LEN], Error> {
        self.require(id, KeyAlg::HmacSha256)?;
        self.call(|backend| backend.hmac_sha256(id, msg))
    }

    /// `eki_ks_wrap`: kek exists → key exists → kek is AES-256 → key is AES-256 or HMAC-SHA256.
    /// Self-wrap (`kek == key`) is allowed.
    pub fn wrap(&mut self, kek: &KeyId, key: &KeyId) -> Result<[u8; EKI_WRAPPED_KEY_LEN], Error> {
        let kek_found = self.existing(kek)?;
        let key_found = self.existing(key)?;
        if self.described(kek_found)?.alg != KeyAlg::Aes256 {
            return Err(Error::WrongKeyType);
        }
        if !self.described(key_found)?.alg.is_wrappable() {
            return Err(Error::WrongKeyType);
        }
        self.call(|backend| backend.wrap(kek, key))
    }

    /// `eki_ks_unwrap`: `alg` unknown → `blob` not 40 bytes → `alg` is ECDSA → label format, all
    /// `INVALID_ARGUMENT`; kek exists → kek is AES-256 → `id` free (any object counts) → the
    /// integrity check, which the backend performs (`AUTH_FAILED`).
    pub fn unwrap(
        &mut self,
        kek: &KeyId,
        blob: &[u8],
        alg: eki_key_alg,
        label: &[u8],
        id: &KeyId,
    ) -> Result<(), Error> {
        let alg = KeyAlg::parse(alg).ok_or(Error::InvalidArgument)?;
        let blob: &[u8; EKI_WRAPPED_KEY_LEN] =
            blob.try_into().map_err(|_| Error::InvalidArgument)?;
        if !alg.is_wrappable() {
            return Err(Error::InvalidArgument);
        }
        let label = Label::parse(label).ok_or(Error::InvalidArgument)?;
        self.require(kek, KeyAlg::Aes256)?;
        if self.call(|backend| backend.find(id))?.is_some() {
            return Err(Error::KeyExists);
        }
        self.call(|backend| backend.unwrap(kek, blob, alg, &label, id))
    }

    /// `eki_ks_destroy`: any object that carries `id`, foreign ones included; missing →
    /// `KEY_NOT_FOUND`.
    pub fn destroy(&mut self, id: &KeyId) -> Result<(), Error> {
        self.existing(id)?;
        self.call(|backend| backend.destroy(id))
    }

    // --- Steps shared by the operations ---

    /// A fresh id for `generate`: 16 bytes from the operating system's RNG. An id that something
    /// already carries would mean a broken RNG; it is a backend failure and never overwrites a
    /// key, which also keeps the precondition of [`Backend::create`].
    fn fresh_id(&mut self) -> Result<KeyId, Error> {
        let mut id = KeyId([0; EKI_KEY_ID_LEN]);
        if let Err(error) = getrandom::fill(&mut id.0) {
            return Err(self.backend_failure(format!("getrandom for a key id failed: {error}")));
        }
        if self.call(|backend| backend.find(&id))?.is_some() {
            return Err(self.backend_failure("the random key id is already in use".to_owned()));
        }
        Ok(id)
    }

    /// The object that carries `id`: `KEY_NOT_FOUND` when nothing does.
    fn existing(&mut self, id: &KeyId) -> Result<Found, Error> {
        self.call(|backend| backend.find(id))?
            .ok_or(Error::KeyNotFound)
    }

    /// The algorithm and label of an object that exists: an object this library cannot describe
    /// is a backend failure (plan 4.3).
    fn described(&mut self, found: Found) -> Result<KeyInfo, Error> {
        match found {
            Found::Key(info) => Ok(info),
            Found::Foreign => Err(self.backend_failure(FOREIGN_OBJECT.to_owned())),
        }
    }

    /// The algorithm and label of the key `id`: `KEY_NOT_FOUND`, then a foreign object.
    fn key_info(&mut self, id: &KeyId) -> Result<KeyInfo, Error> {
        let found = self.existing(id)?;
        self.described(found)
    }

    /// `id` names a key of algorithm `wanted`: `KEY_NOT_FOUND`, then `WRONG_KEY_TYPE`.
    fn require(&mut self, id: &KeyId, wanted: KeyAlg) -> Result<(), Error> {
        if self.key_info(id)?.alg == wanted {
            Ok(())
        } else {
            Err(Error::WrongKeyType)
        }
    }

    /// Runs one backend operation and turns its failure into an error, recording the message.
    fn call<T>(
        &mut self,
        operation: impl FnOnce(&mut dyn Backend) -> BackendResult<T>,
    ) -> Result<T, Error> {
        let result = operation(self.backend.as_mut());
        self.record(result)
    }

    /// The error for a backend result. A backend failure's text becomes the last-error message,
    /// a generic one when the backend gave none; an internal failure's text too.
    fn record<T>(&mut self, result: BackendResult<T>) -> Result<T, Error> {
        match result {
            Ok(value) => Ok(value),
            Err(BackendError::Failed(text)) if text.is_empty() => {
                Err(self.backend_failure(NO_REASON.to_owned()))
            }
            Err(BackendError::Failed(text)) => Err(self.backend_failure(text)),
            Err(BackendError::AuthFailed) => Err(Error::AuthFailed),
            Err(BackendError::Internal(text)) => {
                self.last_error = text.to_owned();
                Err(Error::Internal)
            }
        }
    }

    /// Records `text` as the message and returns [`Error::Backend`].
    fn backend_failure(&mut self, text: String) -> Error {
        self.last_error = text;
        Error::Backend
    }
}

/// A scripted backend for the unit tests of the store logic and of the FFI layer: it reaches
/// paths the software backend cannot (backend failures, foreign objects, an id collision after a
/// random draw, a panic under the lock).
#[cfg(test)]
pub(crate) mod scripted {
    use std::collections::BTreeMap;

    use super::*;

    /// Each object it holds is described by a [`Found`]; operations succeed with fixed outputs
    /// unless told otherwise.
    #[derive(Default)]
    pub(crate) struct Scripted {
        /// The objects, by id.
        pub(crate) objects: BTreeMap<KeyId, Found>,
        /// Every `find` reports something, whatever the id (a colliding RNG).
        pub(crate) find_always: bool,
        /// Every operation other than `find` fails with this text.
        pub(crate) fail_with: Option<String>,
        /// `sign` panics.
        pub(crate) panic_in_sign: bool,
        /// `unwrap` stores nothing and reports an integrity failure.
        pub(crate) reject_blobs: bool,
    }

    impl Scripted {
        fn outcome(&self) -> BackendResult<()> {
            match &self.fail_with {
                Some(text) => Err(BackendError::Failed(text.clone())),
                None => Ok(()),
            }
        }

        pub(crate) fn add(&mut self, alg: KeyAlg, label: &Label, id: &KeyId) {
            let info = KeyInfo { alg, label: *label };
            self.objects.insert(*id, Found::Key(info));
        }
    }

    impl Backend for Scripted {
        fn find(&mut self, id: &KeyId) -> BackendResult<Option<Found>> {
            if self.find_always {
                return Ok(Some(Found::Foreign));
            }
            Ok(self.objects.get(id).copied())
        }

        fn create(&mut self, alg: KeyAlg, label: &Label, id: &KeyId) -> BackendResult<()> {
            self.outcome()?;
            self.add(alg, label, id);
            Ok(())
        }

        fn public_key(&mut self, _: &KeyId) -> BackendResult<[u8; EKI_P256_PUBLIC_KEY_LEN]> {
            self.outcome().map(|()| [4; EKI_P256_PUBLIC_KEY_LEN])
        }

        fn sign(&mut self, _: &KeyId, _: &[u8]) -> BackendResult<[u8; EKI_P256_SIGNATURE_LEN]> {
            assert!(!self.panic_in_sign, "deliberate panic in a backend method");
            self.outcome().map(|()| [1; EKI_P256_SIGNATURE_LEN])
        }

        fn hmac_sha256(&mut self, _: &KeyId, _: &[u8]) -> BackendResult<[u8; 32]> {
            self.outcome().map(|()| [2; EKI_HMAC_SHA256_LEN])
        }

        fn wrap(&mut self, _: &KeyId, _: &KeyId) -> BackendResult<[u8; EKI_WRAPPED_KEY_LEN]> {
            self.outcome().map(|()| [3; EKI_WRAPPED_KEY_LEN])
        }

        fn unwrap(
            &mut self,
            _: &KeyId,
            _: &[u8; EKI_WRAPPED_KEY_LEN],
            alg: KeyAlg,
            label: &Label,
            id: &KeyId,
        ) -> BackendResult<()> {
            self.outcome()?;
            if self.reject_blobs {
                return Err(BackendError::AuthFailed);
            }
            self.add(alg, label, id);
            Ok(())
        }

        fn destroy(&mut self, id: &KeyId) -> BackendResult<()> {
            self.outcome()?;
            self.objects
                .remove(id)
                .map(drop)
                .ok_or(BackendError::Internal("destroy of an id nothing carries"))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::scripted::Scripted;
    use super::*;

    const AES: KeyId = KeyId([1; EKI_KEY_ID_LEN]);
    const MAC: KeyId = KeyId([2; EKI_KEY_ID_LEN]);
    const EC: KeyId = KeyId([3; EKI_KEY_ID_LEN]);
    const FOREIGN: KeyId = KeyId([4; EKI_KEY_ID_LEN]);
    const FREE: KeyId = KeyId([5; EKI_KEY_ID_LEN]);
    const BLOB: [u8; EKI_WRAPPED_KEY_LEN] = [0; EKI_WRAPPED_KEY_LEN];

    fn label(text: &str) -> Label {
        Label::parse(text.as_bytes()).expect("valid test label")
    }

    /// A scripted backend holding one key of each algorithm and one foreign object.
    fn populated() -> Scripted {
        let mut backend = Scripted::default();
        for (id, alg) in [
            (AES, KeyAlg::Aes256),
            (MAC, KeyAlg::HmacSha256),
            (EC, KeyAlg::EcdsaP256),
        ] {
            backend.add(alg, &label("test"), &id);
        }
        backend.objects.insert(FOREIGN, Found::Foreign);
        backend
    }

    fn handle(backend: Scripted) -> Handle {
        Handle::new(Box::new(backend))
    }

    #[test]
    fn label_boundaries() {
        assert_eq!(Label::parse(b""), None);
        assert_eq!(Label::parse(&[b'a'; 65]), None);
        assert_eq!(Label::parse(b"a\x1f"), None);
        assert_eq!(Label::parse(b"a\x7f"), None);
        assert_eq!(Label::parse(b"a\x80"), None);
        assert_eq!(Label::parse(b"a\0b"), None);
        for text in [&b" "[..], b"~", &[b'z'; 64]] {
            assert_eq!(
                Label::parse(text).map(|l| l.as_bytes().to_vec()),
                Some(text.to_vec())
            );
        }
    }

    #[test]
    fn key_info_to_abi_pads_the_label_with_nul() {
        let info = KeyInfo {
            alg: KeyAlg::HmacSha256,
            label: label("abc"),
        };
        let abi = info.to_abi();
        assert_eq!(abi.alg, EKI_KEY_HMAC_SHA256);
        assert_eq!(
            &abi.label[..3],
            &[b'a' as c_char, b'b' as c_char, b'c' as c_char]
        );
        assert!(abi.label[3..].iter().all(|&c| c == 0));
    }

    #[test]
    fn copy_message_follows_snprintf() {
        let mut buf = [0xA5_u8; 4];
        assert_eq!(copy_message(b"hello", &mut buf[..0]), 5);
        assert_eq!(buf, [0xA5; 4], "an empty buffer is not written");
        assert_eq!(copy_message(b"hello", &mut buf[..1]), 5);
        assert_eq!(buf, [0, 0xA5, 0xA5, 0xA5]);
        assert_eq!(copy_message(b"hello", &mut buf), 5);
        assert_eq!(&buf, b"hel\0");
        assert_eq!(copy_message(b"hi", &mut buf), 2);
        assert_eq!(&buf[..3], b"hi\0");
        assert_eq!(copy_message(b"", &mut buf), 0);
        assert_eq!(buf[0], 0);
    }

    #[test]
    fn select_answers_by_selector() {
        assert_eq!(select(EKI_KS_SOFTWARE), Ok(Selected::Software));
        let pkcs11 = if cfg!(feature = "pkcs11") {
            Ok(Selected::Pkcs11)
        } else {
            Err(Error::Unsupported)
        };
        assert_eq!(select(EKI_KS_PKCS11), pkcs11);
        for backend in [0, 3, -1, i32::MIN, i32::MAX] {
            assert_eq!(select(eki_ks_backend(backend)), Err(Error::InvalidArgument));
        }
    }

    #[test]
    fn pkcs11_field_formats_precede_any_backend_work() {
        // The module does not exist: a format error must be reported before anything is loaded.
        let module_path: &[u8] = b"/nonexistent/ekibridge-test-module.so";
        let expected = |status| {
            if cfg!(feature = "pkcs11") {
                status
            } else {
                Error::Unsupported
            }
        };
        let long_label = [b'a'; PKCS11_TOKEN_LABEL_MAX_LEN + 1];
        let long_pin = [b'1'; PKCS11_USER_PIN_MAX_LEN + 1];
        let max_label = [b'a'; PKCS11_TOKEN_LABEL_MAX_LEN];
        let max_pin = [b'1'; PKCS11_USER_PIN_MAX_LEN];
        let rows: [(&[u8], &[u8], Error); 7] = [
            (b"", b"1234", Error::InvalidArgument),
            (&long_label, b"1234", Error::InvalidArgument),
            (b"eki\x01", b"1234", Error::InvalidArgument),
            (b"eki\x80", b"", Error::InvalidArgument),
            (b"ekibridge", b"", Error::InvalidArgument),
            (b"ekibridge", &long_pin, Error::InvalidArgument),
            // Both at their maximum: the formats pass and loading the module fails.
            (&max_label, &max_pin, Error::Backend),
        ];
        for (token_label, user_pin, status) in rows {
            let fields = Pkcs11Fields {
                module_path,
                token_label,
                user_pin,
            };
            assert_eq!(open_pkcs11(&fields).err(), Some(expected(status)));
        }
    }

    #[test]
    fn backend_failure_leaves_a_message_until_the_next_operation() {
        let handle = handle(Scripted {
            fail_with: Some("module said no".to_owned()),
            ..populated()
        });
        assert_eq!(handle.begin().hmac_sha256(&MAC, b"m"), Err(Error::Backend));
        assert_eq!(handle.lock().last_error(), "module said no");
        assert_eq!(
            handle.lock().last_error(),
            "module said no",
            "reading keeps it"
        );
        // A status decided by the store leaves no text, and starting an operation resets it.
        assert_eq!(
            handle.begin().hmac_sha256(&FREE, b"m"),
            Err(Error::KeyNotFound)
        );
        assert_eq!(handle.lock().last_error(), "");
    }

    #[test]
    fn backend_failure_without_text_gets_a_generic_message() {
        let handle = handle(Scripted {
            fail_with: Some(String::new()),
            ..populated()
        });
        assert_eq!(handle.begin().sign(&EC, b"m"), Err(Error::Backend));
        assert_eq!(handle.lock().last_error(), NO_REASON);
    }

    #[test]
    fn random_id_already_in_use_is_a_backend_failure() {
        let handle = handle(Scripted {
            find_always: true,
            ..Scripted::default()
        });
        let mut store = handle.begin();
        assert_eq!(
            store.generate(EKI_KEY_AES_256, b"test"),
            Err(Error::Backend)
        );
        assert!(!store.last_error().is_empty());
        // Format checks still come first.
        assert_eq!(
            store.generate(eki_key_alg(0), b"test"),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn generate_stores_a_key_under_a_fresh_id() {
        let handle = handle(Scripted::default());
        let mut store = handle.begin();
        let id = store
            .generate(EKI_KEY_HMAC_SHA256, b"fresh")
            .expect("generate succeeds");
        let info = store.get_info(&id).expect("the key exists");
        assert_eq!(info.alg, KeyAlg::HmacSha256);
        assert_eq!(info.label.as_bytes(), b"fresh");
    }

    #[test]
    fn foreign_object_exists_but_cannot_be_described() {
        let handle = handle(populated());
        let mut store = handle.begin();
        // Operations that need its algorithm or label: BACKEND with a message.
        assert_eq!(store.get_info(&FOREIGN), Err(Error::Backend));
        assert_eq!(store.last_error(), FOREIGN_OBJECT);
        assert_eq!(store.sign(&FOREIGN, b"m"), Err(Error::Backend));
        assert_eq!(store.public_key(&FOREIGN), Err(Error::Backend));
        assert_eq!(store.hmac_sha256(&FOREIGN, b"m"), Err(Error::Backend));
        assert_eq!(store.wrap(&FOREIGN, &MAC), Err(Error::Backend), "as kek");
        assert_eq!(store.wrap(&AES, &FOREIGN), Err(Error::Backend), "as key");
        let unwrap_under = |store: &mut Store, kek: &KeyId, id: &KeyId| {
            store.unwrap(kek, &BLOB, EKI_KEY_AES_256, b"copy", id)
        };
        assert_eq!(
            unwrap_under(&mut store, &FOREIGN, &FREE),
            Err(Error::Backend)
        );
        // Existence comes before description: a missing key still wins over a foreign kek.
        assert_eq!(store.wrap(&FOREIGN, &FREE), Err(Error::KeyNotFound));
        // It counts as existing: KEY_EXISTS on unwrap, and destroyable.
        assert_eq!(
            unwrap_under(&mut store, &AES, &FOREIGN),
            Err(Error::KeyExists)
        );
        assert_eq!(store.destroy(&FOREIGN), Ok(()));
        assert_eq!(store.destroy(&FOREIGN), Err(Error::KeyNotFound));
    }

    #[test]
    fn wrap_checks_existence_before_type() {
        let handle = handle(populated());
        let mut store = handle.begin();
        assert_eq!(store.wrap(&MAC, &FREE), Err(Error::KeyNotFound));
        assert_eq!(store.wrap(&MAC, &AES), Err(Error::WrongKeyType));
        assert_eq!(store.wrap(&AES, &EC), Err(Error::WrongKeyType));
        assert_eq!(store.wrap(&AES, &AES), Ok([3; EKI_WRAPPED_KEY_LEN]));
    }

    #[test]
    fn failed_unwrap_leaves_the_store_unchanged() {
        let handle = handle(Scripted {
            reject_blobs: true,
            ..populated()
        });
        let mut store = handle.begin();
        assert_eq!(
            store.unwrap(&AES, &BLOB, EKI_KEY_HMAC_SHA256, b"copy", &FREE),
            Err(Error::AuthFailed)
        );
        assert_eq!(store.get_info(&FREE), Err(Error::KeyNotFound));
        assert_eq!(
            store.unwrap(&AES, &BLOB, EKI_KEY_HMAC_SHA256, b"copy", &MAC),
            Err(Error::KeyExists)
        );
        assert_eq!(
            store.get_info(&MAC).map(|info| info.label),
            Ok(label("test"))
        );
    }

    #[test]
    fn unwrap_format_checks_precede_store_state() {
        let handle = handle(populated());
        let mut store = handle.begin();
        let rows: [(&[u8], eki_key_alg, &[u8]); 4] = [
            (&BLOB[..39], EKI_KEY_HMAC_SHA256, b"copy"),
            (&BLOB, eki_key_alg(9), b"copy"),
            (&BLOB, EKI_KEY_ECDSA_P256, b"copy"),
            (&BLOB, EKI_KEY_AES_256, b""),
        ];
        for (blob, alg, text) in rows {
            // Missing kek and a taken id are both ignored until the format checks pass.
            assert_eq!(
                store.unwrap(&FREE, blob, alg, text, &MAC),
                Err(Error::InvalidArgument)
            );
        }
    }

    #[test]
    fn poisoned_lock_is_recovered_and_the_store_still_works() {
        let handle = handle(Scripted {
            panic_in_sign: true,
            ..populated()
        });
        let result = catch_unwind(AssertUnwindSafe(|| handle.begin().sign(&EC, b"m")));
        assert!(result.is_err(), "the backend panicked");
        assert!(handle.store.is_poisoned());
        let mut store = handle.begin();
        assert_eq!(store.last_error(), "");
        assert_eq!(
            store.get_info(&EC).map(|info| info.alg),
            Ok(KeyAlg::EcdsaP256)
        );
        let id = store
            .generate(EKI_KEY_AES_256, b"after the panic")
            .expect("the store still works");
        assert_eq!(store.destroy(&id), Ok(()));
    }
}
