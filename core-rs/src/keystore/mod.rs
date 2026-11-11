//! Key store: the handle behind `eki_ks`, the logic every backend shares, and the backend
//! interface.
//!
//! The design has three layers, the same as in the C++ library:
//!
//! 1. [`Handle`] is the object an `eki_ks *` points to. It owns a mutex around the [`Store`],
//!    which holds the backend, the last-error text, the dual-control state and the audit log.
//!    One lock serialises every operation on a handle.
//! 2. [`Store`] is the logic shared by all backends. Each method is one `eki_ks_*` function and
//!    runs the per-function sequence of docs/ffi-contract.md ("Validation order", "Per-function
//!    contract" and "Key states"): selector and format checks, then the store-state checks in
//!    their fixed order (existence, type, lifecycle state, dual control), and only then the
//!    backend operation. It decides every status that follows from caller input or store state
//!    (`INVALID_ARGUMENT`, `KEY_NOT_FOUND`, `WRONG_KEY_TYPE`, `KEY_EXISTS`, `KEY_STATE`,
//!    `APPROVAL_REQUIRED`) and records a non-empty message for every backend failure. Every
//!    logged operation runs inside [`Store::audited`], which writes its audit record with the
//!    final status.
//! 3. [`Backend`] is what differs per backend: find a key's algorithm, label and state, create,
//!    public key, sign, HMAC, verify an HMAC tag, wrap, unwrap-and-store, set the state,
//!    destroy. A backend reports only success, a failure with text, an authentication failure
//!    (unwrap integrity, HMAC tag) or a broken internal invariant. No method returns key bytes,
//!    because a token may refuse to export them: wrap and unwrap are backend operations.
//!
//! Nothing here touches a C pointer. `ffi.rs` checks and converts the C arguments and calls the
//! methods of [`Store`] with Rust values and slices.

use core::ffi::c_char;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, PoisonError};

use ekicore_abi::{
    EKI_AUDIT_HASH_LEN, EKI_DESTROY_REQUEST_LEN, EKI_HMAC_SHA256_LEN, EKI_KEY_AES_256,
    EKI_KEY_ECDSA_P256, EKI_KEY_HMAC_SHA256, EKI_KEY_ID_LEN, EKI_KEY_STATE_ACTIVE,
    EKI_KEY_STATE_RETIRED, EKI_KEY_STATE_REVOKED, EKI_KS_PKCS11, EKI_KS_SOFTWARE,
    EKI_LABEL_MAX_LEN, EKI_P256_PUBLIC_KEY_LEN, EKI_P256_SIGNATURE_LEN, EKI_WRAPPED_KEY_LEN,
    eki_key_alg, eki_key_id, eki_key_info, eki_key_info_v2, eki_key_state, eki_ks_backend,
    eki_status,
};

use crate::ecdsa;
use crate::error::Error;

pub mod audit;
pub mod dual;
pub mod software;

#[cfg(feature = "pkcs11")]
pub mod pkcs11;

use audit::{AuditLog, Op};
use dual::DualControl;

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

/// The lifecycle state of a stored key (docs/ffi-contract.md, "Key states"). The order is the
/// order of the transitions: a key only ever moves to a later state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyState {
    /// Generated or unwrapped; every operation of the algorithm is allowed.
    Active,
    /// Replaced by `eki_ks_rotate`: may still check or recover what it once protected.
    Retired,
    /// Revoked by `eki_ks_revoke`: may only be described, revoked again and destroyed.
    Revoked,
}

/// The uses of a key whose permission depends on its state: the rows of the state table that
/// are not allowed in every state. Describing, revoking, destroying and requesting the
/// destruction of a key are allowed in every state and have no entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Usage {
    /// `get_public_key`.
    PublicKey,
    /// `sign`.
    Sign,
    /// `hmac_sha256`: make a tag.
    MakeTag,
    /// `hmac_sha256_verify`: check a tag.
    CheckTag,
    /// `wrap`, as the key-encryption key.
    WrapAsKek,
    /// `wrap`, as the key being wrapped.
    BeWrapped,
    /// `unwrap`, as the key-encryption key.
    UnwrapAsKek,
    /// `rotate`, as the old key.
    RotateAway,
}

impl KeyState {
    /// The state table: whether a key in this state may be used for `usage`. A retired key may
    /// still check or recover what it once protected, and may not protect anything new.
    pub fn permits(self, usage: Usage) -> bool {
        match self {
            Self::Active => true,
            Self::Retired => match usage {
                Usage::PublicKey | Usage::CheckTag | Usage::BeWrapped | Usage::UnwrapAsKek => true,
                Usage::Sign | Usage::MakeTag | Usage::WrapAsKek | Usage::RotateAway => false,
            },
            Self::Revoked => false,
        }
    }

    /// The C value of the state.
    pub fn to_abi(self) -> eki_key_state {
        match self {
            Self::Active => EKI_KEY_STATE_ACTIVE,
            Self::Retired => EKI_KEY_STATE_RETIRED,
            Self::Revoked => EKI_KEY_STATE_REVOKED,
        }
    }
}

/// `KEY_STATE` unless `state` permits `usage`.
fn permit(state: KeyState, usage: Usage) -> Result<(), Error> {
    if state.permits(usage) {
        Ok(())
    } else {
        Err(Error::KeyState)
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

    /// The C form: the text NUL-padded through byte 64.
    fn to_abi(self) -> [c_char; EKI_LABEL_MAX_LEN + 1] {
        let mut label: [c_char; EKI_LABEL_MAX_LEN + 1] = [0; EKI_LABEL_MAX_LEN + 1];
        for (dst, &src) in label.iter_mut().zip(self.as_bytes()) {
            // Label bytes are `0x20..=0x7E`, so the value is the same whether `c_char` is signed
            // or not.
            *dst = src as c_char;
        }
        label
    }
}

/// What the library knows of a stored key: its algorithm, label and lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyInfo {
    /// The algorithm.
    pub alg: KeyAlg,
    /// The label.
    pub label: Label,
    /// The lifecycle state.
    pub state: KeyState,
}

impl KeyInfo {
    /// The C form of `eki_ks_get_info`: the selector value and the label.
    pub fn to_abi(&self) -> eki_key_info {
        eki_key_info {
            alg: self.alg.to_abi(),
            label: self.label.to_abi(),
        }
    }

    /// The C form of `eki_ks_get_info_v2`: the selector value, the state and the label.
    pub fn to_abi_v2(&self) -> eki_key_info_v2 {
        eki_key_info_v2 {
            alg: self.alg.to_abi(),
            state: self.state.to_abi(),
            label: self.label.to_abi(),
        }
    }
}

/// What carries an id, when something does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Found {
    /// A key this library can describe.
    Key(KeyInfo),
    /// An object that carries the id but is not a key this library can describe: a PKCS#11
    /// object of another shape, or one whose label is not a valid label, or one whose usage
    /// attributes form none of the three states (docs/ffi-contract.md, "Foreign objects"). It
    /// counts as existing (`KEY_EXISTS` on unwrap, destroyable); an operation that needs its
    /// algorithm, label or state fails as a backend failure. The software backend never reports
    /// it.
    Foreign,
}

/// How a backend operation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackendError {
    /// The backend itself failed (an RNG, a crypto crate, the PKCS#11 module): `EKI_ERR_BACKEND`.
    /// The text becomes the handle's last-error message; it names the operation and the cause.
    Failed(String),
    /// The wrapped key failed the RFC 3394 integrity check, or the HMAC tag does not match:
    /// `EKI_ERR_AUTH_FAILED`. Only [`Backend::unwrap`] and [`Backend::hmac_sha256_verify`]
    /// report it. The text, empty when there is nothing to add, becomes the last-error message:
    /// a token reports a failed integrity check with a return code that other causes share,
    /// so its unwrap names the `CKR_*` code.
    AuthFailed(String),
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
/// one as [`BackendError::Internal`]. In particular the store has checked the key's state
/// against the state table before it calls an operation, so a backend never refuses an
/// operation because of the state.
///
/// Panics: a method may panic (the FFI barrier turns that into `EKI_ERR_INTERNAL`), but at every
/// point where it can panic the backend must be as it was before the call or as a completed call
/// leaves it, because the handle recovers its lock after a panic and goes on using the backend
/// (see [`Handle::lock`]).
///
/// Dropping the backend wipes the secrets it holds in memory (software) or closes its session
/// (PKCS#11), and must not panic.
pub trait Backend: Send {
    /// What carries `id`, with the key's state: `None` when no object of any class does.
    fn find(&mut self, id: &KeyId) -> BackendResult<Option<Found>>;

    /// Creates a new ACTIVE key of `alg` labelled `label` under `id`.
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

    /// Checks that `tag` is HMAC-SHA256 of `msg` under the key `id`, in constant time;
    /// [`BackendError::AuthFailed`] when it is not. `msg` may be empty.
    ///
    /// Precondition: `id` names an HMAC-SHA256 key.
    fn hmac_sha256_verify(
        &mut self,
        id: &KeyId,
        msg: &[u8],
        tag: &[u8; EKI_HMAC_SHA256_LEN],
    ) -> BackendResult<()>;

    /// The RFC 3394 AES Key Wrap of the secret key `key` under `kek`. `kek` and `key` may be the
    /// same id.
    ///
    /// Precondition: `kek` names an AES-256 key, `key` an AES-256 or HMAC-SHA256 key.
    fn wrap(&mut self, kek: &KeyId, key: &KeyId) -> BackendResult<[u8; EKI_WRAPPED_KEY_LEN]>;

    /// Unwraps `blob` under `kek` and stores the 32-byte result as a new ACTIVE key of `alg`
    /// labelled `label` under `id`. [`BackendError::AuthFailed`] when the blob fails the
    /// integrity check.
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

    /// Moves the key `id` to `state`. A key never moves back: asked for a state earlier than
    /// its own, a backend leaves the key as it is.
    ///
    /// Precondition: `id` names a key of the library. On failure the key is in its old state,
    /// or (PKCS#11, revoking an ACTIVE key) RETIRED; it is never left in a state outside the
    /// three.
    fn set_state(&mut self, id: &KeyId, state: KeyState) -> BackendResult<()>;

    /// Removes every object that carries `id`; the software backend wipes the key material.
    ///
    /// Precondition: something carries `id`.
    fn destroy(&mut self, id: &KeyId) -> BackendResult<()>;
}

// --- Layer 1: the handle ------------------------------------------------------------------------

/// The object an `eki_ks *` points to: the store behind a mutex.
///
/// `eki_ks_open` and `eki_ks_open_v2` box one and hand the caller the raw pointer;
/// `eki_ks_close` takes the box back and calls [`Handle::close`], which writes the `close`
/// record and drops the backend and with it every key.
pub struct Handle {
    store: Mutex<Store>,
}

impl Handle {
    /// A handle over `backend` without audit log and without dual control, with an empty
    /// last-error message.
    pub fn new(backend: Box<dyn Backend>) -> Self {
        Self::with(backend, None, None)
    }

    fn with(backend: Box<dyn Backend>, dual: Option<DualControl>, audit: Option<AuditLog>) -> Self {
        Self {
            store: Mutex::new(Store {
                backend,
                last_error: String::new(),
                dual,
                audit,
            }),
        }
    }

    /// The handle `eki_ks_open_v2` returns: over an open backend, with the dual-control state
    /// and the audit log of the configuration. The `open` record is the first one the handle
    /// writes; when it cannot be written the handle is dropped again, which closes the backend
    /// and releases the log, and the open fails as a backend failure.
    pub fn open(
        backend: Box<dyn Backend>,
        dual: Option<DualControl>,
        audit: Option<AuditLog>,
    ) -> Result<Self, Error> {
        let handle = Self::with(backend, dual, audit);
        handle.lock().log_lifecycle(Op::Open)?;
        Ok(handle)
    }

    /// Closes the handle: writes the `close` record, the last one the handle writes, then drops
    /// the store (the backend first, the audit log and its lock last). `eki_ks_close` returns no
    /// status, so a `close` record that cannot be written is not reported.
    pub fn close(self) {
        let store = self
            .store
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner);
        let mut store = store;
        let _ = store.log_lifecycle(Op::Close);
    }

    /// Starts an operation on the handle: takes the lock and resets the last-error message to
    /// `""`, as every store call except `last_error_message` and `close` does on entry
    /// (docs/ffi-contract.md, "Last error message"). The guard keeps the handle locked until the
    /// operation ends.
    pub fn begin(&self) -> MutexGuard<'_, Store> {
        let mut store = self.lock();
        store.last_error.clear();
        store
    }

    /// Takes the lock without starting an operation, for reading the last-error message.
    ///
    /// A panic while the lock is held poisons the mutex. The lock is recovered instead of the
    /// poison being propagated ("Thread safety" in docs/ffi-contract.md), and that is sound
    /// because no panic can leave the store inconsistent:
    ///
    /// - `last_error` only ever changes by `clear` or by a move of a finished `String`, neither
    ///   of which can panic midway, so it holds `""` or a complete message. The next operation
    ///   resets it on entry anyway.
    /// - The dual-control state changes only by single map operations whose keys are 32-byte
    ///   arrays with the derived `Ord` (`insert`, `remove`, `retain` with a comparison of key
    ///   ids, an assignment of a `Copy` value), each made after everything that can fail; none
    ///   can stop halfway, and an allocation failure aborts instead of unwinding. The approver
    ///   keys never change after open.
    /// - The audit log's chain (count, head, length) changes in one assignment after the record
    ///   was written and flushed; a panic before it leaves the chain as it was. A record that
    ///   was written but not yet counted cannot exist: nothing between the write and the
    ///   assignment can panic. [`Store::audited`] writes the record of an operation that
    ///   panicked (status `EKI_ERR_INTERNAL`) before the panic continues.
    /// - The [`Backend`] contract requires each method to leave the backend unchanged or
    ///   completely changed at every point where it can panic. The software backend meets it:
    ///   key generation, signing, HMAC, wrap and unwrap work on locals and on borrowed keys, and
    ///   its only mutations are a single `BTreeMap` insertion (after everything that can fail),
    ///   a single removal and the assignment of a key's state. None can stop halfway: the key
    ///   comparisons are the derived `Ord` of a 16-byte array and the values are moved, so
    ///   nothing in them can panic, and an allocation failure aborts the process instead of
    ///   unwinding.
    /// - The PKCS#11 backend meets it too. Its own state, the session and the module reference,
    ///   is never changed by an operation. Each change to the token is one PKCS#11 call
    ///   (generate, generate pair, unwrap, set attributes, destroy object), which the token
    ///   completes or rejects whole, and keys are looked up again on every call, so nothing
    ///   cached can go stale. A state change of several calls passes only through states of the
    ///   table. An object search is finished by the drop of the search iterator, which also runs
    ///   during unwinding, so a panic cannot leave the session in the middle of a search.
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

/// A backend whose configuration passed its format checks and that is not opened yet.
pub enum BackendConfig {
    /// The software backend, which has no configuration.
    Software,
    /// The PKCS#11 backend with its checked configuration.
    #[cfg(feature = "pkcs11")]
    Pkcs11(pkcs11::Config),
}

impl BackendConfig {
    /// Validation step 3 for the PKCS#11 fields, in field order: the token label and the PIN
    /// (`INVALID_ARGUMENT`). Nothing is loaded yet.
    ///
    /// Called only after [`select`] answered [`Selected::Pkcs11`], which it does only when the
    /// backend is compiled in.
    pub fn pkcs11(fields: &Pkcs11Fields<'_>) -> Result<Self, Error> {
        #[cfg(feature = "pkcs11")]
        {
            pkcs11::Config::parse(fields).map(Self::Pkcs11)
        }
        #[cfg(not(feature = "pkcs11"))]
        {
            let _ = fields;
            Err(Error::Unsupported)
        }
    }

    /// Opens the backend. For PKCS#11: load, initialise, slot, session and login, where every
    /// failure is `EKI_ERR_BACKEND`. There is no handle yet to carry a message, so the reason is
    /// dropped and only the status is reported ("Opening a store with ABI 2" in
    /// docs/ffi-contract.md).
    fn open(self) -> Result<Box<dyn Backend>, Error> {
        match self {
            Self::Software => Ok(Box::new(software::Software::new())),
            #[cfg(feature = "pkcs11")]
            Self::Pkcs11(config) => match pkcs11::Pkcs11Backend::open(config) {
                Ok(backend) => Ok(Box::new(backend)),
                Err(BackendError::Internal(_)) => Err(Error::Internal),
                Err(BackendError::Failed(_) | BackendError::AuthFailed(_)) => Err(Error::Backend),
            },
        }
    }
}

/// Opens a PKCS#11 store without audit log or approvers: the format checks of the PKCS#11
/// fields, then the backend.
pub fn open_pkcs11(fields: &Pkcs11Fields<'_>) -> Result<Handle, Error> {
    let backend = BackendConfig::pkcs11(fields)?.open()?;
    Ok(Handle::new(backend))
}

/// Everything `eki_ks_open_v2` needs once every field has passed its NULL and format checks.
/// `eki_ks_open` builds the same value with no log and no approvers.
pub struct OpenConfig {
    /// The backend.
    pub backend: BackendConfig,
    /// The audit log path, 1 to `EKI_AUDIT_PATH_MAX_LEN` bytes; `None` for no log.
    pub audit_log: Option<PathBuf>,
    /// The approver keys; `None` for single control.
    pub dual: Option<DualControl>,
}

/// The last two steps of `eki_ks_open_v2`: the backend is opened, then the audit log (an
/// existing log that fails verification is `AUTH_FAILED`, any I/O or locking failure
/// `BACKEND`), then the `open` record is written. A failure after the backend opened drops it
/// again, which closes it.
pub fn open(config: OpenConfig) -> Result<Handle, Error> {
    let backend = config.backend.open()?;
    let audit = match &config.audit_log {
        Some(path) => Some(AuditLog::open(path).map_err(|error| match error {
            audit::OpenError::Invalid => Error::AuthFailed,
            audit::OpenError::Failed(_) => Error::Backend,
        })?),
        None => None,
    };
    Handle::open(backend, config.dual, audit)
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
const FOREIGN_OBJECT: &str = "the object with this id is not a key this library can describe \
                              (unknown shape, label or usage attributes)";

/// What one call contributes to its audit record, and what has to be undone when the record
/// cannot be written.
#[derive(Clone, Copy, Debug)]
struct Entry {
    op: Op,
    /// The `key` field: set from the caller's ids at the start, or once the call establishes
    /// the id (the new key of `generate`, the key a request of `destroy_approve` names).
    key: Option<KeyId>,
    /// The `key2` field.
    key2: Option<KeyId>,
    /// A key the call created, destroyed again when the record cannot be written.
    created: Option<KeyId>,
    /// The call destroyed a key, which cannot be undone.
    destroyed: bool,
    /// The call moved a key to a later state, which cannot be undone.
    state_changed: bool,
}

impl Entry {
    fn new(op: Op, key: Option<KeyId>, key2: Option<KeyId>) -> Self {
        Self {
            op,
            key,
            key2,
            created: None,
            destroyed: false,
            state_changed: false,
        }
    }
}

/// The state behind a handle's lock: the backend, the last-error message, the dual-control state
/// and the audit log, and the logic every backend shares.
///
/// The methods run with the lock held, inside an operation started by [`Handle::begin`]. Each
/// one follows its sequence in docs/ffi-contract.md ("Validation order" and "Per-function
/// contract") from top to bottom; the first failing step decides the error.
pub struct Store {
    backend: Box<dyn Backend>,
    last_error: String,
    /// The approvers and pending destroy requests of a handle with dual control.
    dual: Option<DualControl>,
    /// The audit log, last so that it is dropped (and its lock released) after the backend.
    audit: Option<AuditLog>,
}

impl Store {
    /// The message of the most recent operation on the handle: `""` after a success, non-empty
    /// after a backend failure.
    pub fn last_error(&self) -> &str {
        &self.last_error
    }

    /// `eki_ks_generate`: `alg` → label format → a fresh random id → the new key.
    pub fn generate(&mut self, alg: eki_key_alg, label: &[u8]) -> Result<KeyId, Error> {
        self.audited(Entry::new(Op::Generate, None, None), |store, entry| {
            let alg = KeyAlg::parse(alg).ok_or(Error::InvalidArgument)?;
            let label = Label::parse(label).ok_or(Error::InvalidArgument)?;
            let id = store.fresh_id()?;
            store.call(|backend| backend.create(alg, &label, &id))?;
            entry.key = Some(id);
            entry.created = Some(id);
            Ok(id)
        })
    }

    /// `eki_ks_get_info` and `eki_ks_get_info_v2`: the algorithm, label and state of a key of
    /// any type in any state. Not logged.
    pub fn get_info(&mut self, id: &KeyId) -> Result<KeyInfo, Error> {
        self.key_info(id)
    }

    /// `eki_ks_get_public_key`: missing → not ECDSA → state.
    pub fn public_key(&mut self, id: &KeyId) -> Result<[u8; EKI_P256_PUBLIC_KEY_LEN], Error> {
        self.audited(Entry::new(Op::GetPublicKey, Some(*id), None), |store, _| {
            store.usable(id, KeyAlg::EcdsaP256, Usage::PublicKey)?;
            store.call(|backend| backend.public_key(id))
        })
    }

    /// `eki_ks_sign`: missing → not ECDSA → state.
    pub fn sign(&mut self, id: &KeyId, msg: &[u8]) -> Result<[u8; EKI_P256_SIGNATURE_LEN], Error> {
        self.audited(Entry::new(Op::Sign, Some(*id), None), |store, _| {
            store.usable(id, KeyAlg::EcdsaP256, Usage::Sign)?;
            store.call(|backend| backend.sign(id, msg))
        })
    }

    /// `eki_ks_hmac_sha256`: missing → not HMAC → state.
    pub fn hmac_sha256(
        &mut self,
        id: &KeyId,
        msg: &[u8],
    ) -> Result<[u8; EKI_HMAC_SHA256_LEN], Error> {
        self.audited(Entry::new(Op::Hmac, Some(*id), None), |store, _| {
            store.usable(id, KeyAlg::HmacSha256, Usage::MakeTag)?;
            store.call(|backend| backend.hmac_sha256(id, msg))
        })
    }

    /// `eki_ks_hmac_sha256_verify`: `tag` not 32 bytes (`INVALID_ARGUMENT`) → missing → not
    /// HMAC → state → the comparison, which the backend makes in constant time (`AUTH_FAILED`).
    pub fn hmac_sha256_verify(&mut self, id: &KeyId, msg: &[u8], tag: &[u8]) -> Result<(), Error> {
        self.audited(Entry::new(Op::HmacVerify, Some(*id), None), |store, _| {
            let tag: &[u8; EKI_HMAC_SHA256_LEN] =
                tag.try_into().map_err(|_| Error::InvalidArgument)?;
            store.usable(id, KeyAlg::HmacSha256, Usage::CheckTag)?;
            store.call(|backend| backend.hmac_sha256_verify(id, msg, tag))
        })
    }

    /// `eki_ks_wrap`: kek exists → key exists → kek is AES-256 → key is AES-256 or HMAC-SHA256
    /// → kek state → key state. Self-wrap (`kek == key`) is allowed.
    pub fn wrap(&mut self, kek: &KeyId, key: &KeyId) -> Result<[u8; EKI_WRAPPED_KEY_LEN], Error> {
        self.audited(Entry::new(Op::Wrap, Some(*key), Some(*kek)), |store, _| {
            let kek_found = store.existing(kek)?;
            let key_found = store.existing(key)?;
            let kek_info = store.described(kek_found)?;
            if kek_info.alg != KeyAlg::Aes256 {
                return Err(Error::WrongKeyType);
            }
            let key_info = store.described(key_found)?;
            if !key_info.alg.is_wrappable() {
                return Err(Error::WrongKeyType);
            }
            permit(kek_info.state, Usage::WrapAsKek)?;
            permit(key_info.state, Usage::BeWrapped)?;
            store.call(|backend| backend.wrap(kek, key))
        })
    }

    /// `eki_ks_unwrap`: `alg` unknown → `blob` not 40 bytes → `alg` is ECDSA → label format, all
    /// `INVALID_ARGUMENT`; kek exists → kek is AES-256 → kek state → `id` free (any object
    /// counts) → the integrity check, which the backend performs (`AUTH_FAILED`).
    pub fn unwrap(
        &mut self,
        kek: &KeyId,
        blob: &[u8],
        alg: eki_key_alg,
        label: &[u8],
        id: &KeyId,
    ) -> Result<(), Error> {
        self.audited(
            Entry::new(Op::Unwrap, Some(*id), Some(*kek)),
            |store, entry| {
                let alg = KeyAlg::parse(alg).ok_or(Error::InvalidArgument)?;
                let blob: &[u8; EKI_WRAPPED_KEY_LEN] =
                    blob.try_into().map_err(|_| Error::InvalidArgument)?;
                if !alg.is_wrappable() {
                    return Err(Error::InvalidArgument);
                }
                let label = Label::parse(label).ok_or(Error::InvalidArgument)?;
                store.usable(kek, KeyAlg::Aes256, Usage::UnwrapAsKek)?;
                if store.call(|backend| backend.find(id))?.is_some() {
                    return Err(Error::KeyExists);
                }
                store.call(|backend| backend.unwrap(kek, blob, alg, &label, id))?;
                entry.created = Some(*id);
                Ok(())
            },
        )
    }

    /// `eki_ks_rotate`: old exists → old ACTIVE → a fresh random id → a new ACTIVE key with the
    /// old key's algorithm and label → the old key becomes RETIRED. When retiring fails the new
    /// key is destroyed again and the call fails with the retiring failure.
    pub fn rotate(&mut self, old: &KeyId) -> Result<KeyId, Error> {
        self.audited(Entry::new(Op::Rotate, Some(*old), None), |store, entry| {
            let info = store.key_info(old)?;
            permit(info.state, Usage::RotateAway)?;
            let new = store.fresh_id()?;
            store.call(|backend| backend.create(info.alg, &info.label, &new))?;
            if let Err(error) = store.call(|backend| backend.set_state(old, KeyState::Retired)) {
                store.discard(&new, "the new key");
                return Err(error);
            }
            entry.key2 = Some(new);
            entry.created = Some(new);
            entry.state_changed = true;
            Ok(new)
        })
    }

    /// `eki_ks_revoke`: exists → REVOKED. A REVOKED key stays as it is and the call succeeds.
    pub fn revoke(&mut self, id: &KeyId) -> Result<(), Error> {
        self.audited(Entry::new(Op::Revoke, Some(*id), None), |store, entry| {
            let info = store.key_info(id)?;
            if info.state == KeyState::Revoked {
                return Ok(());
            }
            store.call(|backend| backend.set_state(id, KeyState::Revoked))?;
            entry.state_changed = true;
            Ok(())
        })
    }

    /// `eki_ks_destroy`: any object that carries `id`, foreign ones included; missing →
    /// `KEY_NOT_FOUND`; a handle with dual control → `APPROVAL_REQUIRED` and nothing changes.
    pub fn destroy(&mut self, id: &KeyId) -> Result<(), Error> {
        self.audited(Entry::new(Op::Destroy, Some(*id), None), |store, entry| {
            store.existing(id)?;
            if store.dual.is_some() {
                return Err(Error::ApprovalRequired);
            }
            store.call(|backend| backend.destroy(id))?;
            entry.destroyed = true;
            Ok(())
        })
    }

    /// `eki_ks_destroy_request`: a handle without approvers → `UNSUPPORTED`; missing →
    /// `KEY_NOT_FOUND`; then 32 fresh random bytes, remembered for the key in place of an
    /// earlier request for it.
    pub fn destroy_request(&mut self, id: &KeyId) -> Result<dual::Request, Error> {
        self.audited(
            Entry::new(Op::DestroyRequest, Some(*id), None),
            |store, _| {
                if store.dual.is_none() {
                    return Err(Error::Unsupported);
                }
                store.existing(id)?;
                let request = store.fresh_request()?;
                if let Some(dual) = store.dual.as_mut() {
                    dual.replace(*id, request);
                }
                Ok(request)
            },
        )
    }

    /// `eki_ks_destroy_approve`: a handle without approvers → `UNSUPPORTED`; the approver key is
    /// not a valid point → `INVALID_ARGUMENT`; no pending request with this value →
    /// `KEY_NOT_FOUND`; the key is not an approver, or the signature does not verify →
    /// `AUTH_FAILED`. A valid approval is recorded and the approvals still needed are returned
    /// (a second approval by the same approver changes nothing). The approval that completes
    /// the request destroys the key and removes the request: `KEY_NOT_FOUND` (request removed)
    /// if the key is gone by then.
    pub fn destroy_approve(
        &mut self,
        request: &dual::Request,
        approver: &dual::PublicKey,
        sig: &[u8; EKI_P256_SIGNATURE_LEN],
    ) -> Result<u32, Error> {
        self.audited(
            Entry::new(Op::DestroyApprove, None, None),
            |store, entry| {
                let Some(dual) = store.dual.as_ref() else {
                    return Err(Error::Unsupported);
                };
                ecdsa::p256_check_public_key(approver)?;
                let pending = dual.pending(request).ok_or(Error::KeyNotFound)?;
                entry.key = Some(pending.key);
                let index = dual.approver_index(approver).ok_or(Error::AuthFailed)?;
                let message = dual::approval_message(request, &pending.key);
                ecdsa::p256_verify(approver, &message, sig)?;
                let approved = pending.approved_by(index);
                if approved.remaining() > 0 {
                    if let Some(dual) = store.dual.as_mut() {
                        dual.update(request, approved);
                    }
                    return Ok(approved.remaining());
                }
                store.complete_destroy(request, &pending.key, entry)
            },
        )
    }

    /// `eki_ks_audit_head`: the hash and `seq` of the last record; a handle without an audit log
    /// → `UNSUPPORTED`. Not logged.
    pub fn audit_head(&self) -> Result<([u8; EKI_AUDIT_HASH_LEN], u64), Error> {
        self.audit
            .as_ref()
            .map(AuditLog::head)
            .ok_or(Error::Unsupported)
    }

    // --- Steps shared by the operations ---

    /// The end of an approved request: the key still exists → it is destroyed → the request is
    /// removed. A key that is gone ends the request with `KEY_NOT_FOUND`. A backend failure
    /// keeps the request with the approvals it had before this call.
    fn complete_destroy(
        &mut self,
        request: &dual::Request,
        key: &KeyId,
        entry: &mut Entry,
    ) -> Result<u32, Error> {
        if self.call(|backend| backend.find(key))?.is_none() {
            self.forget_request(request);
            return Err(Error::KeyNotFound);
        }
        self.call(|backend| backend.destroy(key))?;
        entry.destroyed = true;
        self.forget_request(request);
        Ok(0)
    }

    fn forget_request(&mut self, request: &dual::Request) {
        if let Some(dual) = self.dual.as_mut() {
            dual.remove(request);
        }
    }

    /// A fresh id for `generate` and `rotate`: 16 bytes from the operating system's RNG. An id
    /// that something already carries would mean a broken RNG; it is a backend failure and
    /// never overwrites a key, which also keeps the precondition of [`Backend::create`].
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

    /// A fresh destroy request: 32 bytes from the operating system's RNG, different from every
    /// pending request (a repeat would mean a broken RNG and is a backend failure).
    fn fresh_request(&mut self) -> Result<dual::Request, Error> {
        let mut request = [0; EKI_DESTROY_REQUEST_LEN];
        if let Err(error) = getrandom::fill(&mut request) {
            return Err(
                self.backend_failure(format!("getrandom for a destroy request failed: {error}"))
            );
        }
        if self
            .dual
            .as_ref()
            .is_some_and(|dual| dual.is_pending(&request))
        {
            return Err(
                self.backend_failure("the random destroy request is already in use".to_owned())
            );
        }
        Ok(request)
    }

    /// The object that carries `id`: `KEY_NOT_FOUND` when nothing does.
    fn existing(&mut self, id: &KeyId) -> Result<Found, Error> {
        self.call(|backend| backend.find(id))?
            .ok_or(Error::KeyNotFound)
    }

    /// The algorithm, label and state of an object that exists: an object this library cannot
    /// describe is a backend failure ("Foreign objects" in docs/ffi-contract.md).
    fn described(&mut self, found: Found) -> Result<KeyInfo, Error> {
        match found {
            Found::Key(info) => Ok(info),
            Found::Foreign => Err(self.backend_failure(FOREIGN_OBJECT.to_owned())),
        }
    }

    /// The algorithm, label and state of the key `id`: `KEY_NOT_FOUND`, then a foreign object.
    fn key_info(&mut self, id: &KeyId) -> Result<KeyInfo, Error> {
        let found = self.existing(id)?;
        self.described(found)
    }

    /// `id` names a key of algorithm `wanted`: `KEY_NOT_FOUND`, then `WRONG_KEY_TYPE`.
    fn require(&mut self, id: &KeyId, wanted: KeyAlg) -> Result<KeyInfo, Error> {
        let info = self.key_info(id)?;
        if info.alg == wanted {
            Ok(info)
        } else {
            Err(Error::WrongKeyType)
        }
    }

    /// `id` names a key of algorithm `wanted` whose state permits `usage`: `KEY_NOT_FOUND`,
    /// then `WRONG_KEY_TYPE`, then `KEY_STATE`. The state check comes right after the existence
    /// and type checks of the same key.
    fn usable(&mut self, id: &KeyId, wanted: KeyAlg, usage: Usage) -> Result<KeyInfo, Error> {
        let info = self.require(id, wanted)?;
        permit(info.state, usage)?;
        Ok(info)
    }

    /// Destroys a key this call created, after a later step of the call failed. The failure of
    /// the call is already decided and its message recorded; a failure here is added to that
    /// message.
    fn discard(&mut self, id: &KeyId, what: &str) {
        if let Err(error) = self.backend.destroy(id) {
            let reason = match error {
                BackendError::Failed(text) => text,
                BackendError::AuthFailed(text) if text.is_empty() => {
                    "authentication failure".to_owned()
                }
                BackendError::AuthFailed(text) => text,
                BackendError::Internal(text) => text.to_owned(),
            };
            self.last_error
                .push_str(&format!("; destroying {what} again failed: {reason}"));
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
    /// a generic one when the backend gave none; an internal failure's text too, and that of an
    /// authentication failure, which may be empty.
    fn record<T>(&mut self, result: BackendResult<T>) -> Result<T, Error> {
        match result {
            Ok(value) => Ok(value),
            Err(BackendError::Failed(text)) if text.is_empty() => {
                Err(self.backend_failure(NO_REASON.to_owned()))
            }
            Err(BackendError::Failed(text)) => Err(self.backend_failure(text)),
            Err(BackendError::AuthFailed(text)) => {
                self.last_error = text;
                Err(Error::AuthFailed)
            }
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

    // --- The audit record of a call ---

    /// Runs one logged operation and writes its audit record with the status the call returns.
    /// This is the one place records of operations are written, so no operation can forget its
    /// record, and it writes exactly one per call.
    ///
    /// When the record cannot be written the call fails with `BACKEND` and a message that says
    /// so, even if the operation succeeded, and what the operation did is undone where that is
    /// possible: a key it created is destroyed again, and the pending destroy requests are put
    /// back as they were. A destroyed key and a state change cannot be undone; the message says
    /// which happened. Without an audit log nothing is written and the result passes through.
    ///
    /// A panic in the operation is caught long enough to write its record with status
    /// `EKI_ERR_INTERNAL`, the status the FFI barrier returns for it, and then continues.
    fn audited<T>(
        &mut self,
        entry: Entry,
        body: impl FnOnce(&mut Self, &mut Entry) -> Result<T, Error>,
    ) -> Result<T, Error> {
        if self.audit.is_none() {
            let mut entry = entry;
            return body(self, &mut entry);
        }
        let requests_before = self.dual.clone();
        let mut entry = entry;
        // `AssertUnwindSafe`: after a caught panic only the audit log and `entry` are used
        // before the panic continues. `entry` holds `Copy` values that are each assigned whole,
        // and the store is consistent at every point where an operation can panic (the argument
        // at `Handle::lock`).
        let outcome = catch_unwind(AssertUnwindSafe(|| body(self, &mut entry)));
        let result = match outcome {
            Ok(result) => result,
            Err(payload) => {
                let _ = self.append(&entry, eki_status::EKI_ERR_INTERNAL);
                resume_unwind(payload);
            }
        };
        let status = result
            .as_ref()
            .map_or_else(|error| eki_status::from(*error), |_| eki_status::EKI_OK);
        match self.append(&entry, status) {
            Ok(()) => result,
            Err(text) => Err(self.unlogged(&entry, requests_before, text)),
        }
    }

    /// The failure of a call whose record could not be written: undoes what can be undone and
    /// records a message that names what could not.
    fn unlogged(
        &mut self,
        entry: &Entry,
        requests_before: Option<DualControl>,
        text: String,
    ) -> Error {
        self.last_error = text;
        if let Some(id) = entry.created {
            self.last_error
                .push_str("; the key the call created was destroyed again");
            self.discard(&id, "that key");
        }
        if entry.destroyed {
            self.last_error
                .push_str("; the key was destroyed and its destruction is not logged");
        } else {
            self.dual = requests_before;
        }
        if entry.state_changed {
            self.last_error
                .push_str("; the state change of the key took effect and is not logged");
        }
        Error::Backend
    }

    /// Writes the record of `entry` with `status` at the current time. Without an audit log
    /// there is nothing to write.
    fn append(&mut self, entry: &Entry, status: eki_status) -> Result<(), String> {
        let Some(audit) = self.audit.as_mut() else {
            return Ok(());
        };
        let fields = audit::Fields {
            time: audit::Timestamp::now()?,
            op: entry.op,
            key: entry.key,
            key2: entry.key2,
            status: audit::status_value(status),
        };
        audit.append(&fields)
    }

    /// Writes the `open` or `close` record of the handle, both with status 0 and empty keys.
    fn log_lifecycle(&mut self, op: Op) -> Result<(), Error> {
        let entry = Entry::new(op, None, None);
        self.append(&entry, eki_status::EKI_OK)
            .map_err(|text| self.backend_failure(text))
    }
}

/// A scripted backend for the unit tests of the store logic and of the FFI layer: it reaches
/// paths the software backend cannot (backend failures, foreign objects, an id collision after a
/// random draw, a panic under the lock, a state change that fails).
#[cfg(test)]
pub(crate) mod scripted {
    use std::collections::BTreeMap;

    use super::*;

    /// Each object it holds is described by a [`Found`]; operations succeed with fixed outputs
    /// unless told otherwise. The tag of every message is 32 bytes of 2.
    #[derive(Default)]
    pub(crate) struct Scripted {
        /// The objects, by id.
        pub(crate) objects: BTreeMap<KeyId, Found>,
        /// Every `find` reports something, whatever the id (a colliding RNG).
        pub(crate) find_always: bool,
        /// Every operation other than `find` fails with this text.
        pub(crate) fail_with: Option<String>,
        /// `set_state` fails with a text.
        pub(crate) fail_set_state: bool,
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
            self.add_in(KeyState::Active, alg, label, id);
        }

        pub(crate) fn add_in(&mut self, state: KeyState, alg: KeyAlg, label: &Label, id: &KeyId) {
            let info = KeyInfo {
                alg,
                label: *label,
                state,
            };
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

        fn hmac_sha256_verify(&mut self, _: &KeyId, _: &[u8], tag: &[u8; 32]) -> BackendResult<()> {
            self.outcome()?;
            if *tag == [2; EKI_HMAC_SHA256_LEN] {
                Ok(())
            } else {
                Err(BackendError::AuthFailed(String::new()))
            }
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
                return Err(BackendError::AuthFailed(String::new()));
            }
            self.add(alg, label, id);
            Ok(())
        }

        fn set_state(&mut self, id: &KeyId, state: KeyState) -> BackendResult<()> {
            self.outcome()?;
            if self.fail_set_state {
                return Err(BackendError::Failed("the state did not change".to_owned()));
            }
            match self.objects.get_mut(id) {
                Some(Found::Key(info)) => {
                    info.state = info.state.max(state);
                    Ok(())
                }
                _ => Err(BackendError::Internal("set_state of an id that is no key")),
            }
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

    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;

    use super::audit::Chain;
    use super::audit::recorder::Recorder;
    use super::scripted::Scripted;
    use super::*;

    const AES: KeyId = KeyId([1; EKI_KEY_ID_LEN]);
    const MAC: KeyId = KeyId([2; EKI_KEY_ID_LEN]);
    const EC: KeyId = KeyId([3; EKI_KEY_ID_LEN]);
    const FOREIGN: KeyId = KeyId([4; EKI_KEY_ID_LEN]);
    const FREE: KeyId = KeyId([5; EKI_KEY_ID_LEN]);
    const BLOB: [u8; EKI_WRAPPED_KEY_LEN] = [0; EKI_WRAPPED_KEY_LEN];
    const TAG: [u8; EKI_HMAC_SHA256_LEN] = [2; EKI_HMAC_SHA256_LEN];

    fn label(text: &str) -> Label {
        Label::parse(text.as_bytes()).expect("valid test label")
    }

    /// A scripted backend holding one key of each algorithm and one foreign object.
    fn populated() -> Scripted {
        populated_in(KeyState::Active)
    }

    /// [`populated`] with every key in `state`.
    fn populated_in(state: KeyState) -> Scripted {
        let mut backend = Scripted::default();
        for (id, alg) in [
            (AES, KeyAlg::Aes256),
            (MAC, KeyAlg::HmacSha256),
            (EC, KeyAlg::EcdsaP256),
        ] {
            backend.add_in(state, alg, &label("test"), &id);
        }
        backend.objects.insert(FOREIGN, Found::Foreign);
        backend
    }

    fn handle(backend: Scripted) -> Handle {
        Handle::new(Box::new(backend))
    }

    fn state_of(store: &mut Store, id: &KeyId) -> Option<KeyState> {
        store.get_info(id).ok().map(|info| info.state)
    }

    // --- Approvers ---

    fn approver(seed: u8) -> SigningKey {
        SigningKey::from_slice(&[seed; 32]).expect("valid scalar")
    }

    fn approver_key(seed: u8) -> dual::PublicKey {
        approver(seed)
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .try_into()
            .expect("65 bytes")
    }

    fn approval(seed: u8, request: &dual::Request, id: &KeyId) -> [u8; EKI_P256_SIGNATURE_LEN] {
        let signature: p256::ecdsa::Signature =
            approver(seed).sign(&dual::approval_message(request, id));
        signature.to_bytes().into()
    }

    /// Approvers 1, 2 and 3.
    fn three_approvers() -> DualControl {
        let keys = [approver_key(1), approver_key(2), approver_key(3)].concat();
        DualControl::parse(&keys).expect("valid approvers")
    }

    // --- Audit logs ---

    /// A handle over `backend` whose log is a [`Recorder`], with the `open` record written.
    fn logged(backend: Scripted, dual: Option<DualControl>) -> (Handle, Recorder) {
        let recorder = Recorder::default();
        let log = AuditLog::continuing(Box::new(recorder.clone()), Chain::empty());
        let handle = Handle::open(Box::new(backend), dual, Some(log)).expect("open record");
        (handle, recorder)
    }

    /// The records written so far, after checking that they form a valid chain.
    fn records(recorder: &Recorder) -> Vec<String> {
        let bytes = recorder.bytes.lock().expect("test lock").clone();
        audit::verify(bytes.as_slice()).expect("a valid chain");
        String::from_utf8(bytes)
            .expect("ASCII")
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// The `op`, `key`, `key2` and `status` fields of a record, as text.
    fn summary(record: &str) -> String {
        let field = |name: &str| {
            let start = record.find(&format!("\"{name}\":")).expect("field") + name.len() + 3;
            let rest = &record[start..];
            rest[..rest.find(',').expect("comma")]
                .trim_matches('"')
                .to_owned()
        };
        format!(
            "{} {} {} {}",
            field("op"),
            field("key"),
            field("key2"),
            field("status")
        )
    }

    fn hex(id: &KeyId) -> String {
        id.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn set_failing(flag: &std::sync::Arc<std::sync::Mutex<bool>>, value: bool) {
        *flag.lock().expect("test lock") = value;
    }

    // --- Types ---

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
            state: KeyState::Retired,
        };
        let abc = [b'a' as c_char, b'b' as c_char, b'c' as c_char];
        let abi = info.to_abi();
        assert_eq!(abi.alg, EKI_KEY_HMAC_SHA256);
        assert_eq!(&abi.label[..3], &abc);
        assert!(abi.label[3..].iter().all(|&c| c == 0));
        let abi = info.to_abi_v2();
        assert_eq!(abi.alg, EKI_KEY_HMAC_SHA256);
        assert_eq!(abi.state, EKI_KEY_STATE_RETIRED);
        assert_eq!(&abi.label[..3], &abc);
        assert!(abi.label[3..].iter().all(|&c| c == 0));
    }

    #[test]
    fn state_table_matches_the_contract() {
        use KeyState::{Active, Retired, Revoked};
        let rows = [
            (Usage::PublicKey, [true, true, false]),
            (Usage::Sign, [true, false, false]),
            (Usage::MakeTag, [true, false, false]),
            (Usage::CheckTag, [true, true, false]),
            (Usage::WrapAsKek, [true, false, false]),
            (Usage::BeWrapped, [true, true, false]),
            (Usage::UnwrapAsKek, [true, true, false]),
            (Usage::RotateAway, [true, false, false]),
        ];
        for (usage, allowed) in rows {
            for (state, allowed) in [Active, Retired, Revoked].into_iter().zip(allowed) {
                assert_eq!(state.permits(usage), allowed, "{usage:?} {state:?}");
            }
        }
        assert_eq!(Active.to_abi(), EKI_KEY_STATE_ACTIVE);
        assert_eq!(Revoked.to_abi(), EKI_KEY_STATE_REVOKED);
        assert!(Active < Retired && Retired < Revoked);
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

    // --- ABI 1 behaviour ---

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
    fn generate_stores_an_active_key_under_a_fresh_id() {
        let handle = handle(Scripted::default());
        let mut store = handle.begin();
        let id = store
            .generate(EKI_KEY_HMAC_SHA256, b"fresh")
            .expect("generate succeeds");
        let info = store.get_info(&id).expect("the key exists");
        assert_eq!(info.alg, KeyAlg::HmacSha256);
        assert_eq!(info.label.as_bytes(), b"fresh");
        assert_eq!(info.state, KeyState::Active);
    }

    #[test]
    fn foreign_object_exists_but_cannot_be_described() {
        let handle = handle(populated());
        let mut store = handle.begin();
        // Operations that need its algorithm, label or state: BACKEND with a message.
        assert_eq!(store.get_info(&FOREIGN), Err(Error::Backend));
        assert_eq!(store.last_error(), FOREIGN_OBJECT);
        assert_eq!(store.sign(&FOREIGN, b"m"), Err(Error::Backend));
        assert_eq!(store.public_key(&FOREIGN), Err(Error::Backend));
        assert_eq!(store.hmac_sha256(&FOREIGN, b"m"), Err(Error::Backend));
        assert_eq!(
            store.hmac_sha256_verify(&FOREIGN, b"m", &TAG),
            Err(Error::Backend)
        );
        assert_eq!(store.wrap(&FOREIGN, &MAC), Err(Error::Backend), "as kek");
        assert_eq!(store.wrap(&AES, &FOREIGN), Err(Error::Backend), "as key");
        assert_eq!(store.rotate(&FOREIGN), Err(Error::Backend));
        assert_eq!(store.revoke(&FOREIGN), Err(Error::Backend));
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

    // --- Lifecycle ---

    #[test]
    fn retired_keys_check_and_recover_but_protect_nothing_new() {
        let handle = handle(populated_in(KeyState::Retired));
        let mut store = handle.begin();
        assert_eq!(store.sign(&EC, b"m"), Err(Error::KeyState));
        assert_eq!(store.hmac_sha256(&MAC, b"m"), Err(Error::KeyState));
        assert_eq!(store.wrap(&AES, &MAC), Err(Error::KeyState), "as kek");
        assert_eq!(store.rotate(&AES), Err(Error::KeyState));
        assert!(store.public_key(&EC).is_ok());
        assert_eq!(store.hmac_sha256_verify(&MAC, b"m", &TAG), Ok(()));
        assert_eq!(
            store.hmac_sha256_verify(&MAC, b"m", &[0; 32]),
            Err(Error::AuthFailed)
        );
        assert_eq!(
            store.unwrap(&AES, &BLOB, EKI_KEY_AES_256, b"copy", &FREE),
            Ok(()),
            "as kek"
        );
        assert_eq!(state_of(&mut store, &FREE), Some(KeyState::Active));
        assert!(
            store.wrap(&FREE, &MAC).is_ok(),
            "a retired key under an active kek"
        );
        assert_eq!(store.revoke(&MAC), Ok(()));
        assert_eq!(state_of(&mut store, &MAC), Some(KeyState::Revoked));
    }

    #[test]
    fn revoked_keys_are_only_described_revoked_and_destroyed() {
        let handle = handle(populated_in(KeyState::Revoked));
        let mut store = handle.begin();
        assert_eq!(store.public_key(&EC), Err(Error::KeyState));
        assert_eq!(store.sign(&EC, b"m"), Err(Error::KeyState));
        assert_eq!(store.hmac_sha256(&MAC, b"m"), Err(Error::KeyState));
        assert_eq!(
            store.hmac_sha256_verify(&MAC, b"m", &TAG),
            Err(Error::KeyState)
        );
        assert_eq!(store.wrap(&AES, &AES), Err(Error::KeyState));
        assert_eq!(store.rotate(&MAC), Err(Error::KeyState));
        assert_eq!(
            store.unwrap(&AES, &BLOB, EKI_KEY_AES_256, b"copy", &FREE),
            Err(Error::KeyState)
        );
        assert_eq!(
            store.unwrap(&AES, &BLOB, EKI_KEY_AES_256, b"copy", &MAC),
            Err(Error::KeyState),
            "the kek state comes before the id check"
        );
        assert_eq!(store.revoke(&MAC), Ok(()), "idempotent");
        assert_eq!(state_of(&mut store, &MAC), Some(KeyState::Revoked));
        assert_eq!(store.destroy(&MAC), Ok(()));
    }

    #[test]
    fn state_comes_after_existence_and_type() {
        let handle = handle(populated_in(KeyState::Revoked));
        let mut store = handle.begin();
        assert_eq!(store.sign(&FREE, b"m"), Err(Error::KeyNotFound));
        assert_eq!(store.sign(&MAC, b"m"), Err(Error::WrongKeyType));
        assert_eq!(store.hmac_sha256(&AES, b"m"), Err(Error::WrongKeyType));
        assert_eq!(
            store.hmac_sha256_verify(&EC, b"m", &TAG),
            Err(Error::WrongKeyType)
        );
        assert_eq!(store.public_key(&AES), Err(Error::WrongKeyType));
        assert_eq!(store.wrap(&AES, &FREE), Err(Error::KeyNotFound));
        assert_eq!(store.wrap(&MAC, &AES), Err(Error::WrongKeyType));
        assert_eq!(store.wrap(&AES, &EC), Err(Error::WrongKeyType));
        assert_eq!(
            store.unwrap(&MAC, &BLOB, EKI_KEY_AES_256, b"copy", &FREE),
            Err(Error::WrongKeyType)
        );
        assert_eq!(store.rotate(&FREE), Err(Error::KeyNotFound));
        assert_eq!(store.revoke(&FREE), Err(Error::KeyNotFound));
    }

    #[test]
    fn wrap_checks_the_kek_state_before_the_key_state() {
        let mut backend = populated();
        backend.add_in(KeyState::Retired, KeyAlg::Aes256, &label("kek"), &FREE);
        backend.add_in(KeyState::Revoked, KeyAlg::HmacSha256, &label("mac"), &MAC);
        let handle = handle(backend);
        let mut store = handle.begin();
        assert_eq!(store.wrap(&FREE, &MAC), Err(Error::KeyState));
        assert_eq!(store.wrap(&AES, &MAC), Err(Error::KeyState));
        // A self-wrap of a retired kek fails on the kek's own state.
        assert_eq!(store.wrap(&FREE, &FREE), Err(Error::KeyState));
    }

    #[test]
    fn hmac_verify_checks_the_tag_length_first() {
        let handle = handle(populated_in(KeyState::Revoked));
        let mut store = handle.begin();
        for tag in [&[][..], &[2; 31], &[2; 33]] {
            assert_eq!(
                store.hmac_sha256_verify(&FREE, b"m", tag),
                Err(Error::InvalidArgument)
            );
        }
    }

    #[test]
    fn rotate_makes_a_new_active_key_and_retires_the_old() {
        let handle = handle(populated());
        let mut store = handle.begin();
        let new = store.rotate(&MAC).expect("rotate succeeds");
        assert_ne!(new, MAC);
        let info = store.get_info(&new).expect("the new key exists");
        assert_eq!(
            (info.alg, info.label, info.state),
            (KeyAlg::HmacSha256, label("test"), KeyState::Active)
        );
        assert_eq!(state_of(&mut store, &MAC), Some(KeyState::Retired));
        assert_eq!(store.rotate(&MAC), Err(Error::KeyState));
    }

    #[test]
    fn rotate_that_cannot_retire_destroys_the_new_key() {
        let handle = handle(Scripted {
            fail_set_state: true,
            ..populated()
        });
        let mut store = handle.begin();
        assert_eq!(store.rotate(&EC), Err(Error::Backend));
        assert_eq!(store.last_error(), "the state did not change");
        assert_eq!(state_of(&mut store, &EC), Some(KeyState::Active));
        drop(store);
        let keys = handle.lock().backend.as_mut().find(&FREE);
        assert_eq!(keys, Ok(None));
    }

    // --- Dual control ---

    #[test]
    fn dual_control_refuses_plain_destroy() {
        let handle = Handle::with(Box::new(populated()), Some(three_approvers()), None);
        let mut store = handle.begin();
        assert_eq!(
            store.destroy(&FREE),
            Err(Error::KeyNotFound),
            "existence first"
        );
        assert_eq!(store.destroy(&MAC), Err(Error::ApprovalRequired));
        assert_eq!(state_of(&mut store, &MAC), Some(KeyState::Active));
    }

    #[test]
    fn requests_need_approvers() {
        let handle = handle(populated());
        let mut store = handle.begin();
        assert_eq!(store.destroy_request(&FREE), Err(Error::Unsupported));
        let sig = [0; EKI_P256_SIGNATURE_LEN];
        assert_eq!(
            store.destroy_approve(&[0; 32], &[0; 65], &sig),
            Err(Error::Unsupported),
            "even with an invalid approver key"
        );
    }

    #[test]
    fn two_distinct_approvals_destroy_the_key() {
        let handle = Handle::with(Box::new(populated()), Some(three_approvers()), None);
        let mut store = handle.begin();
        assert_eq!(store.destroy_request(&FREE), Err(Error::KeyNotFound));
        let request = store.destroy_request(&MAC).expect("request");
        let approve = |store: &mut Store, seed: u8| {
            store.destroy_approve(
                &request,
                &approver_key(seed),
                &approval(seed, &request, &MAC),
            )
        };
        assert_eq!(approve(&mut store, 2), Ok(1));
        assert_eq!(approve(&mut store, 2), Ok(1), "the same approver twice");
        assert_eq!(approve(&mut store, 3), Ok(0));
        assert_eq!(store.get_info(&MAC), Err(Error::KeyNotFound));
        assert_eq!(
            approve(&mut store, 1),
            Err(Error::KeyNotFound),
            "request gone"
        );
    }

    #[test]
    fn approval_checks_run_in_contract_order() {
        let handle = Handle::with(Box::new(populated()), Some(three_approvers()), None);
        let mut store = handle.begin();
        let request = store.destroy_request(&MAC).expect("request");
        let good = approval(1, &request, &MAC);
        let mut off_curve = approver_key(1);
        off_curve[64] ^= 1;
        let unknown = [0x55; 32];
        // The key format before the request lookup, the lookup before membership.
        assert_eq!(
            store.destroy_approve(&unknown, &off_curve, &good),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            store.destroy_approve(&unknown, &approver_key(9), &good),
            Err(Error::KeyNotFound)
        );
        assert_eq!(
            store.destroy_approve(&request, &approver_key(9), &approval(9, &request, &MAC)),
            Err(Error::AuthFailed),
            "not an approver"
        );
        assert_eq!(
            store.destroy_approve(&request, &approver_key(2), &good),
            Err(Error::AuthFailed),
            "signed by another approver"
        );
        assert_eq!(
            store.destroy_approve(&request, &approver_key(1), &approval(1, &request, &AES)),
            Err(Error::AuthFailed),
            "signed for another key"
        );
        assert_eq!(
            store.destroy_approve(&request, &approver_key(1), &good),
            Ok(1)
        );
    }

    #[test]
    fn a_new_request_drops_the_old_one_and_its_approvals() {
        let handle = Handle::with(Box::new(populated()), Some(three_approvers()), None);
        let mut store = handle.begin();
        let old = store.destroy_request(&MAC).expect("request");
        let sig = approval(1, &old, &MAC);
        assert_eq!(store.destroy_approve(&old, &approver_key(1), &sig), Ok(1));
        let new = store.destroy_request(&MAC).expect("request");
        assert_ne!(old, new);
        assert_eq!(
            store.destroy_approve(&old, &approver_key(2), &approval(2, &old, &MAC)),
            Err(Error::KeyNotFound)
        );
        let sig = approval(2, &new, &MAC);
        assert_eq!(store.destroy_approve(&new, &approver_key(2), &sig), Ok(1));
    }

    #[test]
    fn completing_approval_for_a_vanished_key_ends_the_request() {
        let handle = Handle::with(Box::new(populated()), Some(three_approvers()), None);
        let mut store = handle.begin();
        let request = store.destroy_request(&MAC).expect("request");
        let sig = approval(1, &request, &MAC);
        assert_eq!(
            store.destroy_approve(&request, &approver_key(1), &sig),
            Ok(1)
        );
        assert_eq!(store.backend.destroy(&MAC), Ok(()), "destroyed elsewhere");
        let sig = approval(2, &request, &MAC);
        assert_eq!(
            store.destroy_approve(&request, &approver_key(2), &sig),
            Err(Error::KeyNotFound)
        );
        assert_eq!(
            store.dual.as_ref().map(|d| d.is_pending(&request)),
            Some(false)
        );
    }

    #[test]
    fn failed_destroy_keeps_the_request_without_the_second_approval() {
        let handle = Handle::with(Box::new(populated()), Some(three_approvers()), None);
        let mut store = handle.begin();
        let request = store.destroy_request(&MAC).expect("request");
        let sig = approval(1, &request, &MAC);
        assert_eq!(
            store.destroy_approve(&request, &approver_key(1), &sig),
            Ok(1)
        );
        store.backend = Box::new(Scripted {
            fail_with: Some("token busy".to_owned()),
            ..populated()
        });
        let sig = approval(2, &request, &MAC);
        assert_eq!(
            store.destroy_approve(&request, &approver_key(2), &sig),
            Err(Error::Backend)
        );
        let pending = store.dual.as_ref().and_then(|d| d.pending(&request));
        assert_eq!(pending.map(|p| p.remaining()), Some(1));
    }

    // --- Audit records ---

    #[test]
    fn every_logged_call_writes_one_record_with_its_status() {
        let (handle, recorder) = logged(populated(), None);
        {
            let mut store = handle.begin();
            assert!(store.sign(&EC, b"m").is_ok());
            assert_eq!(store.sign(&FREE, b"m"), Err(Error::KeyNotFound));
            assert_eq!(store.get_info(&EC).map(|i| i.alg), Ok(KeyAlg::EcdsaP256));
            assert_eq!(store.audit_head().map(|(_, seq)| seq), Ok(3));
            assert_eq!(
                store.generate(EKI_KEY_AES_256, b""),
                Err(Error::InvalidArgument)
            );
            assert!(store.wrap(&AES, &MAC).is_ok());
            assert!(
                store
                    .unwrap(&AES, &BLOB, EKI_KEY_AES_256, b"c", &FREE)
                    .is_ok()
            );
            assert!(store.hmac_sha256(&MAC, b"m").is_ok());
            assert_eq!(
                store.hmac_sha256_verify(&MAC, b"m", &[0; 32]),
                Err(Error::AuthFailed)
            );
            assert_eq!(store.revoke(&EC), Ok(()));
            assert_eq!(store.public_key(&EC), Err(Error::KeyState));
            assert_eq!(store.rotate(&EC), Err(Error::KeyState));
            assert_eq!(store.destroy(&FREE), Ok(()));
        }
        handle.close();
        let (ec, mac, aes, free) = (hex(&EC), hex(&MAC), hex(&AES), hex(&FREE));
        let expected = [
            "open   0".to_owned(),
            format!("sign {ec}  0"),
            format!("sign {free}  6"),
            "generate   2".to_owned(),
            format!("wrap {mac} {aes} 0"),
            format!("unwrap {free} {aes} 0"),
            format!("hmac {mac}  0"),
            format!("hmac_verify {mac}  5"),
            format!("revoke {ec}  0"),
            format!("get_public_key {ec}  11"),
            format!("rotate {ec}  11"),
            format!("destroy {free}  0"),
            "close   0".to_owned(),
        ];
        let summaries: Vec<String> = records(&recorder).iter().map(|r| summary(r)).collect();
        assert_eq!(summaries, expected);
    }

    #[test]
    fn records_name_the_new_keys() {
        let (handle, recorder) = logged(populated(), Some(three_approvers()));
        let mut store = handle.begin();
        let id = store.generate(EKI_KEY_HMAC_SHA256, b"k").expect("generate");
        let new = store.rotate(&id).expect("rotate");
        let request = store.destroy_request(&new).expect("request");
        let sig = approval(1, &request, &new);
        assert_eq!(
            store.destroy_approve(&request, &approver_key(1), &sig),
            Ok(1)
        );
        assert_eq!(
            store.destroy_approve(&[0x55; 32], &approver_key(1), &sig),
            Err(Error::KeyNotFound)
        );
        assert_eq!(store.destroy(&new), Err(Error::ApprovalRequired));
        let (id, new) = (hex(&id), hex(&new));
        let expected = [
            "open   0".to_owned(),
            format!("generate {id}  0"),
            format!("rotate {id} {new} 0"),
            format!("destroy_request {new}  0"),
            format!("destroy_approve {new}  0"),
            "destroy_approve   6".to_owned(),
            format!("destroy {new}  12"),
        ];
        let summaries: Vec<String> = records(&recorder).iter().map(|r| summary(r)).collect();
        assert_eq!(summaries, expected);
    }

    #[test]
    fn unlogged_generate_and_unwrap_leave_no_key() {
        let (handle, recorder) = logged(populated(), None);
        let mut store = handle.begin();
        set_failing(&recorder.fail_append, true);
        assert_eq!(store.generate(EKI_KEY_AES_256, b"k"), Err(Error::Backend));
        assert!(store.last_error().contains("injected write failure"));
        assert!(store.last_error().contains("destroyed again"));
        assert_eq!(
            store.unwrap(&AES, &BLOB, EKI_KEY_AES_256, b"c", &FREE),
            Err(Error::Backend)
        );
        assert_eq!(state_of(&mut store, &FREE), None);
        assert_eq!(store.rotate(&MAC), Err(Error::Backend));
        assert!(store.last_error().contains("state change"));
        set_failing(&recorder.fail_append, false);
        // Only the open record remains, and the scripted backend holds the four objects again.
        assert_eq!(store.audit_head().map(|(_, seq)| seq), Ok(1));
        let objects = store.backend.find(&MAC);
        assert!(matches!(objects, Ok(Some(Found::Key(_)))));
        assert_eq!(records(&recorder).len(), 1);
    }

    #[test]
    fn unlogged_request_and_approval_are_undone() {
        let (handle, recorder) = logged(populated(), Some(three_approvers()));
        let mut store = handle.begin();
        let request = store.destroy_request(&MAC).expect("request");
        set_failing(&recorder.fail_append, true);
        assert_eq!(store.destroy_request(&MAC), Err(Error::Backend));
        let sig = approval(1, &request, &MAC);
        assert_eq!(
            store.destroy_approve(&request, &approver_key(1), &sig),
            Err(Error::Backend)
        );
        set_failing(&recorder.fail_append, false);
        let pending = store.dual.as_ref().and_then(|d| d.pending(&request));
        assert_eq!(
            pending.map(|p| p.remaining()),
            Some(2),
            "as before both calls"
        );
        assert_eq!(
            store.destroy_approve(&request, &approver_key(1), &sig),
            Ok(1)
        );
        set_failing(&recorder.fail_append, true);
        let sig = approval(2, &request, &MAC);
        assert_eq!(
            store.destroy_approve(&request, &approver_key(2), &sig),
            Err(Error::Backend)
        );
        assert!(
            store
                .last_error()
                .contains("destroyed and its destruction is not logged")
        );
        assert_eq!(state_of(&mut store, &MAC), None, "the destroy happened");
    }

    #[test]
    fn open_fails_when_its_record_cannot_be_written() {
        let recorder = Recorder::default();
        set_failing(&recorder.fail_append, true);
        let log = AuditLog::continuing(Box::new(recorder.clone()), Chain::empty());
        let result = Handle::open(Box::new(populated()), None, Some(log));
        assert_eq!(result.err().map(|_| ()), Some(()));
        assert!(recorder.bytes.lock().expect("test lock").is_empty());
    }

    #[test]
    fn a_panicking_call_is_logged_as_internal() {
        let (handle, recorder) = logged(
            Scripted {
                panic_in_sign: true,
                ..populated()
            },
            None,
        );
        let result = catch_unwind(AssertUnwindSafe(|| handle.begin().sign(&EC, b"m")));
        assert!(result.is_err(), "the panic continues");
        assert!(handle.store.is_poisoned());
        assert_eq!(handle.begin().hmac_sha256(&MAC, b"m"), Ok(TAG));
        let summaries: Vec<String> = records(&recorder).iter().map(|r| summary(r)).collect();
        let ec = hex(&EC);
        let mac = hex(&MAC);
        assert_eq!(
            summaries,
            [
                "open   0".to_owned(),
                format!("sign {ec}  10"),
                format!("hmac {mac}  0")
            ]
        );
    }

    #[test]
    fn audit_head_needs_a_log() {
        let handle = handle(populated());
        assert_eq!(handle.begin().audit_head(), Err(Error::Unsupported));
    }
}
