//! The PKCS#11 backend (plan 4.3): keys are token objects, reached through one read-write
//! session per handle on a module that a process-wide registry loads and initialises.
//!
//! Objects follow the plan's mapping table, so that the C++ library and this one can each use
//! the keys the other created in the same token. A key is the set of objects that carry its
//! `CKA_ID`: one secret key object (AES-256, HMAC-SHA256), or a private and a public key object
//! (ECDSA P-256). Objects that carry an id but form none of these shapes, or whose `CKA_LABEL` is
//! not a valid label, were made by another program: they still take the id ([`Found::Foreign`]).
//!
//! The lifecycle state of a key is its usage attributes (ABI 2 contract section 3): the
//! "protect" group (`CKA_WRAP` and `CKA_ENCRYPT` of an AES key, `CKA_SIGN` of an HMAC key or of
//! the private half of a key pair) and the "check" group (`CKA_UNWRAP` and `CKA_DECRYPT`,
//! `CKA_VERIFY`, `CKA_VERIFY` of the public half). Both groups TRUE is ACTIVE, protect FALSE and
//! check TRUE is RETIRED, both FALSE is REVOKED; any other combination, or a flag that cannot be
//! read, makes the objects foreign. Only these attributes are read: SoftHSM2 sets usage flags
//! outside the templates to TRUE by default (for example `CKA_SIGN` of an AES key), so they say
//! nothing about the state. The token itself then refuses what the state forbids.
//!
//! Every operation looks its objects up again by id. Object handles are not kept between calls,
//! because another session or process may destroy or replace the objects in between; when that
//! happens between the store's checks and the operation, the operation is a backend failure.
//!
//! The module is driven through `cryptoki`, whose API is safe: this file has no `unsafe`.
//!
//! Panics: every token-side change is one module call (`C_GenerateKey`, `C_GenerateKeyPair`,
//! `C_UnwrapKey`, `C_SetAttributeValue`, `C_DestroyObject`), made after everything that can fail
//! on this side, so a panic finds the token as it was before the call or as the call left it. A
//! state change of two calls clears the protect group first, so between them the key is
//! RETIRED, a state of the table. An object search is finished by the drop of cryptoki's search
//! iterator, which also runs while a panic unwinds.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::{RawAuthPin, Ulong};
use ekicore_abi::{
    EKI_HMAC_SHA256_LEN, EKI_P256_PUBLIC_KEY_LEN, EKI_P256_SIGNATURE_LEN, EKI_WRAPPED_KEY_LEN,
};
use secrecy::SecretBox;
use sha2::{Digest, Sha256};

use super::{
    Backend, BackendError, BackendResult, Found, KeyAlg, KeyId, KeyInfo, KeyState, Label,
    PKCS11_TOKEN_LABEL_MAX_LEN, PKCS11_USER_PIN_MAX_LEN, Pkcs11Fields,
};
use crate::error::Error;
use crate::keywrap;

/// `CKA_EC_PARAMS` of P-256: the DER encoding of the named-curve OID 1.2.840.10045.3.1.7.
/// cbindgen:ignore
const P256_PARAMS: [u8; 10] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

/// The start of `CKA_EC_POINT` of a P-256 public key: a DER OCTET STRING header (tag 0x04,
/// length 65) around the SEC1 uncompressed point, which itself starts with 0x04.
/// cbindgen:ignore
const EC_POINT_DER_HEADER: [u8; 2] = [0x04, 0x41];

/// `CKA_VALUE_LEN` of a generated secret key.
/// cbindgen:ignore
const SECRET_KEY_LEN: Ulong = Ulong::new(keywrap::KEY_LEN as _);

// --- Configuration ------------------------------------------------------------------------------

/// The configuration of a PKCS#11 store, checked and copied out of the caller's strings: the
/// library keeps no caller pointer.
pub struct Config {
    module_path: PathBuf,
    token_label: [u8; PKCS11_TOKEN_LABEL_MAX_LEN],
    /// Zeroised when dropped, which [`Pkcs11Backend::open`] does right after `C_Login`.
    user_pin: RawAuthPin,
}

impl Config {
    /// Validation step 3 for the PKCS#11 fields, in field order: the token label is 1 to 32
    /// printable bytes, the PIN 1 to 255 bytes, else `INVALID_ARGUMENT`. The module path has no
    /// format: a path that names no module fails when it is loaded.
    pub fn parse(fields: &Pkcs11Fields<'_>) -> Result<Self, Error> {
        let token_label = token_label(fields.token_label).ok_or(Error::InvalidArgument)?;
        if !(1..=PKCS11_USER_PIN_MAX_LEN).contains(&fields.user_pin.len()) {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            module_path: PathBuf::from(OsStr::from_bytes(fields.module_path)),
            token_label,
            user_pin: copy_pin(fields.user_pin),
        })
    }
}

/// The token label as `CK_TOKEN_INFO` holds it, blank-padded to 32 bytes, if `text` is 1 to 32
/// printable bytes.
fn token_label(text: &[u8]) -> Option<[u8; PKCS11_TOKEN_LABEL_MAX_LEN]> {
    let printable = text.iter().all(|byte| (0x20..=0x7E).contains(byte));
    if text.is_empty() || !printable {
        return None;
    }
    blank_padded(text)
}

/// `text` followed by blanks up to 32 bytes; `None` if it is longer.
fn blank_padded(text: &[u8]) -> Option<[u8; PKCS11_TOKEN_LABEL_MAX_LEN]> {
    let mut padded = [b' '; PKCS11_TOKEN_LABEL_MAX_LEN];
    padded.get_mut(..text.len())?.copy_from_slice(text);
    Some(padded)
}

/// A copy of the PIN in zeroizing heap storage. The vector is allocated at its final size, so
/// filling it never reallocates and leaves no unwiped copy behind.
fn copy_pin(pin: &[u8]) -> RawAuthPin {
    let mut copy = Vec::with_capacity(pin.len());
    copy.extend_from_slice(pin);
    SecretBox::new(Box::new(copy))
}

// --- Module registry ----------------------------------------------------------------------------

/// A loaded module.
///
/// `C_Initialize` and the login state belong to the whole process, not to a session, so every
/// handle on a module shares one entry: the first handle to open initialises the module, the
/// last to close finalises it, and only if this library was the one that initialised it.
struct Module {
    /// The loaded module. The registry holds this clone for as long as the process lives, so the
    /// library is never unloaded: dropping the last `Pkcs11` would `dlclose` it, while a
    /// finalised module may still run code from its exit handlers and static destructors, and
    /// the C++ library in the same process may be using the same module.
    context: Pkcs11,
    /// `C_Initialize` returned `CKR_OK` for this library, rather than
    /// `CKR_CRYPTOKI_ALREADY_INITIALIZED` because another component of the process initialised
    /// the module first. Only then does this library call `C_Finalize`.
    we_initialized: bool,
    /// The handles of this library that hold a lease on the module.
    open_handles: usize,
}

/// The registry: module path → loaded module. The lock is held while a module is loaded,
/// initialised or finalised, so two handles opening or closing at the same time agree on which
/// of them initialises and which finalises.
///
/// A poisoned lock is recovered: nothing in the registry's critical sections can panic midway
/// (map operations on owned paths, counter updates, and calls into the module, which is C code).
/// cbindgen:ignore
static REGISTRY: Mutex<BTreeMap<PathBuf, Module>> = Mutex::new(BTreeMap::new());

fn registry() -> MutexGuard<'static, BTreeMap<PathBuf, Module>> {
    REGISTRY.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One handle's claim on a module: initialised while any lease exists. Dropping the lease
/// releases it.
struct Lease {
    path: PathBuf,
    context: Pkcs11,
}

impl Lease {
    /// Loads the module at `path` unless it is loaded already, and initialises it unless a lease
    /// on it exists already.
    fn acquire(path: &Path) -> BackendResult<Self> {
        // An empty path would load the main program rather than fail.
        if path.as_os_str().is_empty() {
            return Err(BackendError::Failed("the module path is empty".to_owned()));
        }
        let mut modules = registry();
        let module = match modules.entry(path.to_path_buf()) {
            Entry::Occupied(entry) => entry.into_mut(),
            // A module that fails to load is not recorded; cryptoki unloads the library again.
            Entry::Vacant(entry) => entry.insert(Module::load(path)?),
        };
        if module.open_handles == 0 {
            module.we_initialized = initialize(&module.context)?;
        }
        module.open_handles += 1;
        Ok(Self {
            path: path.to_path_buf(),
            context: module.context.clone(),
        })
    }
}

impl Drop for Lease {
    /// Ends the lease. At the last one the module is finalised if this library initialised it;
    /// a component that initialised it first keeps it initialised. The next lease initialises it
    /// again. A failing `C_Finalize` is ignored: nothing useful can be done about it.
    fn drop(&mut self) {
        let mut modules = registry();
        let Some(module) = modules.get_mut(&self.path) else {
            return;
        };
        module.open_handles = module.open_handles.saturating_sub(1);
        if module.open_handles == 0 && module.we_initialized {
            module.we_initialized = false;
            let _ = module.context.clone().finalize();
        }
    }
}

impl Module {
    /// Loads the module and fetches its function list.
    fn load(path: &Path) -> BackendResult<Self> {
        let context = Pkcs11::new(path).map_err(failure)?;
        Ok(Self {
            context,
            we_initialized: false,
            open_handles: 0,
        })
    }
}

/// `C_Initialize` with the operating system's locking. `Ok(true)` when this call initialised
/// the module, `Ok(false)` when another component of the process had done so already.
fn initialize(context: &Pkcs11) -> BackendResult<bool> {
    match context.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) => Ok(true),
        Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => Ok(false),
        Err(error) => Err(failure(error)),
    }
}

// --- The backend --------------------------------------------------------------------------------

/// A PKCS#11 store: one read-write session on the token, logged in as the user.
///
/// The fields drop in declaration order: the session closes before the lease is released, so
/// `C_Finalize`, when it comes, finds no session of this handle open. Closing never logs out:
/// the login state belongs to the whole process, and `C_Logout` would log out every other handle
/// on the token (plan 4.3).
pub struct Pkcs11Backend {
    session: Session,
    _lease: Lease,
}

impl Pkcs11Backend {
    /// Load, initialise, find the slot, open a session, log in. The PIN is dropped, and so
    /// wiped, as soon as `C_Login` returns. On a failure after the session opened, the session
    /// closes before the lease is released, as for a handle that closes.
    pub fn open(config: Config) -> BackendResult<Self> {
        let Config {
            module_path,
            token_label,
            user_pin,
        } = config;
        let lease = Lease::acquire(&module_path)?;
        let slot = find_slot(&lease.context, &token_label)?;
        let session = lease.context.open_rw_session(slot).map_err(failure)?;
        log_in(&session, user_pin)?;
        Ok(Self {
            session,
            _lease: lease,
        })
    }
}

/// The first slot whose token label, blank-padded to 32 bytes, equals `wanted`. Slots whose
/// token cannot be read (removed meanwhile, not recognised) are passed over.
fn find_slot(context: &Pkcs11, wanted: &[u8; PKCS11_TOKEN_LABEL_MAX_LEN]) -> BackendResult<Slot> {
    let slots = context.get_slots_with_token().map_err(failure)?;
    slots
        .into_iter()
        .find(|&slot| {
            context
                .get_token_info(slot)
                .is_ok_and(|info| token_label_is(info.label(), wanted))
        })
        .ok_or_else(|| {
            let label = String::from_utf8_lossy(wanted);
            BackendError::Failed(format!("no token with label \"{}\"", label.trim_end()))
        })
}

/// Whether a token label as cryptoki reports it (the 32 bytes of `CK_TOKEN_INFO.label`, decoded
/// as UTF-8 with replacement, trailing blanks removed) is the blank-padded `wanted`. A label of
/// printable ASCII bytes comes back unchanged once padded again; any other byte becomes a
/// replacement character, which is never equal to the printable `wanted`. The result is
/// therefore the comparison of the raw 32 bytes, as the C++ library makes it.
fn token_label_is(reported: &str, wanted: &[u8; PKCS11_TOKEN_LABEL_MAX_LEN]) -> bool {
    blank_padded(reported.as_bytes()).is_some_and(|label| label == *wanted)
}

/// `C_Login` as the user. While a handle of this process is logged in to the token, the module
/// answers `CKR_USER_ALREADY_LOGGED_IN` whatever the PIN, which counts as success (plan 4.3).
fn log_in(session: &Session, user_pin: RawAuthPin) -> BackendResult<()> {
    match session.login_with_raw(UserType::User, &user_pin) {
        Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(()),
        Err(error) => Err(failure(error)),
    }
}

impl Backend for Pkcs11Backend {
    fn find(&mut self, id: &KeyId) -> BackendResult<Option<Found>> {
        let located = self.locate(id)?;
        if located.objects.is_empty() {
            return Ok(None);
        }
        Ok(Some(match located.key {
            Some(key) => Found::Key(key.info),
            None => Found::Foreign,
        }))
    }

    fn create(&mut self, alg: KeyAlg, label: &Label, id: &KeyId) -> BackendResult<()> {
        let mechanism = match alg {
            KeyAlg::Aes256 => Mechanism::AesKeyGen,
            KeyAlg::HmacSha256 => Mechanism::GenericSecretKeyGen,
            KeyAlg::EcdsaP256 => return self.create_key_pair(label, id),
        };
        let mut template = secret_key_template(alg, label, id)?;
        template.push(Attribute::ValueLen(SECRET_KEY_LEN));
        self.session
            .generate_key(&mechanism, &template)
            .map_err(failure)?;
        Ok(())
    }

    fn public_key(&mut self, id: &KeyId) -> BackendResult<[u8; EKI_P256_PUBLIC_KEY_LEN]> {
        let key = self.locate_key(id, KeyAlg::EcdsaP256)?;
        let public = key.public.ok_or_else(changed_meanwhile)?;
        let point = match self.read(public, AttributeType::EcPoint)? {
            Some(Attribute::EcPoint(point)) => point,
            _ => Vec::new(),
        };
        point
            .strip_prefix(&EC_POINT_DER_HEADER)
            .filter(|point| point.first() == Some(&0x04))
            .and_then(|point| point.try_into().ok())
            .ok_or_else(|| {
                BackendError::Failed(
                    "CKA_EC_POINT of the public key is not a DER OCTET STRING holding an \
                     uncompressed P-256 point"
                        .to_owned(),
                )
            })
    }

    fn sign(&mut self, id: &KeyId, msg: &[u8]) -> BackendResult<[u8; EKI_P256_SIGNATURE_LEN]> {
        let key = self.locate_key(id, KeyAlg::EcdsaP256)?;
        // CKM_ECDSA signs a digest that the caller computes (plan 4.3, "sign").
        let digest = Sha256::digest(msg);
        self.sign_with(&Mechanism::Ecdsa, key.key, &digest)
    }

    fn hmac_sha256(&mut self, id: &KeyId, msg: &[u8]) -> BackendResult<[u8; EKI_HMAC_SHA256_LEN]> {
        let key = self.locate_key(id, KeyAlg::HmacSha256)?;
        self.sign_with(&Mechanism::Sha256Hmac, key.key, msg)
    }

    fn hmac_sha256_verify(
        &mut self,
        id: &KeyId,
        msg: &[u8],
        tag: &[u8; EKI_HMAC_SHA256_LEN],
    ) -> BackendResult<()> {
        let key = self.locate_key(id, KeyAlg::HmacSha256)?;
        // C_Verify compares inside the token. A wrong tag of the right length is
        // CKR_SIGNATURE_INVALID; CKR_SIGNATURE_LEN_RANGE cannot occur for 32 bytes but means a
        // mismatch as well.
        match self
            .session
            .verify(&Mechanism::Sha256Hmac, key.key, msg, tag)
        {
            Ok(()) => Ok(()),
            Err(CkError::Pkcs11(RvError::SignatureInvalid | RvError::SignatureLenRange, _)) => {
                Err(BackendError::AuthFailed(String::new()))
            }
            Err(error) => Err(failure(error)),
        }
    }

    fn wrap(&mut self, kek: &KeyId, key: &KeyId) -> BackendResult<[u8; EKI_WRAPPED_KEY_LEN]> {
        let wrapping = self.locate_key(kek, KeyAlg::Aes256)?;
        let wrapped = self
            .locate(key)?
            .key
            .filter(|wrapped| wrapped.info.alg.is_wrappable())
            .ok_or_else(changed_meanwhile)?;
        let blob = self
            .session
            .wrap_key(&Mechanism::AesKeyWrap, wrapping.key, wrapped.key)
            .map_err(failure)?;
        // A 32-byte key wraps to 40 bytes; another length means a key of another size that
        // carries a type the library maps to a 32-byte key.
        let length = blob.len();
        blob.try_into().map_err(|_| {
            BackendError::Failed(format!(
                "C_WrapKey produced {length} bytes instead of {EKI_WRAPPED_KEY_LEN}: the key \
                 is not 32 bytes long"
            ))
        })
    }

    fn unwrap(
        &mut self,
        kek: &KeyId,
        blob: &[u8; EKI_WRAPPED_KEY_LEN],
        alg: KeyAlg,
        label: &Label,
        id: &KeyId,
    ) -> BackendResult<()> {
        let wrapping = self.locate_key(kek, KeyAlg::Aes256)?;
        let template = secret_key_template(alg, label, id)?;
        // Every failure here counts as a failed integrity check (plan 4.3, return-code mapping):
        // SoftHSM2 reports a wrong RFC 3394 check value as CKR_GENERAL_ERROR, which cannot be
        // told apart from other causes, so the message names the code. The store has checked
        // everything else by now.
        self.session
            .unwrap_key(&Mechanism::AesKeyWrap, wrapping.key, blob, &template)
            .map_err(|error| BackendError::AuthFailed(reason(error)))?;
        Ok(())
    }

    fn set_state(&mut self, id: &KeyId, state: KeyState) -> BackendResult<()> {
        let key = self.locate(id)?.key.ok_or_else(changed_meanwhile)?;
        let [protect, check] = usage_groups(key.info.alg);
        // Protect first, so that the key is RETIRED between the two calls; for a key pair that
        // is the private half first.
        if key.info.state < KeyState::Retired && state >= KeyState::Retired {
            self.clear(&key, &protect)?;
        }
        if key.info.state < KeyState::Revoked && state >= KeyState::Revoked {
            self.clear(&key, &check)?;
        }
        Ok(())
    }

    fn destroy(&mut self, id: &KeyId) -> BackendResult<()> {
        let located = self.locate(id)?;
        if located.objects.is_empty() {
            return Err(changed_meanwhile());
        }
        // Objects destroyed before a failing one stay destroyed: the token offers no
        // transaction over several objects.
        for object in located.objects {
            self.session.destroy_object(object).map_err(failure)?;
        }
        Ok(())
    }
}

impl Pkcs11Backend {
    /// Generates an ECDSA P-256 key pair whose two objects share `id` and `label`.
    fn create_key_pair(&mut self, label: &Label, id: &KeyId) -> BackendResult<()> {
        let (public, private) = key_pair_templates(label, id);
        self.session
            .generate_key_pair(&Mechanism::EccKeyPairGen, &public, &private)
            .map_err(failure)?;
        Ok(())
    }

    /// A single-part signature or MAC with `mechanism` under `key`: exactly `N` bytes out.
    /// cryptoki passes `data.as_ptr()`, which is never NULL, even for an empty slice: SoftHSM2
    /// answers `CKR_ARGUMENTS_BAD` for a NULL data pointer even with length 0 (plan 4.3).
    fn sign_with<const N: usize>(
        &mut self,
        mechanism: &Mechanism<'_>,
        key: ObjectHandle,
        data: &[u8],
    ) -> BackendResult<[u8; N]> {
        let output = self.session.sign(mechanism, key, data).map_err(failure)?;
        let length = output.len();
        output.try_into().map_err(|_| {
            BackendError::Failed(format!("C_Sign produced {length} bytes instead of {N}"))
        })
    }

    /// [`Self::locate`], then the requirement the store has already checked: the id names a key
    /// of `alg`.
    fn locate_key(&mut self, id: &KeyId, alg: KeyAlg) -> BackendResult<KeyObjects> {
        self.locate(id)?
            .key
            .filter(|key| key.info.alg == alg)
            .ok_or_else(changed_meanwhile)
    }

    /// Finds every object that carries `id` and works out whether they form a key of the
    /// library.
    fn locate(&mut self, id: &KeyId) -> BackendResult<Located> {
        let objects = self.find_objects(id)?;
        let kinds = objects
            .iter()
            .map(|&object| self.read_kind(object))
            .collect::<BackendResult<Vec<_>>>()?;
        let key = self.describe(&kinds)?;
        Ok(Located { objects, key })
    }

    /// `C_FindObjectsInit` / `C_FindObjects` / `C_FindObjectsFinal` on `CKA_ID`. cryptoki's
    /// search iterator calls `C_FindObjectsFinal` when it is dropped, whether the search ended,
    /// failed or is unwinding, so the session can always search again; the result of that call is
    /// not reported.
    fn find_objects(&mut self, id: &KeyId) -> BackendResult<Vec<ObjectHandle>> {
        self.session
            .find_objects(&[Attribute::Id(id.0.to_vec())])
            .map_err(failure)
    }

    /// The class of `object` and, for a key object, its key type.
    fn read_kind(&self, object: ObjectHandle) -> BackendResult<ObjectKind<ObjectHandle>> {
        let class = match self.read(object, AttributeType::Class)? {
            Some(Attribute::Class(class)) => Some(class),
            _ => None,
        };
        let is_key = class.is_some_and(|class| {
            [
                ObjectClass::SECRET_KEY,
                ObjectClass::PRIVATE_KEY,
                ObjectClass::PUBLIC_KEY,
            ]
            .contains(&class)
        });
        let key_type = if is_key {
            match self.read(object, AttributeType::KeyType)? {
                Some(Attribute::KeyType(key_type)) => Some(key_type),
                _ => None,
            }
        } else {
            None
        };
        Ok(ObjectKind {
            handle: object,
            class,
            key_type,
        })
    }

    /// The key that `kinds` form, with its label; `None` when they are not a key of the
    /// library. For a key pair both halves must name P-256 in `CKA_EC_PARAMS`, the private half
    /// checked first. `CKA_VALUE_LEN` is never read (plan 4.3, "get_info").
    fn describe(&self, kinds: &[ObjectKind<ObjectHandle>]) -> BackendResult<Option<KeyObjects>> {
        let (alg, key, public) = match shape(kinds) {
            Shape::Foreign => return Ok(None),
            Shape::Secret { alg, key } => (alg, key, None),
            Shape::KeyPair { private, public } => {
                if !self.is_p256(private)? || !self.is_p256(public)? {
                    return Ok(None);
                }
                (KeyAlg::EcdsaP256, private, Some(public))
            }
        };
        let label = match self.read(key, AttributeType::Label)? {
            Some(Attribute::Label(text)) => Label::parse(&text),
            _ => None,
        };
        let Some(label) = label else {
            return Ok(None);
        };
        let mut objects = KeyObjects {
            info: KeyInfo {
                alg,
                label,
                state: KeyState::Active,
            },
            key,
            public,
        };
        let [protect, check] = usage_groups(alg);
        let protect = self.read_flags(&objects, &protect)?;
        let check = self.read_flags(&objects, &check)?;
        Ok(state_of(&protect, &check).map(|state| {
            objects.info.state = state;
            objects
        }))
    }

    /// The values of the usage flags of `group`, `None` for a flag that cannot be read.
    fn read_flags(&self, key: &KeyObjects, group: &Group) -> BackendResult<Vec<Option<bool>>> {
        let Some(object) = key.object(group.half) else {
            return Ok(vec![None]);
        };
        group
            .flags
            .iter()
            .map(|&kind| Ok(self.read(object, kind)?.as_ref().and_then(flag_value)))
            .collect()
    }

    /// Sets every flag of `group` to FALSE in one `C_SetAttributeValue` call.
    fn clear(&mut self, key: &KeyObjects, group: &Group) -> BackendResult<()> {
        let object = key.object(group.half).ok_or_else(changed_meanwhile)?;
        let template = group
            .flags
            .iter()
            .map(|&kind| cleared(kind))
            .collect::<BackendResult<Vec<_>>>()?;
        self.session
            .update_attributes(object, &template)
            .map_err(failure)
    }

    /// Whether `CKA_EC_PARAMS` of `object` names P-256 by its OID.
    fn is_p256(&self, object: ObjectHandle) -> BackendResult<bool> {
        Ok(matches!(
            self.read(object, AttributeType::EcParams)?,
            Some(Attribute::EcParams(params)) if params == P256_PARAMS
        ))
    }

    /// One attribute of `object`, alone in its `C_GetAttributeValue` call, or `None` when the
    /// object has no such attribute, keeps it secret, or holds a value that is not of the
    /// attribute's type. cryptoki answers `CKR_ATTRIBUTE_TYPE_INVALID`, `CKR_ATTRIBUTE_SENSITIVE`
    /// and `CKR_BUFFER_TOO_SMALL` itself by leaving the attribute out, and reports a value of
    /// the wrong size or an unknown class or key type as a conversion error: all of these
    /// describe the object, not a failure. Any other failure of the call is a backend failure.
    fn read(&self, object: ObjectHandle, kind: AttributeType) -> BackendResult<Option<Attribute>> {
        match self.session.get_attributes(object, &[kind]) {
            Ok(attributes) => Ok(attributes.into_iter().find(|a| a.attribute_type() == kind)),
            Err(error @ (CkError::Pkcs11(..) | CkError::NullFunctionPointer)) => {
                Err(failure(error))
            }
            Err(
                CkError::LibraryLoading(_)
                | CkError::NotSupported
                | CkError::TryFromInt(_)
                | CkError::TryFromSlice(_)
                | CkError::ParseInt(_)
                | CkError::Utf8(_)
                | CkError::NulError(_)
                | CkError::MissingSymbol(_)
                | CkError::InvalidValue
                | CkError::PinNotSet,
            ) => Ok(None),
        }
    }
}

/// The token's objects for one id changed between the store's checks and the operation: the
/// token is shared with other sessions and processes, so this is a backend condition, not a
/// broken invariant.
fn changed_meanwhile() -> BackendError {
    BackendError::Failed(
        "the token's objects for this key id changed during the operation".to_owned(),
    )
}

// --- Object classification ----------------------------------------------------------------------

/// The objects that carry one id.
struct Located {
    /// Every object that carries the id, of any class.
    objects: Vec<ObjectHandle>,
    /// The key they form, when they form one of the library's key shapes with a valid label.
    key: Option<KeyObjects>,
}

/// A key of the library in the token.
#[derive(Clone, Copy)]
struct KeyObjects {
    info: KeyInfo,
    /// The secret key, or the private half of a key pair.
    key: ObjectHandle,
    /// The public half of a key pair.
    public: Option<ObjectHandle>,
}

impl KeyObjects {
    /// The object that holds the flags of `half`.
    fn object(&self, half: Half) -> Option<ObjectHandle> {
        match half {
            Half::Key => Some(self.key),
            Half::Public => self.public,
        }
    }
}

// --- Lifecycle state (ABI 2 contract section 3) -------------------------------------------------

/// Which object of a key carries a group of flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Half {
    /// The secret key, or the private half of a key pair.
    Key,
    /// The public half of a key pair.
    Public,
}

/// The usage flags that together say whether a key may protect, or check, anything.
#[derive(Clone, Copy, Debug)]
struct Group {
    half: Half,
    flags: &'static [AttributeType],
}

/// The protect group and the check group of a key of `alg`, from the contract's table.
fn usage_groups(alg: KeyAlg) -> [Group; 2] {
    let group = |half, flags| Group { half, flags };
    match alg {
        KeyAlg::Aes256 => [
            group(Half::Key, &[AttributeType::Wrap, AttributeType::Encrypt]),
            group(Half::Key, &[AttributeType::Unwrap, AttributeType::Decrypt]),
        ],
        KeyAlg::HmacSha256 => [
            group(Half::Key, &[AttributeType::Sign]),
            group(Half::Key, &[AttributeType::Verify]),
        ],
        KeyAlg::EcdsaP256 => [
            group(Half::Key, &[AttributeType::Sign]),
            group(Half::Public, &[AttributeType::Verify]),
        ],
    }
}

/// The state that the values of the protect and the check flags form: all TRUE is ACTIVE,
/// protect FALSE and check TRUE is RETIRED, all FALSE is REVOKED. Any other combination, an
/// unreadable flag (`None`) included, is no state.
fn state_of(protect: &[Option<bool>], check: &[Option<bool>]) -> Option<KeyState> {
    let all = |flags: &[Option<bool>], value: bool| flags.iter().all(|&flag| flag == Some(value));
    match (
        all(protect, true),
        all(protect, false),
        all(check, true),
        all(check, false),
    ) {
        (true, _, true, _) => Some(KeyState::Active),
        (_, true, true, _) => Some(KeyState::Retired),
        (_, true, _, true) => Some(KeyState::Revoked),
        _ => None,
    }
}

/// The value of a usage flag attribute; `None` for any other attribute.
fn flag_value(attribute: &Attribute) -> Option<bool> {
    match *attribute {
        Attribute::Wrap(value)
        | Attribute::Encrypt(value)
        | Attribute::Unwrap(value)
        | Attribute::Decrypt(value)
        | Attribute::Sign(value)
        | Attribute::Verify(value) => Some(value),
        _ => None,
    }
}

/// The usage flag `kind` set to FALSE.
fn cleared(kind: AttributeType) -> BackendResult<Attribute> {
    match kind {
        AttributeType::Wrap => Ok(Attribute::Wrap(false)),
        AttributeType::Encrypt => Ok(Attribute::Encrypt(false)),
        AttributeType::Unwrap => Ok(Attribute::Unwrap(false)),
        AttributeType::Decrypt => Ok(Attribute::Decrypt(false)),
        AttributeType::Sign => Ok(Attribute::Sign(false)),
        AttributeType::Verify => Ok(Attribute::Verify(false)),
        _ => Err(BackendError::Internal(
            "a usage group holds an attribute that is not a usage flag",
        )),
    }
}

/// What one object is, as far as the shapes care: its class and, for a key object, its key
/// type. `None` when the attribute is absent or unreadable. Generic over the handle so that the
/// classification can be tested without a token.
#[derive(Clone, Copy, Debug)]
struct ObjectKind<H> {
    handle: H,
    class: Option<ObjectClass>,
    key_type: Option<KeyType>,
}

/// The shape a set of objects with one id forms, before the curve and the label are checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape<H> {
    /// One secret key of type AES (AES-256) or GENERIC_SECRET (HMAC-SHA256).
    Secret { alg: KeyAlg, key: H },
    /// One private and one public key, both of type EC.
    KeyPair { private: H, public: H },
    /// Anything else: a missing class or key type, a lone half of a key pair, two secret keys,
    /// a certificate, ...
    Foreign,
}

/// The shapes the library creates. The order of the objects does not matter.
fn shape<H: Copy>(kinds: &[ObjectKind<H>]) -> Shape<H> {
    match kinds {
        [only] => secret_key(only),
        [first, second] => key_pair(first, second),
        _ => Shape::Foreign,
    }
}

fn secret_key<H: Copy>(object: &ObjectKind<H>) -> Shape<H> {
    if object.class != Some(ObjectClass::SECRET_KEY) {
        return Shape::Foreign;
    }
    let alg = match object.key_type {
        Some(KeyType::AES) => KeyAlg::Aes256,
        Some(KeyType::GENERIC_SECRET) => KeyAlg::HmacSha256,
        _ => return Shape::Foreign,
    };
    Shape::Secret {
        alg,
        key: object.handle,
    }
}

fn key_pair<H: Copy>(first: &ObjectKind<H>, second: &ObjectKind<H>) -> Shape<H> {
    let ec = Some(KeyType::EC);
    if first.key_type != ec || second.key_type != ec {
        return Shape::Foreign;
    }
    let (private, public) = (
        Some(ObjectClass::PRIVATE_KEY),
        Some(ObjectClass::PUBLIC_KEY),
    );
    if first.class == private && second.class == public {
        Shape::KeyPair {
            private: first.handle,
            public: second.handle,
        }
    } else if first.class == public && second.class == private {
        Shape::KeyPair {
            private: second.handle,
            public: first.handle,
        }
    } else {
        Shape::Foreign
    }
}

// --- Templates (plan 4.3, "PKCS#11 object mapping") ---------------------------------------------

/// The attributes every object of the library carries: token object, private unless it is the
/// public half of a key pair, the 16 id bytes, the label without its NUL.
fn common_attributes(private: bool, label: &Label, id: &KeyId) -> [Attribute; 4] {
    [
        Attribute::Token(true),
        Attribute::Private(private),
        Attribute::Id(id.0.to_vec()),
        Attribute::Label(label.as_bytes().to_vec()),
    ]
}

/// The template of a new secret key of `alg`: class, key type, the common attributes, then the
/// usage attributes of its row. `CKA_VALUE_LEN` is not part of it: generate adds it, unwrap must
/// not (SoftHSM2 rejects it there as read-only; the length comes from the blob).
fn secret_key_template(alg: KeyAlg, label: &Label, id: &KeyId) -> BackendResult<Vec<Attribute>> {
    let (key_type, usage) = match alg {
        KeyAlg::Aes256 => (
            KeyType::AES,
            vec![
                Attribute::Sensitive(true),
                Attribute::Extractable(true),
                Attribute::Wrap(true),
                Attribute::Unwrap(true),
                Attribute::Encrypt(true),
                Attribute::Decrypt(true),
            ],
        ),
        KeyAlg::HmacSha256 => (
            KeyType::GENERIC_SECRET,
            vec![
                Attribute::Sign(true),
                Attribute::Verify(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(true),
            ],
        ),
        KeyAlg::EcdsaP256 => {
            return Err(BackendError::Internal(
                "a secret key template was requested for an ECDSA P-256 key",
            ));
        }
    };
    let mut template = vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(key_type),
    ];
    template.extend(common_attributes(true, label, id));
    template.extend(usage);
    Ok(template)
}

/// The public and private templates of a new ECDSA P-256 key pair.
fn key_pair_templates(label: &Label, id: &KeyId) -> (Vec<Attribute>, Vec<Attribute>) {
    let mut public = vec![
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(KeyType::EC),
    ];
    public.extend(common_attributes(false, label, id));
    public.extend([
        Attribute::EcParams(P256_PARAMS.to_vec()),
        Attribute::Verify(true),
    ]);
    let mut private = vec![
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(KeyType::EC),
    ];
    private.extend(common_attributes(true, label, id));
    private.extend([
        Attribute::Sign(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
    ]);
    (public, private)
}

// --- Failures -----------------------------------------------------------------------------------

/// A backend failure whose text names the PKCS#11 function and the `CKR_*` code, for example
/// `C_Login failed: CKR_PIN_INCORRECT`, or says why the module could not be used.
fn failure(error: CkError) -> BackendError {
    BackendError::Failed(reason(error))
}

/// The text of a cryptoki error: the function and the `CKR_*` name, or what kept the call from
/// reaching the module.
fn reason(error: CkError) -> String {
    match error {
        // cryptoki's function names are the C names without their `C_` prefix.
        CkError::Pkcs11(rv, function) => format!("C_{function:?} failed: {}", rv_name(rv)),
        CkError::LibraryLoading(error) => format!("loading the PKCS#11 module failed: {error}"),
        CkError::MissingSymbol(symbol) => format!("the PKCS#11 module does not export {symbol}"),
        CkError::NullFunctionPointer => {
            "the PKCS#11 module's function list lacks a function this library calls".to_owned()
        }
        other => format!("PKCS#11 call failed: {other}"),
    }
}

/// The `CKR_*` name of a return code; a code without a name prints as `CKR_0x` and at least
/// eight hexadecimal digits, as in the C++ library.
fn rv_name(rv: RvError) -> String {
    let name = match rv {
        RvError::Cancel => "CKR_CANCEL",
        RvError::HostMemory => "CKR_HOST_MEMORY",
        RvError::SlotIdInvalid => "CKR_SLOT_ID_INVALID",
        RvError::GeneralError => "CKR_GENERAL_ERROR",
        RvError::FunctionFailed => "CKR_FUNCTION_FAILED",
        RvError::ArgumentsBad => "CKR_ARGUMENTS_BAD",
        RvError::NoEvent => "CKR_NO_EVENT",
        RvError::NeedToCreateThreads => "CKR_NEED_TO_CREATE_THREADS",
        RvError::CantLock => "CKR_CANT_LOCK",
        RvError::AttributeReadOnly => "CKR_ATTRIBUTE_READ_ONLY",
        RvError::AttributeSensitive => "CKR_ATTRIBUTE_SENSITIVE",
        RvError::AttributeTypeInvalid => "CKR_ATTRIBUTE_TYPE_INVALID",
        RvError::AttributeValueInvalid => "CKR_ATTRIBUTE_VALUE_INVALID",
        RvError::ActionProhibited => "CKR_ACTION_PROHIBITED",
        RvError::DataInvalid => "CKR_DATA_INVALID",
        RvError::DataLenRange => "CKR_DATA_LEN_RANGE",
        RvError::DeviceError => "CKR_DEVICE_ERROR",
        RvError::DeviceMemory => "CKR_DEVICE_MEMORY",
        RvError::DeviceRemoved => "CKR_DEVICE_REMOVED",
        RvError::EncryptedDataInvalid => "CKR_ENCRYPTED_DATA_INVALID",
        RvError::EncryptedDataLenRange => "CKR_ENCRYPTED_DATA_LEN_RANGE",
        RvError::FunctionCanceled => "CKR_FUNCTION_CANCELED",
        RvError::FunctionNotParallel => "CKR_FUNCTION_NOT_PARALLEL",
        RvError::FunctionNotSupported => "CKR_FUNCTION_NOT_SUPPORTED",
        RvError::CurveNotSupported => "CKR_CURVE_NOT_SUPPORTED",
        RvError::KeyHandleInvalid => "CKR_KEY_HANDLE_INVALID",
        RvError::KeySizeRange => "CKR_KEY_SIZE_RANGE",
        RvError::KeyTypeInconsistent => "CKR_KEY_TYPE_INCONSISTENT",
        RvError::KeyNotNeeded => "CKR_KEY_NOT_NEEDED",
        RvError::KeyChanged => "CKR_KEY_CHANGED",
        RvError::KeyNeeded => "CKR_KEY_NEEDED",
        RvError::KeyIndigestible => "CKR_KEY_INDIGESTIBLE",
        RvError::KeyFunctionNotPermitted => "CKR_KEY_FUNCTION_NOT_PERMITTED",
        RvError::KeyNotWrappable => "CKR_KEY_NOT_WRAPPABLE",
        RvError::KeyUnextractable => "CKR_KEY_UNEXTRACTABLE",
        RvError::MechanismInvalid => "CKR_MECHANISM_INVALID",
        RvError::MechanismParamInvalid => "CKR_MECHANISM_PARAM_INVALID",
        RvError::ObjectHandleInvalid => "CKR_OBJECT_HANDLE_INVALID",
        RvError::OperationActive => "CKR_OPERATION_ACTIVE",
        RvError::OperationNotInitialized => "CKR_OPERATION_NOT_INITIALIZED",
        RvError::PinIncorrect => "CKR_PIN_INCORRECT",
        RvError::PinInvalid => "CKR_PIN_INVALID",
        RvError::PinLenRange => "CKR_PIN_LEN_RANGE",
        RvError::PinExpired => "CKR_PIN_EXPIRED",
        RvError::PinLocked => "CKR_PIN_LOCKED",
        RvError::SessionClosed => "CKR_SESSION_CLOSED",
        RvError::SessionCount => "CKR_SESSION_COUNT",
        RvError::SessionHandleInvalid => "CKR_SESSION_HANDLE_INVALID",
        RvError::SessionParallelNotSupported => "CKR_SESSION_PARALLEL_NOT_SUPPORTED",
        RvError::SessionReadOnly => "CKR_SESSION_READ_ONLY",
        RvError::SessionExists => "CKR_SESSION_EXISTS",
        RvError::SessionReadOnlyExists => "CKR_SESSION_READ_ONLY_EXISTS",
        RvError::SessionReadWriteSoExists => "CKR_SESSION_READ_WRITE_SO_EXISTS",
        RvError::SignatureInvalid => "CKR_SIGNATURE_INVALID",
        RvError::SignatureLenRange => "CKR_SIGNATURE_LEN_RANGE",
        RvError::TemplateIncomplete => "CKR_TEMPLATE_INCOMPLETE",
        RvError::TemplateInconsistent => "CKR_TEMPLATE_INCONSISTENT",
        RvError::TokenNotPresent => "CKR_TOKEN_NOT_PRESENT",
        RvError::TokenNotRecognized => "CKR_TOKEN_NOT_RECOGNIZED",
        RvError::TokenWriteProtected => "CKR_TOKEN_WRITE_PROTECTED",
        RvError::UnwrappingKeyHandleInvalid => "CKR_UNWRAPPING_KEY_HANDLE_INVALID",
        RvError::UnwrappingKeySizeRange => "CKR_UNWRAPPING_KEY_SIZE_RANGE",
        RvError::UnwrappingKeyTypeInconsistent => "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT",
        RvError::UserAlreadyLoggedIn => "CKR_USER_ALREADY_LOGGED_IN",
        RvError::UserNotLoggedIn => "CKR_USER_NOT_LOGGED_IN",
        RvError::UserPinNotInitialized => "CKR_USER_PIN_NOT_INITIALIZED",
        RvError::UserTypeInvalid => "CKR_USER_TYPE_INVALID",
        RvError::UserAnotherAlreadyLoggedIn => "CKR_USER_ANOTHER_ALREADY_LOGGED_IN",
        RvError::UserTooManyTypes => "CKR_USER_TOO_MANY_TYPES",
        RvError::WrappedKeyInvalid => "CKR_WRAPPED_KEY_INVALID",
        RvError::WrappedKeyLenRange => "CKR_WRAPPED_KEY_LEN_RANGE",
        RvError::WrappingKeyHandleInvalid => "CKR_WRAPPING_KEY_HANDLE_INVALID",
        RvError::WrappingKeySizeRange => "CKR_WRAPPING_KEY_SIZE_RANGE",
        RvError::WrappingKeyTypeInconsistent => "CKR_WRAPPING_KEY_TYPE_INCONSISTENT",
        RvError::RandomSeedNotSupported => "CKR_RANDOM_SEED_NOT_SUPPORTED",
        RvError::RandomNoRng => "CKR_RANDOM_NO_RNG",
        RvError::DomainParamsInvalid => "CKR_DOMAIN_PARAMS_INVALID",
        RvError::BufferTooSmall => "CKR_BUFFER_TOO_SMALL",
        RvError::SavedStateInvalid => "CKR_SAVED_STATE_INVALID",
        RvError::InformationSensitive => "CKR_INFORMATION_SENSITIVE",
        RvError::StateUnsaveable => "CKR_STATE_UNSAVEABLE",
        RvError::CryptokiNotInitialized => "CKR_CRYPTOKI_NOT_INITIALIZED",
        RvError::CryptokiAlreadyInitialized => "CKR_CRYPTOKI_ALREADY_INITIALIZED",
        RvError::MutexBad => "CKR_MUTEX_BAD",
        RvError::MutexNotLocked => "CKR_MUTEX_NOT_LOCKED",
        RvError::NewPinMode => "CKR_NEW_PIN_MODE",
        RvError::NextOtp => "CKR_NEXT_OTP",
        RvError::ExceededMaxIterations => "CKR_EXCEEDED_MAX_ITERATIONS",
        RvError::FipsSelfTestFailed => "CKR_FIPS_SELF_TEST_FAILED",
        RvError::LibraryLoadFailed => "CKR_LIBRARY_LOAD_FAILED",
        RvError::PinTooWeak => "CKR_PIN_TOO_WEAK",
        RvError::PublicKeyInvalid => "CKR_PUBLIC_KEY_INVALID",
        RvError::FunctionRejected => "CKR_FUNCTION_REJECTED",
        RvError::VendorDefined(code) | RvError::UnknownErrorCode(code) => {
            return format!("CKR_0x{code:08X}");
        }
    };
    name.to_owned()
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    fn kind(handle: u8, class: ObjectClass, key_type: Option<KeyType>) -> ObjectKind<u8> {
        ObjectKind {
            handle,
            class: Some(class),
            key_type,
        }
    }

    fn secret(handle: u8, key_type: KeyType) -> ObjectKind<u8> {
        kind(handle, ObjectClass::SECRET_KEY, Some(key_type))
    }

    fn private_ec(handle: u8) -> ObjectKind<u8> {
        kind(handle, ObjectClass::PRIVATE_KEY, Some(KeyType::EC))
    }

    fn public_ec(handle: u8) -> ObjectKind<u8> {
        kind(handle, ObjectClass::PUBLIC_KEY, Some(KeyType::EC))
    }

    #[test]
    fn library_shapes_are_recognised() {
        assert_eq!(
            shape(&[secret(1, KeyType::AES)]),
            Shape::Secret {
                alg: KeyAlg::Aes256,
                key: 1
            }
        );
        assert_eq!(
            shape(&[secret(1, KeyType::GENERIC_SECRET)]),
            Shape::Secret {
                alg: KeyAlg::HmacSha256,
                key: 1
            }
        );
        let pair = Shape::KeyPair {
            private: 1,
            public: 2,
        };
        assert_eq!(shape(&[private_ec(1), public_ec(2)]), pair);
        assert_eq!(shape(&[public_ec(2), private_ec(1)]), pair, "any order");
    }

    #[test]
    fn other_shapes_are_foreign() {
        let certificate = kind(1, ObjectClass::CERTIFICATE, None);
        let no_class = ObjectKind {
            handle: 1,
            class: None,
            key_type: Some(KeyType::AES),
        };
        let no_key_type = kind(1, ObjectClass::SECRET_KEY, None);
        let rows: [&[ObjectKind<u8>]; 11] = [
            &[],
            &[certificate],
            &[no_class],
            &[no_key_type],
            &[secret(1, KeyType::DES3)],
            &[secret(1, KeyType::EC)],
            &[private_ec(1)],
            &[public_ec(1)],
            &[secret(1, KeyType::AES), secret(2, KeyType::AES)],
            &[private_ec(1), private_ec(2)],
            &[private_ec(1), public_ec(2), secret(3, KeyType::AES)],
        ];
        for kinds in rows {
            assert_eq!(shape(kinds), Shape::Foreign, "{kinds:?}");
        }
        let rsa_private = kind(1, ObjectClass::PRIVATE_KEY, Some(KeyType::RSA));
        assert_eq!(shape(&[rsa_private, public_ec(2)]), Shape::Foreign);
        let ec_secret = kind(1, ObjectClass::SECRET_KEY, Some(KeyType::EC));
        assert_eq!(shape(&[ec_secret, public_ec(2)]), Shape::Foreign);
    }

    #[test]
    fn token_label_is_one_to_32_printable_bytes() {
        assert_eq!(token_label(b""), None);
        assert_eq!(token_label(&[b'a'; 33]), None);
        assert_eq!(token_label(b"eki\x01"), None);
        assert_eq!(token_label(b"eki\x7f"), None);
        assert_eq!(token_label(b"eki\x80"), None);
        let mut padded = [b' '; 32];
        padded[..3].copy_from_slice(b"eki");
        assert_eq!(token_label(b"eki"), Some(padded));
        assert_eq!(token_label(&[b'z'; 32]), Some([b'z'; 32]));
    }

    #[test]
    fn token_labels_compare_blank_padded() {
        let wanted = token_label(b"ekibridge").expect("valid label");
        assert!(token_label_is("ekibridge", &wanted));
        assert!(!token_label_is("ekibridge2", &wanted));
        assert!(!token_label_is("ekibridg", &wanted));
        // A requested label with trailing blanks matches the token without them, as the 32
        // padded bytes are the same.
        let blanks = token_label(b"ekibridge  ").expect("valid label");
        assert!(token_label_is("ekibridge", &blanks));
        // Bytes that are not ASCII reach cryptoki's text as replacement characters.
        assert!(!token_label_is(
            "eki\u{FFFD}",
            &token_label(b"eki?").expect("valid")
        ));
        assert!(!token_label_is(&"x".repeat(33), &[b'x'; 32]));
    }

    #[test]
    fn config_checks_formats_in_field_order() {
        let fields = |token_label, user_pin| Pkcs11Fields {
            module_path: b"/nonexistent/module.so",
            token_label,
            user_pin,
        };
        let parse = |token_label, user_pin| Config::parse(&fields(token_label, user_pin)).err();
        assert_eq!(parse(b"", b"1234"), Some(Error::InvalidArgument));
        assert_eq!(parse(b"ekibridge", b""), Some(Error::InvalidArgument));
        assert_eq!(
            parse(b"ekibridge", &[b'1'; 256]),
            Some(Error::InvalidArgument)
        );
        let config = Config::parse(&fields(b"ekibridge", &[0xFF; 255])).expect("valid fields");
        assert_eq!(config.module_path, Path::new("/nonexistent/module.so"));
        assert_eq!(&config.token_label[..9], b"ekibridge");
        assert_eq!(config.user_pin.expose_secret().as_slice(), &[0xFF; 255]);
    }

    #[test]
    fn empty_and_missing_modules_are_backend_failures() {
        for path in ["", "/nonexistent/ekibridge-test-module.so"] {
            let result = Lease::acquire(Path::new(path));
            assert!(
                matches!(&result, Err(BackendError::Failed(text)) if !text.is_empty()),
                "{path:?}"
            );
        }
        assert!(
            !registry().contains_key(Path::new("/nonexistent/ekibridge-test-module.so")),
            "a module that failed to load is not recorded"
        );
    }

    #[test]
    fn failures_name_the_function_and_the_code() {
        let error = CkError::Pkcs11(RvError::PinIncorrect, cryptoki::context::Function::Login);
        assert_eq!(
            failure(error),
            BackendError::Failed("C_Login failed: CKR_PIN_INCORRECT".to_owned())
        );
        let error = CkError::Pkcs11(
            RvError::VendorDefined(0x8000_0001),
            cryptoki::context::Function::UnwrapKey,
        );
        assert_eq!(
            failure(error),
            BackendError::Failed("C_UnwrapKey failed: CKR_0x80000001".to_owned())
        );
        assert_eq!(rv_name(RvError::UnknownErrorCode(0x1F)), "CKR_0x0000001F");
    }

    #[test]
    fn templates_follow_the_mapping_table() {
        let label = Label::parse(b"eki").expect("valid label");
        let id = KeyId([7; 16]);
        let aes = secret_key_template(KeyAlg::Aes256, &label, &id).expect("secret alg");
        assert!(aes.contains(&Attribute::KeyType(KeyType::AES)));
        assert!(aes.contains(&Attribute::Wrap(true)));
        let mac = secret_key_template(KeyAlg::HmacSha256, &label, &id).expect("secret alg");
        assert!(mac.contains(&Attribute::KeyType(KeyType::GENERIC_SECRET)));
        assert!(mac.contains(&Attribute::Sign(true)));
        for template in [&aes, &mac] {
            assert!(template.contains(&Attribute::Id(vec![7; 16])));
            assert!(template.contains(&Attribute::Label(b"eki".to_vec())));
            assert!(template.contains(&Attribute::Private(true)));
            let no_value_len = template
                .iter()
                .all(|attribute| attribute.attribute_type() != AttributeType::ValueLen);
            assert!(no_value_len, "the unwrap template has no CKA_VALUE_LEN");
        }
        assert!(matches!(
            secret_key_template(KeyAlg::EcdsaP256, &label, &id),
            Err(BackendError::Internal(_))
        ));
        let (public, private) = key_pair_templates(&label, &id);
        assert!(public.contains(&Attribute::Private(false)));
        assert!(public.contains(&Attribute::EcParams(P256_PARAMS.to_vec())));
        assert!(private.contains(&Attribute::Extractable(false)));
        assert!(private.contains(&Attribute::Sensitive(true)));
    }

    #[test]
    fn states_follow_the_attribute_table() {
        let (t, f) = (Some(true), Some(false));
        assert_eq!(state_of(&[t, t], &[t, t]), Some(KeyState::Active));
        assert_eq!(state_of(&[f, f], &[t, t]), Some(KeyState::Retired));
        assert_eq!(state_of(&[f, f], &[f, f]), Some(KeyState::Revoked));
        assert_eq!(state_of(&[t], &[t]), Some(KeyState::Active));
        assert_eq!(state_of(&[f], &[t]), Some(KeyState::Retired));
        assert_eq!(state_of(&[f], &[f]), Some(KeyState::Revoked));
        type Flags<'a> = &'a [Option<bool>];
        let foreign: [(Flags, Flags); 8] = [
            (&[t], &[f]),
            (&[t, f], &[t, t]),
            (&[f, t], &[t, t]),
            (&[f, f], &[t, f]),
            (&[f, f], &[f, t]),
            (&[None], &[t]),
            (&[t], &[None]),
            (&[f], &[None]),
        ];
        for (protect, check) in foreign {
            assert_eq!(state_of(protect, check), None, "{protect:?} {check:?}");
        }
    }

    #[test]
    fn usage_groups_name_flags_only() {
        for alg in [KeyAlg::Aes256, KeyAlg::HmacSha256, KeyAlg::EcdsaP256] {
            for group in usage_groups(alg) {
                for &kind in group.flags {
                    let attribute = cleared(kind).expect("a usage flag");
                    assert_eq!(attribute.attribute_type(), kind);
                    assert_eq!(flag_value(&attribute), Some(false));
                }
            }
        }
        let [protect, check] = usage_groups(KeyAlg::EcdsaP256);
        assert_eq!((protect.half, check.half), (Half::Key, Half::Public));
        assert!(cleared(AttributeType::Label).is_err());
        assert_eq!(flag_value(&Attribute::Token(true)), None);
    }
}
