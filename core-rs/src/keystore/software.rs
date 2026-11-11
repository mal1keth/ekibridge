//! The software backend: keys in memory, for the lifetime of the handle.
//!
//! A map from id to label, lifecycle state and key material. AES-256 and HMAC-SHA256 keys are 32 random bytes;
//! an ECDSA P-256 key is a `p256` signing key. Every value is wiped when its key is destroyed and
//! when the handle is closed, because dropping the map drops each key.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use ekicore_abi::{
    EKI_HMAC_SHA256_LEN, EKI_P256_PUBLIC_KEY_LEN, EKI_P256_SIGNATURE_LEN, EKI_WRAPPED_KEY_LEN,
};
use getrandom::SysRng;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::Generate;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};

use super::{Backend, BackendError, BackendResult, Found, KeyAlg, KeyId, KeyInfo, KeyState, Label};
use crate::error::Error;
use crate::{hmac, keywrap};

/// The value of an AES-256 or HMAC-SHA256 key.
///
/// `SecretBox` rather than `Zeroizing<[u8; 32]>`: the bytes live on the heap from the moment
/// they are drawn, so moving a key (into the map, and between nodes when the `BTreeMap` splits
/// or merges them, which it does by bitwise moves that run no destructor) moves only the
/// pointer and never leaves an unwiped copy of the bytes behind. `SecretBox` also has no `Clone`
/// for this type, a redacted `Debug`, and makes every read an explicit `expose_secret`.
/// cbindgen:ignore
type Secret = SecretBox<[u8; keywrap::KEY_LEN]>;

/// Both kinds of material wipe themselves when dropped; these assertions make that a
/// compile-time fact rather than a reading of the crates' sources.
/// cbindgen:ignore
const _: () = {
    const fn wipes_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    wipes_on_drop::<Secret>();
    wipes_on_drop::<SigningKey>();
};

/// Key material; the variant is the algorithm, so the two can never disagree.
enum Material {
    Aes256(Secret),
    HmacSha256(Secret),
    /// Boxed for the reason given at [`Secret`]: the map moves only the pointer. `SigningKey`
    /// zeroes its secret scalar in its own `Drop` (`ecdsa` 0.17.0, `src/signing.rs`, the
    /// `impl Drop for SigningKey`), which is unconditional, not behind a feature.
    EcdsaP256(Box<SigningKey>),
}

impl Material {
    fn alg(&self) -> KeyAlg {
        match self {
            Self::Aes256(_) => KeyAlg::Aes256,
            Self::HmacSha256(_) => KeyAlg::HmacSha256,
            Self::EcdsaP256(_) => KeyAlg::EcdsaP256,
        }
    }

    /// New random material for `alg`.
    fn generate(alg: KeyAlg) -> BackendResult<Self> {
        match alg {
            KeyAlg::Aes256 => random_secret().map(Self::Aes256),
            KeyAlg::HmacSha256 => random_secret().map(Self::HmacSha256),
            KeyAlg::EcdsaP256 => random_signing_key().map(Self::EcdsaP256),
        }
    }

    /// The material of a key of the secret algorithm `alg` whose value is `secret`.
    fn from_secret(alg: KeyAlg, secret: Secret) -> BackendResult<Self> {
        match alg {
            KeyAlg::Aes256 => Ok(Self::Aes256(secret)),
            KeyAlg::HmacSha256 => Ok(Self::HmacSha256(secret)),
            KeyAlg::EcdsaP256 => Err(PRECONDITION),
        }
    }

    /// The 32-byte value of a secret key; `None` for a key pair.
    fn secret(&self) -> Option<&[u8; keywrap::KEY_LEN]> {
        match self {
            Self::Aes256(secret) | Self::HmacSha256(secret) => Some(secret.expose_secret()),
            Self::EcdsaP256(_) => None,
        }
    }
}

/// 32 bytes from the operating system's RNG, drawn straight into zeroizing heap storage.
fn random_secret() -> BackendResult<Secret> {
    let mut secret = Secret::default();
    getrandom::fill(secret.expose_secret_mut()).map_err(|error| {
        BackendError::Failed(format!("getrandom for key material failed: {error}"))
    })?;
    Ok(secret)
}

/// A new P-256 signing key from the operating system's RNG, by the crate's own generator
/// (rejection sampling of a scalar in `1..n`).
///
/// `getrandom::SysRng` is `getrandom::fill` behind the RNG traits the crate takes. It exists
/// because the `sys_rng` feature of `getrandom` is on: `crypto-common`, through which `p256` and
/// `aes-gcm` reach their RNG, enables it.
fn random_signing_key() -> BackendResult<Box<SigningKey>> {
    let key = SigningKey::try_generate_from_rng(&mut SysRng).map_err(|error| {
        BackendError::Failed(format!("getrandom for an ECDSA P-256 key failed: {error}"))
    })?;
    Ok(Box::new(key))
}

/// One stored key.
struct StoredKey {
    label: Label,
    /// The lifecycle state, a plain field: the store has already checked it against the state
    /// table before any operation reaches the backend.
    state: KeyState,
    material: Material,
}

impl StoredKey {
    /// A new ACTIVE key.
    fn active(label: &Label, material: Material) -> Self {
        Self {
            label: *label,
            state: KeyState::Active,
            material,
        }
    }
}

/// The store logic broke a precondition of [`Backend`].
/// cbindgen:ignore
const PRECONDITION: BackendError = BackendError::Internal(
    "the software key store was called with an id that does not name a key of the expected type",
);

/// The software backend.
///
/// `BTreeMap` rather than `HashMap`: callers choose ids in `eki_ks_unwrap`, and a tree gives
/// O(log n) operations for any set of ids without depending on a hash function; it is also what
/// the C++ library uses (`std::map`), so the two implementations read alike. Ids are public, so
/// the variable-time comparisons leak nothing.
pub struct Software {
    keys: BTreeMap<KeyId, StoredKey>,
}

impl Software {
    /// An empty store.
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
        }
    }

    fn key(&self, id: &KeyId) -> BackendResult<&StoredKey> {
        self.keys.get(id).ok_or(PRECONDITION)
    }

    /// The value of the secret key `id`, which must have algorithm `alg`.
    fn secret(&self, id: &KeyId, alg: KeyAlg) -> BackendResult<&[u8; keywrap::KEY_LEN]> {
        let key = self.key(id)?;
        if key.material.alg() != alg {
            return Err(PRECONDITION);
        }
        key.material.secret().ok_or(PRECONDITION)
    }

    /// The value of the secret key `id` of either secret algorithm.
    fn wrappable(&self, id: &KeyId) -> BackendResult<&[u8; keywrap::KEY_LEN]> {
        self.key(id)?.material.secret().ok_or(PRECONDITION)
    }

    fn signing_key(&self, id: &KeyId) -> BackendResult<&SigningKey> {
        match &self.key(id)?.material {
            Material::EcdsaP256(key) => Ok(key),
            Material::Aes256(_) | Material::HmacSha256(_) => Err(PRECONDITION),
        }
    }

    /// Adds a key under `id`: the single mutation of `create` and `unwrap`, made after everything
    /// that can fail. An id already in use breaks the precondition; the existing key is kept and
    /// the new one is dropped, which wipes it.
    fn insert(&mut self, id: KeyId, key: StoredKey) -> BackendResult<()> {
        match self.keys.entry(id) {
            Entry::Vacant(slot) => {
                slot.insert(key);
                Ok(())
            }
            Entry::Occupied(_) => Err(PRECONDITION),
        }
    }
}

impl Default for Software {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for Software {
    fn find(&mut self, id: &KeyId) -> BackendResult<Option<Found>> {
        Ok(self.keys.get(id).map(|key| {
            Found::Key(KeyInfo {
                alg: key.material.alg(),
                label: key.label,
                state: key.state,
            })
        }))
    }

    fn create(&mut self, alg: KeyAlg, label: &Label, id: &KeyId) -> BackendResult<()> {
        let material = Material::generate(alg)?;
        self.insert(*id, StoredKey::active(label, material))
    }

    fn public_key(&mut self, id: &KeyId) -> BackendResult<[u8; EKI_P256_PUBLIC_KEY_LEN]> {
        let point = self.signing_key(id)?.verifying_key().to_sec1_point(false);
        point
            .as_bytes()
            .try_into()
            .map_err(|_| BackendError::Internal("the uncompressed P-256 point is not 65 bytes"))
    }

    fn sign(&mut self, id: &KeyId, msg: &[u8]) -> BackendResult<[u8; EKI_P256_SIGNATURE_LEN]> {
        // `Signer::try_sign` hashes `msg` with SHA-256 and signs the digest with a nonce derived
        // by RFC 6979, so the signature is deterministic. The crate does not normalise `s` for
        // P-256 (`NORMALIZE_S` is false in `p256::ecdsa`), so either member of the pair can come
        // out; the contract accepts both.
        let signature: Signature = self.signing_key(id)?.try_sign(msg).map_err(|error| {
            BackendError::Failed(format!("ECDSA P-256 signing failed: {error}"))
        })?;
        Ok(signature.to_bytes().into())
    }

    fn hmac_sha256(&mut self, id: &KeyId, msg: &[u8]) -> BackendResult<[u8; EKI_HMAC_SHA256_LEN]> {
        let key = self.secret(id, KeyAlg::HmacSha256)?;
        // The only error `hmac_sha256` has is an empty key, and this one has 32 bytes.
        hmac::hmac_sha256(key, msg)
            .map_err(|_| BackendError::Internal("HMAC-SHA256 rejected a 32-byte key"))
    }

    fn hmac_sha256_verify(
        &mut self,
        id: &KeyId,
        msg: &[u8],
        tag: &[u8; EKI_HMAC_SHA256_LEN],
    ) -> BackendResult<()> {
        let key = self.secret(id, KeyAlg::HmacSha256)?;
        // `hmac_sha256_verify` compares in constant time (the `hmac` crate's `verify_slice`).
        match hmac::hmac_sha256_verify(key, msg, tag) {
            Ok(()) => Ok(()),
            Err(Error::AuthFailed) => Err(BackendError::AuthFailed(String::new())),
            Err(_) => Err(BackendError::Internal(
                "HMAC-SHA256 rejected a 32-byte key or tag",
            )),
        }
    }

    fn wrap(&mut self, kek: &KeyId, key: &KeyId) -> BackendResult<[u8; EKI_WRAPPED_KEY_LEN]> {
        Ok(keywrap::wrap(
            self.secret(kek, KeyAlg::Aes256)?,
            self.wrappable(key)?,
        ))
    }

    fn unwrap(
        &mut self,
        kek: &KeyId,
        blob: &[u8; EKI_WRAPPED_KEY_LEN],
        alg: KeyAlg,
        label: &Label,
        id: &KeyId,
    ) -> BackendResult<()> {
        let secret = match keywrap::unwrap(self.secret(kek, KeyAlg::Aes256)?, blob) {
            Ok(secret) => secret,
            Err(Error::AuthFailed) => return Err(BackendError::AuthFailed(String::new())),
            Err(_) => return Err(BackendError::Internal("AES key unwrap failed on sizes")),
        };
        let material = Material::from_secret(alg, secret)?;
        self.insert(*id, StoredKey::active(label, material))
    }

    fn set_state(&mut self, id: &KeyId, state: KeyState) -> BackendResult<()> {
        let key = self.keys.get_mut(id).ok_or(PRECONDITION)?;
        // `max` keeps a later state: a key never moves back.
        key.state = key.state.max(state);
        Ok(())
    }

    fn destroy(&mut self, id: &KeyId) -> BackendResult<()> {
        // Dropping the removed key wipes it: a `SecretBox` zeroes its bytes, a `SigningKey` its
        // scalar.
        self.keys.remove(id).map(drop).ok_or(PRECONDITION)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecdsa;

    const KEK: KeyId = KeyId([1; 16]);
    const MAC: KeyId = KeyId([2; 16]);
    const EC: KeyId = KeyId([3; 16]);
    const COPY: KeyId = KeyId([4; 16]);

    fn label(text: &str) -> Label {
        Label::parse(text.as_bytes()).expect("valid test label")
    }

    fn with_keys(algs: &[(KeyId, KeyAlg)]) -> Software {
        let mut store = Software::new();
        for (id, alg) in algs {
            store
                .create(*alg, &label("test"), id)
                .expect("create succeeds");
        }
        store
    }

    #[test]
    fn find_describes_each_algorithm() {
        let mut store = with_keys(&[
            (KEK, KeyAlg::Aes256),
            (MAC, KeyAlg::HmacSha256),
            (EC, KeyAlg::EcdsaP256),
        ]);
        for (id, alg) in [
            (KEK, KeyAlg::Aes256),
            (MAC, KeyAlg::HmacSha256),
            (EC, KeyAlg::EcdsaP256),
        ] {
            let info = KeyInfo {
                alg,
                label: label("test"),
                state: KeyState::Active,
            };
            assert_eq!(store.find(&id), Ok(Some(Found::Key(info))));
        }
        assert_eq!(store.find(&COPY), Ok(None));
    }

    #[test]
    fn create_on_a_used_id_keeps_the_existing_key() {
        let mut store = with_keys(&[(KEK, KeyAlg::Aes256), (MAC, KeyAlg::HmacSha256)]);
        let tag = store.hmac_sha256(&MAC, b"m").expect("hmac succeeds");
        let blob = store.wrap(&KEK, &MAC).expect("wrap succeeds");
        assert_eq!(
            store.create(KeyAlg::Aes256, &label("other"), &MAC),
            Err(PRECONDITION)
        );
        assert_eq!(store.keys.len(), 2);
        assert_eq!(store.hmac_sha256(&MAC, b"m"), Ok(tag));
        assert_eq!(store.wrap(&KEK, &MAC), Ok(blob));
    }

    #[test]
    fn failed_unwrap_inserts_nothing() {
        let mut store = with_keys(&[(KEK, KeyAlg::Aes256), (MAC, KeyAlg::HmacSha256)]);
        let mut blob = store.wrap(&KEK, &MAC).expect("wrap succeeds");
        blob[0] ^= 1;
        let copy = label("copy");
        assert_eq!(
            store.unwrap(&KEK, &blob, KeyAlg::HmacSha256, &copy, &COPY),
            Err(BackendError::AuthFailed(String::new()))
        );
        blob[0] ^= 1;
        assert_eq!(
            store.unwrap(&KEK, &blob, KeyAlg::EcdsaP256, &copy, &COPY),
            Err(PRECONDITION),
            "a key pair cannot come from a blob"
        );
        assert_eq!(
            store.unwrap(&KEK, &blob, KeyAlg::Aes256, &copy, &MAC),
            Err(PRECONDITION),
            "an id in use is never overwritten"
        );
        assert_eq!(store.keys.len(), 2);
        assert_eq!(store.find(&COPY), Ok(None));
    }

    #[test]
    fn unwrapped_copy_behaves_like_the_original() {
        let mut store = with_keys(&[(KEK, KeyAlg::Aes256), (MAC, KeyAlg::HmacSha256)]);
        let blob = store.wrap(&KEK, &MAC).expect("wrap succeeds");
        store
            .unwrap(&KEK, &blob, KeyAlg::HmacSha256, &label("copy"), &COPY)
            .expect("unwrap succeeds");
        assert_eq!(
            store.hmac_sha256(&COPY, b"m"),
            store.hmac_sha256(&MAC, b"m")
        );
        assert_eq!(store.destroy(&COPY), Ok(()));
        assert_eq!(store.find(&COPY), Ok(None));
        assert_eq!(store.destroy(&COPY), Err(PRECONDITION));
    }

    #[test]
    fn operations_on_the_wrong_material_break_the_precondition() {
        let mut store = with_keys(&[(KEK, KeyAlg::Aes256), (MAC, KeyAlg::HmacSha256)]);
        assert_eq!(store.hmac_sha256(&KEK, b"m"), Err(PRECONDITION));
        assert_eq!(store.sign(&KEK, b"m"), Err(PRECONDITION));
        assert_eq!(store.public_key(&MAC), Err(PRECONDITION));
        assert_eq!(store.wrap(&MAC, &KEK), Err(PRECONDITION));
        assert_eq!(store.wrap(&COPY, &KEK), Err(PRECONDITION));
    }

    #[test]
    fn signature_verifies_under_the_public_key() {
        let mut store = with_keys(&[(EC, KeyAlg::EcdsaP256)]);
        let public_key = store.public_key(&EC).expect("public key");
        assert_eq!(public_key[0], 0x04);
        for msg in [&b""[..], b"message"] {
            let sig = store.sign(&EC, msg).expect("sign succeeds");
            assert_eq!(ecdsa::p256_verify(&public_key, msg, &sig), Ok(()));
            assert_eq!(store.sign(&EC, msg), Ok(sig), "RFC 6979 is deterministic");
        }
    }

    #[test]
    fn state_moves_forward_only() {
        let mut store = with_keys(&[(MAC, KeyAlg::HmacSha256)]);
        let state = |store: &mut Software| match store.find(&MAC) {
            Ok(Some(Found::Key(info))) => Some(info.state),
            _ => None,
        };
        assert_eq!(state(&mut store), Some(KeyState::Active));
        assert_eq!(store.set_state(&MAC, KeyState::Retired), Ok(()));
        assert_eq!(state(&mut store), Some(KeyState::Retired));
        assert_eq!(store.set_state(&MAC, KeyState::Active), Ok(()));
        assert_eq!(state(&mut store), Some(KeyState::Retired), "never back");
        assert_eq!(store.set_state(&MAC, KeyState::Revoked), Ok(()));
        assert_eq!(state(&mut store), Some(KeyState::Revoked));
        assert_eq!(store.set_state(&COPY, KeyState::Revoked), Err(PRECONDITION));
    }

    #[test]
    fn hmac_verify_accepts_only_the_tag() {
        let mut store = with_keys(&[(KEK, KeyAlg::Aes256), (MAC, KeyAlg::HmacSha256)]);
        for msg in [&b""[..], b"message"] {
            let mut tag = store.hmac_sha256(&MAC, msg).expect("hmac succeeds");
            assert_eq!(store.hmac_sha256_verify(&MAC, msg, &tag), Ok(()));
            tag[31] ^= 1;
            assert_eq!(
                store.hmac_sha256_verify(&MAC, msg, &tag),
                Err(BackendError::AuthFailed(String::new()))
            );
        }
        assert_eq!(
            store.hmac_sha256_verify(&KEK, b"m", &[0; 32]),
            Err(PRECONDITION)
        );
    }
}
