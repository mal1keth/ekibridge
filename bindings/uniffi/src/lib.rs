//! `ekicore-uniffi`: UniFFI bindings over the safe API of `ekicore-rs`.
//!
//! The functions here wrap the safe modules (`hmac`, `hkdf`, `aead`, `ecdsa`), never the
//! `extern "C"` layer. UniFFI's proc macros generate the C scaffolding the foreign code calls and
//! the metadata `uniffi-bindgen` reads from the built library to write Python, Kotlin and Swift.
//!
//! Every argument and result crosses the boundary as a copy: UniFFI serialises a byte string into
//! a buffer, and the receiving side reads it into its own object. The copies of secret inputs
//! that this crate holds (keys and input keying material) and of secret outputs before they are
//! handed to UniFFI are wiped on drop; the serialisation buffers and the foreign objects are not.

// The macros below generate `unsafe` scaffolding (`#[unsafe(no_mangle)]` exports and their
// bodies). Denying `unsafe_code` still rejects any `unsafe` written in this file, because the
// lint skips only tokens that come from the macros.
#![deny(unsafe_code)]
#![warn(missing_docs)]

use ekicore_abi::{
    EKI_AEAD_AES_256_GCM, EKI_AEAD_CHACHA20_POLY1305, EKI_AEAD_TAG_LEN, eki_aead_alg,
};
use ekicore_rs::error::Error;
use ekicore_rs::{aead, ecdsa, hkdf, hmac};
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

/// Failure of a call: one variant per error status of the C ABI. The message is the status name,
/// for example `EKI_ERR_AUTH_FAILED`.
///
/// The functions of this module raise only `InvalidArgument` and `AuthFailed`; the other variants
/// complete the one-to-one mapping from the Rust error type.
// `flat_error`: the variants carry no fields, and a flat error crosses as its variant plus its
// `Display` text, which gives every foreign exception the status name as its message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Error)]
#[uniffi(flat_error)]
pub enum EkiError {
    /// A tag or signature does not match the data it covers (`EKI_ERR_AUTH_FAILED`).
    AuthFailed,
    /// An argument has an invalid length, range or format (`EKI_ERR_INVALID_ARGUMENT`).
    InvalidArgument,
    /// A required pointer was NULL (`EKI_ERR_NULL_POINTER`).
    NullPointer,
    /// No key carries the given id (`EKI_ERR_KEY_NOT_FOUND`).
    KeyNotFound,
    /// A key already carries the given id (`EKI_ERR_KEY_EXISTS`).
    KeyExists,
    /// The key's algorithm does not allow the operation (`EKI_ERR_WRONG_KEY_TYPE`).
    WrongKeyType,
    /// The operation is not compiled into this library (`EKI_ERR_UNSUPPORTED`).
    Unsupported,
    /// The key store backend failed (`EKI_ERR_BACKEND`).
    Backend,
    /// An internal invariant did not hold (`EKI_ERR_INTERNAL`).
    Internal,
    /// The key's lifecycle state does not allow the operation (`EKI_ERR_KEY_STATE`).
    KeyState,
    /// Destroying a key needs approvals (`EKI_ERR_APPROVAL_REQUIRED`).
    ApprovalRequired,
}

impl From<Error> for EkiError {
    fn from(error: Error) -> Self {
        // No wildcard arm, as in `From<Error> for eki_status`: a variant added to the Rust error
        // fails to compile here until it is mapped.
        match error {
            Error::AuthFailed => Self::AuthFailed,
            Error::InvalidArgument => Self::InvalidArgument,
            Error::NullPointer => Self::NullPointer,
            Error::KeyNotFound => Self::KeyNotFound,
            Error::KeyExists => Self::KeyExists,
            Error::WrongKeyType => Self::WrongKeyType,
            Error::Unsupported => Self::Unsupported,
            Error::Backend => Self::Backend,
            Error::Internal => Self::Internal,
            Error::KeyState => Self::KeyState,
            Error::ApprovalRequired => Self::ApprovalRequired,
        }
    }
}

impl std::fmt::Display for EkiError {
    /// The C status name, the same text `eki_status_name` returns.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AuthFailed => "EKI_ERR_AUTH_FAILED",
            Self::InvalidArgument => "EKI_ERR_INVALID_ARGUMENT",
            Self::NullPointer => "EKI_ERR_NULL_POINTER",
            Self::KeyNotFound => "EKI_ERR_KEY_NOT_FOUND",
            Self::KeyExists => "EKI_ERR_KEY_EXISTS",
            Self::WrongKeyType => "EKI_ERR_WRONG_KEY_TYPE",
            Self::Unsupported => "EKI_ERR_UNSUPPORTED",
            Self::Backend => "EKI_ERR_BACKEND",
            Self::Internal => "EKI_ERR_INTERNAL",
            Self::KeyState => "EKI_ERR_KEY_STATE",
            Self::ApprovalRequired => "EKI_ERR_APPROVAL_REQUIRED",
        })
    }
}

impl std::error::Error for EkiError {}

/// AEAD algorithm. A closed enum: a foreign caller cannot name an unknown algorithm, so the
/// selector check of the C ABI has nothing to reject here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AeadAlgorithm {
    /// AES-256-GCM.
    Aes256Gcm,
    /// ChaCha20-Poly1305 (RFC 8439).
    Chacha20Poly1305,
}

impl AeadAlgorithm {
    /// The C selector value the safe module takes.
    fn selector(self) -> eki_aead_alg {
        match self {
            Self::Aes256Gcm => EKI_AEAD_AES_256_GCM,
            Self::Chacha20Poly1305 => EKI_AEAD_CHACHA20_POLY1305,
        }
    }
}

/// Result of [`aead_seal`]: the ciphertext, as long as the plaintext, and the detached 16-byte
/// tag.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SealedBox {
    /// Ciphertext, the same length as the plaintext.
    pub ciphertext: Vec<u8>,
    /// Authentication tag, 16 bytes.
    pub tag: Vec<u8>,
}

/// HMAC-SHA256 of `msg` under `key`: a 32-byte tag. An empty `key` is `InvalidArgument`.
#[uniffi::export]
pub fn hmac_sha256(key: Vec<u8>, msg: Vec<u8>) -> Result<Vec<u8>, EkiError> {
    let key = Zeroizing::new(key);
    Ok(hmac::hmac_sha256(&key, &msg)?.to_vec())
}

/// Checks in constant time that `tag` is the HMAC-SHA256 of `msg` under `key`. An empty `key` or
/// a `tag` that is not 32 bytes is `InvalidArgument`; a wrong tag is `AuthFailed`.
#[uniffi::export]
pub fn hmac_sha256_verify(key: Vec<u8>, msg: Vec<u8>, tag: Vec<u8>) -> Result<(), EkiError> {
    let key = Zeroizing::new(key);
    Ok(hmac::hmac_sha256_verify(&key, &msg, &tag)?)
}

/// HKDF-SHA256 (RFC 5869): derives `length` bytes from `ikm`, `salt` and `info`. An empty `salt`
/// is the RFC default. `ikm` empty or over 32768 bytes, `salt` or `info` over 32768 bytes, and
/// `length` 0 or over 8160 are `InvalidArgument`.
#[uniffi::export]
pub fn hkdf_sha256(
    ikm: Vec<u8>,
    salt: Vec<u8>,
    info: Vec<u8>,
    length: u32,
) -> Result<Vec<u8>, EkiError> {
    let ikm = Zeroizing::new(ikm);
    let length = usize::try_from(length).map_err(|_| EkiError::InvalidArgument)?;
    // `length` is caller input, so it is checked before it sizes an allocation: the safe module
    // rejects an over-long output anyway, but only after the buffer would have been allocated.
    if length > ekicore_abi::EKI_HKDF_MAX_OKM_LEN {
        return Err(EkiError::InvalidArgument);
    }
    let mut okm = Zeroizing::new(vec![0u8; length]);
    hkdf::hkdf_sha256(&ikm, &salt, &info, &mut okm)?;
    // The returned copy goes to UniFFI, which serialises it and drops it unwiped; `okm` itself is
    // wiped here.
    Ok(okm.to_vec())
}

/// Encrypts `plaintext` with `algorithm` under a 32-byte `key` and a 12-byte `nonce`,
/// authenticating `aad` as well. A key or nonce of another length is `InvalidArgument`. A nonce
/// must never be reused with the same key; choosing it is the caller's job.
#[uniffi::export]
pub fn aead_seal(
    algorithm: AeadAlgorithm,
    key: Vec<u8>,
    nonce: Vec<u8>,
    aad: Vec<u8>,
    plaintext: Vec<u8>,
) -> Result<SealedBox, EkiError> {
    let key = Zeroizing::new(key);
    let plaintext = Zeroizing::new(plaintext);
    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut tag = vec![0u8; EKI_AEAD_TAG_LEN];
    aead::seal(
        algorithm.selector(),
        &key,
        &nonce,
        &aad,
        &plaintext,
        &mut ciphertext,
        &mut tag,
    )?;
    Ok(SealedBox { ciphertext, tag })
}

/// Verifies `tag` and decrypts `ciphertext`. A key, nonce or tag of the wrong length is
/// `InvalidArgument`; a tag that does not verify (wrong key, nonce, aad, ciphertext or tag) is
/// `AuthFailed`, and no plaintext is returned.
#[uniffi::export]
pub fn aead_open(
    algorithm: AeadAlgorithm,
    key: Vec<u8>,
    nonce: Vec<u8>,
    aad: Vec<u8>,
    ciphertext: Vec<u8>,
    tag: Vec<u8>,
) -> Result<Vec<u8>, EkiError> {
    let key = Zeroizing::new(key);
    let mut plaintext = Zeroizing::new(vec![0u8; ciphertext.len()]);
    aead::open(
        algorithm.selector(),
        &key,
        &nonce,
        &aad,
        &ciphertext,
        &tag,
        &mut plaintext,
    )?;
    Ok(plaintext.to_vec())
}

/// Verifies an ECDSA P-256 / SHA-256 signature `signature` (`r || s`, 64 bytes) over `msg` by
/// `public_key` (SEC1 uncompressed, 65 bytes). A malformed key is `InvalidArgument`; a signature
/// that does not verify is `AuthFailed`.
#[uniffi::export]
pub fn ecdsa_p256_verify(
    public_key: Vec<u8>,
    msg: Vec<u8>,
    signature: Vec<u8>,
) -> Result<(), EkiError> {
    Ok(ecdsa::p256_verify(&public_key, &msg, &signature)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_maps_to_its_variant_and_status_name() {
        let pairs = [
            (Error::AuthFailed, EkiError::AuthFailed),
            (Error::InvalidArgument, EkiError::InvalidArgument),
            (Error::NullPointer, EkiError::NullPointer),
            (Error::KeyNotFound, EkiError::KeyNotFound),
            (Error::KeyExists, EkiError::KeyExists),
            (Error::WrongKeyType, EkiError::WrongKeyType),
            (Error::Unsupported, EkiError::Unsupported),
            (Error::Backend, EkiError::Backend),
            (Error::Internal, EkiError::Internal),
            (Error::KeyState, EkiError::KeyState),
            (Error::ApprovalRequired, EkiError::ApprovalRequired),
        ];
        for (error, expected) in pairs {
            assert_eq!(EkiError::from(error), expected, "{error:?}");
            // The variants of `eki_status` are named after the C identifiers, so their derived
            // `Debug` output is the status name.
            let status = ekicore_abi::eki_status::from(error);
            assert_eq!(expected.to_string(), format!("{status:?}"));
        }
    }

    #[test]
    fn hkdf_length_above_the_cap_is_rejected_before_allocating() {
        let result = hkdf_sha256(vec![1; 16], Vec::new(), Vec::new(), u32::MAX);
        assert_eq!(result, Err(EkiError::InvalidArgument));
    }

    #[test]
    fn seal_then_open_round_trips() {
        for algorithm in [AeadAlgorithm::Aes256Gcm, AeadAlgorithm::Chacha20Poly1305] {
            let sealed = aead_seal(
                algorithm,
                vec![7; 32],
                vec![9; 12],
                b"aad".to_vec(),
                b"pt".to_vec(),
            )
            .expect("valid arguments");
            let opened = aead_open(
                algorithm,
                vec![7; 32],
                vec![9; 12],
                b"aad".to_vec(),
                sealed.ciphertext,
                sealed.tag,
            );
            assert_eq!(opened, Ok(b"pt".to_vec()), "{algorithm:?}");
        }
    }
}
