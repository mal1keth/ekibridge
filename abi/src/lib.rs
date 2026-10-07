//! C ABI types and constants shared by `libekicore` (C++) and `libekicore_rs` (Rust).
//!
//! Every item here mirrors a declaration in `include/ekicore.h`. The header is produced from
//! these definitions together with `core-rs/src/ffi.rs`, so the C names are kept as the Rust
//! names. Nothing in this crate does any work: it only fixes layouts, values and names.
//!
//! Conventions:
//!
//! * `eki_status` is written by the library and read by the caller, so it is a real enum.
//! * Selectors the caller passes in (`eki_aead_alg`, `eki_key_alg`, `eki_ks_backend`) are
//!   transparent `i32` newtypes with `const` values, so every C integer is representable and
//!   an unknown value can be answered with a status instead of undefined behaviour.
//! * `eki_ks` is opaque: C only ever holds a pointer to it.

#![no_std]
#![forbid(unsafe_code)]
#![allow(non_camel_case_types)]
#![warn(missing_docs)]

use core::ffi::c_char;

// ---------------------------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------------------------

/// ABI version implemented by both libraries. Bumped only for incompatible changes.
pub const EKI_ABI_VERSION: u32 = 1;
/// Length in bytes of an HMAC-SHA256 tag.
pub const EKI_HMAC_SHA256_LEN: usize = 32;
/// Length in bytes of an AEAD key (AES-256-GCM and ChaCha20-Poly1305).
pub const EKI_AEAD_KEY_LEN: usize = 32;
/// Length in bytes of an AEAD nonce.
pub const EKI_AEAD_NONCE_LEN: usize = 12;
/// Length in bytes of an AEAD authentication tag.
pub const EKI_AEAD_TAG_LEN: usize = 16;
/// Largest plaintext or ciphertext length for both algorithms: 2^36 - 32 (the GCM limit).
pub const EKI_AEAD_MAX_LEN: u64 = 68_719_476_704u64;
/// Largest HKDF-SHA256 output length: 255 * 32.
pub const EKI_HKDF_MAX_OKM_LEN: usize = 8160;
/// Cap on the HKDF input lengths `ikm_len`, `salt_len` and `info_len` (OpenSSL `HKDF_MAXINFO`).
pub const EKI_HKDF_MAX_INPUT_LEN: usize = 32768;
/// Length in bytes of a key id.
pub const EKI_KEY_ID_LEN: usize = 16;
/// Largest key label length in bytes, excluding the terminating NUL.
pub const EKI_LABEL_MAX_LEN: usize = 64;
/// Length in bytes of a P-256 public key in SEC1 uncompressed form: `0x04 || X || Y`.
pub const EKI_P256_PUBLIC_KEY_LEN: usize = 65;
/// Length in bytes of an ECDSA P-256 signature: big-endian `r || s`, fixed width.
pub const EKI_P256_SIGNATURE_LEN: usize = 64;
/// Length in bytes of a wrapped key: the RFC 3394 output for a 32-byte key.
pub const EKI_WRAPPED_KEY_LEN: usize = 40;

/// Length in bytes of a hybrid KEM public key:
/// X25519 public key (32) || ML-KEM-768 encapsulation key (1184).
pub const EKI_HYBRID_PK_LEN: usize = 1216;
/// Length in bytes of a hybrid KEM secret key:
/// X25519 secret key (32) || ML-KEM-768 seed d || z (64).
pub const EKI_HYBRID_SK_LEN: usize = 96;
/// Length in bytes of a hybrid KEM ciphertext:
/// X25519 ephemeral public key (32) || ML-KEM-768 ciphertext (1088).
pub const EKI_HYBRID_CT_LEN: usize = 1120;
/// Length in bytes of a hybrid KEM shared secret.
pub const EKI_HYBRID_SS_LEN: usize = 32;

// ---------------------------------------------------------------------------------------------
// Status codes
// ---------------------------------------------------------------------------------------------

/// Result of every fallible call. Values are stable and only ever appended.
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum eki_status {
    /// The call succeeded.
    EKI_OK = 0,
    /// A required pointer argument was NULL.
    EKI_ERR_NULL_POINTER = 1,
    /// An argument had an invalid length, range, format or an unknown selector value.
    EKI_ERR_INVALID_ARGUMENT = 2,
    /// Reserved for future variable-length outputs.
    EKI_ERR_BUFFER_TOO_SMALL = 3,
    /// The selector or function is known but not compiled into this library.
    EKI_ERR_UNSUPPORTED = 4,
    /// Authentication failed: AEAD tag, HMAC verify, ECDSA verify or AES key wrap integrity.
    EKI_ERR_AUTH_FAILED = 5,
    /// No key with the given id exists in the store.
    EKI_ERR_KEY_NOT_FOUND = 6,
    /// A key with the given id already exists in the store.
    EKI_ERR_KEY_EXISTS = 7,
    /// The key exists but has the wrong algorithm for this operation.
    EKI_ERR_WRONG_KEY_TYPE = 8,
    /// Internal failure of OpenSSL or the PKCS#11 module; never caused by caller input.
    EKI_ERR_BACKEND = 9,
    /// A panic or exception was caught, or an internal invariant was violated.
    EKI_ERR_INTERNAL = 10,
}

// ---------------------------------------------------------------------------------------------
// Selectors (input-only, so any C integer must be representable)
// ---------------------------------------------------------------------------------------------

/// AEAD algorithm selector. Unknown values are answered with `EKI_ERR_INVALID_ARGUMENT`.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct eki_aead_alg(pub i32);

/// AES-256-GCM.
pub const EKI_AEAD_AES_256_GCM: eki_aead_alg = eki_aead_alg(1);
/// ChaCha20-Poly1305 (RFC 8439).
pub const EKI_AEAD_CHACHA20_POLY1305: eki_aead_alg = eki_aead_alg(2);

/// Key algorithm selector. Unknown values are answered with `EKI_ERR_INVALID_ARGUMENT`.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct eki_key_alg(pub i32);

/// 32-byte AES secret; usable as a key-encryption key; wrappable.
pub const EKI_KEY_AES_256: eki_key_alg = eki_key_alg(1);
/// 32-byte HMAC-SHA256 secret; used through `eki_ks_hmac_sha256`; wrappable.
pub const EKI_KEY_HMAC_SHA256: eki_key_alg = eki_key_alg(2);
/// ECDSA P-256 key pair; used through `eki_ks_sign` and `eki_ks_get_public_key`; not wrappable.
pub const EKI_KEY_ECDSA_P256: eki_key_alg = eki_key_alg(3);

/// Key store backend selector. Unknown values are answered with `EKI_ERR_INVALID_ARGUMENT`.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct eki_ks_backend(pub i32);

/// In-memory software key store.
pub const EKI_KS_SOFTWARE: eki_ks_backend = eki_ks_backend(1);
/// Key store held in a PKCS#11 token.
pub const EKI_KS_PKCS11: eki_ks_backend = eki_ks_backend(2);

// ---------------------------------------------------------------------------------------------
// Structs and the opaque handle
// ---------------------------------------------------------------------------------------------

/// Identifier of a stored key: 16 random bytes made by the library at generation time.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct eki_key_id {
    /// The id bytes.
    pub bytes: [u8; 16],
}

/// Public description of a stored key.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct eki_key_info {
    /// Algorithm of the key.
    pub alg: eki_key_alg,
    /// Label, NUL-padded through byte 64.
    pub label: [c_char; 65],
}

// Deliberately not `#[repr(C)]`: cbindgen then declares an incomplete type in the header, so C
// and C++ callers can only hold pointers to it.
/// Key store handle. Opaque and library-allocated; freed only by `eki_ks_close`.
pub struct eki_ks {
    _private: [u8; 0],
}

/// Configuration for `eki_ks_open`. The library copies the strings and keeps no pointer.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct eki_ks_config {
    /// Which backend to open.
    pub backend: eki_ks_backend,
    /// Path of the PKCS#11 module. PKCS#11 backend only.
    pub pkcs11_module_path: *const c_char,
    /// Label of the PKCS#11 token, 1 to 32 printable bytes. PKCS#11 backend only.
    pub pkcs11_token_label: *const c_char,
    /// User PIN, 1 to 255 bytes; copied into zeroizing storage. PKCS#11 backend only.
    pub pkcs11_user_pin: *const c_char,
}
