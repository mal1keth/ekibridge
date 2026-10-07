//! The C ABI of `libekicore_rs`.
//!
//! This is the only file in the crate that may contain `unsafe`. Every `extern "C"` function
//! here will wrap its body in `catch_unwind`, so a panic becomes `EKI_ERR_INTERNAL` and never
//! unwinds into the C caller. The declarations in this file and in the `ekicore-abi` crate are
//! the source of `include/ekicore.h`: `scripts/check-header.sh` regenerates the header from
//! them and fails if the committed copy differs.
//!
//! Until the lessons land, the functions below are stubs that return `EKI_ERR_UNSUPPORTED`
//! without looking at any argument. The three metadata functions and `eki_ks_close` are
//! complete. The pointer, length and validation rules every function will follow are in
//! `docs/ffi-contract.md`.

// The C ABI fixes the argument lists, and the stubs ignore their arguments for now.
#![allow(unused_variables)]
#![allow(clippy::too_many_arguments)]
// A `# Safety` section on each function would be copied into the generated C header. The
// shared contract is stated once, in the module documentation and in `docs/ffi-contract.md`.
#![allow(clippy::missing_safety_doc)]

use core::ffi::{CStr, c_char};

use ekicore_abi::{
    EKI_ABI_VERSION, eki_aead_alg, eki_key_alg, eki_key_id, eki_key_info, eki_ks, eki_ks_config,
    eki_status,
};

/// `eki_version()` result: implementation name, a space, the crate version, and a NUL.
/// cbindgen:ignore
static VERSION: &str = concat!("ekicore-rs ", env!("CARGO_PKG_VERSION"), "\0");

/// Names of the status values, indexed by value.
/// cbindgen:ignore
static STATUS_NAMES: [&CStr; 11] = [
    c"EKI_OK",
    c"EKI_ERR_NULL_POINTER",
    c"EKI_ERR_INVALID_ARGUMENT",
    c"EKI_ERR_BUFFER_TOO_SMALL",
    c"EKI_ERR_UNSUPPORTED",
    c"EKI_ERR_AUTH_FAILED",
    c"EKI_ERR_KEY_NOT_FOUND",
    c"EKI_ERR_KEY_EXISTS",
    c"EKI_ERR_WRONG_KEY_TYPE",
    c"EKI_ERR_BACKEND",
    c"EKI_ERR_INTERNAL",
];

/// Name returned for any integer that is not a status value.
/// cbindgen:ignore
static STATUS_UNKNOWN: &CStr = c"EKI_STATUS_UNKNOWN";

/// Returns the ABI version this library implements (`EKI_ABI_VERSION`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_abi_version() -> u32 {
    EKI_ABI_VERSION
}

/// Returns the implementation name and version, for example `ekicore-rs 0.1.0`.
/// The string has static storage and is never NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_version() -> *const c_char {
    VERSION.as_ptr().cast()
}

/// Returns the identifier of a status value, for example `EKI_ERR_AUTH_FAILED`, or
/// `EKI_STATUS_UNKNOWN` for any other integer. The string has static storage and is never NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_status_name(status: i32) -> *const c_char {
    let name = usize::try_from(status)
        .ok()
        .and_then(|index| STATUS_NAMES.get(index).copied())
        .unwrap_or(STATUS_UNKNOWN);
    name.as_ptr()
}

/// Computes HMAC-SHA256 of `msg` under `key` and writes the 32-byte tag to `out`.
/// `key_len` must be non-zero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_hmac_sha256(
    key: *const u8,
    key_len: usize,
    msg: *const u8,
    msg_len: usize,
    out: *mut u8,
) -> eki_status {
    eki_status::EKI_ERR_UNSUPPORTED
}

/// Compares `tag`, which must be exactly 32 bytes, with HMAC-SHA256 of `msg` under `key` in
/// constant time. A mismatch returns `EKI_ERR_AUTH_FAILED`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_hmac_sha256_verify(
    key: *const u8,
    key_len: usize,
    msg: *const u8,
    msg_len: usize,
    tag: *const u8,
    tag_len: usize,
) -> eki_status {
    eki_status::EKI_ERR_UNSUPPORTED
}

/// Derives `okm_len` bytes (1 to 8160) with HKDF-SHA256 (RFC 5869). An empty `salt` selects the
/// RFC default salt.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_hkdf_sha256(
    ikm: *const u8,
    ikm_len: usize,
    salt: *const u8,
    salt_len: usize,
    info: *const u8,
    info_len: usize,
    okm: *mut u8,
    okm_len: usize,
) -> eki_status {
    eki_status::EKI_ERR_UNSUPPORTED
}

/// Encrypts `pt` into `ct_out` (`pt_len` bytes) and writes the 16-byte tag to `tag_out`.
/// `key_len` must be 32 and `nonce_len` 12.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_aead_seal(
    alg: eki_aead_alg,
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    pt: *const u8,
    pt_len: usize,
    ct_out: *mut u8,
    tag_out: *mut u8,
) -> eki_status {
    eki_status::EKI_ERR_UNSUPPORTED
}

/// Verifies the 16-byte `tag` and decrypts `ct` into `pt_out` (`ct_len` bytes). On any failure
/// `pt_out` is zero-filled.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_aead_open(
    alg: eki_aead_alg,
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    ct: *const u8,
    ct_len: usize,
    tag: *const u8,
    pt_out: *mut u8,
) -> eki_status {
    eki_status::EKI_ERR_UNSUPPORTED
}

/// Verifies a 64-byte `r || s` ECDSA P-256 signature over SHA-256 of `msg` against a 65-byte
/// SEC1 uncompressed public key.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_ecdsa_p256_verify(
    public_key: *const u8,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
) -> eki_status {
    eki_status::EKI_ERR_UNSUPPORTED
}

/// Opens a key store as described by `config` and stores the handle in `*out`.
/// `*out` is NULL on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_ks_open(
    config: *const eki_ks_config,
    out: *mut *mut eki_ks,
) -> eki_status {
    eki_status::EKI_ERR_UNSUPPORTED
}

/// Closes the store and frees the handle. Passing NULL is allowed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_ks_close(ks: *mut eki_ks) {}

/// Copies the most recent error message of the handle into `buf` with snprintf semantics and
/// returns its full length, excluding the NUL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_ks_last_error_message(
    ks: *const eki_ks,
    buf: *mut c_char,
    buf_len: usize,
) -> usize {
    0
}

/// Generates a key of algorithm `alg` with a label of 1 to 64 printable bytes and returns its
/// new id in `id_out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_ks_generate(
    ks: *mut eki_ks,
    alg: eki_key_alg,
    label: *const c_char,
    id_out: *mut eki_key_id,
) -> eki_status {
    eki_status::EKI_ERR_UNSUPPORTED
}

/// Reports the algorithm and label of the key with the given id.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_ks_get_info(
    ks: *mut eki_ks,
    id: *const eki_key_id,
    info_out: *mut eki_key_info,
) -> eki_status {
    eki_status::EKI_ERR_UNSUPPORTED
}

/// Writes the 65-byte SEC1 uncompressed public key of an ECDSA P-256 key to `out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_ks_get_public_key(
    ks: *mut eki_ks,
    id: *const eki_key_id,
    out: *mut u8,
) -> eki_status {
    eki_status::EKI_ERR_UNSUPPORTED
}

/// Signs SHA-256 of `msg` with an ECDSA P-256 key and writes the 64-byte `r || s` signature to
/// `sig_out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_ks_sign(
    ks: *mut eki_ks,
    id: *const eki_key_id,
    msg: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
) -> eki_status {
    eki_status::EKI_ERR_UNSUPPORTED
}

/// Computes HMAC-SHA256 of `msg` under a stored HMAC key and writes the 32-byte tag to `out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_ks_hmac_sha256(
    ks: *mut eki_ks,
    id: *const eki_key_id,
    msg: *const u8,
    msg_len: usize,
    out: *mut u8,
) -> eki_status {
    eki_status::EKI_ERR_UNSUPPORTED
}

/// Wraps the AES or HMAC key `key_id` under the AES key `kek_id` (RFC 3394) and writes the
/// 40-byte blob to `out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_ks_wrap(
    ks: *mut eki_ks,
    kek_id: *const eki_key_id,
    key_id: *const eki_key_id,
    out: *mut u8,
) -> eki_status {
    eki_status::EKI_ERR_UNSUPPORTED
}

/// Unwraps the 40-byte `blob` under the AES key `kek_id` and stores the result as a new key with
/// algorithm `alg`, label `label` and id `id`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_ks_unwrap(
    ks: *mut eki_ks,
    kek_id: *const eki_key_id,
    blob: *const u8,
    blob_len: usize,
    alg: eki_key_alg,
    label: *const c_char,
    id: *const eki_key_id,
) -> eki_status {
    eki_status::EKI_ERR_UNSUPPORTED
}

/// Destroys the key with the given id, including both halves of a key pair.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_ks_destroy(ks: *mut eki_ks, id: *const eki_key_id) -> eki_status {
    eki_status::EKI_ERR_UNSUPPORTED
}

/// Generates a hybrid X25519 + ML-KEM-768 key pair. Returns `EKI_ERR_UNSUPPORTED` when the
/// library is built without hybrid support.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_hybrid_kem_keygen(pk_out: *mut u8, sk_out: *mut u8) -> eki_status {
    eki_status::EKI_ERR_UNSUPPORTED
}

/// Encapsulates a fresh shared secret to `pk`: writes the ciphertext to `ct_out` and the shared
/// secret to `ss_out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_hybrid_kem_encap(
    pk: *const u8,
    ct_out: *mut u8,
    ss_out: *mut u8,
) -> eki_status {
    eki_status::EKI_ERR_UNSUPPORTED
}

/// Recovers the shared secret from `ct` with the secret key `sk` and writes it to `ss_out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_hybrid_kem_decap(
    sk: *const u8,
    ct: *const u8,
    ss_out: *mut u8,
) -> eki_status {
    eki_status::EKI_ERR_UNSUPPORTED
}
