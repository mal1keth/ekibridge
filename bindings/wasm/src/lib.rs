//! `ekicore-wasm`: the safe API of `ekicore-rs` compiled to WebAssembly and exported to
//! JavaScript with wasm-bindgen.
//!
//! The functions here wrap the safe modules (`hmac`, `hkdf`, `aead`, `ecdsa`), never the
//! `extern "C"` layer. Byte strings are `Uint8Array` in both directions and every failure is a
//! thrown `Error` whose `code` and `message` are the C status name, for example
//! `EKI_ERR_AUTH_FAILED`.
//!
//! A WebAssembly module and its JavaScript host share no address space: the module has its own
//! linear memory. Every input is copied from the JavaScript `Uint8Array` into that memory and
//! every result is copied out into a new `Uint8Array`. The copies of secret inputs (keys, input
//! keying material, plaintext) and of secret outputs held in linear memory are wiped once the
//! result has been copied out; the JavaScript objects on either side are the caller's and are
//! not.

// The `#[wasm_bindgen]` attributes generate `unsafe` glue (ABI conversions and exports). Denying
// `unsafe_code` still rejects any `unsafe` written in this file, because the lint skips only
// tokens that come from the macros.
#![deny(unsafe_code)]
#![warn(missing_docs)]

use ekicore_abi::{
    EKI_AEAD_AES_256_GCM, EKI_AEAD_CHACHA20_POLY1305, EKI_AEAD_TAG_LEN, EKI_HKDF_MAX_OKM_LEN,
    eki_aead_alg, eki_status,
};
use ekicore_rs::error::Error;
use ekicore_rs::{aead, ecdsa, hkdf, hmac};
use js_sys::{Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

pub use algorithm::AeadAlgorithm;

/// The string enum in a module of its own, so that the lint allowance below covers only it.
mod algorithm {
    // For a string enum wasm-bindgen adds a hidden `__Invalid` variant and a public
    // `from_js_value` function, both without documentation; `missing_docs` would reject them.
    #![allow(missing_docs)]

    use wasm_bindgen::prelude::*;

    /// AEAD algorithm, passed from JavaScript as a string.
    ///
    /// A string that is not one of the two names reaches the hidden `__Invalid` variant that
    /// wasm-bindgen adds to string enums, and is answered with `EKI_ERR_INVALID_ARGUMENT`, as an
    /// unknown selector is in the C ABI.
    #[wasm_bindgen]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum AeadAlgorithm {
        /// AES-256-GCM.
        Aes256Gcm = "aes-256-gcm",
        /// ChaCha20-Poly1305 (RFC 8439).
        Chacha20Poly1305 = "chacha20-poly1305",
    }
}

impl AeadAlgorithm {
    /// The C selector value the safe module takes.
    fn selector(self) -> Result<eki_aead_alg, Error> {
        match self {
            Self::Aes256Gcm => Ok(EKI_AEAD_AES_256_GCM),
            Self::Chacha20Poly1305 => Ok(EKI_AEAD_CHACHA20_POLY1305),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// TypeScript declaration of the object `aeadSeal` returns. A plain object, not an exported Rust
// struct: a wasm-bindgen class keeps its fields in linear memory until `free()` is called, which
// a JavaScript caller would have to remember.
#[wasm_bindgen(typescript_custom_section)]
const SEALED_BOX: &str = r#"
/** Result of `aeadSeal`: the ciphertext, as long as the plaintext, and the detached 16-byte tag. */
export interface SealedBox {
  ciphertext: Uint8Array;
  tag: Uint8Array;
}
"#;

/// The JavaScript error for `error`: an `Error` named `EkiError` whose `message` and `code` are
/// the C status name.
fn js_error(error: Error) -> JsValue {
    // The variants of `eki_status` are named after the C identifiers, so their derived `Debug`
    // output is the status name; `eki_status::from` is the ABI's own total mapping.
    let name = format!("{:?}", eki_status::from(error));
    let js = js_sys::Error::new(&name);
    js.set_name("EkiError");
    // `Reflect::set` fails only on a frozen or non-extensible target, and the error was created
    // just above, so there is nothing to handle.
    let _ = Reflect::set(&js, &JsValue::from_str("code"), &JsValue::from_str(&name));
    js.into()
}

/// A copy of `array` in linear memory, wiped when dropped. Used for every input, secret or not,
/// so that each call follows one rule.
fn copy_in(array: &Uint8Array) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(array.to_vec())
}

/// A new `Uint8Array` holding a copy of `bytes`.
fn copy_out(bytes: &[u8]) -> Uint8Array {
    Uint8Array::from(bytes)
}

/// HMAC-SHA256 of `msg` under `key`: a 32-byte tag. An empty `key` is `EKI_ERR_INVALID_ARGUMENT`.
#[wasm_bindgen(js_name = hmacSha256)]
pub fn hmac_sha256(key: &Uint8Array, msg: &Uint8Array) -> Result<Uint8Array, JsValue> {
    let tag = hmac::hmac_sha256(&copy_in(key), &copy_in(msg)).map_err(js_error)?;
    Ok(copy_out(&tag))
}

/// Checks in constant time that `tag` is the HMAC-SHA256 of `msg` under `key`. An empty `key` or
/// a `tag` that is not 32 bytes is `EKI_ERR_INVALID_ARGUMENT`; a wrong tag is
/// `EKI_ERR_AUTH_FAILED`.
#[wasm_bindgen(js_name = hmacSha256Verify)]
pub fn hmac_sha256_verify(
    key: &Uint8Array,
    msg: &Uint8Array,
    tag: &Uint8Array,
) -> Result<(), JsValue> {
    hmac::hmac_sha256_verify(&copy_in(key), &copy_in(msg), &copy_in(tag)).map_err(js_error)
}

/// HKDF-SHA256 (RFC 5869): derives `length` bytes from `ikm`, `salt` and `info`. An empty `salt`
/// is the RFC default. `ikm` empty or over 32768 bytes, `salt` or `info` over 32768 bytes, and
/// `length` 0 or over 8160 are `EKI_ERR_INVALID_ARGUMENT`.
#[wasm_bindgen(js_name = hkdfSha256)]
pub fn hkdf_sha256(
    ikm: &Uint8Array,
    salt: &Uint8Array,
    info: &Uint8Array,
    length: u32,
) -> Result<Uint8Array, JsValue> {
    let length = usize::try_from(length).map_err(|_| js_error(Error::InvalidArgument))?;
    // `length` is caller input, so it is checked before it sizes an allocation: the safe module
    // rejects an over-long output anyway, but only after the buffer would have been allocated.
    if length > EKI_HKDF_MAX_OKM_LEN {
        return Err(js_error(Error::InvalidArgument));
    }
    let mut okm = Zeroizing::new(vec![0u8; length]);
    hkdf::hkdf_sha256(&copy_in(ikm), &copy_in(salt), &copy_in(info), &mut okm).map_err(js_error)?;
    Ok(copy_out(&okm))
}

/// Encrypts `plaintext` with `algorithm` under a 32-byte `key` and a 12-byte `nonce`,
/// authenticating `aad` as well; returns `{ ciphertext, tag }`. An unknown algorithm or a key or
/// nonce of another length is `EKI_ERR_INVALID_ARGUMENT`. A nonce must never be reused with the
/// same key; choosing it is the caller's job.
#[wasm_bindgen(js_name = aeadSeal, unchecked_return_type = "SealedBox")]
pub fn aead_seal(
    algorithm: AeadAlgorithm,
    key: &Uint8Array,
    nonce: &Uint8Array,
    aad: &Uint8Array,
    plaintext: &Uint8Array,
) -> Result<JsValue, JsValue> {
    let alg = algorithm.selector().map_err(js_error)?;
    let plaintext = copy_in(plaintext);
    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut tag = [0u8; EKI_AEAD_TAG_LEN];
    aead::seal(
        alg,
        &copy_in(key),
        &copy_in(nonce),
        &copy_in(aad),
        &plaintext,
        &mut ciphertext,
        &mut tag,
    )
    .map_err(js_error)?;
    let sealed = Object::new();
    let _ = Reflect::set(&sealed, &"ciphertext".into(), &copy_out(&ciphertext));
    let _ = Reflect::set(&sealed, &"tag".into(), &copy_out(&tag));
    Ok(sealed.into())
}

/// Verifies `tag` and decrypts `ciphertext`. An unknown algorithm or a key, nonce or tag of the
/// wrong length is `EKI_ERR_INVALID_ARGUMENT`; a tag that does not verify (wrong key, nonce, aad,
/// ciphertext or tag) is `EKI_ERR_AUTH_FAILED`, and no plaintext is returned.
#[wasm_bindgen(js_name = aeadOpen)]
pub fn aead_open(
    algorithm: AeadAlgorithm,
    key: &Uint8Array,
    nonce: &Uint8Array,
    aad: &Uint8Array,
    ciphertext: &Uint8Array,
    tag: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let alg = algorithm.selector().map_err(js_error)?;
    let ciphertext = copy_in(ciphertext);
    let mut plaintext = Zeroizing::new(vec![0u8; ciphertext.len()]);
    aead::open(
        alg,
        &copy_in(key),
        &copy_in(nonce),
        &copy_in(aad),
        &ciphertext,
        &copy_in(tag),
        &mut plaintext,
    )
    .map_err(js_error)?;
    Ok(copy_out(&plaintext))
}

/// Verifies an ECDSA P-256 / SHA-256 `signature` (`r || s`, 64 bytes) over `msg` by `publicKey`
/// (SEC1 uncompressed, 65 bytes). A malformed key is `EKI_ERR_INVALID_ARGUMENT`; a signature
/// that does not verify is `EKI_ERR_AUTH_FAILED`.
#[wasm_bindgen(js_name = ecdsaP256Verify)]
pub fn ecdsa_p256_verify(
    #[wasm_bindgen(js_name = publicKey)] public_key: &Uint8Array,
    msg: &Uint8Array,
    signature: &Uint8Array,
) -> Result<(), JsValue> {
    ecdsa::p256_verify(&copy_in(public_key), &copy_in(msg), &copy_in(signature)).map_err(js_error)
}
