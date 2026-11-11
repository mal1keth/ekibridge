//! Tests of the exported functions in WebAssembly under Node, run by wasm-bindgen-test-runner:
//!
//! ```text
//! CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
//!     cargo test -p ekicore-wasm --target wasm32-unknown-unknown
//! ```
//!
//! Arguments are real `Uint8Array` objects and failures are inspected as the JavaScript errors a
//! caller catches, so the tests cross the same boundary a JavaScript caller does. The vectors are
//! the ones in conformance/vectors/, which name their sources.

// The functions under test call into JavaScript, which exists only when the module runs in a
// host; on a native target there is nothing to run.
#![cfg(target_arch = "wasm32")]

use ekicore_wasm::{
    AeadAlgorithm, aead_open, aead_seal, ecdsa_p256_verify, hkdf_sha256, hmac_sha256,
    hmac_sha256_verify,
};
use js_sys::{Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_test::wasm_bindgen_test;

fn bytes(hex: &str) -> Uint8Array {
    Uint8Array::from(unhex(hex).as_slice())
}

fn unhex(hex: &str) -> Vec<u8> {
    assert!(
        hex.len().is_multiple_of(2),
        "test vector has an odd number of digits"
    );
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("test vector is valid hex"))
        .collect()
}

fn text(value: &[u8]) -> Uint8Array {
    Uint8Array::from(value)
}

fn get(object: &JsValue, field: &str) -> JsValue {
    Reflect::get(object, &JsValue::from_str(field)).expect("readable field")
}

fn to_vec(value: &JsValue) -> Vec<u8> {
    value
        .dyn_ref::<Uint8Array>()
        .expect("a Uint8Array")
        .to_vec()
}

fn flip_first_bit(array: &Uint8Array) -> Uint8Array {
    let mut copy = array.to_vec();
    copy[0] ^= 0x01;
    Uint8Array::from(copy.as_slice())
}

/// Asserts that `result` is a thrown `EkiError` carrying `status` as its code and message.
fn assert_status<T: std::fmt::Debug>(result: Result<T, JsValue>, status: &str) {
    let error = result.expect_err("the call must fail");
    assert!(
        error.is_instance_of::<js_sys::Error>(),
        "a JavaScript Error"
    );
    assert_eq!(get(&error, "name").as_string().as_deref(), Some("EkiError"));
    assert_eq!(get(&error, "code").as_string().as_deref(), Some(status));
    assert_eq!(get(&error, "message").as_string().as_deref(), Some(status));
}

const INVALID: &str = "EKI_ERR_INVALID_ARGUMENT";
const AUTH_FAILED: &str = "EKI_ERR_AUTH_FAILED";
const ALGORITHMS: [AeadAlgorithm; 2] = [AeadAlgorithm::Aes256Gcm, AeadAlgorithm::Chacha20Poly1305];

// RFC 4231 section 4.3, test case 2.
const HMAC_KEY: &[u8] = b"Jefe";
const HMAC_MSG: &[u8] = b"what do ya want for nothing?";
const HMAC_TAG: &str = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

// RFC 5869 appendix A.1.
const HKDF_IKM: &str = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
const HKDF_SALT: &str = "000102030405060708090a0b0c";
const HKDF_INFO: &str = "f0f1f2f3f4f5f6f7f8f9";
const HKDF_OKM: &str =
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";

/// An AEAD known answer: key, nonce, aad, plaintext, ciphertext, tag.
struct AeadVector {
    key: &'static str,
    nonce: &'static str,
    aad: &'static str,
    pt: &'static str,
    ct: &'static str,
    tag: &'static str,
}

// RFC 8439 section 2.8.2.
const CHACHA: AeadVector = AeadVector {
    key: "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    nonce: "070000004041424344454647",
    aad: "50515253c0c1c2c3c4c5c6c7",
    pt: concat!(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a",
        "204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f72207468",
        "65206675747572652c2073756e73637265656e20776f756c642062652069742e",
    ),
    ct: concat!(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca967128",
        "2fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fa",
        "b324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
    ),
    tag: "1ae10b594f09e26a7e902ecbd0600691",
};

// The GCM specification (McGrew and Viega), appendix B, test case 16. AES-GCM has no RFC vector
// with a 256-bit key and a 96-bit nonce; this is the one conformance/vectors uses.
const GCM: AeadVector = AeadVector {
    key: "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
    nonce: "cafebabefacedbaddecaf888",
    aad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
    pt: concat!(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532f",
        "cf0e2449a6b525b16aedf5aa0de657ba637b39",
    ),
    ct: concat!(
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7",
        "b08b1056828838c5f61e6393ba7a0abcc9f662",
    ),
    tag: "76fc6ece0f4e1768cddf8853bb2d551b",
};

// RFC 6979 appendix A.2.5: P-256 public key and the SHA-256 signature of "sample".
const ECDSA_PUBLIC_KEY: &str = concat!(
    "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
    "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
);
const ECDSA_MSG: &[u8] = b"sample";
const ECDSA_SIG: &str = concat!(
    "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
    "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
);

fn check_aead_vector(algorithm: AeadAlgorithm, v: &AeadVector) {
    let (key, nonce, aad) = (bytes(v.key), bytes(v.nonce), bytes(v.aad));
    let sealed = aead_seal(algorithm, &key, &nonce, &aad, &bytes(v.pt)).expect("valid arguments");
    assert_eq!(to_vec(&get(&sealed, "ciphertext")), unhex(v.ct));
    assert_eq!(to_vec(&get(&sealed, "tag")), unhex(v.tag));
    let opened = aead_open(algorithm, &key, &nonce, &aad, &bytes(v.ct), &bytes(v.tag))
        .expect("the vector authenticates");
    assert_eq!(opened.to_vec(), unhex(v.pt));
}

#[wasm_bindgen_test]
fn hmac_rfc4231() {
    let tag = hmac_sha256(&text(HMAC_KEY), &text(HMAC_MSG)).expect("valid arguments");
    assert_eq!(tag.to_vec(), unhex(HMAC_TAG));
    hmac_sha256_verify(&text(HMAC_KEY), &text(HMAC_MSG), &bytes(HMAC_TAG)).expect("tag matches");
}

#[wasm_bindgen_test]
fn hkdf_rfc5869() {
    let okm = hkdf_sha256(&bytes(HKDF_IKM), &bytes(HKDF_SALT), &bytes(HKDF_INFO), 42)
        .expect("valid arguments");
    assert_eq!(okm.to_vec(), unhex(HKDF_OKM));
}

#[wasm_bindgen_test]
fn chacha20_poly1305_rfc8439() {
    check_aead_vector(AeadAlgorithm::Chacha20Poly1305, &CHACHA);
}

#[wasm_bindgen_test]
fn aes_256_gcm_spec() {
    check_aead_vector(AeadAlgorithm::Aes256Gcm, &GCM);
}

#[wasm_bindgen_test]
fn ecdsa_p256_rfc6979() {
    ecdsa_p256_verify(
        &bytes(ECDSA_PUBLIC_KEY),
        &text(ECDSA_MSG),
        &bytes(ECDSA_SIG),
    )
    .expect("signature verifies");
}

#[wasm_bindgen_test]
fn seal_then_open_each_algorithm() {
    let key = Uint8Array::from((0u8..32).collect::<Vec<_>>().as_slice());
    let nonce = Uint8Array::from((0u8..12).collect::<Vec<_>>().as_slice());
    let aad = text(b"header");
    let plaintext = text(b"attack at dawn");
    for algorithm in ALGORITHMS {
        let sealed = aead_seal(algorithm, &key, &nonce, &aad, &plaintext).expect("valid arguments");
        let ciphertext = get(&sealed, "ciphertext").unchecked_into::<Uint8Array>();
        let tag = get(&sealed, "tag").unchecked_into::<Uint8Array>();
        assert_eq!(ciphertext.length(), plaintext.length(), "{algorithm:?}");
        assert_eq!(tag.length(), 16, "{algorithm:?}");
        let opened = aead_open(algorithm, &key, &nonce, &aad, &ciphertext, &tag).expect("opens");
        assert_eq!(opened.to_vec(), b"attack at dawn", "{algorithm:?}");
    }
}

#[wasm_bindgen_test]
fn invalid_argument() {
    let empty = text(b"");
    assert_status(hmac_sha256(&empty, &text(HMAC_MSG)), INVALID);
    let short_tag = Uint8Array::from(&unhex(HMAC_TAG)[..31]);
    assert_status(
        hmac_sha256_verify(&text(HMAC_KEY), &text(HMAC_MSG), &short_tag),
        INVALID,
    );
    let ikm = bytes(HKDF_IKM);
    assert_status(hkdf_sha256(&ikm, &empty, &empty, 0), INVALID);
    assert_status(hkdf_sha256(&ikm, &empty, &empty, 8161), INVALID);
    assert_status(hkdf_sha256(&empty, &empty, &empty, 32), INVALID);
    let (key, nonce, pt) = (text(&[0; 32]), text(&[0; 12]), text(b"pt"));
    for algorithm in ALGORITHMS {
        assert_status(
            aead_seal(algorithm, &text(&[0; 16]), &nonce, &empty, &pt),
            INVALID,
        );
        assert_status(
            aead_seal(algorithm, &key, &text(&[0; 11]), &empty, &pt),
            INVALID,
        );
        assert_status(
            aead_open(algorithm, &key, &nonce, &empty, &pt, &text(&[0; 15])),
            INVALID,
        );
    }
    let mut bad_point = unhex(ECDSA_PUBLIC_KEY);
    bad_point[0] = 0x02;
    assert_status(
        ecdsa_p256_verify(&text(&bad_point), &text(ECDSA_MSG), &bytes(ECDSA_SIG)),
        INVALID,
    );
}

#[wasm_bindgen_test]
fn unknown_algorithm_name_is_invalid_argument() {
    // An unknown string from JavaScript arrives as the hidden variant wasm-bindgen adds to a
    // string enum; this is the value the generated glue passes for, say, "aes-128-gcm".
    let unknown = AeadAlgorithm::__Invalid;
    let (key, nonce, empty) = (text(&[0; 32]), text(&[0; 12]), text(b""));
    assert_status(aead_seal(unknown, &key, &nonce, &empty, &empty), INVALID);
    assert_status(
        aead_open(unknown, &key, &nonce, &empty, &empty, &text(&[0; 16])),
        INVALID,
    );
}

#[wasm_bindgen_test]
fn authentication_failure() {
    assert_status(
        hmac_sha256_verify(
            &text(HMAC_KEY),
            &text(HMAC_MSG),
            &flip_first_bit(&bytes(HMAC_TAG)),
        ),
        AUTH_FAILED,
    );
    let (key, nonce, aad) = (bytes(CHACHA.key), bytes(CHACHA.nonce), bytes(CHACHA.aad));
    for algorithm in ALGORITHMS {
        let sealed = aead_seal(algorithm, &key, &nonce, &aad, &bytes(CHACHA.pt)).expect("seals");
        let ct = get(&sealed, "ciphertext").unchecked_into::<Uint8Array>();
        let tag = get(&sealed, "tag").unchecked_into::<Uint8Array>();
        let changed_aad = flip_first_bit(&aad);
        let changed_ct = flip_first_bit(&ct);
        let changed_tag = flip_first_bit(&tag);
        assert_status(
            aead_open(algorithm, &key, &nonce, &changed_aad, &ct, &tag),
            AUTH_FAILED,
        );
        assert_status(
            aead_open(algorithm, &key, &nonce, &aad, &changed_ct, &tag),
            AUTH_FAILED,
        );
        assert_status(
            aead_open(algorithm, &key, &nonce, &aad, &ct, &changed_tag),
            AUTH_FAILED,
        );
    }
    assert_status(
        ecdsa_p256_verify(&bytes(ECDSA_PUBLIC_KEY), &text(b"other"), &bytes(ECDSA_SIG)),
        AUTH_FAILED,
    );
}
