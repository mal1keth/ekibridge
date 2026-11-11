//! `eki_ecdsa_p256_verify` through the C ABI.
//!
//! Vectors: RFC 6979 A.2.5 (P-256 with SHA-256, messages "sample" and "test"). Rows: plan
//! §4.4 `ecdsa_verify`; §4.2 sequence (format and parse failures of the public key are
//! INVALID_ARGUMENT, every signature failure is AUTH_FAILED, high-s is accepted).

mod common;

use common::{In, hex, hex_array};
use ekicore_abi::eki_status;
use ekicore_rs::ffi::eki_ecdsa_p256_verify;

use eki_status::{EKI_ERR_AUTH_FAILED, EKI_ERR_INVALID_ARGUMENT, EKI_ERR_NULL_POINTER, EKI_OK};

/// RFC 6979 A.2.5 public key `U = xG`, SEC1 uncompressed.
const PUBLIC_KEY: &str = "04\
    60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6\
    7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";

/// RFC 6979 A.2.5, SHA-256, message "sample": `r || s`.
const SIG_SAMPLE: &str = "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716\
                          f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8";

/// RFC 6979 A.2.5, SHA-256, message "test": `r || s`.
const SIG_TEST: &str = "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367\
                        019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083";

/// The "sample" signature with `s` replaced by `n - s` (the other member of the malleable pair;
/// the RFC's `s` is the high one, so this is low-s). Both must verify.
const SIG_SAMPLE_OTHER_S: &str = "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716\
                                  0834e36ad29a83bf2bc9385e491d6099c8fdf9d1ed67aa7ea5f51f93782857a9";

/// A signature over the empty message under the RFC 6979 key, made with an independent
/// implementation (random nonce). Used for the `msg NULL, msg_len 0` case.
const SIG_EMPTY: &str = "9b764e1b7356ce0afc0ef77f30ea035b156ca8f8f70209f213db5a4752b7c5f1\
                         d971d1b0f6cee519766877bc76afa8bc4c7b59a2781d1e5d8e6d37a4f9775dc0";

/// The order `n` of the P-256 group.
const N: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

/// The field prime `p` of P-256.
const P: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";

/// A `y` with `(0, y)` on P-256: `y^2 = b (mod p)`.
const Y_AT_X_ZERO: &str = "66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4";

fn verify(public_key: Option<&[u8; 65]>, msg: In, sig: Option<&[u8; 64]>) -> eki_status {
    let pk = public_key.map_or(core::ptr::null(), |k| k.as_ptr());
    let sig = sig.map_or(core::ptr::null(), |s| s.as_ptr());
    // SAFETY: `pk` is NULL or a live 65-byte array, `sig` NULL or a live 64-byte array, and
    // `msg` NULL or a live slice of the length passed.
    unsafe { eki_ecdsa_p256_verify(pk, msg.ptr(), msg.len(), sig) }
}

fn public_key() -> [u8; 65] {
    hex_array(PUBLIC_KEY)
}

fn sig(r: &str, s: &str) -> [u8; 64] {
    hex_array(&format!("{r}{s}"))
}

#[test]
fn rfc6979_vectors() {
    let pk = public_key();
    for (msg, sig) in [(&b"sample"[..], SIG_SAMPLE), (&b"test"[..], SIG_TEST)] {
        let sig: [u8; 64] = hex_array(sig);
        assert_eq!(
            verify(Some(&pk), In::Bytes(msg), Some(&sig)),
            EKI_OK,
            "{}",
            String::from_utf8_lossy(msg)
        );
    }
}

#[test]
fn high_and_low_s_both_verify() {
    let pk = public_key();
    for s in [SIG_SAMPLE, SIG_SAMPLE_OTHER_S] {
        let sig: [u8; 64] = hex_array(s);
        assert_eq!(verify(Some(&pk), In::Bytes(b"sample"), Some(&sig)), EKI_OK);
    }
}

#[test]
fn empty_message_with_null_pointer() {
    let pk = public_key();
    let sig: [u8; 64] = hex_array(SIG_EMPTY);
    for msg in [In::Null(0), In::Bytes(&[])] {
        assert_eq!(verify(Some(&pk), msg, Some(&sig)), EKI_OK, "{msg:?}");
    }
}

// --- §4.4 rows ----------------------------------------------------------------------------

#[test]
fn public_key_prefix_not_04_is_invalid() {
    let sig: [u8; 64] = hex_array(SIG_SAMPLE);
    for prefix in [0x00, 0x02, 0x03, 0x05, 0x06, 0x07, 0xff] {
        let mut pk = public_key();
        pk[0] = prefix;
        assert_eq!(
            verify(Some(&pk), In::Bytes(b"sample"), Some(&sig)),
            EKI_ERR_INVALID_ARGUMENT,
            "prefix {prefix:#04x}"
        );
    }
}

#[test]
fn off_curve_point_is_invalid() {
    let sig: [u8; 64] = hex_array(SIG_SAMPLE);
    let mut pk = public_key();
    pk[64] ^= 0x01; // y - 1: (x, y - 1) is not on the curve
    assert_eq!(
        verify(Some(&pk), In::Bytes(b"sample"), Some(&sig)),
        EKI_ERR_INVALID_ARGUMENT,
        "y changed"
    );

    let mut zero = [0_u8; 65];
    zero[0] = 0x04;
    assert_eq!(
        verify(Some(&zero), In::Bytes(b"sample"), Some(&sig)),
        EKI_ERR_INVALID_ARGUMENT,
        "(0, 0)"
    );
}

#[test]
fn coordinate_not_below_p_is_invalid() {
    let sig: [u8; 64] = hex_array(SIG_SAMPLE);
    let p = hex(P);
    let mut pk = public_key();
    pk[1..33].copy_from_slice(&p);
    assert_eq!(
        verify(Some(&pk), In::Bytes(b"sample"), Some(&sig)),
        EKI_ERR_INVALID_ARGUMENT,
        "x = p"
    );
    let mut pk = public_key();
    pk[33..65].copy_from_slice(&p);
    assert_eq!(
        verify(Some(&pk), In::Bytes(b"sample"), Some(&sig)),
        EKI_ERR_INVALID_ARGUMENT,
        "y = p"
    );

    // The rows above cannot tell "rejects x >= p" from "reduces x mod p and then finds the
    // point off the curve". (0, y) is a point of the curve, so its key is accepted and the
    // signature fails; (p, y) is the same point with x written as p, which only a library that
    // rejects the coordinate turns away as INVALID_ARGUMENT.
    let y = hex(Y_AT_X_ZERO);
    let mut pk = [0; 65];
    pk[0] = 0x04;
    pk[33..65].copy_from_slice(&y);
    assert_eq!(
        verify(Some(&pk), In::Bytes(b"sample"), Some(&sig)),
        EKI_ERR_AUTH_FAILED,
        "(0, y) is a point of the curve"
    );
    pk[1..33].copy_from_slice(&p);
    assert_eq!(
        verify(Some(&pk), In::Bytes(b"sample"), Some(&sig)),
        EKI_ERR_INVALID_ARGUMENT,
        "x = p, the y of (0, y)"
    );
}

#[test]
fn r_or_s_out_of_range_is_auth_failed() {
    let pk = public_key();
    let (r, s) = SIG_SAMPLE.split_at(64);
    let zero = "00".repeat(32);
    let ff = "ff".repeat(32);
    for (name, sig) in [
        ("r = 0", sig(&zero, s)),
        ("s = 0", sig(r, &zero)),
        ("r = n", sig(N, s)),
        ("s = n", sig(r, N)),
        ("r = 2^256 - 1", sig(&ff, s)),
        ("s = 2^256 - 1", sig(r, &ff)),
    ] {
        assert_eq!(
            verify(Some(&pk), In::Bytes(b"sample"), Some(&sig)),
            EKI_ERR_AUTH_FAILED,
            "{name}"
        );
    }
}

#[test]
fn signature_over_other_message_is_auth_failed() {
    let pk = public_key();
    let sig: [u8; 64] = hex_array(SIG_SAMPLE);
    assert_eq!(
        verify(Some(&pk), In::Bytes(b"test"), Some(&sig)),
        EKI_ERR_AUTH_FAILED
    );
    assert_eq!(
        verify(Some(&pk), In::Null(0), Some(&sig)),
        EKI_ERR_AUTH_FAILED,
        "empty message"
    );
}

#[test]
fn signature_bit_flip_is_auth_failed() {
    let pk = public_key();
    for byte in [0, 31, 32, 63] {
        let mut sig: [u8; 64] = hex_array(SIG_SAMPLE);
        sig[byte] ^= 0x01;
        assert_eq!(
            verify(Some(&pk), In::Bytes(b"sample"), Some(&sig)),
            EKI_ERR_AUTH_FAILED,
            "byte {byte}"
        );
    }
}

#[test]
fn null_pointers() {
    let pk = public_key();
    let sig: [u8; 64] = hex_array(SIG_SAMPLE);
    assert_eq!(
        verify(None, In::Bytes(b"sample"), Some(&sig)),
        EKI_ERR_NULL_POINTER,
        "public_key"
    );
    assert_eq!(
        verify(Some(&pk), In::Null(6), Some(&sig)),
        EKI_ERR_NULL_POINTER,
        "msg"
    );
    assert_eq!(
        verify(Some(&pk), In::Bytes(b"sample"), None),
        EKI_ERR_NULL_POINTER,
        "sig"
    );
    // NULL is reported before the public key format is looked at.
    let mut bad = public_key();
    bad[0] = 0x02;
    assert_eq!(
        verify(Some(&bad), In::Bytes(b"sample"), None),
        EKI_ERR_NULL_POINTER,
        "sig NULL, bad key"
    );
}
