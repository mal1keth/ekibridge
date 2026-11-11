//! `eki_hkdf_sha256` through the C ABI.
//!
//! Vectors: RFC 5869 A.1–A.3 (the SHA-256 cases). Rows: `hkdf` of docs/ffi-contract.md
//! ("Per-function contract"); the per-function sequence and the zero-on-error rule for
//! variable-length outputs ("Outputs on error").

mod common;

use common::{In, Out, assert_untouched, assert_zero, hex, prefill};
use ekicore_abi::{EKI_HKDF_MAX_INPUT_LEN, EKI_HKDF_MAX_OKM_LEN, eki_status};
use ekicore_rs::ffi::eki_hkdf_sha256;
use proptest::prelude::*;

use eki_status::{EKI_ERR_INVALID_ARGUMENT, EKI_ERR_NULL_POINTER, EKI_OK};

struct Vector {
    case: &'static str,
    ikm: &'static str,
    salt: &'static str,
    info: &'static str,
    okm: &'static str,
}

const RFC5869: &[Vector] = &[
    Vector {
        case: "A.1",
        ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        salt: "000102030405060708090a0b0c",
        info: "f0f1f2f3f4f5f6f7f8f9",
        okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
              34007208d5b887185865",
    },
    Vector {
        case: "A.2",
        ikm: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
              202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
              404142434445464748494a4b4c4d4e4f",
        salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
               808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
               a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
               d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
               f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        okm: "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
              59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
              cc30c58179ec3e87c14c01d5c1f3434f1d87",
    },
    Vector {
        case: "A.3",
        ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        salt: "",
        info: "",
        okm: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
              9d201395faa4b61a96c8",
    },
];

fn hkdf(ikm: In, salt: In, info: In, mut okm: Out) -> eki_status {
    // SAFETY: every non-NULL pointer comes from a live slice of at least the length passed with
    // it; `okm` is a distinct mutable buffer, so nothing overlaps.
    unsafe {
        eki_hkdf_sha256(
            ikm.ptr(),
            ikm.len(),
            salt.ptr(),
            salt.len(),
            info.ptr(),
            info.len(),
            okm.ptr(),
            okm.len(),
        )
    }
}

/// HKDF with the A.1 inputs into a fresh pre-filled buffer of `len` bytes.
fn a1(len: usize) -> (eki_status, Vec<u8>) {
    let v = &RFC5869[0];
    let (ikm, salt, info) = (hex(v.ikm), hex(v.salt), hex(v.info));
    let mut okm = prefill(len);
    let status = hkdf(
        In::Bytes(&ikm),
        In::Bytes(&salt),
        In::Bytes(&info),
        Out::Bytes(&mut okm),
    );
    (status, okm)
}

#[test]
fn rfc5869_vectors() {
    for v in RFC5869 {
        let (ikm, salt, info, expected) = (hex(v.ikm), hex(v.salt), hex(v.info), hex(v.okm));
        let mut okm = prefill(expected.len());
        let status = hkdf(
            In::Bytes(&ikm),
            In::Bytes(&salt),
            In::Bytes(&info),
            Out::Bytes(&mut okm),
        );
        assert_eq!(status, EKI_OK, "{}", v.case);
        assert_eq!(okm, expected, "{}", v.case);
    }
}

#[test]
fn salt_and_info_null_len_zero_are_ok() {
    // A.3 has an empty salt (the RFC default salt) and empty info; NULL and a non-NULL empty
    // slice must give the same result.
    let v = &RFC5869[2];
    let (ikm, expected) = (hex(v.ikm), hex(v.okm));
    for (salt, info) in [
        (In::Null(0), In::Null(0)),
        (In::Bytes(&[]), In::Bytes(&[])),
        (In::Null(0), In::Bytes(&[])),
        (In::Bytes(&[]), In::Null(0)),
    ] {
        let mut okm = prefill(expected.len());
        assert_eq!(
            hkdf(In::Bytes(&ikm), salt, info, Out::Bytes(&mut okm)),
            EKI_OK,
            "salt {salt:?} info {info:?}"
        );
        assert_eq!(okm, expected);
    }
}

#[test]
fn okm_len_8160_is_ok_and_extends_the_shorter_output() {
    let (status, okm) = a1(EKI_HKDF_MAX_OKM_LEN);
    assert_eq!(status, EKI_OK);
    // HKDF-Expand output blocks do not depend on L, so A.1's 42 bytes are a prefix.
    assert_eq!(&okm[..42], &hex(RFC5869[0].okm)[..]);
}

#[test]
fn okm_len_zero_is_invalid() {
    let (status, _) = a1(0);
    assert_eq!(status, EKI_ERR_INVALID_ARGUMENT);
    let ikm = hex(RFC5869[0].ikm);
    assert_eq!(
        hkdf(In::Bytes(&ikm), In::Null(0), In::Null(0), Out::Null(0)),
        EKI_ERR_INVALID_ARGUMENT
    );
}

#[test]
fn okm_len_8161_is_invalid_and_leaves_okm_untouched() {
    let (status, okm) = a1(EKI_HKDF_MAX_OKM_LEN + 1);
    assert_eq!(status, EKI_ERR_INVALID_ARGUMENT);
    // The length is outside its valid range, so the buffer is not touched ("Outputs on error").
    assert_untouched(&okm);
}

#[test]
fn ikm_len_zero_is_invalid_and_zeroes_okm() {
    for ikm in [In::Null(0), In::Bytes(&[])] {
        let mut okm = prefill(42);
        assert_eq!(
            hkdf(ikm, In::Null(0), In::Null(0), Out::Bytes(&mut okm)),
            EKI_ERR_INVALID_ARGUMENT,
            "{ikm:?}"
        );
        assert_zero(&okm);
    }
}

#[test]
fn input_lengths_above_32768_are_invalid() {
    let big = vec![0x0b_u8; EKI_HKDF_MAX_INPUT_LEN + 1];
    let ikm = hex(RFC5869[0].ikm);
    let cases: [(&str, In, In, In); 3] = [
        ("ikm", In::Bytes(&big), In::Null(0), In::Null(0)),
        ("salt", In::Bytes(&ikm), In::Bytes(&big), In::Null(0)),
        ("info", In::Bytes(&ikm), In::Null(0), In::Bytes(&big)),
    ];
    for (name, ikm, salt, info) in cases {
        let mut okm = prefill(42);
        assert_eq!(
            hkdf(ikm, salt, info, Out::Bytes(&mut okm)),
            EKI_ERR_INVALID_ARGUMENT,
            "{name}_len 32769"
        );
        assert_zero(&okm);
    }
}

#[test]
fn input_lengths_of_exactly_32768_are_ok() {
    let max = vec![0x0b_u8; EKI_HKDF_MAX_INPUT_LEN];
    let mut okm = prefill(32);
    assert_eq!(
        hkdf(
            In::Bytes(&max),
            In::Bytes(&max),
            In::Bytes(&max),
            Out::Bytes(&mut okm)
        ),
        EKI_OK
    );
}

#[test]
fn length_checks_run_in_parameter_order() {
    // Every one of these is INVALID_ARGUMENT whichever check fires first; the point is that no
    // combination of bad lengths yields anything else.
    let big = vec![0_u8; EKI_HKDF_MAX_INPUT_LEN + 1];
    let mut okm = prefill(EKI_HKDF_MAX_OKM_LEN + 1);
    assert_eq!(
        hkdf(
            In::Null(0),
            In::Bytes(&big),
            In::Bytes(&big),
            Out::Bytes(&mut okm)
        ),
        EKI_ERR_INVALID_ARGUMENT
    );
    assert_untouched(&okm);
}

#[test]
fn null_pointers() {
    let ikm = hex(RFC5869[0].ikm);
    let mut okm = prefill(42);
    assert_eq!(
        hkdf(In::Null(22), In::Null(0), In::Null(0), Out::Bytes(&mut okm)),
        EKI_ERR_NULL_POINTER
    );
    assert_zero(&okm);
    for (salt, info) in [(In::Null(13), In::Null(0)), (In::Null(0), In::Null(10))] {
        let mut okm = prefill(42);
        assert_eq!(
            hkdf(In::Bytes(&ikm), salt, info, Out::Bytes(&mut okm)),
            EKI_ERR_NULL_POINTER
        );
        assert_zero(&okm);
    }
    assert_eq!(
        hkdf(In::Bytes(&ikm), In::Null(0), In::Null(0), Out::Null(42)),
        EKI_ERR_NULL_POINTER
    );
    // NULL before length: a NULL ikm with ikm_len > 0 and okm_len 0 is a NULL pointer.
    assert_eq!(
        hkdf(In::Null(22), In::Null(0), In::Null(0), Out::Null(0)),
        EKI_ERR_NULL_POINTER
    );
}

proptest! {
    // Failure persistence is off: a failing run prints the shrunk input, and a case worth keeping
    // becomes a fixed test in this file.
    #![proptest_config(ProptestConfig {
        cases: 64,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    #[cfg_attr(miri, ignore = "property test: too slow to interpret")]
    fn output_length_is_honoured_and_prefix_stable(
        ikm in proptest::collection::vec(any::<u8>(), 1..=64),
        salt in proptest::collection::vec(any::<u8>(), 0..=64),
        info in proptest::collection::vec(any::<u8>(), 0..=64),
        len in 1..=EKI_HKDF_MAX_OKM_LEN,
    ) {
        let mut full = prefill(EKI_HKDF_MAX_OKM_LEN);
        prop_assert_eq!(
            hkdf(In::Bytes(&ikm), In::Bytes(&salt), In::Bytes(&info), Out::Bytes(&mut full)),
            EKI_OK
        );
        let mut okm = prefill(len);
        prop_assert_eq!(
            hkdf(In::Bytes(&ikm), In::Bytes(&salt), In::Bytes(&info), Out::Bytes(&mut okm)),
            EKI_OK
        );
        prop_assert_eq!(&okm[..], &full[..len]);
    }
}
