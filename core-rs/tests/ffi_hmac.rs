//! `eki_hmac_sha256` and `eki_hmac_sha256_verify` through the C ABI (lesson L1).
//!
//! Vectors: RFC 4231 §4.2–§4.8, the HMAC-SHA-256 lines. Test case 5 publishes only the first
//! 16 bytes of the tag, so it is compared as a prefix and left out of the `verify` tests.
//! Rows: plan §4.4 `hmac` and `hmac_verify`; validation order and zero-on-error from §4.2.

mod common;

use common::{In, assert_zero, hex, prefill};
use ekicore_abi::{EKI_HMAC_SHA256_LEN, eki_status};
use ekicore_rs::ffi::{eki_hmac_sha256, eki_hmac_sha256_verify};

use eki_status::{EKI_ERR_AUTH_FAILED, EKI_ERR_INVALID_ARGUMENT, EKI_ERR_NULL_POINTER, EKI_OK};

/// One RFC 4231 test case: key, data, HMAC-SHA-256 (possibly truncated).
struct Vector {
    case: u32,
    key: &'static str,
    data: &'static str,
    mac: &'static str,
}

const AA_131: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                      aaaaaa";

const RFC4231: &[Vector] = &[
    Vector {
        case: 1,
        key: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        data: "4869205468657265",
        mac: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    },
    Vector {
        case: 2,
        key: "4a656665",
        data: "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
        mac: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    },
    Vector {
        case: 3,
        key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        data: "dddddddddddddddddddddddddddddddddddddddddddddddddd\
               dddddddddddddddddddddddddddddddddddddddddddddddddd",
        mac: "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
    },
    Vector {
        case: 4,
        key: "0102030405060708090a0b0c0d0e0f10111213141516171819",
        data: "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\
               cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        mac: "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
    },
    Vector {
        case: 5,
        key: "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
        data: "546573742057697468205472756e636174696f6e",
        mac: "a3b6167473100ee06e0c796c2955552b",
    },
    Vector {
        case: 6,
        key: AA_131,
        data: "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a\
               65204b6579202d2048617368204b6579204669727374",
        mac: "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
    },
    Vector {
        case: 7,
        key: AA_131,
        data: "5468697320697320612074657374207573696e672061206c6172676572207468\
               616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074\
               68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565\
               647320746f20626520686173686564206265666f7265206265696e6720757365\
               642062792074686520484d414320616c676f726974686d2e",
        mac: "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
    },
];

/// HMAC-SHA256 of the empty message under the RFC 4231 case 1 key (computed with an
/// independent implementation; used for the `msg NULL, msg_len 0` row).
const EMPTY_MSG_MAC: &str = "999a901219f032cd497cadb5e6051e97b6a29ab297bd6ae722bd6062a2f59542";

fn hmac(key: In, msg: In, out: Option<&mut [u8]>) -> eki_status {
    let out_ptr = out.map_or(core::ptr::null_mut(), |o| {
        assert_eq!(o.len(), EKI_HMAC_SHA256_LEN);
        o.as_mut_ptr()
    });
    // SAFETY: every non-NULL pointer comes from a live slice of at least the length passed with
    // it, and `out_ptr` is NULL or a live 32-byte buffer.
    unsafe { eki_hmac_sha256(key.ptr(), key.len(), msg.ptr(), msg.len(), out_ptr) }
}

fn verify(key: In, msg: In, tag: In) -> eki_status {
    // SAFETY: every non-NULL pointer comes from a live slice of at least the length passed.
    unsafe {
        eki_hmac_sha256_verify(
            key.ptr(),
            key.len(),
            msg.ptr(),
            msg.len(),
            tag.ptr(),
            tag.len(),
        )
    }
}

#[test]
#[ignore = "lesson L1"]
fn rfc4231_vectors() {
    for v in RFC4231 {
        let (key, data, mac) = (hex(v.key), hex(v.data), hex(v.mac));
        let mut out = prefill(32);
        let status = hmac(In::Bytes(&key), In::Bytes(&data), Some(&mut out));
        assert_eq!(status, EKI_OK, "case {}", v.case);
        assert_eq!(&out[..mac.len()], &mac[..], "case {}", v.case);
    }
}

#[test]
#[ignore = "lesson L1"]
fn rfc4231_verify_accepts_full_tags() {
    for v in RFC4231.iter().filter(|v| v.case != 5) {
        let (key, data, mac) = (hex(v.key), hex(v.data), hex(v.mac));
        assert_eq!(
            verify(In::Bytes(&key), In::Bytes(&data), In::Bytes(&mac)),
            EKI_OK,
            "case {}",
            v.case
        );
    }
}

#[test]
#[ignore = "lesson L1"]
fn verify_rejects_every_single_bit_flip() {
    let v = &RFC4231[1];
    let (key, data, mac) = (hex(v.key), hex(v.data), hex(v.mac));
    for bit in 0..mac.len() * 8 {
        let mut bad = mac.clone();
        bad[bit / 8] ^= 1 << (bit % 8);
        assert_eq!(
            verify(In::Bytes(&key), In::Bytes(&data), In::Bytes(&bad)),
            EKI_ERR_AUTH_FAILED,
            "bit {bit}"
        );
    }
}

#[test]
#[ignore = "lesson L1"]
fn verify_wrong_message_is_auth_failed() {
    let v = &RFC4231[0];
    let (key, mac) = (hex(v.key), hex(v.mac));
    assert_eq!(
        verify(In::Bytes(&key), In::Bytes(b"Hi there"), In::Bytes(&mac)),
        EKI_ERR_AUTH_FAILED
    );
}

// --- §4.4 rows: hmac ----------------------------------------------------------------------

#[test]
#[ignore = "lesson L1"]
fn key_len_zero_is_invalid_and_zeroes_out() {
    for key in [In::Null(0), In::Bytes(&[])] {
        let mut out = prefill(32);
        assert_eq!(
            hmac(key, In::Bytes(b"msg"), Some(&mut out)),
            EKI_ERR_INVALID_ARGUMENT,
            "{key:?}"
        );
        assert_zero(&out);
    }
}

#[test]
#[ignore = "lesson L1"]
fn msg_null_len_zero_is_ok() {
    let key = hex(RFC4231[0].key);
    let expected = hex(EMPTY_MSG_MAC);
    for msg in [In::Null(0), In::Bytes(&[])] {
        let mut out = prefill(32);
        assert_eq!(
            hmac(In::Bytes(&key), msg, Some(&mut out)),
            EKI_OK,
            "{msg:?}"
        );
        assert_eq!(out, expected, "{msg:?}");
    }
}

#[test]
#[ignore = "lesson L1"]
fn null_pointers() {
    let key = hex(RFC4231[0].key);
    let mut out = prefill(32);
    assert_eq!(
        hmac(In::Null(20), In::Bytes(b"m"), Some(&mut out)),
        EKI_ERR_NULL_POINTER
    );
    assert_zero(&out);

    let mut out = prefill(32);
    assert_eq!(
        hmac(In::Bytes(&key), In::Null(3), Some(&mut out)),
        EKI_ERR_NULL_POINTER
    );
    assert_zero(&out);

    assert_eq!(
        hmac(In::Bytes(&key), In::Bytes(b"m"), None),
        EKI_ERR_NULL_POINTER
    );
}

#[test]
#[ignore = "lesson L1"]
fn null_pointer_comes_before_length_checks() {
    // `key_len 0` alone is INVALID_ARGUMENT, but a NULL `out` is detected first (§4.2 step 1).
    assert_eq!(
        hmac(In::Null(0), In::Bytes(b"m"), None),
        EKI_ERR_NULL_POINTER
    );
}

// --- §4.4 rows: hmac_verify ---------------------------------------------------------------

#[test]
#[ignore = "lesson L1"]
fn verify_tag_len_not_32_is_invalid() {
    let v = &RFC4231[0];
    let (key, data, mac) = (hex(v.key), hex(v.data), hex(v.mac));
    let mut long = mac.clone();
    long.push(0);
    for tag in [
        In::Bytes(&mac[..31]),
        In::Bytes(&long),
        In::Null(0),
        In::Bytes(&[]),
    ] {
        assert_eq!(
            verify(In::Bytes(&key), In::Bytes(&data), tag),
            EKI_ERR_INVALID_ARGUMENT,
            "{tag:?}"
        );
    }
}

#[test]
#[ignore = "lesson L1"]
fn verify_key_len_zero_is_invalid_before_tag_len() {
    let mac = hex(RFC4231[0].mac);
    assert_eq!(
        verify(In::Null(0), In::Bytes(b"m"), In::Bytes(&mac)),
        EKI_ERR_INVALID_ARGUMENT
    );
    assert_eq!(
        verify(In::Bytes(&[]), In::Bytes(b"m"), In::Bytes(&mac[..31])),
        EKI_ERR_INVALID_ARGUMENT
    );
}

#[test]
#[ignore = "lesson L1"]
fn verify_null_pointers() {
    let v = &RFC4231[0];
    let (key, data, mac) = (hex(v.key), hex(v.data), hex(v.mac));
    assert_eq!(
        verify(In::Null(20), In::Bytes(&data), In::Bytes(&mac)),
        EKI_ERR_NULL_POINTER
    );
    assert_eq!(
        verify(In::Bytes(&key), In::Null(8), In::Bytes(&mac)),
        EKI_ERR_NULL_POINTER
    );
    assert_eq!(
        verify(In::Bytes(&key), In::Bytes(&data), In::Null(32)),
        EKI_ERR_NULL_POINTER
    );
    // NULL with a wrong length is still a NULL pointer: step 1 precedes step 3.
    assert_eq!(
        verify(In::Bytes(&key), In::Bytes(&data), In::Null(31)),
        EKI_ERR_NULL_POINTER
    );
}

#[test]
#[ignore = "lesson L1"]
fn verify_empty_message() {
    let key = hex(RFC4231[0].key);
    let mac = hex(EMPTY_MSG_MAC);
    assert_eq!(
        verify(In::Bytes(&key), In::Null(0), In::Bytes(&mac)),
        EKI_OK
    );
}
