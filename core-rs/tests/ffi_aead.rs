//! `eki_aead_seal` and `eki_aead_open` through the C ABI.
//!
//! Vectors: RFC 8439 §2.8.2 and Appendix A.5 (ChaCha20-Poly1305); the GCM specification
//! (McGrew and Viega, "The Galois/Counter Mode of Operation", revised) test cases 13–16, the
//! AES-256 cases with 96-bit IVs (17 and 18 use 8- and 60-byte IVs and are excluded, since the
//! ABI mandates 12-byte nonces). Rows: plan §4.4 `aead_seal` and `aead_open`; §4.2 sequences
//! and zero-on-error.

mod common;

use common::{In, Out, assert_untouched, assert_zero, hex, prefill};
use ekicore_abi::{
    EKI_AEAD_AES_256_GCM, EKI_AEAD_CHACHA20_POLY1305, EKI_AEAD_MAX_LEN, EKI_AEAD_TAG_LEN,
    eki_aead_alg, eki_status,
};
use ekicore_rs::ffi::{eki_aead_open, eki_aead_seal};
use proptest::prelude::*;

use eki_status::{EKI_ERR_AUTH_FAILED, EKI_ERR_INVALID_ARGUMENT, EKI_ERR_NULL_POINTER, EKI_OK};

struct Vector {
    source: &'static str,
    alg: eki_aead_alg,
    key: &'static str,
    nonce: &'static str,
    aad: &'static str,
    pt: &'static str,
    ct: &'static str,
    tag: &'static str,
}

const GCM_KEY_FEFFE9: &str = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
const GCM_PT: &str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                      1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
const GCM_CT: &str = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
                      8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad";

const VECTORS: &[Vector] = &[
    Vector {
        source: "RFC 8439 2.8.2",
        alg: EKI_AEAD_CHACHA20_POLY1305,
        key: "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        nonce: "070000004041424344454647",
        aad: "50515253c0c1c2c3c4c5c6c7",
        pt: "4c616469657320616e642047656e746c656d656e206f662074686520636c6173\
             73206f66202739393a204966204920636f756c64206f6666657220796f75206f\
             6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73\
             637265656e20776f756c642062652069742e",
        ct: "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b6116",
        tag: "1ae10b594f09e26a7e902ecbd0600691",
    },
    Vector {
        source: "RFC 8439 A.5",
        alg: EKI_AEAD_CHACHA20_POLY1305,
        key: "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
        nonce: "000000000102030405060708",
        aad: "f33388860000000000004e91",
        pt: "496e7465726e65742d4472616674732061726520647261667420646f63756d65\
             6e74732076616c696420666f722061206d6178696d756d206f6620736978206d\
             6f6e74687320616e64206d617920626520757064617465642c207265706c6163\
             65642c206f72206f62736f6c65746564206279206f7468657220646f63756d65\
             6e747320617420616e792074696d652e20497420697320696e617070726f7072\
             6961746520746f2075736520496e7465726e65742d4472616674732061732072\
             65666572656e6365206d6174657269616c206f7220746f206369746520746865\
             6d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67\
             726573732e2fe2809d",
        ct: "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb2\
             4c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf\
             332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855\
             9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4\
             b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e\
             af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a\
             0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a10\
             49e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29\
             a6ad5cb4022b02709b",
        tag: "eead9d67890cbb22392336fea1851f38",
    },
    Vector {
        source: "GCM spec test case 13",
        alg: EKI_AEAD_AES_256_GCM,
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        nonce: "000000000000000000000000",
        aad: "",
        pt: "",
        ct: "",
        tag: "530f8afbc74536b9a963b4f1c4cb738b",
    },
    Vector {
        source: "GCM spec test case 14",
        alg: EKI_AEAD_AES_256_GCM,
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        nonce: "000000000000000000000000",
        aad: "",
        pt: "00000000000000000000000000000000",
        ct: "cea7403d4d606b6e074ec5d3baf39d18",
        tag: "d0d1c8a799996bf0265b98b5d48ab919",
    },
    Vector {
        source: "GCM spec test case 15",
        alg: EKI_AEAD_AES_256_GCM,
        key: GCM_KEY_FEFFE9,
        nonce: "cafebabefacedbaddecaf888",
        aad: "",
        pt: GCM_PT,
        ct: GCM_CT,
        tag: "b094dac5d93471bdec1a502270e3cc6c",
    },
    Vector {
        source: "GCM spec test case 16",
        alg: EKI_AEAD_AES_256_GCM,
        key: GCM_KEY_FEFFE9,
        nonce: "cafebabefacedbaddecaf888",
        aad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        // The first 60 bytes of GCM_PT / GCM_CT.
        pt: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        ct: "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
             8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        tag: "76fc6ece0f4e1768cddf8853bb2d551b",
    },
];

const ALGS: [eki_aead_alg; 2] = [EKI_AEAD_AES_256_GCM, EKI_AEAD_CHACHA20_POLY1305];

/// Decoded form of a [`Vector`].
#[derive(Clone)]
struct Case {
    alg: eki_aead_alg,
    key: Vec<u8>,
    nonce: Vec<u8>,
    aad: Vec<u8>,
    pt: Vec<u8>,
    ct: Vec<u8>,
    tag: Vec<u8>,
}

fn case(v: &Vector) -> Case {
    Case {
        alg: v.alg,
        key: hex(v.key),
        nonce: hex(v.nonce),
        aad: hex(v.aad),
        pt: hex(v.pt),
        ct: hex(v.ct),
        tag: hex(v.tag),
    }
}

/// The GCM test case 16 inputs (AES-256-GCM, with AAD).
fn gcm16() -> Case {
    case(&VECTORS[5])
}

/// The RFC 8439 §2.8.2 inputs (ChaCha20-Poly1305, with AAD).
fn chacha282() -> Case {
    case(&VECTORS[0])
}

/// Calls `eki_aead_seal`; the plaintext length is `pt.len()` and `ct_out` must match it.
fn seal(
    alg: eki_aead_alg,
    key: In,
    nonce: In,
    aad: In,
    pt: In,
    mut ct_out: Out,
    tag_out: Option<&mut [u8]>,
) -> eki_status {
    if let Out::Bytes(b) = &ct_out {
        assert_eq!(b.len(), pt.len(), "test bug: ct_out must have pt_len bytes");
    }
    let tag_ptr = tag_out.map_or(core::ptr::null_mut(), |t| {
        assert_eq!(t.len(), EKI_AEAD_TAG_LEN);
        t.as_mut_ptr()
    });
    // SAFETY: every non-NULL input pointer comes from a live slice of at least the length
    // passed with it; `ct_out` is NULL or a live buffer of `pt.len()` bytes and `tag_ptr` NULL
    // or a live 16-byte buffer; the outputs are distinct allocations from the inputs.
    unsafe {
        eki_aead_seal(
            alg,
            key.ptr(),
            key.len(),
            nonce.ptr(),
            nonce.len(),
            aad.ptr(),
            aad.len(),
            pt.ptr(),
            pt.len(),
            ct_out.ptr(),
            tag_ptr,
        )
    }
}

/// Calls `eki_aead_open`; the ciphertext length is `ct.len()` and `pt_out` must match it.
fn open(
    alg: eki_aead_alg,
    key: In,
    nonce: In,
    aad: In,
    ct: In,
    tag: In,
    mut pt_out: Out,
) -> eki_status {
    if let Out::Bytes(b) = &pt_out {
        assert_eq!(b.len(), ct.len(), "test bug: pt_out must have ct_len bytes");
    }
    if let In::Bytes(t) = tag {
        assert_eq!(t.len(), EKI_AEAD_TAG_LEN, "test bug: tag must be 16 bytes");
    }
    // SAFETY: every non-NULL input pointer comes from a live slice of at least the length
    // passed with it (`tag` is 16 bytes); `pt_out` is NULL or a live buffer of `ct.len()` bytes
    // in its own allocation.
    unsafe {
        eki_aead_open(
            alg,
            key.ptr(),
            key.len(),
            nonce.ptr(),
            nonce.len(),
            aad.ptr(),
            aad.len(),
            ct.ptr(),
            ct.len(),
            tag.ptr(),
            pt_out.ptr(),
        )
    }
}

/// Seals `c.pt` with every input taken from `c`; returns status, ciphertext, tag.
fn seal_case(c: &Case) -> (eki_status, Vec<u8>, Vec<u8>) {
    let mut ct = prefill(c.pt.len());
    let mut tag = prefill(EKI_AEAD_TAG_LEN);
    let status = seal(
        c.alg,
        In::Bytes(&c.key),
        In::Bytes(&c.nonce),
        In::Bytes(&c.aad),
        In::Bytes(&c.pt),
        Out::Bytes(&mut ct),
        Some(&mut tag),
    );
    (status, ct, tag)
}

/// Opens `ct` / `tag` with key, nonce and AAD from `c`; returns status and plaintext.
fn open_with(c: &Case, aad: &[u8], ct: &[u8], tag: &[u8]) -> (eki_status, Vec<u8>) {
    let mut pt = prefill(ct.len());
    let status = open(
        c.alg,
        In::Bytes(&c.key),
        In::Bytes(&c.nonce),
        In::Bytes(aad),
        In::Bytes(ct),
        In::Bytes(tag),
        Out::Bytes(&mut pt),
    );
    (status, pt)
}

// --- vectors ------------------------------------------------------------------------------

#[test]
fn vectors_seal() {
    for v in VECTORS {
        let c = case(v);
        let (status, ct, tag) = seal_case(&c);
        assert_eq!(status, EKI_OK, "{}", v.source);
        assert_eq!(ct, c.ct, "{}: ciphertext", v.source);
        assert_eq!(tag, c.tag, "{}: tag", v.source);
    }
}

#[test]
fn vectors_open() {
    for v in VECTORS {
        let c = case(v);
        let (status, pt) = open_with(&c, &c.aad, &c.ct, &c.tag);
        assert_eq!(status, EKI_OK, "{}", v.source);
        assert_eq!(pt, c.pt, "{}: plaintext", v.source);
    }
}

// --- §4.4 rows: aead_seal -----------------------------------------------------------------

#[test]
fn seal_unknown_alg_is_invalid_and_zeroes_outputs() {
    let c = gcm16();
    for alg in [0, 3, -1, 99, i32::MIN, i32::MAX] {
        let mut ct = prefill(c.pt.len());
        let mut tag = prefill(16);
        let status = seal(
            eki_aead_alg(alg),
            In::Bytes(&c.key),
            In::Bytes(&c.nonce),
            In::Bytes(&c.aad),
            In::Bytes(&c.pt),
            Out::Bytes(&mut ct),
            Some(&mut tag),
        );
        assert_eq!(status, EKI_ERR_INVALID_ARGUMENT, "alg {alg}");
        assert_zero(&ct);
        assert_zero(&tag);
    }
}

#[test]
fn seal_key_len_not_32_is_invalid_and_zeroes_outputs() {
    let c = gcm16();
    let long_key = [0_u8; 33];
    for alg in ALGS {
        for key in [
            In::Bytes(&c.key[..16]),
            In::Bytes(&c.key[..31]),
            In::Bytes(&long_key),
            In::Null(0),
        ] {
            let mut ct = prefill(c.pt.len());
            let mut tag = prefill(16);
            let status = seal(
                alg,
                key,
                In::Bytes(&c.nonce),
                In::Bytes(&c.aad),
                In::Bytes(&c.pt),
                Out::Bytes(&mut ct),
                Some(&mut tag),
            );
            assert_eq!(status, EKI_ERR_INVALID_ARGUMENT, "alg {alg:?} key {key:?}");
            assert_zero(&ct);
            assert_zero(&tag);
        }
    }
}

#[test]
fn seal_nonce_len_not_12_is_invalid() {
    let c = gcm16();
    let long_nonce = [0_u8; 13];
    for alg in ALGS {
        for nonce in [
            In::Bytes(&c.nonce[..11]),
            In::Bytes(&long_nonce),
            In::Null(0),
        ] {
            let mut ct = prefill(c.pt.len());
            let mut tag = prefill(16);
            let status = seal(
                alg,
                In::Bytes(&c.key),
                nonce,
                In::Bytes(&c.aad),
                In::Bytes(&c.pt),
                Out::Bytes(&mut ct),
                Some(&mut tag),
            );
            assert_eq!(
                status, EKI_ERR_INVALID_ARGUMENT,
                "alg {alg:?} nonce {nonce:?}"
            );
            assert_zero(&ct);
            assert_zero(&tag);
        }
    }
}

#[test]
fn seal_empty_plaintext_with_null_buffers_is_ok() {
    // GCM test case 13: empty plaintext and AAD; `pt`, `ct_out` and `aad` are all NULL.
    let c = case(&VECTORS[2]);
    let mut tag = prefill(16);
    let status = seal(
        c.alg,
        In::Bytes(&c.key),
        In::Bytes(&c.nonce),
        In::Null(0),
        In::Null(0),
        Out::Null(0),
        Some(&mut tag),
    );
    assert_eq!(status, EKI_OK);
    assert_eq!(tag, c.tag);
}

#[test]
fn seal_aad_null_len_zero_is_ok() {
    // GCM test case 15 has no AAD.
    let c = case(&VECTORS[4]);
    for aad in [In::Null(0), In::Bytes(&[])] {
        let mut ct = prefill(c.pt.len());
        let mut tag = prefill(16);
        let status = seal(
            c.alg,
            In::Bytes(&c.key),
            In::Bytes(&c.nonce),
            aad,
            In::Bytes(&c.pt),
            Out::Bytes(&mut ct),
            Some(&mut tag),
        );
        assert_eq!(status, EKI_OK, "{aad:?}");
        assert_eq!(ct, c.ct);
        assert_eq!(tag, c.tag);
    }
}

#[test]
fn seal_null_ct_out_is_checked_before_the_selector() {
    // §4.4: `ct_out NULL, pt_len 1, alg 99` → NULL_POINTER (step 1 precedes step 2).
    let c = gcm16();
    let mut tag = prefill(16);
    let status = seal(
        eki_aead_alg(99),
        In::Bytes(&c.key),
        In::Bytes(&c.nonce),
        In::Null(0),
        In::Bytes(&[0x42]),
        Out::Null(1),
        Some(&mut tag),
    );
    assert_eq!(status, EKI_ERR_NULL_POINTER);
    assert_zero(&tag);
}

#[test]
fn seal_null_pointers() {
    let c = gcm16();
    let n = c.pt.len();
    let rows: [(&str, In, In, In, In, bool, bool); 6] = [
        (
            "key",
            In::Null(32),
            In::Bytes(&c.nonce),
            In::Bytes(&c.aad),
            In::Bytes(&c.pt),
            true,
            true,
        ),
        (
            "nonce",
            In::Bytes(&c.key),
            In::Null(12),
            In::Bytes(&c.aad),
            In::Bytes(&c.pt),
            true,
            true,
        ),
        (
            "aad",
            In::Bytes(&c.key),
            In::Bytes(&c.nonce),
            In::Null(20),
            In::Bytes(&c.pt),
            true,
            true,
        ),
        (
            "pt",
            In::Bytes(&c.key),
            In::Bytes(&c.nonce),
            In::Bytes(&c.aad),
            In::Null(n),
            true,
            true,
        ),
        (
            "ct_out",
            In::Bytes(&c.key),
            In::Bytes(&c.nonce),
            In::Bytes(&c.aad),
            In::Bytes(&c.pt),
            false,
            true,
        ),
        (
            "tag_out",
            In::Bytes(&c.key),
            In::Bytes(&c.nonce),
            In::Bytes(&c.aad),
            In::Bytes(&c.pt),
            true,
            false,
        ),
    ];
    for (name, key, nonce, aad, pt, with_ct, with_tag) in rows {
        let mut ct = prefill(n);
        let mut tag = prefill(16);
        let ct_out = if with_ct {
            Out::Bytes(&mut ct)
        } else {
            Out::Null(n)
        };
        let tag_out = if with_tag { Some(&mut tag[..]) } else { None };
        let status = seal(c.alg, key, nonce, aad, pt, ct_out, tag_out);
        assert_eq!(status, EKI_ERR_NULL_POINTER, "{name} NULL");
        if with_ct {
            assert_zero(&ct);
        }
        if with_tag {
            assert_zero(&tag);
        }
    }
}

#[cfg(target_pointer_width = "64")]
#[test]
fn seal_pt_len_above_max_is_invalid_and_leaves_ct_out_untouched() {
    let c = gcm16();
    let too_long = usize::try_from(EKI_AEAD_MAX_LEN + 1).expect("64-bit usize");
    let pt = [0_u8; 1];
    let mut ct = prefill(1);
    let mut tag = prefill(16);
    // SAFETY: `pt_len` deliberately exceeds the 1-byte buffers. The contract requires the
    // library to reject `pt_len > EKI_AEAD_MAX_LEN` (§4.2 step 3) before touching `pt` or
    // `ct_out`, so no out-of-bounds access happens in a conforming library; every other pointer
    // is a live buffer of the length passed with it.
    let status = unsafe {
        eki_aead_seal(
            c.alg,
            c.key.as_ptr(),
            c.key.len(),
            c.nonce.as_ptr(),
            c.nonce.len(),
            core::ptr::null(),
            0,
            pt.as_ptr(),
            too_long,
            ct.as_mut_ptr(),
            tag.as_mut_ptr(),
        )
    };
    assert_eq!(status, EKI_ERR_INVALID_ARGUMENT);
    // `pt_len` is outside its valid range, so `ct_out` is not written (§4.2 outputs on error).
    assert_untouched(&ct);
    assert_zero(&tag);
}

// --- §4.4 rows: aead_open -----------------------------------------------------------------

#[test]
fn open_tag_bit_flipped_is_auth_failed_and_zeroes_pt_out() {
    for c in [gcm16(), chacha282()] {
        for bit in [0, 7, 64, 127] {
            let mut tag = c.tag.clone();
            tag[bit / 8] ^= 1 << (bit % 8);
            let (status, pt) = open_with(&c, &c.aad, &c.ct, &tag);
            assert_eq!(status, EKI_ERR_AUTH_FAILED, "alg {:?} bit {bit}", c.alg);
            assert_zero(&pt);
        }
    }
}

#[test]
fn open_aad_changed_is_auth_failed_and_zeroes_pt_out() {
    for c in [gcm16(), chacha282()] {
        let mut aad = c.aad.clone();
        aad[0] ^= 0x01;
        let (status, pt) = open_with(&c, &aad, &c.ct, &c.tag);
        assert_eq!(status, EKI_ERR_AUTH_FAILED, "alg {:?}", c.alg);
        assert_zero(&pt);

        let (status, pt) = open_with(&c, &[], &c.ct, &c.tag);
        assert_eq!(status, EKI_ERR_AUTH_FAILED, "alg {:?}: AAD dropped", c.alg);
        assert_zero(&pt);
    }
}

#[test]
fn open_ct_truncated_by_one_is_auth_failed_and_zeroes_pt_out() {
    for c in [gcm16(), chacha282()] {
        let (status, pt) = open_with(&c, &c.aad, &c.ct[..c.ct.len() - 1], &c.tag);
        assert_eq!(status, EKI_ERR_AUTH_FAILED, "alg {:?}", c.alg);
        assert_eq!(pt.len(), c.ct.len() - 1);
        assert_zero(&pt);
    }
}

#[test]
fn open_ct_byte_flipped_is_auth_failed_and_zeroes_pt_out() {
    for c in [gcm16(), chacha282()] {
        for index in [0, c.ct.len() / 2, c.ct.len() - 1] {
            let mut ct = c.ct.clone();
            ct[index] ^= 0x80;
            let (status, pt) = open_with(&c, &c.aad, &ct, &c.tag);
            assert_eq!(status, EKI_ERR_AUTH_FAILED, "alg {:?} byte {index}", c.alg);
            assert_zero(&pt);
        }
    }
}

#[test]
fn open_wrong_key_or_nonce_is_auth_failed() {
    for c in [gcm16(), chacha282()] {
        let mut wrong_key = c.clone();
        wrong_key.key[0] ^= 1;
        let (status, pt) = open_with(&wrong_key, &c.aad, &c.ct, &c.tag);
        assert_eq!(status, EKI_ERR_AUTH_FAILED, "alg {:?}: key", c.alg);
        assert_zero(&pt);

        let mut wrong_nonce = c.clone();
        wrong_nonce.nonce[11] ^= 1;
        let (status, pt) = open_with(&wrong_nonce, &c.aad, &c.ct, &c.tag);
        assert_eq!(status, EKI_ERR_AUTH_FAILED, "alg {:?}: nonce", c.alg);
        assert_zero(&pt);
    }
}

#[test]
fn open_ct_len_zero_with_the_right_tag_is_ok() {
    // GCM test case 13, with `ct` and `pt_out` NULL.
    let c = case(&VECTORS[2]);
    let status = open(
        c.alg,
        In::Bytes(&c.key),
        In::Bytes(&c.nonce),
        In::Null(0),
        In::Null(0),
        In::Bytes(&c.tag),
        Out::Null(0),
    );
    assert_eq!(status, EKI_OK);

    let mut tag = c.tag.clone();
    tag[15] ^= 1;
    let status = open(
        c.alg,
        In::Bytes(&c.key),
        In::Bytes(&c.nonce),
        In::Null(0),
        In::Null(0),
        In::Bytes(&tag),
        Out::Null(0),
    );
    assert_eq!(status, EKI_ERR_AUTH_FAILED, "empty ciphertext, wrong tag");
}

#[test]
fn open_unknown_alg_key_len_nonce_len_are_invalid() {
    let c = gcm16();
    let mut pt = prefill(c.ct.len());
    let status = open(
        eki_aead_alg(0),
        In::Bytes(&c.key),
        In::Bytes(&c.nonce),
        In::Bytes(&c.aad),
        In::Bytes(&c.ct),
        In::Bytes(&c.tag),
        Out::Bytes(&mut pt),
    );
    assert_eq!(status, EKI_ERR_INVALID_ARGUMENT, "alg 0");
    assert_zero(&pt);

    let mut pt = prefill(c.ct.len());
    let status = open(
        c.alg,
        In::Bytes(&c.key[..16]),
        In::Bytes(&c.nonce),
        In::Bytes(&c.aad),
        In::Bytes(&c.ct),
        In::Bytes(&c.tag),
        Out::Bytes(&mut pt),
    );
    assert_eq!(status, EKI_ERR_INVALID_ARGUMENT, "key_len 16");
    assert_zero(&pt);

    let mut pt = prefill(c.ct.len());
    let status = open(
        c.alg,
        In::Bytes(&c.key),
        In::Bytes(&c.nonce[..11]),
        In::Bytes(&c.aad),
        In::Bytes(&c.ct),
        In::Bytes(&c.tag),
        Out::Bytes(&mut pt),
    );
    assert_eq!(status, EKI_ERR_INVALID_ARGUMENT, "nonce_len 11");
    assert_zero(&pt);
}

#[test]
fn open_null_pointers() {
    let c = gcm16();
    let n = c.ct.len();
    let rows: [(&str, In, In, In, In, In, bool); 6] = [
        (
            "key",
            In::Null(32),
            In::Bytes(&c.nonce),
            In::Bytes(&c.aad),
            In::Bytes(&c.ct),
            In::Bytes(&c.tag),
            true,
        ),
        (
            "nonce",
            In::Bytes(&c.key),
            In::Null(12),
            In::Bytes(&c.aad),
            In::Bytes(&c.ct),
            In::Bytes(&c.tag),
            true,
        ),
        (
            "aad",
            In::Bytes(&c.key),
            In::Bytes(&c.nonce),
            In::Null(20),
            In::Bytes(&c.ct),
            In::Bytes(&c.tag),
            true,
        ),
        (
            "ct",
            In::Bytes(&c.key),
            In::Bytes(&c.nonce),
            In::Bytes(&c.aad),
            In::Null(n),
            In::Bytes(&c.tag),
            true,
        ),
        (
            "tag",
            In::Bytes(&c.key),
            In::Bytes(&c.nonce),
            In::Bytes(&c.aad),
            In::Bytes(&c.ct),
            In::Null(16),
            true,
        ),
        (
            "pt_out",
            In::Bytes(&c.key),
            In::Bytes(&c.nonce),
            In::Bytes(&c.aad),
            In::Bytes(&c.ct),
            In::Bytes(&c.tag),
            false,
        ),
    ];
    for (name, key, nonce, aad, ct, tag, with_pt) in rows {
        let mut pt = prefill(n);
        let pt_out = if with_pt {
            Out::Bytes(&mut pt)
        } else {
            Out::Null(n)
        };
        let status = open(c.alg, key, nonce, aad, ct, tag, pt_out);
        assert_eq!(status, EKI_ERR_NULL_POINTER, "{name} NULL");
        if with_pt {
            assert_zero(&pt);
        }
    }
    // The tag is a fixed-size input: NULL is an error even when ct_len is 0.
    let status = open(
        c.alg,
        In::Bytes(&c.key),
        In::Bytes(&c.nonce),
        In::Null(0),
        In::Null(0),
        In::Null(16),
        Out::Null(0),
    );
    assert_eq!(status, EKI_ERR_NULL_POINTER, "tag NULL, ct_len 0");
    // NULL before the selector.
    let status = open(
        eki_aead_alg(99),
        In::Bytes(&c.key),
        In::Bytes(&c.nonce),
        In::Null(0),
        In::Bytes(&c.ct),
        In::Bytes(&c.tag),
        Out::Null(n),
    );
    assert_eq!(status, EKI_ERR_NULL_POINTER, "pt_out NULL, alg 99");
}

#[cfg(target_pointer_width = "64")]
#[test]
fn open_ct_len_above_max_is_invalid_and_leaves_pt_out_untouched() {
    let c = gcm16();
    let too_long = usize::try_from(EKI_AEAD_MAX_LEN + 1).expect("64-bit usize");
    let ct = [0_u8; 1];
    let mut pt = prefill(1);
    // SAFETY: `ct_len` deliberately exceeds the 1-byte buffers. The contract requires the
    // library to reject `ct_len > EKI_AEAD_MAX_LEN` (§4.2 step 3) before touching `ct` or
    // `pt_out`; every other pointer is a live buffer of the length passed with it.
    let status = unsafe {
        eki_aead_open(
            c.alg,
            c.key.as_ptr(),
            c.key.len(),
            c.nonce.as_ptr(),
            c.nonce.len(),
            core::ptr::null(),
            0,
            ct.as_ptr(),
            too_long,
            c.tag.as_ptr(),
            pt.as_mut_ptr(),
        )
    };
    assert_eq!(status, EKI_ERR_INVALID_ARGUMENT);
    assert_untouched(&pt);
}

// --- round trips --------------------------------------------------------------------------

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
    fn seal_open_round_trip(
        gcm in any::<bool>(),
        key in proptest::array::uniform32(any::<u8>()),
        nonce in proptest::array::uniform12(any::<u8>()),
        aad in proptest::collection::vec(any::<u8>(), 0..=64),
        pt in proptest::collection::vec(any::<u8>(), 0..=4096),
        flip in any::<prop::sample::Index>(),
    ) {
        let alg = if gcm { EKI_AEAD_AES_256_GCM } else { EKI_AEAD_CHACHA20_POLY1305 };
        let c = Case {
            alg,
            key: key.to_vec(),
            nonce: nonce.to_vec(),
            aad,
            pt,
            ct: Vec::new(),
            tag: Vec::new(),
        };
        let (status, ct, tag) = seal_case(&c);
        prop_assert_eq!(status, EKI_OK);
        prop_assert_eq!(ct.len(), c.pt.len());

        let (status, back) = open_with(&c, &c.aad, &ct, &tag);
        prop_assert_eq!(status, EKI_OK);
        prop_assert_eq!(&back, &c.pt);

        // Any single-bit change of ciphertext or tag is rejected and pt_out is zeroed.
        let mut sealed: Vec<u8> = ct.iter().chain(tag.iter()).copied().collect();
        let bit = flip.index(sealed.len() * 8);
        sealed[bit / 8] ^= 1 << (bit % 8);
        let (bad_ct, bad_tag) = sealed.split_at(ct.len());
        let (status, out) = open_with(&c, &c.aad, bad_ct, bad_tag);
        prop_assert_eq!(status, EKI_ERR_AUTH_FAILED);
        prop_assert!(out.iter().all(|&b| b == 0));
    }
}
