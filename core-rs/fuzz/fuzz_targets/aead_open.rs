//! `eki_aead_open` and `eki_aead_seal` on arbitrary algorithm, key, nonce, AAD, ciphertext and tag.
//!
//! Input: `alg` (i32), key, nonce, AAD and ciphertext (byte strings), the 16-byte tag.
//!
//! Properties:
//! * opening the input fails or succeeds as the contract allows, and a failure leaves `pt_out`
//!   all zero;
//! * when opening succeeds, sealing the recovered plaintext reproduces the ciphertext and tag;
//! * sealing the input's ciphertext bytes as a plaintext succeeds exactly when the algorithm, key
//!   length and nonce length are valid, and opening the result gives those bytes back, while the
//!   same ciphertext with one tag bit flipped is `EKI_ERR_AUTH_FAILED` with `pt_out` all zero.

#![no_main]

use ekicore_abi::{EKI_AEAD_KEY_LEN, EKI_AEAD_NONCE_LEN, EKI_AEAD_TAG_LEN, eki_aead_alg};
use ekicore_rs::ffi::{eki_aead_open, eki_aead_seal};
use ekicore_rs_fuzz::{AUTH_FAILED, Call, INVALID_ARGUMENT, OK, OutBuf, Reader};
use libfuzzer_sys::fuzz_target;

struct Params {
    alg: eki_aead_alg,
    key: Vec<u8>,
    nonce: Vec<u8>,
    aad: Vec<u8>,
}

/// Opens `ct` with `tag`; returns the status and the plaintext buffer after the call.
fn open(p: &Params, ct: &[u8], tag: &[u8; EKI_AEAD_TAG_LEN]) -> (i32, OutBuf) {
    let mut pt = OutBuf::new(false, ct.len());
    // SAFETY: every input pointer comes from a live Vec or array with its own length; `pt` is a
    // distinct allocation of exactly `ct.len()` bytes, as `pt_out` requires.
    let status = unsafe {
        eki_aead_open(
            p.alg,
            p.key.as_ptr(),
            p.key.len(),
            p.nonce.as_ptr(),
            p.nonce.len(),
            p.aad.as_ptr(),
            p.aad.len(),
            ct.as_ptr(),
            ct.len(),
            tag.as_ptr(),
            pt.ptr(),
        )
    } as i32;
    let mut call = Call::new("eki_aead_open", status);
    call.outputs.push(pt.seen());
    call.check();
    (status, pt)
}

/// Seals `pt`; returns the status, the ciphertext and the tag.
fn seal(p: &Params, pt: &[u8]) -> (i32, OutBuf, OutBuf) {
    let mut ct = OutBuf::new(false, pt.len());
    let mut tag = OutBuf::new(false, EKI_AEAD_TAG_LEN);
    // SAFETY: as in `open`; `ct` has exactly `pt.len()` bytes and `tag` the 16 bytes `tag_out`
    // needs, both distinct from every input buffer.
    let status = unsafe {
        eki_aead_seal(
            p.alg,
            p.key.as_ptr(),
            p.key.len(),
            p.nonce.as_ptr(),
            p.nonce.len(),
            p.aad.as_ptr(),
            p.aad.len(),
            pt.as_ptr(),
            pt.len(),
            ct.ptr(),
            tag.ptr(),
        )
    } as i32;
    let mut call = Call::new("eki_aead_seal", status);
    call.outputs.extend([ct.seen(), tag.seen()]);
    call.check();
    (status, ct, tag)
}

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    let p = Params {
        alg: eki_aead_alg(r.i32()),
        key: r.bytes(),
        nonce: r.bytes(),
        aad: r.bytes(),
    };
    let ct = r.bytes();
    let tag: [u8; EKI_AEAD_TAG_LEN] = r.array();
    let valid = (1..=2).contains(&p.alg.0)
        && p.key.len() == EKI_AEAD_KEY_LEN
        && p.nonce.len() == EKI_AEAD_NONCE_LEN;

    let (status, pt) = open(&p, &ct, &tag);
    let expected = if valid {
        [OK, AUTH_FAILED]
    } else {
        [INVALID_ARGUMENT; 2]
    };
    assert!(
        expected.contains(&status),
        "eki_aead_open returned {status}"
    );
    if status == OK {
        let (reseal, ct2, tag2) = seal(&p, pt.bytes());
        assert_eq!(
            reseal, OK,
            "open succeeded but sealing its plaintext failed"
        );
        assert_eq!(
            ct2.bytes(),
            &ct[..],
            "seal(open(ct)) changed the ciphertext"
        );
        assert_eq!(tag2.bytes(), &tag[..], "seal(open(ct)) changed the tag");
    }

    let (sealed, ct2, tag2) = seal(&p, &ct);
    assert_eq!(
        sealed,
        if valid { OK } else { INVALID_ARGUMENT },
        "eki_aead_seal"
    );
    if sealed != OK {
        return;
    }
    let mut tag2: [u8; EKI_AEAD_TAG_LEN] = tag2.bytes().try_into().expect("16-byte tag");
    let (opened, pt2) = open(&p, ct2.bytes(), &tag2);
    assert_eq!(opened, OK, "open(seal(pt)) failed");
    assert_eq!(pt2.bytes(), &ct[..], "open(seal(pt)) changed the plaintext");
    tag2[0] ^= 1;
    let (forged, _) = open(&p, ct2.bytes(), &tag2);
    assert_eq!(forged, AUTH_FAILED, "a flipped tag bit was accepted");
});
