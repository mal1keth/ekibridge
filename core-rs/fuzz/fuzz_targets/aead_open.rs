//! `eki_aead_open` on arbitrary algorithm, key, nonce, AAD, ciphertext and tag.
//!
//! Properties: the status is a defined value, and whenever opening succeeds, sealing the
//! recovered plaintext under the same parameters reproduces the ciphertext and the tag exactly.

#![no_main]

use ekicore_abi::eki_aead_alg;
use ekicore_rs::ffi::{eki_aead_open, eki_aead_seal};
use ekicore_rs_fuzz::{AeadOpenInput, EKI_OK, assert_status_in_range};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: AeadOpenInput| {
    let alg = eki_aead_alg(input.alg);
    let mut pt = vec![0xA5_u8; input.ct.len()];

    // SAFETY: every (pointer, length) pair comes from a live Vec or array owned by this frame
    // and stays valid and unmodified for the whole call; `pt` is a distinct allocation of
    // exactly `ct.len()` bytes as the contract requires for `pt_out`, so no buffers overlap.
    let status = unsafe {
        eki_aead_open(
            alg,
            input.key.as_ptr(),
            input.key.len(),
            input.nonce.as_ptr(),
            input.nonce.len(),
            input.aad.as_ptr(),
            input.aad.len(),
            input.ct.as_ptr(),
            input.ct.len(),
            input.tag.as_ptr(),
            pt.as_mut_ptr(),
        )
    } as i32;
    assert_status_in_range("eki_aead_open", status);
    if status != EKI_OK {
        return;
    }

    let mut ct = vec![0xA5_u8; pt.len()];
    let mut tag = [0xA5_u8; 16];
    // SAFETY: as above; `ct` has exactly `pt.len()` bytes and `tag` has the 16 bytes `tag_out`
    // needs, both distinct from every input buffer.
    let reseal = unsafe {
        eki_aead_seal(
            alg,
            input.key.as_ptr(),
            input.key.len(),
            input.nonce.as_ptr(),
            input.nonce.len(),
            input.aad.as_ptr(),
            input.aad.len(),
            pt.as_ptr(),
            pt.len(),
            ct.as_mut_ptr(),
            tag.as_mut_ptr(),
        )
    } as i32;
    assert_eq!(
        reseal, EKI_OK,
        "open succeeded but sealing its plaintext failed"
    );
    assert_eq!(ct, input.ct, "seal(open(ct)) changed the ciphertext");
    assert_eq!(tag, input.tag, "seal(open(ct)) changed the tag");
});
