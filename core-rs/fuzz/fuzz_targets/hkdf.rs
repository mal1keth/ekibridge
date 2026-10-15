//! `eki_hkdf_sha256` on arbitrary inputs and output lengths from 0 to 9000.
//!
//! Properties: the status is a defined value, and success is only ever reported for an output
//! length the contract allows (1..=8160).

#![no_main]

use ekicore_rs::ffi::eki_hkdf_sha256;
use ekicore_rs_fuzz::{EKI_OK, HkdfInput, assert_status_in_range, okm_len_in_range};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: HkdfInput| {
    let mut okm = vec![0xA5_u8; input.okm_len];

    // SAFETY: each input pointer comes from a live Vec with its own length; `okm` is a distinct
    // allocation of exactly `okm_len` bytes, valid for writes for the whole call.
    let status = unsafe {
        eki_hkdf_sha256(
            input.ikm.as_ptr(),
            input.ikm.len(),
            input.salt.as_ptr(),
            input.salt.len(),
            input.info.as_ptr(),
            input.info.len(),
            okm.as_mut_ptr(),
            okm.len(),
        )
    } as i32;
    assert_status_in_range("eki_hkdf_sha256", status);
    if status == EKI_OK {
        assert!(
            okm_len_in_range(input.okm_len),
            "EKI_OK for okm_len {}, outside 1..=8160",
            input.okm_len
        );
    }
});
