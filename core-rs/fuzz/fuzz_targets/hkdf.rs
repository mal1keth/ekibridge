//! `eki_hkdf_sha256` on arbitrary inputs and two output lengths from 0 to 9000.
//!
//! Input: IKM, salt and info (byte strings), then two lengths (u16 each, modulo 9001).
//!
//! Properties:
//! * the call succeeds exactly when `ikm_len` is 1 to 32768 and `okm_len` 1 to 8160 (salt and
//!   info stay far below their cap); otherwise it is `EKI_ERR_INVALID_ARGUMENT`;
//! * after a failure `okm` is all zero when its length is in range, and untouched above 8160;
//! * prefix stability: of two successful derivations from the same inputs, the shorter output
//!   is a prefix of the longer one.

#![no_main]

use ekicore_abi::{EKI_HKDF_MAX_INPUT_LEN, EKI_HKDF_MAX_OKM_LEN};
use ekicore_rs::ffi::eki_hkdf_sha256;
use ekicore_rs_fuzz::{Call, INVALID_ARGUMENT, OK, OutBuf, Reader};
use libfuzzer_sys::fuzz_target;

/// Upper bound (inclusive) of the lengths asked for: a little past `EKI_HKDF_MAX_OKM_LEN`.
const OKM_LEN_FUZZ_MAX: u16 = 9000;

fn derive(ikm: &[u8], salt: &[u8], info: &[u8], okm_len: usize) -> (i32, OutBuf) {
    let mut okm = if okm_len > EKI_HKDF_MAX_OKM_LEN {
        OutBuf::untouched(false, okm_len)
    } else {
        OutBuf::new(false, okm_len)
    };
    // SAFETY: each input pointer comes from a live Vec with its own length; `okm` is a distinct
    // allocation of exactly `okm_len` bytes.
    let status = unsafe {
        eki_hkdf_sha256(
            ikm.as_ptr(),
            ikm.len(),
            salt.as_ptr(),
            salt.len(),
            info.as_ptr(),
            info.len(),
            okm.ptr(),
            okm_len,
        )
    } as i32;
    let mut call = Call::new("eki_hkdf_sha256", status);
    call.outputs.push(okm.seen());
    call.check();
    let valid = (1..=EKI_HKDF_MAX_INPUT_LEN).contains(&ikm.len())
        && salt.len() <= EKI_HKDF_MAX_INPUT_LEN
        && info.len() <= EKI_HKDF_MAX_INPUT_LEN
        && (1..=EKI_HKDF_MAX_OKM_LEN).contains(&okm_len);
    assert_eq!(
        status,
        if valid { OK } else { INVALID_ARGUMENT },
        "eki_hkdf_sha256 with ikm_len {}, okm_len {okm_len}",
        ikm.len()
    );
    (status, okm)
}

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    let ikm = r.bytes();
    let salt = r.bytes();
    let info = r.bytes();
    let first = usize::from(r.u16() % (OKM_LEN_FUZZ_MAX + 1));
    let second = usize::from(r.u16() % (OKM_LEN_FUZZ_MAX + 1));

    let (status1, okm1) = derive(&ikm, &salt, &info, first);
    let (status2, okm2) = derive(&ikm, &salt, &info, second);
    if status1 == OK && status2 == OK {
        let n = first.min(second);
        assert_eq!(
            okm1.bytes()[..n],
            okm2.bytes()[..n],
            "HKDF outputs of lengths {first} and {second} differ in their common prefix"
        );
    }
});
