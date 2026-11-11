//! `eki_audit_verify` on an arbitrary file, written to a scratch file for each input.
//!
//! Input: one byte modulo 3 choosing `expected_head` (NULL; the head of the harness's own
//! reading of the file, or 32 zero bytes when that reading rejects it; 32 bytes that follow),
//! then the file's bytes, all the rest of the input.
//!
//! The oracle is `audit_rebuild` in the shared library: an independent, strict reading of the
//! record grammar and the hash chain written from the ABI 2 contract. Properties:
//! * the status is `EKI_OK` or `EKI_ERR_AUTH_FAILED` (the file exists and is readable);
//! * the library accepts the file exactly when the rebuild does and `expected_head`, if given,
//!   equals the rebuilt head; it then reports the rebuilt number of records;
//! * after a failure `records_out` is zero.

#![no_main]

use ekicore_abi::EKI_AUDIT_HASH_LEN;
use ekicore_rs::ffi::eki_audit_verify;
use ekicore_rs_fuzz::{AUTH_FAILED, Call, OK, Reader, Scratch, Slot, audit_rebuild};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    let mode = r.u8() % 3;
    let raw_head: Option<[u8; EKI_AUDIT_HASH_LEN]> = (mode == 2).then(|| r.array());
    let log = r.rest();
    let rebuilt = audit_rebuild(&log);
    let head = match mode {
        0 => None,
        1 => Some(rebuilt.map_or([0; EKI_AUDIT_HASH_LEN], |h| h.hash)),
        _ => raw_head,
    };

    let scratch = Scratch::new("audit_verify");
    std::fs::write(&scratch.log_path, &log).expect("writing the scratch log");
    let mut records = Slot::<u64>::new(false);
    let head_ptr = head.as_ref().map_or(core::ptr::null(), |h| h.as_ptr());
    // SAFETY: `scratch.log` is a NUL-terminated path that outlives the call; `head_ptr` is NULL
    // or a live 32-byte array; `records` is a live, writable, aligned `uint64_t`.
    let status = unsafe { eki_audit_verify(scratch.log.as_ptr(), head_ptr, records.ptr()) } as i32;
    let mut call = Call::new("eki_audit_verify", status);
    call.outputs.push(records.seen());
    call.check();

    let accept = rebuilt.filter(|h| head.is_none_or(|head| head == h.hash));
    match accept {
        Some(h) => {
            assert_eq!(status, OK, "a valid log was rejected");
            assert_eq!(records.get(), h.records, "wrong record count");
        }
        None => assert_eq!(status, AUTH_FAILED, "an invalid log was not rejected"),
    }
});
