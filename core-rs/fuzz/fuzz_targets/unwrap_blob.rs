//! `eki_ks_unwrap` on arbitrary blobs, algorithms, labels and ids, in a store opened from an
//! arbitrary configuration.
//!
//! Input: a flag (one byte, low bit); when set, a store configuration (`Config` in the shared
//! library) for `eki_ks_open_v2`, otherwise a plain software store from `eki_ks_open`. Then a flag
//! choosing the blob's origin, the blob or XOR mask (byte string), the algorithm (i32), the id
//! (16 bytes) and the label (`read_label`).
//!
//! Each run generates an AES-256 key to unwrap under. The blob is the input's bytes as they
//! are, or a real wrap of a freshly generated HMAC key with the input's bytes XORed over it, so
//! the success path is reachable. Properties:
//! * opening fails or succeeds as the contract allows; a failed open leaves `*out` NULL;
//! * the unwrap status is exactly the one the contract's validation order gives: a NULL label,
//!   then the algorithm, the blob length, ECDSA, the label format, then the integrity check
//!   (`EKI_OK` only for an unmodified real wrap; a raw blob never authenticates);
//! * after a successful unwrap, `eki_ks_get_info_v2` reports the requested algorithm, the label
//!   and the ACTIVE state, and an HMAC key computes the same tag as the key that was wrapped;
//! * the store closes, and an audit log it wrote verifies afterwards.

#![no_main]

use ekicore_abi::{
    EKI_KEY_AES_256, EKI_KEY_ECDSA_P256, EKI_KEY_HMAC_SHA256, EKI_KEY_STATE_ACTIVE,
    EKI_LABEL_MAX_LEN, EKI_WRAPPED_KEY_LEN, eki_key_alg, eki_key_id, eki_key_info_v2, eki_ks,
};
use ekicore_rs::ffi::{
    eki_audit_verify, eki_ks_get_info_v2, eki_ks_hmac_sha256, eki_ks_open_v2, eki_ks_unwrap,
    eki_ks_wrap,
};
use ekicore_rs_fuzz::{
    AUTH_FAILED, Approvers, Call, Config, INVALID_ARGUMENT, NULL_POINTER, OK, Reader, Scratch,
    Slot, Store, label_is_valid, read_label,
};
use libfuzzer_sys::fuzz_target;

/// Opens the store the input describes, or returns `None` after checking a failed open.
fn open(r: &mut Reader<'_>, scratch: &Scratch, approvers: &mut Approvers) -> Option<Store> {
    if !r.boolean() {
        return Some(Store::software());
    }
    let config = Config::read(r, scratch, approvers);
    let raw = config.v2();
    let mut out = Slot::<*mut eki_ks>::new(false);
    // SAFETY: `raw` points only into buffers `config` owns, which outlive the call, and every
    // pointer field is NULL or valid as the contract requires (`Config` sizes the approver keys
    // to the count); `out` is a live, writable, aligned `eki_ks *`.
    let status = unsafe { eki_ks_open_v2(&raw, out.ptr()) } as i32;
    let mut call = Call::new("eki_ks_open_v2", status);
    call.null_field = config.null_field_v2();
    call.outputs.push(out.seen());
    call.check();
    let expected = config.expected_open(true, scratch, false);
    assert!(
        expected.contains(&status),
        "eki_ks_open_v2: {status}, expected one of {expected:?}"
    );
    (status == OK).then(|| Store::from_raw(out.get()))
}

fn hmac(store: &Store, id: &eki_key_id) -> [u8; 32] {
    let msg = b"ekibridge";
    let mut tag = [0xA5_u8; 32];
    // SAFETY: `store` is open; `id` is a live struct; `msg` is a live 9-byte array; `tag` is a
    // writable 32-byte buffer.
    let status =
        unsafe { eki_ks_hmac_sha256(store.ptr(), id, msg.as_ptr(), msg.len(), tag.as_mut_ptr()) }
            as i32;
    assert_eq!(
        status, OK,
        "eki_ks_hmac_sha256 failed for an active HMAC key"
    );
    tag
}

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    let scratch = Scratch::new("unwrap_blob");
    scratch.reset();
    let mut approvers = Approvers::default();
    let Some(store) = open(&mut r, &scratch, &mut approvers) else {
        return;
    };
    let from_wrap = r.boolean();
    let input_blob = r.bytes();
    let alg = eki_key_alg(r.i32());
    let id = eki_key_id { bytes: r.array() };
    let label = read_label(&mut r);

    let kek = store.generate(EKI_KEY_AES_256, c"fuzz-kek");
    let (blob, wrapped) = if from_wrap {
        let key = store.generate(EKI_KEY_HMAC_SHA256, c"fuzz-wrapped");
        let mut blob = vec![0xA5_u8; EKI_WRAPPED_KEY_LEN];
        // SAFETY: `store` is open; both ids are live structs; `blob` is a writable 40-byte
        // allocation, as `out` requires.
        let status = unsafe { eki_ks_wrap(store.ptr(), &kek, &key, blob.as_mut_ptr()) } as i32;
        assert_eq!(status, OK, "wrapping an HMAC key under an AES key failed");
        let mut changed = false;
        for (byte, mask) in blob.iter_mut().zip(&input_blob) {
            *byte ^= mask;
            changed |= *mask != 0;
        }
        (blob, Some((key, changed)))
    } else {
        (input_blob, None)
    };

    // SAFETY: `store` is open; `kek` and `id` are live structs; `blob` is a live Vec of
    // `blob.len()` bytes; `label` is NULL, NUL-terminated, or 65 readable bytes, of which the
    // library reads at most 65.
    let status = unsafe {
        eki_ks_unwrap(
            store.ptr(),
            &kek,
            blob.as_ptr(),
            blob.len(),
            alg,
            label.ptr(),
            &id,
        )
    } as i32;
    let mut call = Call::new("eki_ks_unwrap", status);
    call.null_param = label.is_null();
    call.check();

    let seen = label.seen(EKI_LABEL_MAX_LEN + 1);
    let expected = if label.is_null() {
        NULL_POINTER
    } else if !(1..=3).contains(&alg.0)
        || blob.len() != EKI_WRAPPED_KEY_LEN
        || alg == EKI_KEY_ECDSA_P256
        || !seen.is_some_and(label_is_valid)
    {
        INVALID_ARGUMENT
    } else if wrapped.is_some_and(|(_, changed)| !changed) {
        OK
    } else {
        AUTH_FAILED
    };
    assert_eq!(status, expected, "eki_ks_unwrap");

    if status == OK {
        let mut info = Slot::<eki_key_info_v2>::new(false);
        // SAFETY: `store` is open; `id` is a live struct; `info` is a live, writable, aligned
        // `eki_key_info_v2`.
        let status = unsafe { eki_ks_get_info_v2(store.ptr(), &id, info.ptr()) } as i32;
        assert_eq!(status, OK, "eki_ks_get_info_v2 failed for an unwrapped key");
        let info = info.get();
        assert_eq!(info.alg, alg, "unwrapped key reports another algorithm");
        assert_eq!(
            info.state, EKI_KEY_STATE_ACTIVE,
            "unwrapped key is not ACTIVE"
        );
        let stored: Vec<u8> = info.label.iter().map(|&c| c as u8).collect();
        let label = seen.expect("a valid label");
        assert_eq!(
            &stored[..label.len()],
            label,
            "unwrapped key reports another label"
        );
        assert!(
            stored[label.len()..].iter().all(|&b| b == 0),
            "label not NUL-padded"
        );
        if alg == EKI_KEY_HMAC_SHA256 {
            let (key, _) = wrapped.expect("only a real wrap unwraps");
            assert_eq!(
                hmac(&store, &id),
                hmac(&store, &key),
                "unwrap changed the key"
            );
        }
    }

    drop(store);
    drop(approvers);
    if scratch.log_path.exists() {
        let mut records = Slot::<u64>::new(false);
        // SAFETY: `scratch.log` is NUL-terminated and outlives the call; `expected_head` is
        // NULL, which the contract allows; `records` is a live, writable, aligned `uint64_t`.
        let status =
            unsafe { eki_audit_verify(scratch.log.as_ptr(), core::ptr::null(), records.ptr()) }
                as i32;
        assert_eq!(
            status, OK,
            "the audit log of a closed store does not verify"
        );
    }
});
