//! Sign with a stored ECDSA P-256 key, then verify with `eki_ecdsa_p256_verify`, unchanged and
//! tampered.
//!
//! Input: the message (byte string), one byte modulo 4 choosing what to tamper with (nothing,
//! the signature, the message, the public key), and an XOR mask (byte string) applied from the
//! first byte; mask bytes past the end of the message are appended to it.
//!
//! Each run generates a key in a fresh software store, signs the message with `eki_ks_sign` and
//! reads the public key with `eki_ks_get_public_key`. Properties:
//! * signing and reading the public key succeed;
//! * the untampered triple verifies;
//! * a changed signature or message is `EKI_ERR_AUTH_FAILED`; a changed public key is
//!   `EKI_ERR_INVALID_ARGUMENT` (not a curve point) or `EKI_ERR_AUTH_FAILED`.

#![no_main]

use ekicore_abi::{EKI_KEY_ECDSA_P256, EKI_P256_PUBLIC_KEY_LEN, EKI_P256_SIGNATURE_LEN};
use ekicore_rs::ffi::{eki_ecdsa_p256_verify, eki_ks_get_public_key, eki_ks_sign};
use ekicore_rs_fuzz::{AUTH_FAILED, Call, INVALID_ARGUMENT, OK, OutBuf, Reader, Store};
use libfuzzer_sys::fuzz_target;

/// XORs `mask` into `bytes` from the first byte; returns whether a byte changed.
fn xor(bytes: &mut [u8], mask: &[u8]) -> bool {
    let mut changed = false;
    for (byte, m) in bytes.iter_mut().zip(mask) {
        *byte ^= m;
        changed |= *m != 0;
    }
    changed
}

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    let mut msg = r.bytes();
    let tamper = r.u8() % 4;
    let mask = r.bytes();

    let store = Store::software();
    let id = store.generate(EKI_KEY_ECDSA_P256, c"fuzz-signer");
    let mut sig = OutBuf::new(false, EKI_P256_SIGNATURE_LEN);
    // SAFETY: `store` is open; `id` is a live struct; `msg` is a live Vec of the stated length;
    // `sig` is a writable 64-byte allocation.
    let status =
        unsafe { eki_ks_sign(store.ptr(), &id, msg.as_ptr(), msg.len(), sig.ptr()) } as i32;
    let mut call = Call::new("eki_ks_sign", status);
    call.outputs.push(sig.seen());
    call.check();
    assert_eq!(status, OK, "signing with a fresh key failed");
    let mut pk = OutBuf::new(false, EKI_P256_PUBLIC_KEY_LEN);
    // SAFETY: `store` is open; `id` is a live struct; `pk` is a writable 65-byte allocation.
    let status = unsafe { eki_ks_get_public_key(store.ptr(), &id, pk.ptr()) } as i32;
    assert_eq!(status, OK, "reading the public key of a fresh key failed");

    let mut sig: [u8; EKI_P256_SIGNATURE_LEN] = sig.bytes().try_into().expect("64 bytes");
    let mut pk: [u8; EKI_P256_PUBLIC_KEY_LEN] = pk.bytes().try_into().expect("65 bytes");
    let changed = match tamper {
        0 => false,
        1 => xor(&mut sig, &mask),
        2 => {
            let mut changed = xor(&mut msg, &mask);
            if mask.len() > msg.len() {
                msg.extend_from_slice(&mask[msg.len()..]);
                changed = true;
            }
            changed
        }
        _ => xor(&mut pk, &mask),
    };

    // SAFETY: `pk` and `sig` are live arrays of 65 and 64 bytes; `msg` is a live Vec of the
    // stated length.
    let status =
        unsafe { eki_ecdsa_p256_verify(pk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr()) } as i32;
    Call::new("eki_ecdsa_p256_verify", status).check();
    let expected: &[i32] = match (changed, tamper) {
        (false, _) => &[OK],
        (true, 3) => &[INVALID_ARGUMENT, AUTH_FAILED],
        (true, _) => &[AUTH_FAILED],
    };
    assert!(
        expected.contains(&status),
        "eki_ecdsa_p256_verify returned {status} (tamper mode {tamper}, changed {changed})"
    );
});
