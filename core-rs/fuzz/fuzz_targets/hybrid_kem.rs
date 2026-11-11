//! The hybrid X25519 + ML-KEM-768 KEM on arbitrary public keys, secret keys and ciphertexts.
//!
//! Input: one byte modulo 3 choosing the mode, then
//! * 0, round trip: an XOR mask for the public key and one for the ciphertext (byte strings,
//!   applied from the first byte). A fresh key pair is generated, the masked public key is
//!   encapsulated to, the masked ciphertext decapsulated;
//! * 1, decapsulation: a secret key and a ciphertext (byte strings, zero-padded or cut to 96 and
//!   1120 bytes);
//! * 2, encapsulation: a public key (byte string, zero-padded or cut to 1216 bytes).
//!
//! Properties, with the `pq` feature:
//! * every status is `EKI_OK` or `EKI_ERR_INVALID_ARGUMENT`, and every output of a failed call is
//!   all zero;
//! * key generation succeeds, and so does encapsulation to an unmodified public key;
//! * decapsulation fails only when the X25519 part of the ciphertext was modified;
//! * without either mask, decapsulation recovers the encapsulated secret; with a mask that
//!   changed anything, a successful decapsulation gives a different secret (implicit rejection,
//!   and the combiner binds the ciphertext and the public key).
//!
//! Without the feature every call is `EKI_ERR_UNSUPPORTED` with all outputs zero.

#![no_main]

use ekicore_abi::{EKI_HYBRID_CT_LEN, EKI_HYBRID_PK_LEN, EKI_HYBRID_SK_LEN, EKI_HYBRID_SS_LEN};
use ekicore_rs::ffi::{eki_hybrid_kem_decap, eki_hybrid_kem_encap, eki_hybrid_kem_keygen};
use ekicore_rs_fuzz::{Call, INVALID_ARGUMENT, OK, OutBuf, Reader, UNSUPPORTED, WITH_PQ, exact};
use libfuzzer_sys::fuzz_target;

/// X25519 part at the front of a ciphertext.
const X25519_LEN: usize = 32;

/// Checks a finished call: the contract's rules, then the statuses this target allows.
fn finish(call: Call) -> i32 {
    call.check();
    let allowed: &[i32] = if WITH_PQ {
        &[OK, INVALID_ARGUMENT]
    } else {
        &[UNSUPPORTED]
    };
    assert!(
        allowed.contains(&call.status),
        "{} returned {}",
        call.function,
        call.status
    );
    call.status
}

fn keygen() -> (i32, OutBuf, OutBuf) {
    let mut pk = OutBuf::new(false, EKI_HYBRID_PK_LEN);
    let mut sk = OutBuf::new(false, EKI_HYBRID_SK_LEN);
    // SAFETY: `pk` and `sk` are distinct writable allocations of exactly 1216 and 96 bytes.
    let status = unsafe { eki_hybrid_kem_keygen(pk.ptr(), sk.ptr()) } as i32;
    let mut call = Call::new("eki_hybrid_kem_keygen", status);
    call.outputs.extend([pk.seen(), sk.seen()]);
    (finish(call), pk, sk)
}

fn encap(pk: &[u8]) -> (i32, OutBuf, OutBuf) {
    assert_eq!(pk.len(), EKI_HYBRID_PK_LEN);
    let mut ct = OutBuf::new(false, EKI_HYBRID_CT_LEN);
    let mut ss = OutBuf::new(false, EKI_HYBRID_SS_LEN);
    // SAFETY: `pk` is a live 1216-byte buffer; `ct` and `ss` are distinct writable allocations
    // of exactly 1120 and 32 bytes.
    let status = unsafe { eki_hybrid_kem_encap(pk.as_ptr(), ct.ptr(), ss.ptr()) } as i32;
    let mut call = Call::new("eki_hybrid_kem_encap", status);
    call.outputs.extend([ct.seen(), ss.seen()]);
    (finish(call), ct, ss)
}

fn decap(sk: &[u8], ct: &[u8]) -> (i32, OutBuf) {
    assert_eq!((sk.len(), ct.len()), (EKI_HYBRID_SK_LEN, EKI_HYBRID_CT_LEN));
    let mut ss = OutBuf::new(false, EKI_HYBRID_SS_LEN);
    // SAFETY: `sk` and `ct` are live buffers of exactly 96 and 1120 bytes; `ss` is a distinct
    // writable allocation of exactly 32 bytes.
    let status = unsafe { eki_hybrid_kem_decap(sk.as_ptr(), ct.as_ptr(), ss.ptr()) } as i32;
    let mut call = Call::new("eki_hybrid_kem_decap", status);
    call.outputs.push(ss.seen());
    (finish(call), ss)
}

/// `bytes` XORed with `mask` from the first byte, in an exact allocation; and whether any byte
/// changed.
fn masked(bytes: &[u8], mask: &[u8]) -> (Vec<u8>, bool) {
    let mut out = exact(bytes, bytes.len(), 0);
    let mut changed = false;
    for (byte, m) in out.iter_mut().zip(mask) {
        *byte ^= m;
        changed |= *m != 0;
    }
    (out, changed)
}

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    match r.u8() % 3 {
        0 => {
            let pk_mask = r.bytes();
            let ct_mask = r.bytes();
            let (status, pk, sk) = keygen();
            if status != OK {
                return;
            }
            let (pk2, pk_changed) = masked(pk.bytes(), &pk_mask);
            let (status, ct, ss) = encap(&pk2);
            if !pk_changed {
                assert_eq!(status, OK, "encapsulation to a fresh public key failed");
            }
            if status != OK {
                return;
            }
            let (ct2, ct_changed) = masked(ct.bytes(), &ct_mask);
            let x25519_changed = ct_mask.iter().take(X25519_LEN).any(|&m| m != 0);
            let (status, ss2) = decap(sk.bytes(), &ct2);
            if !x25519_changed {
                assert_eq!(status, OK, "decapsulation failed");
            }
            if status != OK {
                return;
            }
            if pk_changed || ct_changed {
                assert_ne!(
                    ss2.bytes(),
                    ss.bytes(),
                    "a modified exchange gave the same secret"
                );
            } else {
                assert_eq!(
                    ss2.bytes(),
                    ss.bytes(),
                    "decap(encap(pk)) gave another secret"
                );
            }
        }
        1 => {
            let sk = exact(&r.bytes(), EKI_HYBRID_SK_LEN, 0);
            let ct = exact(&r.bytes(), EKI_HYBRID_CT_LEN, 0);
            decap(&sk, &ct);
        }
        _ => {
            let pk = exact(&r.bytes(), EKI_HYBRID_PK_LEN, 0);
            encap(&pk);
        }
    }
});
