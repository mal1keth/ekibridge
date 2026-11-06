//! Every stateless function of the ABI with arbitrary buffers and a NULL flag per pointer.
//!
//! Properties, from the contract (`docs/ffi-contract.md`):
//! * the status is a defined value (0..=12);
//! * `EKI_ERR_NULL_POINTER` is only returned when some pointer argument was NULL;
//! * on every failure, each non-NULL output whose length is in its valid range is all zero
//!   (outputs are pre-filled with 0xA5, so an untouched output is caught).
//!
//! `EKI_ERR_UNSUPPORTED` is exempt from the zero-fill check for now: the stubs return it
//! without touching their outputs. Lesson L8 removes the exemption once every module is real.

#![no_main]

use ekicore_abi::eki_aead_alg;
use ekicore_rs::ffi::{
    eki_aead_open, eki_aead_seal, eki_ecdsa_p256_verify, eki_hkdf_sha256, eki_hmac_sha256,
    eki_hmac_sha256_verify,
};
use ekicore_rs_fuzz::{
    EKI_ERR_NULL_POINTER, EKI_ERR_UNSUPPORTED, EKI_OK, StatelessCall, assert_status_in_range,
    okm_len_in_range,
};
use libfuzzer_sys::fuzz_target;

/// An output buffer pre-filled with 0xA5, passed as NULL when `null` is set.
struct Out {
    null: bool,
    /// Whether the contract requires zero-fill on error for this length.
    checked: bool,
    bytes: Vec<u8>,
}

impl Out {
    fn new(null: bool, len: usize, checked: bool) -> Self {
        Self {
            null,
            checked,
            bytes: vec![0xA5; len],
        }
    }

    fn ptr(&mut self) -> *mut u8 {
        if self.null {
            core::ptr::null_mut()
        } else {
            self.bytes.as_mut_ptr()
        }
    }
}

/// Runs one call. Returns the status, whether any pointer argument was NULL, and the outputs.
fn run(call: &StatelessCall) -> (&'static str, i32, bool, Vec<Out>) {
    match call {
        StatelessCall::Hmac { key, msg, out_null } => {
            let mut out = Out::new(*out_null, 32, true);
            // SAFETY: input pointers are NULL or point into live Vecs of the stated length;
            // `out` is NULL or a distinct 32-byte allocation, as `out` requires.
            let status =
                unsafe { eki_hmac_sha256(key.ptr(), key.len(), msg.ptr(), msg.len(), out.ptr()) }
                    as i32;
            (
                "eki_hmac_sha256",
                status,
                key.null || msg.null || *out_null,
                vec![out],
            )
        }
        StatelessCall::HmacVerify { key, msg, tag } => {
            // SAFETY: input pointers are NULL or point into live Vecs of the stated length.
            let status = unsafe {
                eki_hmac_sha256_verify(
                    key.ptr(),
                    key.len(),
                    msg.ptr(),
                    msg.len(),
                    tag.ptr(),
                    tag.len(),
                )
            } as i32;
            (
                "eki_hmac_sha256_verify",
                status,
                key.null || msg.null || tag.null,
                vec![],
            )
        }
        StatelessCall::Hkdf {
            ikm,
            salt,
            info,
            okm_null,
            okm_len,
        } => {
            let mut okm = Out::new(*okm_null, *okm_len, okm_len_in_range(*okm_len));
            // SAFETY: input pointers are NULL or point into live Vecs of the stated length;
            // `okm` is NULL or a distinct allocation of exactly `okm_len` bytes.
            let status = unsafe {
                eki_hkdf_sha256(
                    ikm.ptr(),
                    ikm.len(),
                    salt.ptr(),
                    salt.len(),
                    info.ptr(),
                    info.len(),
                    okm.ptr(),
                    *okm_len,
                )
            } as i32;
            let any_null = ikm.null || salt.null || info.null || *okm_null;
            ("eki_hkdf_sha256", status, any_null, vec![okm])
        }
        StatelessCall::AeadSeal {
            alg,
            key,
            nonce,
            aad,
            pt,
            ct_out_null,
            tag_out_null,
        } => {
            // pt_len is far below EKI_AEAD_MAX_LEN, so ct_out is always in range.
            let mut ct = Out::new(*ct_out_null, pt.len(), true);
            let mut tag = Out::new(*tag_out_null, 16, true);
            // SAFETY: input pointers are NULL or point into live Vecs of the stated length;
            // `ct_out` is NULL or a distinct allocation of exactly `pt_len` bytes, `tag_out`
            // NULL or a distinct 16-byte allocation.
            let status = unsafe {
                eki_aead_seal(
                    eki_aead_alg(*alg),
                    key.ptr(),
                    key.len(),
                    nonce.ptr(),
                    nonce.len(),
                    aad.ptr(),
                    aad.len(),
                    pt.ptr(),
                    pt.len(),
                    ct.ptr(),
                    tag.ptr(),
                )
            } as i32;
            let any_null =
                key.null || nonce.null || aad.null || pt.null || *ct_out_null || *tag_out_null;
            ("eki_aead_seal", status, any_null, vec![ct, tag])
        }
        StatelessCall::AeadOpen {
            alg,
            key,
            nonce,
            aad,
            ct,
            tag_null,
            tag,
            pt_out_null,
        } => {
            let mut pt = Out::new(*pt_out_null, ct.len(), true);
            let tag_ptr = if *tag_null {
                core::ptr::null()
            } else {
                tag.as_ptr()
            };
            // SAFETY: input pointers are NULL or point into live Vecs of the stated length;
            // `tag` is NULL or a live 16-byte array; `pt_out` is NULL or a distinct allocation
            // of exactly `ct_len` bytes.
            let status = unsafe {
                eki_aead_open(
                    eki_aead_alg(*alg),
                    key.ptr(),
                    key.len(),
                    nonce.ptr(),
                    nonce.len(),
                    aad.ptr(),
                    aad.len(),
                    ct.ptr(),
                    ct.len(),
                    tag_ptr,
                    pt.ptr(),
                )
            } as i32;
            let any_null =
                key.null || nonce.null || aad.null || ct.null || *tag_null || *pt_out_null;
            ("eki_aead_open", status, any_null, vec![pt])
        }
        StatelessCall::EcdsaVerify {
            public_key_null,
            public_key,
            msg,
            sig_null,
            sig,
        } => {
            let pk_ptr = if *public_key_null {
                core::ptr::null()
            } else {
                public_key.as_ptr()
            };
            let sig_ptr = if *sig_null {
                core::ptr::null()
            } else {
                sig.as_ptr()
            };
            // SAFETY: `public_key` and `sig` are NULL or live arrays of 65 and 64 bytes; `msg`
            // is NULL or points into a live Vec of the stated length.
            let status =
                unsafe { eki_ecdsa_p256_verify(pk_ptr, msg.ptr(), msg.len(), sig_ptr) } as i32;
            let any_null = *public_key_null || msg.null || *sig_null;
            ("eki_ecdsa_p256_verify", status, any_null, vec![])
        }
    }
}

fuzz_target!(|call: StatelessCall| {
    let (function, status, any_null, outputs) = run(&call);
    assert_status_in_range(function, status);
    if status == EKI_ERR_NULL_POINTER {
        assert!(
            any_null,
            "{function} returned EKI_ERR_NULL_POINTER with no NULL argument"
        );
    }
    // TODO(L8): drop the EKI_ERR_UNSUPPORTED exemption once no function is a stub.
    if status != EKI_OK && status != EKI_ERR_UNSUPPORTED {
        for (index, out) in outputs.iter().enumerate() {
            if out.null || !out.checked {
                continue;
            }
            assert!(
                out.bytes.iter().all(|&b| b == 0),
                "{function} returned {status} but output #{index} is not zero-filled"
            );
        }
    }
});
