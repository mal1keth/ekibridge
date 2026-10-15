//! `eki_ks_unwrap` in a software key store on arbitrary blobs, algorithms, labels and ids.
//!
//! Each run opens a fresh store and generates an AES-256 key to unwrap under. The blob is either
//! taken from the input as it is or, when the input asks for it, a genuine wrap of a freshly
//! generated HMAC key with input bytes XORed over it, so the success path is reachable too.
//!
//! Properties: every status is a defined value, and after a successful unwrap the new key is
//! usable under the id it was given (`eki_ks_get_info` reports the requested algorithm and label,
//! and an HMAC key computes a MAC).

#![no_main]

use core::ffi::c_char;

use ekicore_abi::{
    EKI_KEY_AES_256, EKI_KEY_HMAC_SHA256, EKI_KS_SOFTWARE, eki_key_alg, eki_key_id, eki_key_info,
    eki_ks, eki_ks_config,
};
use ekicore_rs::ffi::{
    eki_ks_close, eki_ks_generate, eki_ks_get_info, eki_ks_hmac_sha256, eki_ks_open, eki_ks_unwrap,
    eki_ks_wrap,
};
use ekicore_rs_fuzz::{EKI_OK, UnwrapInput, assert_status_in_range, c_label};
use libfuzzer_sys::fuzz_target;

/// Closes the store when dropped, so a failed assertion still releases it.
struct Store(*mut eki_ks);

impl Drop for Store {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from a successful `eki_ks_open` and is closed exactly once,
        // here, with no other call on it in flight.
        unsafe { eki_ks_close(self.0) };
    }
}

/// Generates a key of `alg` in `store` and returns its id.
fn generate(store: &Store, alg: eki_key_alg, label: &core::ffi::CStr) -> eki_key_id {
    let mut id = eki_key_id { bytes: [0xA5; 16] };
    // SAFETY: `store.0` is an open handle; `label` is a NUL-terminated string that outlives
    // the call; `id` is a live, writable `eki_key_id`.
    let status = unsafe { eki_ks_generate(store.0, alg, label.as_ptr(), &mut id) } as i32;
    assert_eq!(
        status, EKI_OK,
        "eki_ks_generate failed in an open software store"
    );
    id
}

fuzz_target!(|input: UnwrapInput| {
    let config = eki_ks_config {
        backend: EKI_KS_SOFTWARE,
        pkcs11_module_path: core::ptr::null(),
        pkcs11_token_label: core::ptr::null(),
        pkcs11_user_pin: core::ptr::null(),
    };
    let mut handle: *mut eki_ks = core::ptr::null_mut();
    // SAFETY: `config` is a live, initialised struct (the software backend ignores the NULL
    // PKCS#11 fields); `handle` is a live, writable pointer slot.
    let status = unsafe { eki_ks_open(&config, &mut handle) } as i32;
    assert_status_in_range("eki_ks_open", status);
    if status != EKI_OK {
        // The key store is still a stub (EKI_ERR_UNSUPPORTED): nothing more to exercise.
        assert!(
            handle.is_null(),
            "eki_ks_open failed but left a handle in *out"
        );
        return;
    }
    assert!(
        !handle.is_null(),
        "eki_ks_open returned EKI_OK with a NULL handle"
    );
    let store = Store(handle);

    let kek = generate(&store, EKI_KEY_AES_256, c"fuzz-kek");

    let blob = if input.from_wrap {
        let key = generate(&store, EKI_KEY_HMAC_SHA256, c"fuzz-wrapped");
        let mut wrapped = [0xA5_u8; 40];
        // SAFETY: `store.0` is open; both ids are live structs; `wrapped` is a writable
        // 40-byte buffer as `out` requires.
        let status = unsafe { eki_ks_wrap(store.0, &kek, &key, wrapped.as_mut_ptr()) } as i32;
        assert_eq!(
            status, EKI_OK,
            "wrapping an HMAC key under an AES key failed"
        );
        for (byte, mask) in wrapped.iter_mut().zip(input.blob.iter()) {
            *byte ^= mask;
        }
        wrapped.to_vec()
    } else {
        input.blob.clone()
    };

    let alg = eki_key_alg(input.alg);
    let label = c_label(&input.label);
    let id = eki_key_id { bytes: input.id };
    // SAFETY: `store.0` is open; `kek` and `id` are live structs; `blob` points into a live Vec
    // of `blob.len()` bytes; `label` is NUL-terminated (the library reads at most 65 bytes and
    // `label` holds at least one byte, the NUL, so every byte it may read is in bounds).
    let status = unsafe {
        eki_ks_unwrap(
            store.0,
            &kek,
            blob.as_ptr(),
            blob.len(),
            alg,
            label.as_ptr().cast::<c_char>(),
            &id,
        )
    } as i32;
    assert_status_in_range("eki_ks_unwrap", status);
    if status != EKI_OK {
        return;
    }

    let mut info = eki_key_info {
        alg: eki_key_alg(-1),
        label: [0x55; 65],
    };
    // SAFETY: `store.0` is open; `id` is a live struct; `info` is a live, writable struct.
    let status = unsafe { eki_ks_get_info(store.0, &id, &mut info) } as i32;
    assert_eq!(
        status, EKI_OK,
        "eki_ks_get_info failed for a key that was just unwrapped"
    );
    assert_eq!(info.alg, alg, "unwrapped key reports a different algorithm");
    let stored_label: Vec<u8> = info.label.iter().map(|&c| c as u8).collect();
    let nul = label.iter().position(|&b| b == 0).unwrap_or(label.len());
    assert_eq!(
        &stored_label[..nul],
        &label[..nul],
        "unwrapped key reports a different label"
    );
    assert!(
        stored_label[nul..].iter().all(|&b| b == 0),
        "label is not NUL-padded"
    );

    if alg == EKI_KEY_HMAC_SHA256 {
        let mut mac = [0xA5_u8; 32];
        let msg = b"ekibridge";
        // SAFETY: `store.0` is open; `id` is a live struct; `msg` is a live 9-byte array;
        // `mac` is a writable 32-byte buffer as `out` requires.
        let status =
            unsafe { eki_ks_hmac_sha256(store.0, &id, msg.as_ptr(), msg.len(), mac.as_mut_ptr()) }
                as i32;
        assert_eq!(
            status, EKI_OK,
            "eki_ks_hmac_sha256 failed for an unwrapped HMAC key"
        );
    }
});
