//! The software key store through the C ABI (lesson L6).
//!
//! Rows: plan §4.4 `ks_open` and every store row; §4.2 sequences, labels, outputs on error,
//! last error and thread safety; §4.3 "Software". The scenarios shared with the PKCS#11 suite
//! are in `common/ks.rs`.

mod common;

use std::ffi::CString;

use common::ks::{self, unknown_id};
use common::{
    In, Store, assert_info, assert_open_fails, config, fixed_id, label, prefilled_info,
    software_config, try_open,
};
use ekicore_abi::{
    EKI_KEY_AES_256, EKI_KEY_ECDSA_P256, EKI_KEY_HMAC_SHA256, EKI_KS_PKCS11, EKI_KS_SOFTWARE,
    eki_ks, eki_ks_backend, eki_ks_config, eki_status,
};
use ekicore_rs::ffi::{eki_ks_close, eki_ks_open};
use proptest::prelude::*;

use eki_status::{EKI_ERR_INVALID_ARGUMENT, EKI_ERR_KEY_NOT_FOUND, EKI_ERR_NULL_POINTER, EKI_OK};

// --- open / close -------------------------------------------------------------------------

#[test]
fn open_and_close() {
    let opened = try_open(&software_config());
    assert_eq!(opened.status, EKI_OK);
    assert!(!opened.out_is_null);
    drop(opened);
    // SAFETY: closing NULL is explicitly allowed.
    unsafe { eki_ks_close(core::ptr::null_mut()) };
}

#[test]
fn open_ignores_the_pkcs11_fields() {
    let junk = CString::new("not a module").unwrap();
    let cfg = config(EKI_KS_SOFTWARE, Some(&junk), Some(&junk), Some(&junk));
    let store = Store::open(&cfg);
    let id = store.generate(EKI_KEY_HMAC_SHA256, "eki-test");
    assert_info(&store.info(&id), EKI_KEY_HMAC_SHA256, "eki-test");
}

#[test]
fn open_unknown_backend_is_invalid() {
    for backend in [0, 3, 99, -1, i32::MIN, i32::MAX] {
        assert_open_fails(
            &config(eki_ks_backend(backend), None, None, None),
            EKI_ERR_INVALID_ARGUMENT,
        );
    }
}

#[test]
// The expected NULL_POINTER needs the PKCS#11 configuration-field checks of `eki_ks_open`, which
// come with the PKCS#11 backend. Until then `eki_ks_open` answers UNSUPPORTED for EKI_KS_PKCS11
// in every build, which this test expects only without the `pkcs11` feature, so it runs there.
#[cfg_attr(feature = "pkcs11", ignore = "lesson L7")]
fn open_pkcs11_with_null_module_path() {
    // NULL config field → NULL_POINTER, unless PKCS#11 is not compiled in, in which case the
    // selector check (step 2) answers first with UNSUPPORTED.
    let token = label("ekibridge");
    let pin = label("1234");
    let expected = if cfg!(feature = "pkcs11") {
        EKI_ERR_NULL_POINTER
    } else {
        eki_status::EKI_ERR_UNSUPPORTED
    };
    assert_open_fails(
        &config(EKI_KS_PKCS11, None, Some(&token), Some(&pin)),
        expected,
    );
}

#[test]
fn open_null_pointers() {
    let mut handle: *mut eki_ks = core::ptr::dangling_mut();
    // SAFETY: `config` NULL is the case under test; `handle` is a live local.
    let status = unsafe { eki_ks_open(core::ptr::null(), &mut handle) };
    assert_eq!(status, EKI_ERR_NULL_POINTER, "config NULL");
    assert!(handle.is_null(), "*out is NULL on failure");

    let cfg = software_config();
    // SAFETY: `cfg` is a live local; `out` NULL is the case under test.
    let status = unsafe { eki_ks_open(&cfg, core::ptr::null_mut()) };
    assert_eq!(status, EKI_ERR_NULL_POINTER, "out NULL");

    let bad: eki_ks_config = config(eki_ks_backend(99), None, None, None);
    // SAFETY: `bad` is a live local; `out` NULL is the case under test.
    let status = unsafe { eki_ks_open(&bad, core::ptr::null_mut()) };
    assert_eq!(status, EKI_ERR_NULL_POINTER, "out NULL before backend 99");
}

#[test]
fn stores_are_independent() {
    let a = Store::software();
    let b = Store::software();
    let id = a.generate(EKI_KEY_HMAC_SHA256, "eki-test");
    let mut info = prefilled_info();
    assert_eq!(
        ks::get_info(b.ptr(), Some(&id), Some(&mut info)),
        EKI_ERR_KEY_NOT_FOUND
    );
    common::assert_info_zero(&info);
}

#[test]
fn keys_are_gone_after_close_and_reopen() {
    let id = {
        let store = Store::software();
        let id = store.generate(EKI_KEY_AES_256, "eki-test");
        store.forget(&id);
        id
    };
    let store = Store::software();
    let mut info = prefilled_info();
    assert_eq!(
        ks::get_info(store.ptr(), Some(&id), Some(&mut info)),
        EKI_ERR_KEY_NOT_FOUND
    );
}

// --- shared scenarios ---------------------------------------------------------------------

#[test]
fn lifecycle() {
    ks::lifecycle(&Store::software());
}

#[test]
fn wrap_unwrap_round_trip() {
    ks::wrap_unwrap_round_trip(&Store::software());
}

#[test]
fn generate_rows() {
    ks::generate_rows(&Store::software());
}

#[test]
fn generate_null_rows() {
    ks::generate_null_rows(&Store::software());
}

#[test]
fn lookup_rows() {
    ks::lookup_rows(&Store::software());
}

#[test]
fn lookup_null_rows() {
    ks::lookup_null_rows(&Store::software());
}

#[test]
fn wrap_rows() {
    ks::wrap_rows(&Store::software());
}

#[test]
fn unwrap_rows() {
    ks::unwrap_rows(&Store::software());
}

#[test]
fn last_error_rows() {
    ks::last_error_rows(&Store::software());
}

// --- software-only ------------------------------------------------------------------------

#[test]
fn label_bounded_scan() {
    // A 64-byte label is the maximum; its NUL is byte 65, the last one the library may read.
    let store = Store::software();
    let text = String::from_utf8(common::label_of_len(64).into_bytes()).unwrap();
    let id = store.generate(EKI_KEY_ECDSA_P256, &text);
    let info = store.info(&id);
    assert_info(&info, EKI_KEY_ECDSA_P256, &text);
    assert_eq!(info.label[64], 0, "label is NUL-terminated at byte 64");

    // 65 non-NUL bytes in an allocation of exactly 65 bytes: rejected without over-reading.
    let unterminated = common::unterminated_label();
    let mut id = common::prefilled_id();
    let status = ks::generate(
        store.ptr(),
        EKI_KEY_AES_256,
        unterminated.as_ptr().cast(),
        Some(&mut id),
    );
    assert_eq!(status, EKI_ERR_INVALID_ARGUMENT);
    common::assert_zero(&id.bytes);
}

/// A store handle shared by reference across threads.
struct Shared(*mut eki_ks);

// SAFETY: §4.2 "Thread safety": a handle serialises all operations with an internal lock and
// may be shared across threads; the test closes it only after every thread has joined.
unsafe impl Sync for Shared {}

#[test]
fn one_handle_shared_by_threads() {
    let store = Store::software();
    let mac = store.generate(EKI_KEY_HMAC_SHA256, "eki-test shared");
    let expected = store.hmac(&mac, b"message");
    let shared = Shared(store.ptr());
    std::thread::scope(|scope| {
        for t in 0..8_u8 {
            let shared = &shared;
            scope.spawn(move || {
                for i in 0..50_u8 {
                    let mut out = [0_u8; 32];
                    let status =
                        ks::hmac(shared.0, Some(&mac), In::Bytes(b"message"), Some(&mut out));
                    assert_eq!(status, EKI_OK);
                    assert_eq!(out, expected);
                    // Interleave generate/destroy so the lock is contended by writers too.
                    let mut id = common::prefilled_id();
                    let text = label(&format!("eki-test t{t} i{i}"));
                    assert_eq!(
                        ks::generate(shared.0, EKI_KEY_AES_256, text.as_ptr(), Some(&mut id)),
                        EKI_OK
                    );
                    assert_eq!(ks::destroy(shared.0, Some(&id)), EKI_OK);
                }
            });
        }
    });
    assert_eq!(store.hmac(&mac, b"message"), expected);
}

fn printable_label() -> impl Strategy<Value = String> {
    proptest::collection::vec(0x20_u8..=0x7e, 1..=64)
        .prop_map(|bytes| String::from_utf8(bytes).expect("printable ASCII"))
}

proptest! {
    // No regression files: these run against stubs until the lesson lands.
    #![proptest_config(ProptestConfig {
        cases: 32,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn wrap_unwrap_preserves_the_key(
        text in printable_label(),
        id_bytes in proptest::array::uniform16(any::<u8>()),
        msg in proptest::collection::vec(any::<u8>(), 0..=256),
        as_aes in any::<bool>(),
    ) {
        let store = Store::software();
        let kek = store.generate(EKI_KEY_AES_256, "eki-test kek");
        let mac = store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac");
        let id = ekicore_abi::eki_key_id { bytes: id_bytes };
        prop_assume!(id != kek && id != mac && id != unknown_id() && id != fixed_id(0));

        let blob = store.wrap(&kek, &mac);
        // The metadata is unauthenticated (§2): the same blob may be unwrapped as either
        // secret-key algorithm.
        let alg = if as_aes { EKI_KEY_AES_256 } else { EKI_KEY_HMAC_SHA256 };
        store.unwrap(&kek, &blob, alg, &text, &id);
        assert_info(&store.info(&id), alg, &text);
        if !as_aes {
            prop_assert_eq!(store.hmac(&id, &msg), store.hmac(&mac, &msg));
        }
        // Re-wrapping the copy (of either type) gives the same blob: same key value.
        prop_assert_eq!(store.wrap(&kek, &id), blob);
    }
}
