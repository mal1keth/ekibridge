//! Key lifecycle and dual control of destroy on the software store, through the C ABI.
//!
//! Rows: plan-L12 section 3 (state table), section 4 (`eki_ks_open_v2` field rows that need no
//! audit log), section 6 (dual control) and the matching rows of section 7. The same scenarios
//! run on the PKCS#11 store in `ffi_lifecycle_pkcs11.rs`.

mod common;

use common::lifecycle::{self, Approvers};
use common::{Store, config_v2, ks, software_config};
use ekicore_abi::eki_status::{EKI_ERR_APPROVAL_REQUIRED, EKI_OK};
use ekicore_abi::{EKI_KEY_HMAC_SHA256, EKI_KEY_STATE_ACTIVE};

/// A software store opened with `eki_ks_open_v2` and approvers 0, 1 and 2.
fn dual_store(approvers: &Approvers) -> Store {
    let keys = approvers.bytes(3);
    Store::open_v2(&config_v2(&software_config(), None, Some(&keys), 3))
}

#[test]
fn state_table_rows() {
    lifecycle::state_table_rows(&Store::software());
}

#[test]
fn state_table_rows_on_an_open_v2_handle() {
    let store = Store::open_v2(&config_v2(&software_config(), None, None, 0));
    lifecycle::state_table_rows(&store);
}

#[test]
fn rotate_rows() {
    lifecycle::rotate_rows(&Store::software());
}

#[test]
fn revoke_rows() {
    lifecycle::revoke_rows(&Store::software());
}

#[test]
fn hmac_verify_rows() {
    lifecycle::hmac_verify_rows(&Store::software());
}

#[test]
fn get_info_v2_rows() {
    lifecycle::get_info_v2_rows(&Store::software());
}

#[test]
fn no_approver_rows() {
    lifecycle::no_approver_rows(&Store::software());
}

#[test]
fn no_approver_rows_on_an_open_v2_handle() {
    let store = Store::open_v2(&config_v2(&software_config(), None, None, 0));
    lifecycle::no_approver_rows(&store);
}

#[test]
fn dual_control_rows() {
    let approvers = Approvers::new(4);
    lifecycle::dual_control_rows(&dual_store(&approvers), &approvers);
}

#[test]
fn open_v2_rows() {
    lifecycle::open_v2_rows(&software_config(), &Approvers::new(9));
}

#[test]
fn software_config_ignores_malformed_pkcs11_fields() {
    let approvers = Approvers::new(2);
    let keys = approvers.bytes(2);
    let bad = [0xFF_u8, 0];
    let mut cfg = config_v2(&software_config(), None, Some(&keys), 2);
    cfg.pkcs11_module_path = bad.as_ptr().cast();
    cfg.pkcs11_token_label = bad.as_ptr().cast();
    cfg.pkcs11_user_pin = core::ptr::null();
    let store = Store::open_v2(&cfg);
    let id = store.generate(EKI_KEY_HMAC_SHA256, "eki-test");
    store.forget(&id);
    assert_eq!(
        ks::destroy(store.ptr(), Some(&id)),
        EKI_ERR_APPROVAL_REQUIRED
    );
}

#[test]
fn requests_vanish_when_the_handle_closes() {
    let approvers = Approvers::new(3);
    let store = dual_store(&approvers);
    let id = store.generate(EKI_KEY_HMAC_SHA256, "eki-test");
    store.forget(&id);
    let request = store.request(&id);
    assert_eq!(store.approve(&approvers, 0, &request, &id), (EKI_OK, 1));
    drop(store);
    // A software key lives in its handle, so only the request handling can be observed: a new
    // handle has no pending request with that value.
    let store = dual_store(&approvers);
    let other = store.generate(EKI_KEY_HMAC_SHA256, "eki-test other");
    store.forget(&other);
    let (status, remaining) = store.approve(&approvers, 1, &request, &id);
    assert_eq!(
        (status, remaining),
        (ekicore_abi::eki_status::EKI_ERR_KEY_NOT_FOUND, 0)
    );
    assert_eq!(store.state(&other), EKI_KEY_STATE_ACTIVE);
}

#[test]
fn approvals_on_one_handle_do_not_count_on_another() {
    let approvers = Approvers::new(3);
    let a = dual_store(&approvers);
    let b = dual_store(&approvers);
    let id = a.generate(EKI_KEY_HMAC_SHA256, "eki-test");
    a.forget(&id);
    let request = a.request(&id);
    assert_eq!(
        b.approve(&approvers, 0, &request, &id).0,
        ekicore_abi::eki_status::EKI_ERR_KEY_NOT_FOUND
    );
    assert_eq!(a.approve(&approvers, 0, &request, &id), (EKI_OK, 1));
    assert_eq!(a.approve(&approvers, 1, &request, &id), (EKI_OK, 0));
}
