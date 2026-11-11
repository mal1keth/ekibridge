//! Metadata functions: `eki_abi_version`, `eki_version`, `eki_status_name` (docs/ffi-contract.md,
//! "Metadata" and "Status codes"). These are implemented already, so nothing is ignored.

use core::ffi::{CStr, c_char};

use ekicore_abi::{EKI_ABI_VERSION, eki_status};
use ekicore_rs::ffi::{eki_abi_version, eki_status_name, eki_version};

fn read(ptr: *const c_char) -> String {
    assert!(!ptr.is_null(), "the library returned NULL");
    // SAFETY: `ptr` is non-NULL and points to a static NUL-terminated string owned by the library.
    let text = unsafe { CStr::from_ptr(ptr) };
    text.to_str().expect("string is UTF-8").to_owned()
}

fn status_name(value: i32) -> String {
    // SAFETY: `eki_status_name` takes a plain integer and has no preconditions.
    read(unsafe { eki_status_name(value) })
}

#[test]
fn abi_version_is_two() {
    // SAFETY: no arguments, no preconditions.
    let version = unsafe { eki_abi_version() };
    assert_eq!(version, 2);
    assert_eq!(version, EKI_ABI_VERSION);
}

#[test]
fn version_is_impl_space_crate_version() {
    // SAFETY: no arguments, no preconditions.
    let text = read(unsafe { eki_version() });
    assert_eq!(text, concat!("ekicore-rs ", env!("CARGO_PKG_VERSION")));
}

#[test]
fn version_pointer_is_static() {
    // SAFETY: no arguments, no preconditions.
    let (a, b) = unsafe { (eki_version(), eki_version()) };
    assert_eq!(
        a, b,
        "eki_version returns the same static string every time"
    );
}

#[test]
fn status_names_of_every_known_value() {
    let expected = [
        (eki_status::EKI_OK, "EKI_OK"),
        (eki_status::EKI_ERR_NULL_POINTER, "EKI_ERR_NULL_POINTER"),
        (
            eki_status::EKI_ERR_INVALID_ARGUMENT,
            "EKI_ERR_INVALID_ARGUMENT",
        ),
        (
            eki_status::EKI_ERR_BUFFER_TOO_SMALL,
            "EKI_ERR_BUFFER_TOO_SMALL",
        ),
        (eki_status::EKI_ERR_UNSUPPORTED, "EKI_ERR_UNSUPPORTED"),
        (eki_status::EKI_ERR_AUTH_FAILED, "EKI_ERR_AUTH_FAILED"),
        (eki_status::EKI_ERR_KEY_NOT_FOUND, "EKI_ERR_KEY_NOT_FOUND"),
        (eki_status::EKI_ERR_KEY_EXISTS, "EKI_ERR_KEY_EXISTS"),
        (eki_status::EKI_ERR_WRONG_KEY_TYPE, "EKI_ERR_WRONG_KEY_TYPE"),
        (eki_status::EKI_ERR_BACKEND, "EKI_ERR_BACKEND"),
        (eki_status::EKI_ERR_INTERNAL, "EKI_ERR_INTERNAL"),
        (eki_status::EKI_ERR_KEY_STATE, "EKI_ERR_KEY_STATE"),
        (
            eki_status::EKI_ERR_APPROVAL_REQUIRED,
            "EKI_ERR_APPROVAL_REQUIRED",
        ),
    ];
    for (index, (status, name)) in expected.into_iter().enumerate() {
        let value = status as i32;
        assert_eq!(
            value,
            i32::try_from(index).unwrap(),
            "values are 0..=12 in order"
        );
        assert_eq!(status_name(value), name, "status {value}");
    }
}

#[test]
fn status_names_of_unknown_values() {
    for value in [-1, i32::MIN, i32::MAX, 13, 99] {
        assert_eq!(status_name(value), "EKI_STATUS_UNKNOWN", "status {value}");
    }
}
