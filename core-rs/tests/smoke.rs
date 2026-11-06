//! Smoke test for the metadata functions of the FFI layer.

use std::ffi::CStr;

use ekicore_rs::ffi::{eki_abi_version, eki_status_name, eki_version};

/// Reads a NUL-terminated C string returned by the library.
fn read(ptr: *const std::ffi::c_char) -> String {
    assert!(!ptr.is_null(), "the library returned NULL");
    // SAFETY: `ptr` is non-NULL and points to a static NUL-terminated string owned by the library.
    let text = unsafe { CStr::from_ptr(ptr) };
    text.to_str().expect("name is UTF-8").to_owned()
}

#[test]
fn abi_version_is_two() {
    // SAFETY: `eki_abi_version` takes no arguments and has no preconditions.
    let version = unsafe { eki_abi_version() };
    assert_eq!(version, 2);
    assert_eq!(version, ekicore_abi::EKI_ABI_VERSION);
}

#[test]
fn version_names_the_implementation() {
    // SAFETY: `eki_version` takes no arguments and has no preconditions.
    let text = read(unsafe { eki_version() });
    assert!(
        text.starts_with("ekicore-rs 0.1.0"),
        "unexpected version string: {text}"
    );
}

#[test]
fn status_names_match_the_header() {
    for (value, name) in [
        (0, "EKI_OK"),
        (5, "EKI_ERR_AUTH_FAILED"),
        (10, "EKI_ERR_INTERNAL"),
        (11, "EKI_ERR_KEY_STATE"),
        (12, "EKI_ERR_APPROVAL_REQUIRED"),
        (13, "EKI_STATUS_UNKNOWN"),
        (-1, "EKI_STATUS_UNKNOWN"),
    ] {
        // SAFETY: `eki_status_name` takes a plain integer and has no preconditions.
        let got = read(unsafe { eki_status_name(value) });
        assert_eq!(got, name, "status {value}");
    }
}
