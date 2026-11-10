//! Helpers shared by the FFI integration tests.
//!
//! The tests call the `extern "C"` functions of `ekicore_rs::ffi` exactly as a C caller would:
//! raw pointers, explicit lengths, outputs pre-filled with `0xA5` so that "zero-filled on error"
//! and "fully written on success" are both observable.

// Each test binary uses a different subset of these helpers.
#![allow(dead_code)]

use core::ffi::c_char;
use std::cell::RefCell;
use std::ffi::CString;

use ekicore_abi::{
    EKI_KS_SOFTWARE, eki_key_alg, eki_key_id, eki_key_info, eki_ks, eki_ks_backend, eki_ks_config,
    eki_ks_config_v2, eki_status,
};
use ekicore_rs::ffi::{eki_ks_close, eki_ks_destroy, eki_ks_generate, eki_ks_open, eki_ks_open_v2};

/// Byte every output buffer is pre-filled with before a call.
pub const FILL: u8 = 0xA5;

/// Decodes a hex string; ASCII whitespace inside the string is ignored.
pub fn hex(text: &str) -> Vec<u8> {
    let compact: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    hex::decode(compact).expect("test vector is valid hex")
}

/// Decodes a hex string into a fixed-size array.
pub fn hex_array<const N: usize>(text: &str) -> [u8; N] {
    hex(text)
        .try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("expected {N} bytes, got {}", v.len()))
}

/// An output buffer of `n` bytes, every byte `0xA5`.
pub fn prefill(n: usize) -> Vec<u8> {
    vec![FILL; n]
}

/// Asserts that every byte of `buf` is zero (the "outputs on error" rule).
#[track_caller]
pub fn assert_zero(buf: &[u8]) {
    if let Some(pos) = buf.iter().position(|&b| b != 0) {
        panic!(
            "output not zero-filled: byte {pos} of {} is {:#04x}",
            buf.len(),
            buf[pos]
        );
    }
}

/// Asserts that every byte of `buf` still holds the pre-fill value (output left untouched).
#[track_caller]
pub fn assert_untouched(buf: &[u8]) {
    if let Some(pos) = buf.iter().position(|&b| b != FILL) {
        panic!(
            "output was written: byte {pos} of {} is {:#04x}",
            buf.len(),
            buf[pos]
        );
    }
}

/// A `(pointer, length)` input argument.
///
/// `Bytes` passes a live slice (an empty slice gives a dangling but non-NULL pointer, which the
/// library must accept for length 0); `Null(n)` passes a NULL pointer with length `n`, which is
/// how the `(NULL, 0)` and `(NULL, n > 0)` rows of the error matrix are expressed.
#[derive(Clone, Copy, Debug)]
pub enum In<'a> {
    /// A real buffer.
    Bytes(&'a [u8]),
    /// NULL with the given length.
    Null(usize),
}

impl In<'_> {
    /// The pointer argument.
    pub fn ptr(self) -> *const u8 {
        match self {
            In::Bytes(b) => b.as_ptr(),
            In::Null(_) => core::ptr::null(),
        }
    }

    /// The length argument.
    pub fn len(self) -> usize {
        match self {
            In::Bytes(b) => b.len(),
            In::Null(n) => n,
        }
    }
}

/// A `(pointer, length)` output argument, the mutable twin of [`In`].
#[derive(Debug)]
pub enum Out<'a> {
    /// A real buffer.
    Bytes(&'a mut [u8]),
    /// NULL with the given length.
    Null(usize),
}

impl Out<'_> {
    /// The pointer argument.
    pub fn ptr(&mut self) -> *mut u8 {
        match self {
            Out::Bytes(b) => b.as_mut_ptr(),
            Out::Null(_) => core::ptr::null_mut(),
        }
    }

    /// The length argument.
    pub fn len(&self) -> usize {
        match self {
            Out::Bytes(b) => b.len(),
            Out::Null(n) => *n,
        }
    }
}

/// A NUL-terminated label.
pub fn label(text: &str) -> CString {
    CString::new(text).expect("label has no interior NUL")
}

/// A label of exactly `n` printable bytes (`'a'`..`'z'` repeating) plus its NUL.
pub fn label_of_len(n: usize) -> CString {
    let bytes: Vec<u8> = (0..n).map(|i| b'a' + (i % 26) as u8).collect();
    CString::new(bytes).expect("label has no interior NUL")
}

/// A 65-byte buffer of printable bytes with no NUL anywhere, allocated to exactly 65 bytes.
///
/// The library reads at most 65 bytes of a label, so it must reject this with
/// `EKI_ERR_INVALID_ARGUMENT` without reading past the end. Under Miri or AddressSanitizer an
/// over-read of this exact-size allocation is reported.
pub fn unterminated_label() -> Box<[u8]> {
    vec![b'x'; 65].into_boxed_slice()
}

/// Reads the `label` field of an [`eki_key_info`] as bytes.
pub fn info_label_bytes(info: &eki_key_info) -> [u8; 65] {
    info.label.map(|c| c as u8)
}

/// An [`eki_key_info`] with every field set to the pre-fill pattern.
pub fn prefilled_info() -> eki_key_info {
    eki_key_info {
        alg: eki_key_alg(i32::from_ne_bytes([FILL; 4])),
        label: [FILL as c_char; 65],
    }
}

/// Asserts that a key info was zero-filled after an error (fields only; padding is unspecified).
#[track_caller]
pub fn assert_info_zero(info: &eki_key_info) {
    assert_eq!(info.alg, eki_key_alg(0), "info_out.alg not zeroed");
    assert_zero(&info_label_bytes(info));
}

/// Asserts that a key info names `alg` and `text`, NUL-padded through byte 64.
#[track_caller]
pub fn assert_info(info: &eki_key_info, alg: eki_key_alg, text: &str) {
    assert_eq!(info.alg, alg, "info_out.alg");
    let bytes = info_label_bytes(info);
    assert_eq!(&bytes[..text.len()], text.as_bytes(), "info_out.label");
    assert_zero(&bytes[text.len()..]);
}

/// A key id with every byte set to the pre-fill pattern.
pub fn prefilled_id() -> eki_key_id {
    eki_key_id { bytes: [FILL; 16] }
}

/// A key id chosen by the caller (for `eki_ks_unwrap`).
pub fn fixed_id(byte: u8) -> eki_key_id {
    eki_key_id { bytes: [byte; 16] }
}

/// A software store configuration (the PKCS#11 fields are NULL and ignored).
pub fn software_config() -> eki_ks_config {
    config(EKI_KS_SOFTWARE, None, None, None)
}

/// A store configuration; `None` strings become NULL pointers.
pub fn config(
    backend: eki_ks_backend,
    module: Option<&CString>,
    token: Option<&CString>,
    pin: Option<&CString>,
) -> eki_ks_config {
    let ptr = |s: Option<&CString>| s.map_or(core::ptr::null(), |s| s.as_ptr());
    eki_ks_config {
        backend,
        pkcs11_module_path: ptr(module),
        pkcs11_token_label: ptr(token),
        pkcs11_user_pin: ptr(pin),
    }
}

/// Outcome of an `eki_ks_open` call made by [`try_open`].
pub struct Opened {
    /// The returned status.
    pub status: eki_status,
    /// Whether `*out` was NULL after the call.
    pub out_is_null: bool,
    /// The store, when the call succeeded; it is closed on drop.
    pub store: Option<Store>,
}

/// Calls `eki_ks_open` with `*out` pre-set to a non-NULL sentinel. A handle returned with
/// `EKI_OK` is wrapped in a [`Store`] so it is closed even when the test then fails.
pub fn try_open(cfg: &eki_ks_config) -> Opened {
    let mut handle: *mut eki_ks = core::ptr::dangling_mut();
    // SAFETY: `cfg` and `handle` are live locals; the library copies the config strings and
    // writes only `*out`.
    let status = unsafe { eki_ks_open(cfg, &mut handle) };
    let out_is_null = handle.is_null();
    let store = (status == eki_status::EKI_OK && !out_is_null).then(|| Store {
        ks: handle,
        created: RefCell::new(Vec::new()),
    });
    Opened {
        status,
        out_is_null,
        store,
    }
}

/// A version 2 configuration: the fields of `base`, the audit log path (`None` for NULL) and
/// the approver keys (`None` for NULL) with `count`.
pub fn config_v2(
    base: &eki_ks_config,
    audit_log: Option<&CString>,
    approver_keys: Option<&[u8]>,
    count: usize,
) -> eki_ks_config_v2 {
    eki_ks_config_v2 {
        backend: base.backend,
        pkcs11_module_path: base.pkcs11_module_path,
        pkcs11_token_label: base.pkcs11_token_label,
        pkcs11_user_pin: base.pkcs11_user_pin,
        audit_log_path: audit_log.map_or(core::ptr::null(), |path| path.as_ptr()),
        approver_public_keys: approver_keys.map_or(core::ptr::null(), <[u8]>::as_ptr),
        approver_count: count,
    }
}

/// Calls `eki_ks_open_v2` as [`try_open`] calls `eki_ks_open`.
pub fn try_open_v2(cfg: &eki_ks_config_v2) -> Opened {
    let mut handle: *mut eki_ks = core::ptr::dangling_mut();
    // SAFETY: `cfg` and `handle` are live locals; the configuration's pointers are NULL or point
    // to live strings and key arrays of the sizes its counts give; the library writes only
    // `*out`.
    let status = unsafe { eki_ks_open_v2(cfg, &mut handle) };
    let out_is_null = handle.is_null();
    let store = (status == eki_status::EKI_OK && !out_is_null).then(|| Store {
        ks: handle,
        created: RefCell::new(Vec::new()),
    });
    Opened {
        status,
        out_is_null,
        store,
    }
}

/// Asserts that `eki_ks_open_v2` fails with `expected` and leaves `*out` NULL.
#[track_caller]
pub fn assert_open_v2_fails(cfg: &eki_ks_config_v2, expected: eki_status) {
    let opened = try_open_v2(cfg);
    assert_eq!(opened.status, expected, "eki_ks_open_v2");
    assert!(opened.out_is_null, "*out must be NULL on failure");
}

/// Asserts that `eki_ks_open` fails with `expected` and leaves `*out` NULL.
#[track_caller]
pub fn assert_open_fails(cfg: &eki_ks_config, expected: eki_status) {
    let opened = try_open(cfg);
    assert_eq!(opened.status, expected, "eki_ks_open");
    assert!(opened.out_is_null, "*out must be NULL on failure");
}

/// An open key store. Keys created through it are destroyed and the handle is closed on drop,
/// including when a test panics, so a PKCS#11 token is left as it was found.
pub struct Store {
    ks: *mut eki_ks,
    created: RefCell<Vec<eki_key_id>>,
}

impl Store {
    /// Opens a store and asserts success.
    #[track_caller]
    pub fn open(cfg: &eki_ks_config) -> Store {
        let opened = try_open(cfg);
        assert_eq!(opened.status, eki_status::EKI_OK, "eki_ks_open");
        opened
            .store
            .expect("eki_ks_open returned OK and a NULL handle")
    }

    /// Opens a store with `eki_ks_open_v2` and asserts success.
    #[track_caller]
    pub fn open_v2(cfg: &eki_ks_config_v2) -> Store {
        let opened = try_open_v2(cfg);
        assert_eq!(opened.status, eki_status::EKI_OK, "eki_ks_open_v2");
        opened
            .store
            .expect("eki_ks_open_v2 returned OK and a NULL handle")
    }

    /// Opens a software store and asserts success.
    #[track_caller]
    pub fn software() -> Store {
        Store::open(&software_config())
    }

    /// The raw handle.
    pub fn ptr(&self) -> *mut eki_ks {
        self.ks
    }

    /// Generates a key, asserts success, and remembers it for cleanup.
    #[track_caller]
    pub fn generate(&self, alg: eki_key_alg, text: &str) -> eki_key_id {
        let text = label(text);
        let mut id = prefilled_id();
        // SAFETY: `self.ks` is an open handle; `text` is NUL-terminated; `id` is a live local.
        let status = unsafe { eki_ks_generate(self.ks, alg, text.as_ptr(), &mut id) };
        assert_eq!(status, eki_status::EKI_OK, "eki_ks_generate");
        self.track(id);
        id
    }

    /// Remembers a key created another way (unwrap) for cleanup.
    pub fn track(&self, id: eki_key_id) {
        self.created.borrow_mut().push(id);
    }

    /// Forgets a key the test destroyed itself.
    pub fn forget(&self, id: &eki_key_id) {
        self.created.borrow_mut().retain(|k| k != id);
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        for id in self.created.borrow().iter() {
            // SAFETY: `self.ks` is an open handle and `id` a live key id; the status is ignored
            // because the key may already be gone.
            let _ = unsafe { eki_ks_destroy(self.ks, id) };
        }
        // SAFETY: `self.ks` came from a successful `eki_ks_open` and is closed exactly once.
        unsafe { eki_ks_close(self.ks) };
    }
}

/// Reads the last error message of a handle (NULL allowed) through a 512-byte buffer.
pub fn last_error(ks: *const eki_ks) -> String {
    let mut buf = [FILL as c_char; 512];
    // SAFETY: `buf` is a live local of `buf.len()` bytes; `ks` is NULL or an open handle.
    let n = unsafe { ekicore_rs::ffi::eki_ks_last_error_message(ks, buf.as_mut_ptr(), buf.len()) };
    let bytes: Vec<u8> = buf.iter().map(|&c| c as u8).collect();
    let end = bytes
        .iter()
        .position(|&b| b == 0)
        .expect("message is NUL-terminated");
    assert_eq!(
        n.min(buf.len() - 1),
        end,
        "returned length matches the written text"
    );
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

pub mod ks;
pub mod lifecycle;
