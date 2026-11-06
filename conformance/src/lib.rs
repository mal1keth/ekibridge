//! Conformance harness for the ekicore C ABI.
//!
//! The harness loads `libekicore` (C++) and `libekicore_rs` (Rust) side by side with
//! `libloading`, resolves every function of `include/ekicore.h` through each library handle, and
//! wraps them in typed methods. Both libraries export the same `eki_*` names; that is fine because
//! the libraries are opened with `RTLD_LOCAL` and every symbol is looked up through its own handle.
//!
//! Conventions the tests rely on:
//!
//! * Statuses are raw `i32` everywhere (see [`status`]). The harness never converts a status into
//!   the Rust enum of `ekicore-abi`, so an out-of-range value from a library is reported, not UB.
//! * Every pointer/length pair can be expressed, including the `(NULL, len > 0)` rows of the
//!   error matrix: inputs are [`In`], variable-length outputs are [`Out`], fixed-size inputs and
//!   outputs are `Option<&[u8; N]>` / `Option<&mut [u8; N]>` (`None` passes NULL).
//! * The harness never hands a library a length larger than the buffer behind the pointer, so a
//!   library that misbehaves corrupts nothing outside the buffers the harness owns.
//! * This crate does not depend on `ekicore-rs`: it sees both implementations only through the ABI.

use std::ffi::{CStr, CString, c_char};
use std::fmt;
use std::path::{Path, PathBuf};
use std::ptr::{self, NonNull};

pub use ekicore_abi::{
    eki_key_id, eki_key_info, eki_key_info_v2, eki_ks, eki_ks_config, eki_ks_config_v2,
};

use ekicore_abi as abi;

/// Fixed lengths from the header, re-exported so tests need only this crate.
pub use ekicore_abi::{
    EKI_ABI_VERSION, EKI_AEAD_KEY_LEN, EKI_AEAD_MAX_LEN, EKI_AEAD_NONCE_LEN, EKI_AEAD_TAG_LEN,
    EKI_APPROVERS_MAX, EKI_AUDIT_HASH_LEN, EKI_AUDIT_PATH_MAX_LEN, EKI_DESTROY_REQUEST_LEN,
    EKI_HKDF_MAX_INPUT_LEN, EKI_HKDF_MAX_OKM_LEN, EKI_HMAC_SHA256_LEN, EKI_HYBRID_CT_LEN,
    EKI_HYBRID_PK_LEN, EKI_HYBRID_SK_LEN, EKI_HYBRID_SS_LEN, EKI_KEY_ID_LEN, EKI_LABEL_MAX_LEN,
    EKI_P256_PUBLIC_KEY_LEN, EKI_P256_SIGNATURE_LEN, EKI_WRAPPED_KEY_LEN,
};

/// Byte every output buffer is pre-filled with, so "left untouched" and "zero-filled" differ.
pub const PREFILL: u8 = 0xA5;

// ---------------------------------------------------------------------------------------------
// Statuses and selectors as raw integers
// ---------------------------------------------------------------------------------------------

/// Status values of plan §4.1 and the ABI 2 contract §2, written out independently of both
/// libraries.
pub mod status {
    use ekicore_abi::eki_status;

    pub const EKI_OK: i32 = 0;
    pub const EKI_ERR_NULL_POINTER: i32 = 1;
    pub const EKI_ERR_INVALID_ARGUMENT: i32 = 2;
    pub const EKI_ERR_BUFFER_TOO_SMALL: i32 = 3;
    pub const EKI_ERR_UNSUPPORTED: i32 = 4;
    pub const EKI_ERR_AUTH_FAILED: i32 = 5;
    pub const EKI_ERR_KEY_NOT_FOUND: i32 = 6;
    pub const EKI_ERR_KEY_EXISTS: i32 = 7;
    pub const EKI_ERR_WRONG_KEY_TYPE: i32 = 8;
    pub const EKI_ERR_BACKEND: i32 = 9;
    pub const EKI_ERR_INTERNAL: i32 = 10;
    pub const EKI_ERR_KEY_STATE: i32 = 11;
    pub const EKI_ERR_APPROVAL_REQUIRED: i32 = 12;

    /// Name the contract assigns to any value outside the table.
    pub const UNKNOWN_NAME: &str = "EKI_STATUS_UNKNOWN";

    /// The harness's own name table.
    pub const NAMES: [(i32, &str); 13] = [
        (EKI_OK, "EKI_OK"),
        (EKI_ERR_NULL_POINTER, "EKI_ERR_NULL_POINTER"),
        (EKI_ERR_INVALID_ARGUMENT, "EKI_ERR_INVALID_ARGUMENT"),
        (EKI_ERR_BUFFER_TOO_SMALL, "EKI_ERR_BUFFER_TOO_SMALL"),
        (EKI_ERR_UNSUPPORTED, "EKI_ERR_UNSUPPORTED"),
        (EKI_ERR_AUTH_FAILED, "EKI_ERR_AUTH_FAILED"),
        (EKI_ERR_KEY_NOT_FOUND, "EKI_ERR_KEY_NOT_FOUND"),
        (EKI_ERR_KEY_EXISTS, "EKI_ERR_KEY_EXISTS"),
        (EKI_ERR_WRONG_KEY_TYPE, "EKI_ERR_WRONG_KEY_TYPE"),
        (EKI_ERR_BACKEND, "EKI_ERR_BACKEND"),
        (EKI_ERR_INTERNAL, "EKI_ERR_INTERNAL"),
        (EKI_ERR_KEY_STATE, "EKI_ERR_KEY_STATE"),
        (EKI_ERR_APPROVAL_REQUIRED, "EKI_ERR_APPROVAL_REQUIRED"),
    ];

    // The values above are typed in from the plan; the shared ABI crate must agree with them.
    const _: () = {
        assert!(EKI_OK == eki_status::EKI_OK as i32);
        assert!(EKI_ERR_NULL_POINTER == eki_status::EKI_ERR_NULL_POINTER as i32);
        assert!(EKI_ERR_INVALID_ARGUMENT == eki_status::EKI_ERR_INVALID_ARGUMENT as i32);
        assert!(EKI_ERR_BUFFER_TOO_SMALL == eki_status::EKI_ERR_BUFFER_TOO_SMALL as i32);
        assert!(EKI_ERR_UNSUPPORTED == eki_status::EKI_ERR_UNSUPPORTED as i32);
        assert!(EKI_ERR_AUTH_FAILED == eki_status::EKI_ERR_AUTH_FAILED as i32);
        assert!(EKI_ERR_KEY_NOT_FOUND == eki_status::EKI_ERR_KEY_NOT_FOUND as i32);
        assert!(EKI_ERR_KEY_EXISTS == eki_status::EKI_ERR_KEY_EXISTS as i32);
        assert!(EKI_ERR_WRONG_KEY_TYPE == eki_status::EKI_ERR_WRONG_KEY_TYPE as i32);
        assert!(EKI_ERR_BACKEND == eki_status::EKI_ERR_BACKEND as i32);
        assert!(EKI_ERR_INTERNAL == eki_status::EKI_ERR_INTERNAL as i32);
        assert!(EKI_ERR_KEY_STATE == eki_status::EKI_ERR_KEY_STATE as i32);
        assert!(EKI_ERR_APPROVAL_REQUIRED == eki_status::EKI_ERR_APPROVAL_REQUIRED as i32);
    };
}

/// Name of a status according to the harness's own table (never asks a library).
pub fn status_name(s: i32) -> &'static str {
    status::NAMES
        .iter()
        .find(|(v, _)| *v == s)
        .map_or(status::UNKNOWN_NAME, |(_, n)| n)
}

/// `"EKI_ERR_AUTH_FAILED (5)"`, for messages.
pub fn describe(s: i32) -> String {
    format!("{} ({s})", status_name(s))
}

/// Selector values as raw `i32`, so tests can also pass values the contract does not define.
pub mod sel {
    use ekicore_abi as abi;

    pub const AEAD_AES_256_GCM: i32 = abi::EKI_AEAD_AES_256_GCM.0;
    pub const AEAD_CHACHA20_POLY1305: i32 = abi::EKI_AEAD_CHACHA20_POLY1305.0;
    pub const KEY_AES_256: i32 = abi::EKI_KEY_AES_256.0;
    pub const KEY_HMAC_SHA256: i32 = abi::EKI_KEY_HMAC_SHA256.0;
    pub const KEY_ECDSA_P256: i32 = abi::EKI_KEY_ECDSA_P256.0;
    pub const KS_SOFTWARE: i32 = abi::EKI_KS_SOFTWARE.0;
    pub const KS_PKCS11: i32 = abi::EKI_KS_PKCS11.0;
    pub const KEY_STATE_ACTIVE: i32 = abi::EKI_KEY_STATE_ACTIVE.0;
    pub const KEY_STATE_RETIRED: i32 = abi::EKI_KEY_STATE_RETIRED.0;
    pub const KEY_STATE_REVOKED: i32 = abi::EKI_KEY_STATE_REVOKED.0;
}

// ---------------------------------------------------------------------------------------------
// Inputs and outputs
// ---------------------------------------------------------------------------------------------

/// A `(const uint8_t *p, size_t n)` input.
#[derive(Clone, Copy, Debug)]
pub enum In<'a> {
    /// A real buffer: pointer and length come from the slice (an empty slice gives a non-NULL
    /// dangling pointer with length 0).
    Bytes(&'a [u8]),
    /// A NULL pointer with the given length.
    Null { len: usize },
}

impl<'a> In<'a> {
    /// `(NULL, 0)`.
    pub const NULL: In<'static> = In::Null { len: 0 };

    /// `bytes`, except that an empty `bytes` becomes NULL when `null_when_empty` is set.
    pub fn maybe_null(bytes: &'a [u8], null_when_empty: bool) -> Self {
        if bytes.is_empty() && null_when_empty {
            In::Null { len: 0 }
        } else {
            In::Bytes(bytes)
        }
    }

    /// The length passed to the library.
    pub fn len(&self) -> usize {
        match self {
            In::Bytes(b) => b.len(),
            In::Null { len } => *len,
        }
    }

    /// True when the length passed is 0.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn raw(&self) -> (*const u8, usize) {
        match self {
            In::Bytes(b) => (b.as_ptr(), b.len()),
            In::Null { len } => (ptr::null(), *len),
        }
    }
}

impl<'a> From<&'a [u8]> for In<'a> {
    fn from(b: &'a [u8]) -> Self {
        In::Bytes(b)
    }
}

impl<'a> From<&'a Vec<u8>> for In<'a> {
    fn from(b: &'a Vec<u8>) -> Self {
        In::Bytes(b)
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for In<'a> {
    fn from(b: &'a [u8; N]) -> Self {
        In::Bytes(b)
    }
}

/// A variable-length `uint8_t *` output.
#[derive(Debug)]
pub enum Out<'a> {
    /// A real buffer. Its length is the declared length where the function takes one (`okm_len`)
    /// and must be at least the implied length otherwise (`ct_out` needs `pt_len` bytes).
    Buf(&'a mut [u8]),
    /// A NULL pointer; `len` is the declared length where the function takes one.
    Null { len: usize },
}

impl<'a> Out<'a> {
    /// `(NULL, 0)`.
    pub const NULL: Out<'static> = Out::Null { len: 0 };

    /// `buf`, except that an empty `buf` becomes NULL when `null_when_empty` is set.
    pub fn maybe_null(buf: &'a mut [u8], null_when_empty: bool) -> Self {
        if buf.is_empty() && null_when_empty {
            Out::Null { len: 0 }
        } else {
            Out::Buf(buf)
        }
    }

    fn raw(&mut self) -> (*mut u8, usize) {
        match self {
            Out::Buf(b) => (b.as_mut_ptr(), b.len()),
            Out::Null { len } => (ptr::null_mut(), *len),
        }
    }

    /// Panics (a harness bug, not a library failure) when a real buffer is shorter than `need`.
    fn check_capacity(&self, need: usize, what: &str) {
        if let Out::Buf(b) = self {
            assert!(
                b.len() >= need,
                "harness misuse: {what} buffer has {} bytes, the call writes {need}",
                b.len()
            );
        }
    }
}

fn opt_ptr<const N: usize>(p: Option<&[u8; N]>) -> *const u8 {
    p.map_or(ptr::null(), |a| a.as_ptr())
}

fn opt_mut_ptr<const N: usize>(p: Option<&mut [u8; N]>) -> *mut u8 {
    p.map_or(ptr::null_mut(), |a| a.as_mut_ptr())
}

fn opt_ref<T>(p: Option<&T>) -> *const T {
    p.map_or(ptr::null(), |r| r as *const T)
}

fn opt_mut<T>(p: Option<&mut T>) -> *mut T {
    p.map_or(ptr::null_mut(), |r| r as *mut T)
}

fn opt_cstr(p: Option<&CStr>) -> *const c_char {
    p.map_or(ptr::null(), CStr::as_ptr)
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

/// `n` bytes of [`PREFILL`].
pub fn prefill(n: usize) -> Vec<u8> {
    vec![PREFILL; n]
}

/// An array of [`PREFILL`].
pub fn prefill_array<const N: usize>() -> [u8; N] {
    [PREFILL; N]
}

/// True when every byte is zero (vacuously true for an empty slice).
pub fn is_zero(b: &[u8]) -> bool {
    b.iter().all(|&x| x == 0)
}

/// A key id whose bytes are all [`PREFILL`].
pub fn prefill_key_id() -> eki_key_id {
    eki_key_id {
        bytes: [PREFILL; 16],
    }
}

/// An `eki_key_info` whose fields are all [`PREFILL`] bytes.
pub fn prefill_key_info() -> eki_key_info {
    eki_key_info {
        alg: abi::eki_key_alg(i32::from_ne_bytes([PREFILL; 4])),
        label: [PREFILL as c_char; 65],
    }
}

/// An `eki_key_info_v2` whose fields are all [`PREFILL`] bytes.
pub fn prefill_key_info_v2() -> eki_key_info_v2 {
    eki_key_info_v2 {
        alg: abi::eki_key_alg(i32::from_ne_bytes([PREFILL; 4])),
        state: abi::eki_key_state(i32::from_ne_bytes([PREFILL; 4])),
        label: [PREFILL as c_char; 65],
    }
}

/// A `uint32_t` or `uint64_t` output pre-filled with [`PREFILL`] bytes.
pub const PREFILL_U32: u32 = u32::from_ne_bytes([PREFILL; 4]);
/// See [`PREFILL_U32`].
pub const PREFILL_U64: u64 = u64::from_ne_bytes([PREFILL; 8]);

/// The fields of an `eki_key_info`, comparable and printable (padding bytes are never looked at).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KeyInfo {
    pub alg: i32,
    pub label: [u8; 65],
}

impl KeyInfo {
    pub fn from_raw(info: &eki_key_info) -> Self {
        // `c_char` is `i8` on some targets and `u8` on others; this is a byte reinterpretation.
        let label = info.label.map(|c| c as u8);
        KeyInfo {
            alg: info.alg.0,
            label,
        }
    }

    /// True when both fields are zero-filled (the §4.2 rule for `info_out` on error).
    pub fn is_zero(&self) -> bool {
        self.alg == 0 && is_zero(&self.label)
    }

    /// The label up to the first NUL.
    pub fn label_str(&self) -> String {
        let end = self.label.iter().position(|&b| b == 0).unwrap_or(65);
        String::from_utf8_lossy(&self.label[..end]).into_owned()
    }

    /// The label is NUL-padded through byte 64 after its text.
    pub fn label_nul_padded(&self) -> bool {
        let end = self.label.iter().position(|&b| b == 0).unwrap_or(65);
        end <= 64 && is_zero(&self.label[end..])
    }
}

impl fmt::Debug for KeyInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyInfo")
            .field("alg", &self.alg)
            .field("label", &self.label_str())
            .field("label_bytes", &hex::encode(self.label))
            .finish()
    }
}

/// The fields of an `eki_key_info_v2`, comparable and printable (padding is never looked at).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KeyInfoV2 {
    pub alg: i32,
    pub state: i32,
    pub label: [u8; 65],
}

impl KeyInfoV2 {
    pub fn from_raw(info: &eki_key_info_v2) -> Self {
        KeyInfoV2 {
            alg: info.alg.0,
            state: info.state.0,
            label: info.label.map(|c| c as u8),
        }
    }

    /// True when every field is zero-filled (the outputs-on-error rule).
    pub fn is_zero(&self) -> bool {
        self.alg == 0 && self.state == 0 && is_zero(&self.label)
    }

    /// The `eki_key_info` fields of this value, for comparisons with `eki_ks_get_info`.
    pub fn v1(&self) -> KeyInfo {
        KeyInfo {
            alg: self.alg,
            label: self.label,
        }
    }
}

impl fmt::Debug for KeyInfoV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v1 = self.v1();
        f.debug_struct("KeyInfoV2")
            .field("alg", &self.alg)
            .field("state", &self.state)
            .field("label", &v1.label_str())
            .field("label_bytes", &hex::encode(self.label))
            .finish()
    }
}

/// Reads `EKI_CPP_LIB` and `EKI_RS_LIB` and loads both libraries: `(libekicore, libekicore_rs)`.
///
/// Panics with instructions when a variable is unset or a library cannot be loaded.
pub fn both() -> (Lib, Lib) {
    (load_env("EKI_CPP_LIB"), load_env("EKI_RS_LIB"))
}

fn load_env(var: &str) -> Lib {
    let path = std::env::var_os(var).unwrap_or_else(|| {
        panic!(
            "{var} is not set. Run scripts/run-conformance.sh, or set EKI_CPP_LIB and EKI_RS_LIB \
             to the paths of libekicore and libekicore_rs (.dylib or .so)"
        )
    });
    Lib::load(Path::new(&path)).unwrap_or_else(|e| panic!("{var}: {e}"))
}

// ---------------------------------------------------------------------------------------------
// The loaded library
// ---------------------------------------------------------------------------------------------

/// Error from [`Lib::load`].
#[derive(Debug)]
pub enum Error {
    /// The library could not be opened.
    Load {
        path: PathBuf,
        source: libloading::Error,
    },
    /// A symbol of the header is missing from the library.
    Symbol {
        path: PathBuf,
        symbol: &'static str,
        source: libloading::Error,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Load { path, source } => write!(f, "cannot load {}: {source}", path.display()),
            Error::Symbol {
                path,
                symbol,
                source,
            } => write!(f, "{} has no symbol {symbol}: {source}", path.display()),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Load { source, .. } | Error::Symbol { source, .. } => Some(source),
        }
    }
}

type FnAbiVersion = unsafe extern "C" fn() -> u32;
type FnVersion = unsafe extern "C" fn() -> *const c_char;
type FnStatusName = unsafe extern "C" fn(i32) -> *const c_char;
type FnHmac = unsafe extern "C" fn(*const u8, usize, *const u8, usize, *mut u8) -> i32;
type FnHmacVerify =
    unsafe extern "C" fn(*const u8, usize, *const u8, usize, *const u8, usize) -> i32;
type FnHkdf = unsafe extern "C" fn(
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *mut u8,
    usize,
) -> i32;
type FnAeadSeal = unsafe extern "C" fn(
    i32,
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *mut u8,
    *mut u8,
) -> i32;
type FnAeadOpen = unsafe extern "C" fn(
    i32,
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    *mut u8,
) -> i32;
type FnEcdsaVerify = unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> i32;
type FnKsOpen = unsafe extern "C" fn(*const eki_ks_config, *mut *mut eki_ks) -> i32;
type FnKsClose = unsafe extern "C" fn(*mut eki_ks);
type FnKsLastError = unsafe extern "C" fn(*const eki_ks, *mut c_char, usize) -> usize;
type FnKsGenerate = unsafe extern "C" fn(*mut eki_ks, i32, *const c_char, *mut eki_key_id) -> i32;
type FnKsGetInfo = unsafe extern "C" fn(*mut eki_ks, *const eki_key_id, *mut eki_key_info) -> i32;
type FnKsIdOut = unsafe extern "C" fn(*mut eki_ks, *const eki_key_id, *mut u8) -> i32;
type FnKsIdMsgOut =
    unsafe extern "C" fn(*mut eki_ks, *const eki_key_id, *const u8, usize, *mut u8) -> i32;
type FnKsWrap =
    unsafe extern "C" fn(*mut eki_ks, *const eki_key_id, *const eki_key_id, *mut u8) -> i32;
type FnKsUnwrap = unsafe extern "C" fn(
    *mut eki_ks,
    *const eki_key_id,
    *const u8,
    usize,
    i32,
    *const c_char,
    *const eki_key_id,
) -> i32;
type FnKsDestroy = unsafe extern "C" fn(*mut eki_ks, *const eki_key_id) -> i32;
type FnKsOpenV2 = unsafe extern "C" fn(*const eki_ks_config_v2, *mut *mut eki_ks) -> i32;
type FnKsGetInfoV2 =
    unsafe extern "C" fn(*mut eki_ks, *const eki_key_id, *mut eki_key_info_v2) -> i32;
type FnKsRotate = unsafe extern "C" fn(*mut eki_ks, *const eki_key_id, *mut eki_key_id) -> i32;
type FnKsHmacVerify =
    unsafe extern "C" fn(*mut eki_ks, *const eki_key_id, *const u8, usize, *const u8, usize) -> i32;
type FnKsDestroyApprove =
    unsafe extern "C" fn(*mut eki_ks, *const u8, *const u8, *const u8, *mut u32) -> i32;
type FnKsAuditHead = unsafe extern "C" fn(*mut eki_ks, *mut u8, *mut u64) -> i32;
type FnAuditVerify = unsafe extern "C" fn(*const c_char, *const u8, *mut u64) -> i32;
type FnKemKeygen = unsafe extern "C" fn(*mut u8, *mut u8) -> i32;
type FnKemEncap = unsafe extern "C" fn(*const u8, *mut u8, *mut u8) -> i32;
type FnKemDecap = unsafe extern "C" fn(*const u8, *const u8, *mut u8) -> i32;

/// One loaded implementation of the ABI.
///
/// The function pointers stay private: they are valid only while `_lib` is loaded, and the struct
/// owns it, so they can never outlive the library.
pub struct Lib {
    name: String,
    path: PathBuf,
    abi_version: FnAbiVersion,
    version: FnVersion,
    status_name: FnStatusName,
    hmac_sha256: FnHmac,
    hmac_sha256_verify: FnHmacVerify,
    hkdf_sha256: FnHkdf,
    aead_seal: FnAeadSeal,
    aead_open: FnAeadOpen,
    ecdsa_p256_verify: FnEcdsaVerify,
    ks_open: FnKsOpen,
    ks_close: FnKsClose,
    ks_last_error_message: FnKsLastError,
    ks_generate: FnKsGenerate,
    ks_get_info: FnKsGetInfo,
    ks_get_public_key: FnKsIdOut,
    ks_sign: FnKsIdMsgOut,
    ks_hmac_sha256: FnKsIdMsgOut,
    ks_wrap: FnKsWrap,
    ks_unwrap: FnKsUnwrap,
    ks_destroy: FnKsDestroy,
    hybrid_kem_keygen: FnKemKeygen,
    hybrid_kem_encap: FnKemEncap,
    hybrid_kem_decap: FnKemDecap,
    ks_open_v2: FnKsOpenV2,
    ks_get_info_v2: FnKsGetInfoV2,
    ks_rotate: FnKsRotate,
    ks_revoke: FnKsDestroy,
    ks_hmac_sha256_verify: FnKsHmacVerify,
    ks_destroy_request: FnKsIdOut,
    ks_destroy_approve: FnKsDestroyApprove,
    ks_audit_head: FnKsAuditHead,
    audit_verify: FnAuditVerify,
    // Declared last so it is dropped (unloaded) after nothing else could use the pointers.
    _lib: libloading::Library,
}

impl fmt::Debug for Lib {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Lib")
            .field("name", &self.name)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Lib {
    /// Loads the library at `path` (default flags: `RTLD_LAZY | RTLD_LOCAL` on Unix) and resolves
    /// every function of `include/ekicore.h` through its handle.
    pub fn load(path: impl AsRef<Path>) -> Result<Lib, Error> {
        let path = path.as_ref().to_path_buf();
        // SAFETY: loading a library runs its initialisers. The two ekicore libraries are ordinary
        // shared objects built from this repository whose initialisers only set up their language
        // runtimes; the harness loads nothing else.
        let lib = unsafe { libloading::Library::new(&path) }.map_err(|source| Error::Load {
            path: path.clone(),
            source,
        })?;

        macro_rules! sym {
            ($ty:ty, $name:literal) => {{
                // SAFETY: `$ty` is written from the declaration of `$name` in include/ekicore.h
                // (`eki_status` read as `int32_t`, `size_t` as `usize`, `eki_*_alg` and
                // `eki_ks_backend` as `int32_t`). The fn pointer is copied out of the `Symbol`
                // and stored next to `lib`, which keeps the library loaded while it is reachable.
                let s = unsafe { lib.get::<$ty>(concat!($name, "\0").as_bytes()) };
                *s.map_err(|source| Error::Symbol {
                    path: path.clone(),
                    symbol: $name,
                    source,
                })?
            }};
        }

        let name = path.file_stem().map_or_else(
            || path.display().to_string(),
            |s| s.to_string_lossy().into_owned(),
        );
        Ok(Lib {
            abi_version: sym!(FnAbiVersion, "eki_abi_version"),
            version: sym!(FnVersion, "eki_version"),
            status_name: sym!(FnStatusName, "eki_status_name"),
            hmac_sha256: sym!(FnHmac, "eki_hmac_sha256"),
            hmac_sha256_verify: sym!(FnHmacVerify, "eki_hmac_sha256_verify"),
            hkdf_sha256: sym!(FnHkdf, "eki_hkdf_sha256"),
            aead_seal: sym!(FnAeadSeal, "eki_aead_seal"),
            aead_open: sym!(FnAeadOpen, "eki_aead_open"),
            ecdsa_p256_verify: sym!(FnEcdsaVerify, "eki_ecdsa_p256_verify"),
            ks_open: sym!(FnKsOpen, "eki_ks_open"),
            ks_close: sym!(FnKsClose, "eki_ks_close"),
            ks_last_error_message: sym!(FnKsLastError, "eki_ks_last_error_message"),
            ks_generate: sym!(FnKsGenerate, "eki_ks_generate"),
            ks_get_info: sym!(FnKsGetInfo, "eki_ks_get_info"),
            ks_get_public_key: sym!(FnKsIdOut, "eki_ks_get_public_key"),
            ks_sign: sym!(FnKsIdMsgOut, "eki_ks_sign"),
            ks_hmac_sha256: sym!(FnKsIdMsgOut, "eki_ks_hmac_sha256"),
            ks_wrap: sym!(FnKsWrap, "eki_ks_wrap"),
            ks_unwrap: sym!(FnKsUnwrap, "eki_ks_unwrap"),
            ks_destroy: sym!(FnKsDestroy, "eki_ks_destroy"),
            hybrid_kem_keygen: sym!(FnKemKeygen, "eki_hybrid_kem_keygen"),
            hybrid_kem_encap: sym!(FnKemEncap, "eki_hybrid_kem_encap"),
            hybrid_kem_decap: sym!(FnKemDecap, "eki_hybrid_kem_decap"),
            ks_open_v2: sym!(FnKsOpenV2, "eki_ks_open_v2"),
            ks_get_info_v2: sym!(FnKsGetInfoV2, "eki_ks_get_info_v2"),
            ks_rotate: sym!(FnKsRotate, "eki_ks_rotate"),
            ks_revoke: sym!(FnKsDestroy, "eki_ks_revoke"),
            ks_hmac_sha256_verify: sym!(FnKsHmacVerify, "eki_ks_hmac_sha256_verify"),
            ks_destroy_request: sym!(FnKsIdOut, "eki_ks_destroy_request"),
            ks_destroy_approve: sym!(FnKsDestroyApprove, "eki_ks_destroy_approve"),
            ks_audit_head: sym!(FnKsAuditHead, "eki_ks_audit_head"),
            audit_verify: sym!(FnAuditVerify, "eki_audit_verify"),
            name,
            path,
            _lib: lib,
        })
    }

    /// Short name for messages: the file stem (`libekicore`, `libekicore_rs`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Path the library was loaded from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    // --- metadata -----------------------------------------------------------------------------

    /// `eki_abi_version()`.
    pub fn abi_version(&self) -> u32 {
        // SAFETY: no arguments; the function only returns a constant.
        unsafe { (self.abi_version)() }
    }

    /// `eki_version()` as a string; `None` if the library returned NULL.
    pub fn version(&self) -> Option<String> {
        // SAFETY: no arguments.
        let p = unsafe { (self.version)() };
        // SAFETY: the contract says the result is a NUL-terminated string in static storage.
        (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }

    /// `eki_status_name(s)` as a string; `None` if the library returned NULL.
    pub fn status_name(&self, s: i32) -> Option<String> {
        // SAFETY: takes any `int32_t` by value.
        let p = unsafe { (self.status_name)(s) };
        // SAFETY: the contract says the result is a NUL-terminated string in static storage.
        (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }

    // --- stateless primitives -------------------------------------------------------------------

    /// `eki_hmac_sha256(key, msg, out[32])`.
    pub fn hmac_sha256(&self, key: In, msg: In, out: Option<&mut [u8; 32]>) -> i32 {
        let (k, kl) = key.raw();
        let (m, ml) = msg.raw();
        // SAFETY: every non-NULL pointer refers to a live buffer of at least the length passed
        // with it (`In` takes pointer and length from one slice); `out` is NULL or 32 writable
        // bytes. Nothing is retained after the call.
        unsafe { (self.hmac_sha256)(k, kl, m, ml, opt_mut_ptr(out)) }
    }

    /// `eki_hmac_sha256_verify(key, msg, tag)`.
    pub fn hmac_sha256_verify(&self, key: In, msg: In, tag: In) -> i32 {
        let (k, kl) = key.raw();
        let (m, ml) = msg.raw();
        let (t, tl) = tag.raw();
        // SAFETY: every non-NULL pointer refers to a live buffer of the length passed with it.
        unsafe { (self.hmac_sha256_verify)(k, kl, m, ml, t, tl) }
    }

    /// `eki_hkdf_sha256(ikm, salt, info, okm, okm_len)`; the declared `okm_len` comes from `okm`.
    pub fn hkdf_sha256(&self, ikm: In, salt: In, info: In, mut okm: Out) -> i32 {
        let (i, il) = ikm.raw();
        let (s, sl) = salt.raw();
        let (n, nl) = info.raw();
        let (o, ol) = okm.raw();
        // SAFETY: inputs as in `hmac_sha256`; `okm` is NULL or exactly `okm_len` writable bytes.
        unsafe { (self.hkdf_sha256)(i, il, s, sl, n, nl, o, ol) }
    }

    /// `eki_aead_seal`. `ct_out` must hold at least `pt.len()` bytes when it is a buffer.
    #[allow(clippy::too_many_arguments)]
    pub fn aead_seal(
        &self,
        alg: i32,
        key: In,
        nonce: In,
        aad: In,
        pt: In,
        mut ct_out: Out,
        tag_out: Option<&mut [u8; 16]>,
    ) -> i32 {
        ct_out.check_capacity(pt.len(), "ct_out");
        let (k, kl) = key.raw();
        let (n, nl) = nonce.raw();
        let (a, al) = aad.raw();
        let (p, pl) = pt.raw();
        let (c, _) = ct_out.raw();
        // SAFETY: inputs as in `hmac_sha256`; `ct_out` is NULL or at least `pt_len` writable bytes
        // (checked above) and does not overlap `pt`; `tag_out` is NULL or 16 writable bytes.
        unsafe { (self.aead_seal)(alg, k, kl, n, nl, a, al, p, pl, c, opt_mut_ptr(tag_out)) }
    }

    /// `eki_aead_open`. `pt_out` must hold at least `ct.len()` bytes when it is a buffer.
    #[allow(clippy::too_many_arguments)]
    pub fn aead_open(
        &self,
        alg: i32,
        key: In,
        nonce: In,
        aad: In,
        ct: In,
        tag: Option<&[u8; 16]>,
        mut pt_out: Out,
    ) -> i32 {
        pt_out.check_capacity(ct.len(), "pt_out");
        let (k, kl) = key.raw();
        let (n, nl) = nonce.raw();
        let (a, al) = aad.raw();
        let (c, cl) = ct.raw();
        let (p, _) = pt_out.raw();
        // SAFETY: inputs as in `hmac_sha256`; `tag` is NULL or 16 readable bytes; `pt_out` is NULL
        // or at least `ct_len` writable bytes (checked above) and does not overlap `ct`.
        unsafe { (self.aead_open)(alg, k, kl, n, nl, a, al, c, cl, opt_ptr(tag), p) }
    }

    /// `eki_ecdsa_p256_verify(public_key[65], msg, sig[64])`.
    pub fn ecdsa_p256_verify(
        &self,
        public_key: Option<&[u8; 65]>,
        msg: In,
        sig: Option<&[u8; 64]>,
    ) -> i32 {
        let (m, ml) = msg.raw();
        // SAFETY: `public_key` and `sig` are NULL or arrays of exactly the fixed sizes; `msg` as
        // in `hmac_sha256`.
        unsafe { (self.ecdsa_p256_verify)(opt_ptr(public_key), m, ml, opt_ptr(sig)) }
    }

    // --- hybrid KEM ---------------------------------------------------------------------------

    /// `eki_hybrid_kem_keygen(pk_out[1216], sk_out[96])`.
    pub fn hybrid_kem_keygen(
        &self,
        pk_out: Option<&mut [u8; EKI_HYBRID_PK_LEN]>,
        sk_out: Option<&mut [u8; EKI_HYBRID_SK_LEN]>,
    ) -> i32 {
        // SAFETY: each pointer is NULL or an array of exactly the fixed size.
        unsafe { (self.hybrid_kem_keygen)(opt_mut_ptr(pk_out), opt_mut_ptr(sk_out)) }
    }

    /// `eki_hybrid_kem_encap(pk[1216], ct_out[1120], ss_out[32])`.
    pub fn hybrid_kem_encap(
        &self,
        pk: Option<&[u8; EKI_HYBRID_PK_LEN]>,
        ct_out: Option<&mut [u8; EKI_HYBRID_CT_LEN]>,
        ss_out: Option<&mut [u8; EKI_HYBRID_SS_LEN]>,
    ) -> i32 {
        // SAFETY: each pointer is NULL or an array of exactly the fixed size.
        unsafe { (self.hybrid_kem_encap)(opt_ptr(pk), opt_mut_ptr(ct_out), opt_mut_ptr(ss_out)) }
    }

    /// `eki_hybrid_kem_decap(sk[96], ct[1120], ss_out[32])`.
    pub fn hybrid_kem_decap(
        &self,
        sk: Option<&[u8; EKI_HYBRID_SK_LEN]>,
        ct: Option<&[u8; EKI_HYBRID_CT_LEN]>,
        ss_out: Option<&mut [u8; EKI_HYBRID_SS_LEN]>,
    ) -> i32 {
        // SAFETY: each pointer is NULL or an array of exactly the fixed size.
        unsafe { (self.hybrid_kem_decap)(opt_ptr(sk), opt_ptr(ct), opt_mut_ptr(ss_out)) }
    }

    // --- key store ----------------------------------------------------------------------------

    /// `eki_ks_open` with a well-formed config. On `EKI_OK` with a non-NULL handle the store is
    /// returned; it is closed when dropped.
    pub fn ks_open(&self, cfg: &KsConfig) -> (i32, Option<Store<'_>>) {
        let raw_cfg = cfg.as_raw();
        let sentinel = NonNull::<eki_ks>::dangling().as_ptr();
        let mut out = sentinel;
        let st = self.ks_open_raw(Some(&raw_cfg), Some(&mut out));
        if st == status::EKI_OK && !out.is_null() && out != sentinel {
            return (
                st,
                Some(Store {
                    lib: self,
                    raw: out,
                }),
            );
        }
        if st != status::EKI_OK && !out.is_null() && out != sentinel {
            // Contract violation (a handle on failure). Close it so it does not leak; tests that
            // check `*out` use `ks_open_raw`.
            drop(Store {
                lib: self,
                raw: out,
            });
        }
        (st, None)
    }

    /// `eki_ks_open(config, out)` with nothing checked or owned: for the NULL and `*out` rows.
    /// A non-NULL `*out` left behind is the caller's to close (see [`Lib::adopt`]).
    pub fn ks_open_raw(
        &self,
        config: Option<&eki_ks_config>,
        out: Option<&mut *mut eki_ks>,
    ) -> i32 {
        // SAFETY: `config` is NULL or a valid config whose string pointers are NULL or
        // NUL-terminated strings that outlive the call; `out` is NULL or a writable pointer slot.
        unsafe { (self.ks_open)(opt_ref(config), opt_mut(out)) }
    }

    /// Takes ownership of a handle returned through [`Lib::ks_open_raw`].
    ///
    /// # Safety
    ///
    /// `raw` must be NULL or a handle this library returned from `eki_ks_open` that has not been
    /// closed and is not owned by another `Store`.
    pub unsafe fn adopt(&self, raw: *mut eki_ks) -> Store<'_> {
        Store { lib: self, raw }
    }

    /// `eki_ks_open_v2` with a well-formed config. On `EKI_OK` with a non-NULL handle the store
    /// is returned; it is closed when dropped.
    pub fn ks_open_v2(&self, cfg: &KsConfigV2) -> (i32, Option<Store<'_>>) {
        let raw_cfg = cfg.as_raw();
        let sentinel = NonNull::<eki_ks>::dangling().as_ptr();
        let mut out = sentinel;
        let st = self.ks_open_v2_raw(Some(&raw_cfg), Some(&mut out));
        let handle = (!out.is_null() && out != sentinel).then_some(out);
        match (st, handle) {
            (status::EKI_OK, Some(raw)) => (st, Some(Store { lib: self, raw })),
            (_, Some(raw)) => {
                // Contract violation (a handle on failure). Close it so it does not leak; tests
                // that check `*out` use `ks_open_v2_raw`.
                drop(Store { lib: self, raw });
                (st, None)
            }
            (_, None) => (st, None),
        }
    }

    /// `eki_ks_open_v2(config, out)` with nothing checked or owned: for the NULL and `*out` rows.
    /// A non-NULL `*out` left behind is the caller's to close (see [`Lib::adopt`]).
    pub fn ks_open_v2_raw(
        &self,
        config: Option<&eki_ks_config_v2>,
        out: Option<&mut *mut eki_ks>,
    ) -> i32 {
        // SAFETY: `config` is NULL or a config built by `KsConfigV2::as_raw`, whose string
        // pointers are NULL or NUL-terminated strings and whose key pointer is NULL or covers
        // `approver_count * 65` bytes (checked there), all outliving the call; `out` is NULL or a
        // writable pointer slot.
        unsafe { (self.ks_open_v2)(opt_ref(config), opt_mut(out)) }
    }

    /// `eki_audit_verify(path, expected_head[32], records_out)`.
    pub fn audit_verify(
        &self,
        path: Option<&CStr>,
        expected_head: Option<&[u8; 32]>,
        records_out: Option<&mut u64>,
    ) -> i32 {
        // SAFETY: `path` is NULL or a NUL-terminated string; `expected_head` is NULL or 32
        // readable bytes; `records_out` is NULL or a writable `uint64_t`.
        unsafe { (self.audit_verify)(opt_cstr(path), opt_ptr(expected_head), opt_mut(records_out)) }
    }

    /// A store wrapper around a NULL handle, for the `ks == NULL` rows. Dropping it calls
    /// `eki_ks_close(NULL)`, which the contract makes a no-op.
    pub fn null_store(&self) -> Store<'_> {
        Store {
            lib: self,
            raw: ptr::null_mut(),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Key store
// ---------------------------------------------------------------------------------------------

/// Owned strings for an `eki_ks_config`. `None` fields are passed as NULL.
#[derive(Clone, Debug, Default)]
pub struct KsConfig {
    pub backend: i32,
    pub module_path: Option<CString>,
    pub token_label: Option<CString>,
    pub user_pin: Option<CString>,
}

impl KsConfig {
    /// The software backend; the PKCS#11 fields are NULL.
    pub fn software() -> Self {
        KsConfig {
            backend: sel::KS_SOFTWARE,
            ..Default::default()
        }
    }

    /// The PKCS#11 backend. Panics if a string contains a NUL byte.
    pub fn pkcs11(module_path: &str, token_label: &str, user_pin: &str) -> Self {
        let c = |s: &str| CString::new(s).expect("config string contains a NUL byte");
        KsConfig {
            backend: sel::KS_PKCS11,
            module_path: Some(c(module_path)),
            token_label: Some(c(token_label)),
            user_pin: Some(c(user_pin)),
        }
    }

    /// The PKCS#11 backend from `EKI_PKCS11_MODULE`, `EKI_PKCS11_TOKEN_LABEL` and
    /// `EKI_PKCS11_PIN` (as exported by `scripts/softhsm-init.sh`); `None` if any is unset.
    pub fn pkcs11_from_env() -> Option<Self> {
        let module = std::env::var("EKI_PKCS11_MODULE").ok()?;
        let label = std::env::var("EKI_PKCS11_TOKEN_LABEL").ok()?;
        let pin = std::env::var("EKI_PKCS11_PIN").ok()?;
        Some(Self::pkcs11(&module, &label, &pin))
    }

    /// The C struct. Its pointers borrow `self`, which must outlive every use of the result.
    pub fn as_raw(&self) -> eki_ks_config {
        let p = |s: &Option<CString>| s.as_deref().map_or(ptr::null(), CStr::as_ptr);
        eki_ks_config {
            backend: abi::eki_ks_backend(self.backend),
            pkcs11_module_path: p(&self.module_path),
            pkcs11_token_label: p(&self.token_label),
            pkcs11_user_pin: p(&self.user_pin),
        }
    }
}

/// Owned contents of an `eki_ks_config_v2`. `None` fields are passed as NULL.
#[derive(Clone, Debug, Default)]
pub struct KsConfigV2 {
    pub backend: i32,
    pub module_path: Option<CString>,
    pub token_label: Option<CString>,
    pub user_pin: Option<CString>,
    pub audit_log_path: Option<CString>,
    /// The bytes `approver_public_keys` points to (approver keys back to back), or NULL.
    pub approver_public_keys: Option<Vec<u8>>,
    pub approver_count: usize,
}

impl KsConfigV2 {
    /// The fields of an `eki_ks_open` config, with no audit log and no approvers.
    pub fn from_v1(cfg: &KsConfig) -> Self {
        KsConfigV2 {
            backend: cfg.backend,
            module_path: cfg.module_path.clone(),
            token_label: cfg.token_label.clone(),
            user_pin: cfg.user_pin.clone(),
            ..Default::default()
        }
    }

    /// The software backend with no audit log and no approvers.
    pub fn software() -> Self {
        Self::from_v1(&KsConfig::software())
    }

    /// The same config with an audit log at `path`. Panics if the path contains a NUL byte.
    pub fn with_audit_log(mut self, path: &Path) -> Self {
        let bytes = path.as_os_str().as_encoded_bytes().to_vec();
        self.audit_log_path = Some(CString::new(bytes).expect("audit log path contains a NUL"));
        self
    }

    /// The same config with these approver keys (65 bytes each, count = number of keys).
    pub fn with_approvers(mut self, keys: &[[u8; 65]]) -> Self {
        self.approver_public_keys = Some(keys.concat());
        self.approver_count = keys.len();
        self
    }

    /// The C struct. Its pointers borrow `self`, which must outlive every use of the result.
    ///
    /// Panics (a harness bug) when `approver_public_keys` is a buffer shorter than
    /// `approver_count * 65` bytes, so a library is never handed a count its buffer does not
    /// cover.
    pub fn as_raw(&self) -> eki_ks_config_v2 {
        let p = |s: &Option<CString>| s.as_deref().map_or(ptr::null(), CStr::as_ptr);
        if let Some(keys) = &self.approver_public_keys {
            let need = self.approver_count.checked_mul(EKI_P256_PUBLIC_KEY_LEN);
            assert!(
                need.is_some_and(|n| keys.len() >= n),
                "harness misuse: {} approver key bytes for approver_count {}",
                keys.len(),
                self.approver_count
            );
        }
        eki_ks_config_v2 {
            backend: abi::eki_ks_backend(self.backend),
            pkcs11_module_path: p(&self.module_path),
            pkcs11_token_label: p(&self.token_label),
            pkcs11_user_pin: p(&self.user_pin),
            audit_log_path: p(&self.audit_log_path),
            approver_public_keys: self
                .approver_public_keys
                .as_ref()
                .map_or(ptr::null(), |k| k.as_ptr()),
            approver_count: self.approver_count,
        }
    }
}

/// An open `eki_ks` handle of one library (or a NULL handle from [`Lib::null_store`]).
/// Dropping it calls `eki_ks_close`.
pub struct Store<'l> {
    lib: &'l Lib,
    raw: *mut eki_ks,
}

impl fmt::Debug for Store<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store")
            .field("lib", &self.lib.name)
            .field("raw", &self.raw)
            .finish()
    }
}

impl Drop for Store<'_> {
    fn drop(&mut self) {
        // SAFETY: `raw` is NULL or a handle this library returned that nothing else owns; it is
        // closed exactly once, here, and never used afterwards.
        unsafe { (self.lib.ks_close)(self.raw) }
    }
}

impl<'l> Store<'l> {
    /// The library this handle belongs to.
    pub fn lib(&self) -> &'l Lib {
        self.lib
    }

    /// The raw handle (NULL for [`Lib::null_store`]).
    pub fn raw(&self) -> *mut eki_ks {
        self.raw
    }

    /// Closes the handle now (same as dropping it).
    pub fn close(self) {}

    /// `eki_ks_generate(ks, alg, label, id_out)`.
    pub fn generate(&self, alg: i32, label: Option<&CStr>, id_out: Option<&mut eki_key_id>) -> i32 {
        // SAFETY: `raw` is NULL or a live handle of this library; `label` is NULL or a
        // NUL-terminated string; `id_out` is NULL or a writable `eki_key_id`.
        unsafe { (self.lib.ks_generate)(self.raw, alg, opt_cstr(label), opt_mut(id_out)) }
    }

    /// `eki_ks_get_info(ks, id, info_out)`.
    pub fn get_info(&self, id: Option<&eki_key_id>, info_out: Option<&mut eki_key_info>) -> i32 {
        // SAFETY: `raw` as in `generate`; `id` is NULL or a readable id; `info_out` is NULL or a
        // writable `eki_key_info`.
        unsafe { (self.lib.ks_get_info)(self.raw, opt_ref(id), opt_mut(info_out)) }
    }

    /// `eki_ks_get_public_key(ks, id, out[65])`.
    pub fn get_public_key(&self, id: Option<&eki_key_id>, out: Option<&mut [u8; 65]>) -> i32 {
        // SAFETY: `raw` and `id` as in `get_info`; `out` is NULL or 65 writable bytes.
        unsafe { (self.lib.ks_get_public_key)(self.raw, opt_ref(id), opt_mut_ptr(out)) }
    }

    /// `eki_ks_sign(ks, id, msg, sig_out[64])`.
    pub fn sign(&self, id: Option<&eki_key_id>, msg: In, sig_out: Option<&mut [u8; 64]>) -> i32 {
        let (m, ml) = msg.raw();
        // SAFETY: `raw` and `id` as in `get_info`; `msg` is NULL or `msg_len` readable bytes;
        // `sig_out` is NULL or 64 writable bytes.
        unsafe { (self.lib.ks_sign)(self.raw, opt_ref(id), m, ml, opt_mut_ptr(sig_out)) }
    }

    /// `eki_ks_hmac_sha256(ks, id, msg, out[32])`.
    pub fn hmac_sha256(&self, id: Option<&eki_key_id>, msg: In, out: Option<&mut [u8; 32]>) -> i32 {
        let (m, ml) = msg.raw();
        // SAFETY: as in `sign`, with a 32-byte output.
        unsafe { (self.lib.ks_hmac_sha256)(self.raw, opt_ref(id), m, ml, opt_mut_ptr(out)) }
    }

    /// `eki_ks_wrap(ks, kek_id, key_id, out[40])`.
    pub fn wrap(
        &self,
        kek_id: Option<&eki_key_id>,
        key_id: Option<&eki_key_id>,
        out: Option<&mut [u8; 40]>,
    ) -> i32 {
        // SAFETY: `raw` as in `generate`; ids are NULL or readable; `out` is NULL or 40 writable
        // bytes.
        unsafe { (self.lib.ks_wrap)(self.raw, opt_ref(kek_id), opt_ref(key_id), opt_mut_ptr(out)) }
    }

    /// `eki_ks_unwrap(ks, kek_id, blob, alg, label, id)`.
    pub fn unwrap(
        &self,
        kek_id: Option<&eki_key_id>,
        blob: In,
        alg: i32,
        label: Option<&CStr>,
        id: Option<&eki_key_id>,
    ) -> i32 {
        let (b, bl) = blob.raw();
        // SAFETY: `raw` as in `generate`; ids are NULL or readable; `blob` is NULL or `blob_len`
        // readable bytes; `label` is NULL or a NUL-terminated string.
        unsafe {
            (self.lib.ks_unwrap)(
                self.raw,
                opt_ref(kek_id),
                b,
                bl,
                alg,
                opt_cstr(label),
                opt_ref(id),
            )
        }
    }

    /// `eki_ks_destroy(ks, id)`.
    pub fn destroy(&self, id: Option<&eki_key_id>) -> i32 {
        // SAFETY: `raw` as in `generate`; `id` is NULL or readable.
        unsafe { (self.lib.ks_destroy)(self.raw, opt_ref(id)) }
    }

    /// `eki_ks_get_info_v2(ks, id, info_out)`.
    pub fn get_info_v2(
        &self,
        id: Option<&eki_key_id>,
        info_out: Option<&mut eki_key_info_v2>,
    ) -> i32 {
        // SAFETY: `raw` as in `generate`; `id` is NULL or a readable id; `info_out` is NULL or a
        // writable `eki_key_info_v2`.
        unsafe { (self.lib.ks_get_info_v2)(self.raw, opt_ref(id), opt_mut(info_out)) }
    }

    /// `eki_ks_rotate(ks, old_id, new_id_out)`.
    pub fn rotate(&self, old_id: Option<&eki_key_id>, new_id_out: Option<&mut eki_key_id>) -> i32 {
        // SAFETY: `raw` as in `generate`; `old_id` is NULL or readable; `new_id_out` is NULL or a
        // writable `eki_key_id`.
        unsafe { (self.lib.ks_rotate)(self.raw, opt_ref(old_id), opt_mut(new_id_out)) }
    }

    /// `eki_ks_revoke(ks, id)`.
    pub fn revoke(&self, id: Option<&eki_key_id>) -> i32 {
        // SAFETY: `raw` as in `generate`; `id` is NULL or readable.
        unsafe { (self.lib.ks_revoke)(self.raw, opt_ref(id)) }
    }

    /// `eki_ks_hmac_sha256_verify(ks, id, msg, tag)`.
    pub fn hmac_sha256_verify(&self, id: Option<&eki_key_id>, msg: In, tag: In) -> i32 {
        let (m, ml) = msg.raw();
        let (t, tl) = tag.raw();
        // SAFETY: `raw` and `id` as in `get_info`; `msg` and `tag` are NULL or point to as many
        // readable bytes as the length passed with them.
        unsafe { (self.lib.ks_hmac_sha256_verify)(self.raw, opt_ref(id), m, ml, t, tl) }
    }

    /// `eki_ks_destroy_request(ks, id, request_out[32])`.
    pub fn destroy_request(
        &self,
        id: Option<&eki_key_id>,
        request_out: Option<&mut [u8; 32]>,
    ) -> i32 {
        // SAFETY: `raw` and `id` as in `get_info`; `request_out` is NULL or 32 writable bytes.
        unsafe { (self.lib.ks_destroy_request)(self.raw, opt_ref(id), opt_mut_ptr(request_out)) }
    }

    /// `eki_ks_destroy_approve(ks, request[32], approver_public_key[65], sig[64],
    /// remaining_out)`.
    pub fn destroy_approve(
        &self,
        request: Option<&[u8; 32]>,
        approver_public_key: Option<&[u8; 65]>,
        sig: Option<&[u8; 64]>,
        remaining_out: Option<&mut u32>,
    ) -> i32 {
        // SAFETY: `raw` as in `generate`; each array is NULL or exactly its fixed size;
        // `remaining_out` is NULL or a writable `uint32_t`.
        unsafe {
            (self.lib.ks_destroy_approve)(
                self.raw,
                opt_ptr(request),
                opt_ptr(approver_public_key),
                opt_ptr(sig),
                opt_mut(remaining_out),
            )
        }
    }

    /// `eki_ks_audit_head(ks, hash_out[32], seq_out)`.
    pub fn audit_head(&self, hash_out: Option<&mut [u8; 32]>, seq_out: Option<&mut u64>) -> i32 {
        // SAFETY: `raw` as in `generate`; `hash_out` is NULL or 32 writable bytes; `seq_out` is
        // NULL or a writable `uint64_t`.
        unsafe { (self.lib.ks_audit_head)(self.raw, opt_mut_ptr(hash_out), opt_mut(seq_out)) }
    }

    /// `eki_ks_last_error_message(ks, buf, buf_len)` with a caller buffer (`None` passes NULL with
    /// the given length, which the contract treats as length 0).
    pub fn last_error_message_raw(&self, buf: Option<&mut [u8]>, null_len: usize) -> usize {
        let (p, n) = match buf {
            Some(b) => (b.as_mut_ptr().cast::<c_char>(), b.len()),
            None => (ptr::null_mut(), null_len),
        };
        // SAFETY: `raw` as in `generate`; `p` is NULL or `n` writable bytes. A NULL `p` with
        // `n > 0` is allowed by the contract (treated as `buf_len == 0`).
        unsafe { (self.lib.ks_last_error_message)(self.raw, p, n) }
    }

    /// The last error message of this handle as a string (two calls: size, then text).
    pub fn last_error(&self) -> String {
        let n = self.last_error_message_raw(None, 0);
        let mut buf = vec![PREFILL; n.min(1 << 16) + 1];
        self.last_error_message_raw(Some(&mut buf), 0);
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..end]).into_owned()
    }
}

// ---------------------------------------------------------------------------------------------
// Vector files
// ---------------------------------------------------------------------------------------------

/// The JSON vector files under `conformance/vectors/`.
pub mod vectors {
    use serde::de::DeserializeOwned;
    use serde::{Deserialize, Deserializer};
    use std::path::PathBuf;

    /// Directory holding the vector files.
    pub fn dir() -> PathBuf {
        PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/vectors"))
    }

    /// Reads and parses `vectors/<file>`; panics with the file name on any error.
    pub fn load<T: DeserializeOwned>(file: &str) -> T {
        let path = dir().join(file);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("cannot parse {}: {e}", path.display()))
    }

    fn de_hex<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }

    /// Expected outcome of a vector.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
    #[serde(rename_all = "lowercase")]
    pub enum Expect {
        Valid,
        Invalid,
    }

    /// Header shared by every file.
    #[derive(Clone, Debug, Deserialize)]
    pub struct File<C> {
        pub source: String,
        pub url: String,
        #[serde(default)]
        pub license: Option<String>,
        #[serde(default)]
        pub algorithm: Option<String>,
        pub cases: Vec<C>,
    }

    /// `hmac_sha256_rfc4231.json`.
    #[derive(Clone, Debug, Deserialize)]
    pub struct HmacCase {
        pub name: String,
        #[serde(deserialize_with = "de_hex")]
        pub key: Vec<u8>,
        #[serde(deserialize_with = "de_hex")]
        pub data: Vec<u8>,
        #[serde(deserialize_with = "de_hex")]
        pub mac: Vec<u8>,
        /// Only a prefix of the tag is published (RFC 4231 test case 5).
        pub truncated: bool,
    }

    /// `hkdf_sha256_rfc5869.json`.
    #[derive(Clone, Debug, Deserialize)]
    pub struct HkdfCase {
        pub name: String,
        #[serde(deserialize_with = "de_hex")]
        pub ikm: Vec<u8>,
        #[serde(deserialize_with = "de_hex")]
        pub salt: Vec<u8>,
        #[serde(deserialize_with = "de_hex")]
        pub info: Vec<u8>,
        pub length: usize,
        #[serde(deserialize_with = "de_hex")]
        pub prk: Vec<u8>,
        #[serde(deserialize_with = "de_hex")]
        pub okm: Vec<u8>,
    }

    /// Every `aead_*.json` file.
    #[derive(Clone, Debug, Deserialize)]
    pub struct AeadCase {
        #[serde(default)]
        pub name: Option<String>,
        #[serde(default, rename = "tcId")]
        pub tc_id: Option<u32>,
        #[serde(default)]
        pub comment: Option<String>,
        #[serde(deserialize_with = "de_hex")]
        pub key: Vec<u8>,
        #[serde(deserialize_with = "de_hex")]
        pub nonce: Vec<u8>,
        #[serde(deserialize_with = "de_hex")]
        pub aad: Vec<u8>,
        #[serde(deserialize_with = "de_hex")]
        pub pt: Vec<u8>,
        #[serde(deserialize_with = "de_hex")]
        pub ct: Vec<u8>,
        #[serde(deserialize_with = "de_hex")]
        pub tag: Vec<u8>,
        pub result: Expect,
    }

    impl AeadCase {
        /// `name`, or `tcId N (comment)` for Wycheproof cases.
        pub fn label(&self) -> String {
            label(&self.name, self.tc_id, &self.comment)
        }
    }

    /// Every `ecdsa_*.json` file.
    #[derive(Clone, Debug, Deserialize)]
    pub struct EcdsaCase {
        #[serde(default)]
        pub name: Option<String>,
        #[serde(default, rename = "tcId")]
        pub tc_id: Option<u32>,
        #[serde(default)]
        pub comment: Option<String>,
        #[serde(deserialize_with = "de_hex")]
        pub public_key: Vec<u8>,
        #[serde(deserialize_with = "de_hex")]
        pub msg: Vec<u8>,
        #[serde(deserialize_with = "de_hex")]
        pub sig: Vec<u8>,
        pub result: Expect,
    }

    impl EcdsaCase {
        /// `name`, or `tcId N (comment)` for Wycheproof cases.
        pub fn label(&self) -> String {
            label(&self.name, self.tc_id, &self.comment)
        }
    }

    fn label(name: &Option<String>, tc_id: Option<u32>, comment: &Option<String>) -> String {
        match (name, tc_id) {
            (Some(n), _) => n.clone(),
            (None, Some(id)) => match comment.as_deref() {
                Some(c) if !c.is_empty() => format!("tcId {id} ({c})"),
                _ => format!("tcId {id}"),
            },
            (None, None) => "<unnamed>".to_owned(),
        }
    }

    /// File names, so tests and the vector-integrity test agree.
    pub const HMAC_RFC4231: &str = "hmac_sha256_rfc4231.json";
    pub const HKDF_RFC5869: &str = "hkdf_sha256_rfc5869.json";
    pub const CHACHA_RFC8439: &str = "aead_chacha20poly1305_rfc8439.json";
    pub const CHACHA_WYCHEPROOF: &str = "aead_chacha20poly1305_wycheproof.json";
    pub const GCM_SPEC: &str = "aead_aes256gcm_spec.json";
    pub const GCM_WYCHEPROOF: &str = "aead_aes256gcm_wycheproof.json";
    pub const ECDSA_RFC6979: &str = "ecdsa_p256_rfc6979.json";
    pub const ECDSA_WYCHEPROOF: &str = "ecdsa_p256_wycheproof_p1363.json";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_table_is_dense_and_unknown_maps() {
        for (i, (v, n)) in status::NAMES.iter().enumerate() {
            assert_eq!(*v, i as i32);
            assert_eq!(status_name(*v), *n);
        }
        for s in [-1, 13, 99, i32::MIN, i32::MAX] {
            assert_eq!(status_name(s), status::UNKNOWN_NAME);
        }
    }

    #[test]
    fn in_and_out_pass_null_and_lengths() {
        assert_eq!(In::NULL.raw(), (ptr::null(), 0));
        assert_eq!(In::Null { len: 5 }.raw(), (ptr::null(), 5));
        let b = [1u8, 2, 3];
        let (p, n) = In::from(&b).raw();
        assert!(!p.is_null());
        assert_eq!(n, 3);
        assert!(matches!(In::maybe_null(&[], true), In::Null { len: 0 }));
        assert!(matches!(In::maybe_null(&[], false), In::Bytes(_)));
        let mut o = [0u8; 4];
        assert_eq!(Out::Buf(&mut o).raw().1, 4);
        assert!(Out::Null { len: 7 }.raw().0.is_null());
    }

    #[test]
    fn every_vector_file_parses() {
        use vectors::*;
        let n = load::<File<HmacCase>>(HMAC_RFC4231).cases.len();
        assert_eq!(n, 7);
        assert_eq!(load::<File<HkdfCase>>(HKDF_RFC5869).cases.len(), 3);
        for f in [CHACHA_RFC8439, CHACHA_WYCHEPROOF, GCM_SPEC, GCM_WYCHEPROOF] {
            let file = load::<File<AeadCase>>(f);
            assert!(!file.cases.is_empty(), "{f}");
            for c in &file.cases {
                assert_eq!(c.key.len(), 32, "{f} {}", c.label());
                assert_eq!(c.nonce.len(), 12, "{f} {}", c.label());
                assert_eq!(c.tag.len(), 16, "{f} {}", c.label());
            }
        }
        for f in [ECDSA_RFC6979, ECDSA_WYCHEPROOF] {
            let file = load::<File<EcdsaCase>>(f);
            for c in &file.cases {
                assert_eq!(c.public_key.len(), 65, "{f} {}", c.label());
                assert_eq!(c.sig.len(), 64, "{f} {}", c.label());
            }
        }
    }

    #[test]
    fn key_info_label_helpers() {
        let mut info = prefill_key_info();
        let k = KeyInfo::from_raw(&info);
        assert!(!k.is_zero());
        info.alg = abi::eki_key_alg(0);
        info.label = [0; 65];
        info.label[0] = b'a' as c_char;
        let k = KeyInfo::from_raw(&info);
        assert_eq!(k.label_str(), "a");
        assert!(k.label_nul_padded());
    }
}
