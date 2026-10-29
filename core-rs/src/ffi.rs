//! The C ABI of `libekicore_rs`.
//!
//! This is the only file in the crate that may contain `unsafe`. The declarations in this file
//! and in the `ekicore-abi` crate are the source of `include/ekicore.h`:
//! `scripts/check-header.sh` regenerates the header from them and fails if the committed copy
//! differs.
//!
//! # State
//!
//! `eki_hmac_sha256`, `eki_hmac_sha256_verify`, `eki_hkdf_sha256`, `eki_aead_seal`,
//! `eki_aead_open` and `eki_ecdsa_p256_verify` are implemented, as are the three metadata
//! functions. `eki_ks_close` does nothing, which is correct while `eki_ks_open` never creates a
//! handle. Every other function is a stub that returns `EKI_ERR_UNSUPPORTED` without looking at
//! any argument.
//!
//! # Caller contract
//!
//! The C caller's side of the ABI is specified in `docs/ffi-contract.md` ("Pointer and length
//! rules"). The parts that the `unsafe` code here relies on are restated below, and every
//! `// SAFETY:` comment names the rule it uses. They are stated once, here, rather than in a
//! `# Safety` section on each `extern "C"` function, because cbindgen copies the doc comment of
//! every exported function into the C header, which must stay as it is.
//!
//! - **C1, validity.** For each `(p, n)` pointer and length pair, and for each fixed-size
//!   parameter with its size as `n`, `p` is NULL or points to `n` bytes inside one live
//!   allocation (so `n <= isize::MAX`), readable for an input and writable for an output. When
//!   a parameter has a documented maximum length (`okm_len` 8160, `pt_len` and `ct_len`
//!   `EKI_AEAD_MAX_LEN`, ...), C1 holds only for a length within that maximum: above it the
//!   buffer may be smaller than `n`, and the library must not create a slice over it.
//! - **C2, duration.** That memory stays valid until the call returns, and nothing else (another
//!   thread included) writes it meanwhile, nor reads an output buffer. The library keeps no
//!   pointer after returning.
//! - **C3, no overlap.** No output buffer overlaps any other buffer parameter.
//!
//! A NULL pointer with a non-zero length does not break the contract: the call reports it as
//! `EKI_ERR_NULL_POINTER`. A pointer, NULL or not, that comes with length zero is an empty buffer
//! and is never dereferenced or passed to `from_raw_parts`. Byte buffers have alignment 1, so
//! they carry no alignment requirement.
//!
//! # Shape of an implemented function
//!
//! 1. One `unsafe` block wraps the raw arguments in `Input` and `Output` values. This is the
//!    point where C1 to C3 are relied on; the wrappers keep the pointer, the length and the
//!    maximum the length may have, and dereference nothing.
//! 2. `barrier` runs the body inside `catch_unwind` and maps its outcome to an `eki_status`:
//!    `Ok` is `EKI_OK`, an `Error` maps through `From<Error>`, a panic is `EKI_ERR_INTERNAL`.
//!    On any status other than `EKI_OK` it zero-fills every output it was given, whichever
//!    parameter caused the failure.
//! 3. The body first calls `check_null` on every pointer parameter in parameter order, which is
//!    step 1 of the validation order. Only then does it turn the wrappers into slices with
//!    `bytes`, which rejects a length above its maximum before any slice exists, and call the
//!    safe module, which performs the remaining checks.
//!
//! # Panics
//!
//! A panic in a body is caught by `barrier` and never unwinds into C. This depends on the panic
//! strategy being `unwind`, which the root `Cargo.toml` sets for the release profile (and which
//! is the default for the others). Under `panic = "abort"`, `catch_unwind` has nothing to catch:
//! a panic terminates the whole host process before `barrier` regains control, so the caller
//! receives neither `EKI_ERR_INTERNAL` nor zeroed outputs.

// The C ABI fixes the argument lists, and the stubs ignore their arguments.
#![allow(unused_variables)]
#![allow(clippy::too_many_arguments)]
// A `# Safety` section on each exported function would be copied into the generated C header.
// The shared contract is stated once, in the module documentation and in `docs/ffi-contract.md`.
#![allow(clippy::missing_safety_doc)]

use core::ffi::{CStr, c_char};
use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind};

use ekicore_abi::{
    EKI_ABI_VERSION, EKI_AEAD_TAG_LEN, EKI_HKDF_MAX_INPUT_LEN, EKI_HKDF_MAX_OKM_LEN,
    EKI_HMAC_SHA256_LEN, EKI_P256_PUBLIC_KEY_LEN, EKI_P256_SIGNATURE_LEN, eki_aead_alg,
    eki_key_alg, eki_key_id, eki_key_info, eki_ks, eki_ks_config, eki_status,
};

use crate::error::Error;
use crate::{aead, ecdsa, hkdf, hmac};

/// `eki_version()` result: implementation name, a space, the crate version, and a NUL.
/// cbindgen:ignore
static VERSION: &str = concat!("ekicore-rs ", env!("CARGO_PKG_VERSION"), "\0");

/// Names of the status values, indexed by value.
/// cbindgen:ignore
static STATUS_NAMES: [&CStr; 11] = [
    c"EKI_OK",
    c"EKI_ERR_NULL_POINTER",
    c"EKI_ERR_INVALID_ARGUMENT",
    c"EKI_ERR_BUFFER_TOO_SMALL",
    c"EKI_ERR_UNSUPPORTED",
    c"EKI_ERR_AUTH_FAILED",
    c"EKI_ERR_KEY_NOT_FOUND",
    c"EKI_ERR_KEY_EXISTS",
    c"EKI_ERR_WRONG_KEY_TYPE",
    c"EKI_ERR_BACKEND",
    c"EKI_ERR_INTERNAL",
];

/// Name returned for any integer that is not a status value.
/// cbindgen:ignore
static STATUS_UNKNOWN: &CStr = c"EKI_STATUS_UNKNOWN";

// --- Boundary helpers --------------------------------------------------------------------------

/// Maximum for a buffer whose length has no documented upper bound.
/// cbindgen:ignore
const NO_MAX: usize = usize::MAX;

/// A pointer parameter, as seen by step 1 of the validation order.
trait PointerParam {
    /// `Err(Error::NullPointer)` if the parameter is NULL where the contract requires a pointer.
    fn non_null(&self) -> Result<(), Error>;
}

/// Step 1 of the validation order: the NULL check of every pointer parameter, in the order
/// given, which is the parameter order of the C declaration.
///
/// Every body calls this before anything else, so a NULL pointer is reported even when another
/// parameter also has a bad length or selector.
fn check_null(params: &[&dyn PointerParam]) -> Result<(), Error> {
    params.iter().try_for_each(|param| param.non_null())
}

/// The rule shared by every `(pointer, length)` pair: a non-zero length needs a pointer, a zero
/// length accepts any pointer, NULL included.
fn pair_non_null(is_null: bool, len: usize) -> Result<(), Error> {
    if is_null && len > 0 {
        Err(Error::NullPointer)
    } else {
        Ok(())
    }
}

/// An input buffer: a pointer, its length, and the largest length the parameter accepts.
///
/// Holding one dereferences nothing. `bytes` creates the slice, and only after the NULL rule and
/// the maximum have been checked. The raw pointer makes the type neither `Send` nor `Sync`, so a
/// value cannot be handed to another thread that might outlive the call.
struct Input {
    ptr: *const u8,
    len: usize,
    max: usize,
}

impl Input {
    /// Wraps the input pair `(ptr, len)` whose length may be at most `max`.
    ///
    /// # Safety
    ///
    /// If `len <= max`: `ptr` is NULL or valid for reads of `len` bytes within one allocation,
    /// and nothing writes that memory, for as long as the returned value exists. If `len > max`
    /// nothing is required of `ptr`, which is then never used.
    unsafe fn new(ptr: *const u8, len: usize, max: usize) -> Self {
        Self { ptr, len, max }
    }

    /// Wraps a fixed-size input of `N` bytes. `N` is not zero, so a NULL `ptr` is always
    /// rejected, as the contract requires for fixed-size parameters.
    ///
    /// # Safety
    ///
    /// `ptr` is NULL or valid for reads of `N` bytes within one allocation, and nothing writes
    /// that memory, for as long as the returned value exists.
    unsafe fn fixed<const N: usize>(ptr: *const u8) -> Self {
        const { assert!(N > 0, "a fixed-size input has at least one byte") };
        // SAFETY: with `len == max == N`, the precondition of `Input::new` is exactly this
        // function's precondition, which the caller of `fixed` guarantees.
        unsafe { Self::new(ptr, N, N) }
    }

    /// The input as a slice that borrows `self`, so it cannot outlive the wrapper.
    ///
    /// `(NULL, n > 0)` is `Error::NullPointer`. A length of zero gives `&[]` without using the
    /// pointer. A length above the maximum is `Error::InvalidArgument`, and no slice is created.
    fn bytes(&self) -> Result<&[u8], Error> {
        self.non_null()?;
        if self.len == 0 {
            return Ok(&[]);
        }
        if self.len > self.max {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: `ptr` is non-NULL (`non_null` above) and `0 < len <= max` (checked above), so
        // the precondition of `Input::new`, which the extern function establishes from C1 and C2,
        // makes `ptr` valid for reads of `len` bytes of one allocation (hence `len <= isize::MAX`)
        // with no concurrent writer. `u8` has alignment 1. The slice borrows `self`, which lives
        // no longer than the extern call, so it ends before C2 does. By C3 no output slice of the
        // same call overlaps it.
        Ok(unsafe { core::slice::from_raw_parts(self.ptr, self.len) })
    }
}

impl PointerParam for Input {
    fn non_null(&self) -> Result<(), Error> {
        pair_non_null(self.ptr.is_null(), self.len)
    }
}

/// An output buffer: a pointer, its length, and the largest length the parameter accepts.
///
/// `barrier` owns every `Output` of a call and zero-fills it when the call fails. Because `bytes`
/// takes `&mut self`, at most one slice over the buffer exists at a time, and none is live when
/// `barrier` writes the zeros.
struct Output {
    ptr: *mut u8,
    len: usize,
    max: usize,
}

impl Output {
    /// Wraps the output pair `(ptr, len)` whose length may be at most `max`.
    ///
    /// # Safety
    ///
    /// If `len <= max`: `ptr` is NULL or valid for writes of `len` bytes within one allocation,
    /// and nothing else reads or writes that memory, for as long as the returned value exists. If
    /// `len > max` nothing is required of `ptr`, which is then never used.
    unsafe fn new(ptr: *mut u8, len: usize, max: usize) -> Self {
        Self { ptr, len, max }
    }

    /// Wraps a fixed-size output of `N` bytes. `N` is not zero, so a NULL `ptr` is always
    /// rejected, as the contract requires for fixed-size parameters.
    ///
    /// # Safety
    ///
    /// `ptr` is NULL or valid for writes of `N` bytes within one allocation, and nothing else
    /// reads or writes that memory, for as long as the returned value exists.
    unsafe fn fixed<const N: usize>(ptr: *mut u8) -> Self {
        const { assert!(N > 0, "a fixed-size output has at least one byte") };
        // SAFETY: with `len == max == N`, the precondition of `Output::new` is exactly this
        // function's precondition, which the caller of `fixed` guarantees.
        unsafe { Self::new(ptr, N, N) }
    }

    /// The output as a slice that borrows `self` mutably.
    ///
    /// The same rules as `Input::bytes`: `(NULL, n > 0)` is `Error::NullPointer`, a length of zero
    /// gives an empty slice without using the pointer, a length above the maximum is
    /// `Error::InvalidArgument` and no slice is created.
    fn bytes(&mut self) -> Result<&mut [u8], Error> {
        self.non_null()?;
        if self.len == 0 {
            return Ok(&mut []);
        }
        if self.len > self.max {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: `ptr` is non-NULL (`non_null` above) and `0 < len <= max` (checked above), so
        // the precondition of `Output::new` or `Output::fixed`, which the extern function
        // establishes from C1 and C2, makes `ptr` valid for writes of `len` bytes of one
        // allocation (hence `len <= isize::MAX`) that nothing else accesses. `u8` has alignment 1.
        // The slice borrows `self` mutably, so no second slice over the buffer can exist while it
        // lives, and by C3 no other parameter's slice overlaps it.
        Ok(unsafe { core::slice::from_raw_parts_mut(self.ptr, self.len) })
    }

    /// Zero-fills the buffer if it is non-NULL and its length is within the maximum, the "outputs
    /// on error" rule; otherwise leaves it untouched.
    fn zero(&mut self) {
        if self.ptr.is_null() || self.len == 0 || self.len > self.max {
            return;
        }
        // SAFETY: `ptr` is non-NULL and `0 < len <= max` (checked above), so by the precondition
        // of `Output::new` or `Output::fixed` (from C1 and C2) it is valid for writes of `len`
        // bytes. `zero` takes `&mut self`, so no slice returned by `bytes` is still live: the
        // write aliases nothing in use.
        unsafe { self.ptr.write_bytes(0, self.len) };
    }
}

impl PointerParam for Output {
    fn non_null(&self) -> Result<(), Error> {
        pair_non_null(self.ptr.is_null(), self.len)
    }
}

/// Runs the body of an `extern "C"` function and returns its status. This is the panic barrier:
/// nothing but the returned status leaves it.
///
/// `outputs` are all output buffers of the call. On any status other than `EKI_OK` each of them
/// is zero-filled by `Output::zero`, after the body has returned or unwound, so the rule also
/// holds when the failure was a NULL pointer in another parameter or a caught panic, and a
/// buffer the body had partly written is wiped.
///
/// `AssertUnwindSafe` is sound here. Unwind safety is about code observing, after a caught panic,
/// state that the panicking code left half-updated. After a panic this function observes only
/// `outputs`: their fields are never modified (`bytes` and `zero` only read them), and the bytes
/// they point to, which may be half-written, are overwritten with zeros before the status is
/// returned. Everything else the body used is either its own locals, dropped during unwinding
/// (zeroizing types wipe themselves then), or caller memory it only reads. The body is not run
/// again. A later body that captures shared state across calls, such as a key store behind a
/// mutex, must keep that state consistent at every point where it can panic; this argument does
/// not cover it.
fn barrier<const N: usize>(
    mut outputs: [Output; N],
    body: impl FnOnce(&mut [Output; N]) -> Result<(), Error>,
) -> eki_status {
    let status = match catch_unwind(AssertUnwindSafe(|| body(&mut outputs))) {
        Ok(Ok(())) => return eki_status::EKI_OK,
        Ok(Err(error)) => eki_status::from(error),
        Err(payload) => {
            drop_panic_payload(payload);
            eki_status::EKI_ERR_INTERNAL
        }
    };
    for output in &mut outputs {
        output.zero();
    }
    status
}

/// Disposes of the payload of a caught panic without letting a second panic escape.
///
/// The payload is a value of any type (`std::panic::panic_any`), and its destructor may itself
/// panic. A panic escaping here would unwind out of the `extern "C"` function, which Rust turns
/// into an abort of the whole process. So the payload is dropped under `catch_unwind`; if its
/// destructor panics, that panic's payload is disposed of the same way, a bounded number of
/// times. A payload still left after that is leaked with `mem::forget`, the one way to dispose of
/// a value without running code that could panic.
fn drop_panic_payload(mut payload: Box<dyn Any + Send>) {
    // Ordinary payloads (`&str`, `String`) drop at the first attempt; the bound only matters for
    // a chain of destructors that keep panicking.
    const ATTEMPTS: usize = 4;
    for _ in 0..ATTEMPTS {
        // `AssertUnwindSafe`: if the destructor panics, nothing of the dropped value is used
        // again; only the new payload is, and it is a fresh, fully formed value.
        match catch_unwind(AssertUnwindSafe(move || drop(payload))) {
            Ok(()) => return,
            Err(next) => payload = next,
        }
    }
    core::mem::forget(payload);
}

/// Returns the ABI version this library implements (`EKI_ABI_VERSION`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_abi_version() -> u32 {
    EKI_ABI_VERSION
}

/// Returns the implementation name and version, for example `ekicore-rs 0.1.0`.
/// The string has static storage and is never NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_version() -> *const c_char {
    VERSION.as_ptr().cast()
}

/// Returns the identifier of a status value, for example `EKI_ERR_AUTH_FAILED`, or
/// `EKI_STATUS_UNKNOWN` for any other integer. The string has static storage and is never NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_status_name(status: i32) -> *const c_char {
    let name = usize::try_from(status)
        .ok()
        .and_then(|index| STATUS_NAMES.get(index).copied())
        .unwrap_or(STATUS_UNKNOWN);
    name.as_ptr()
}

/// Computes HMAC-SHA256 of `msg` under `key` and writes the 32-byte tag to `out`.
/// `key_len` must be non-zero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_hmac_sha256(
    key: *const u8,
    key_len: usize,
    msg: *const u8,
    msg_len: usize,
    out: *mut u8,
) -> eki_status {
    // SAFETY: the C caller guarantees C1 to C3 for `key`/`key_len`, `msg`/`msg_len` (no maximum)
    // and the 32-byte `out`, which are the preconditions of `Input::new` and `Output::fixed`. The
    // wrappers are locals of this call, so they do not outlive that guarantee.
    let (key, msg, out) = unsafe {
        (
            Input::new(key, key_len, NO_MAX),
            Input::new(msg, msg_len, NO_MAX),
            Output::fixed::<EKI_HMAC_SHA256_LEN>(out),
        )
    };
    barrier([out], |[out]| {
        check_null(&[&key, &msg, out])?;
        let tag = hmac::hmac_sha256(key.bytes()?, msg.bytes()?)?;
        out.bytes()?.copy_from_slice(&tag);
        Ok(())
    })
}

/// Compares `tag`, which must be exactly 32 bytes, with HMAC-SHA256 of `msg` under `key` in
/// constant time. A mismatch returns `EKI_ERR_AUTH_FAILED`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_hmac_sha256_verify(
    key: *const u8,
    key_len: usize,
    msg: *const u8,
    msg_len: usize,
    tag: *const u8,
    tag_len: usize,
) -> eki_status {
    // SAFETY: the C caller guarantees C1 and C2 for `key`/`key_len`, `msg`/`msg_len` and
    // `tag`/`tag_len`, which are the preconditions of `Input::new`. None of the three lengths has
    // a documented maximum (a `tag_len` other than 32 is a format error found by the safe module,
    // not a cap), so C1 holds for any length passed. The wrappers are locals of this call, so they
    // do not outlive that guarantee.
    let (key, msg, tag) = unsafe {
        (
            Input::new(key, key_len, NO_MAX),
            Input::new(msg, msg_len, NO_MAX),
            Input::new(tag, tag_len, NO_MAX),
        )
    };
    barrier([], |[]| {
        check_null(&[&key, &msg, &tag])?;
        hmac::hmac_sha256_verify(key.bytes()?, msg.bytes()?, tag.bytes()?)
    })
}

/// Derives `okm_len` bytes (1 to 8160) with HKDF-SHA256 (RFC 5869). An empty `salt` selects the
/// RFC default salt.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_hkdf_sha256(
    ikm: *const u8,
    ikm_len: usize,
    salt: *const u8,
    salt_len: usize,
    info: *const u8,
    info_len: usize,
    okm: *mut u8,
    okm_len: usize,
) -> eki_status {
    // SAFETY: the C caller guarantees C1 to C3 for `ikm`/`ikm_len`, `salt`/`salt_len` and
    // `info`/`info_len` (each with the maximum `EKI_HKDF_MAX_INPUT_LEN`) and for `okm`/`okm_len`
    // (maximum `EKI_HKDF_MAX_OKM_LEN`), which are the preconditions of `Input::new` and
    // `Output::new`. C1 holds only for a length within its maximum; above it the preconditions
    // require nothing of the pointer, and `bytes` refuses the length before creating a slice. The
    // wrappers are locals of this call, so they do not outlive that guarantee.
    let (ikm, salt, info, okm) = unsafe {
        (
            Input::new(ikm, ikm_len, EKI_HKDF_MAX_INPUT_LEN),
            Input::new(salt, salt_len, EKI_HKDF_MAX_INPUT_LEN),
            Input::new(info, info_len, EKI_HKDF_MAX_INPUT_LEN),
            Output::new(okm, okm_len, EKI_HKDF_MAX_OKM_LEN),
        )
    };
    barrier([okm], |[okm]| {
        check_null(&[&ikm, &salt, &info, okm])?;
        hkdf::hkdf_sha256(ikm.bytes()?, salt.bytes()?, info.bytes()?, okm.bytes()?)
    })
}

/// Encrypts `pt` into `ct_out` (`pt_len` bytes) and writes the 16-byte tag to `tag_out`.
/// `key_len` must be 32 and `nonce_len` 12.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_aead_seal(
    alg: eki_aead_alg,
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    pt: *const u8,
    pt_len: usize,
    ct_out: *mut u8,
    tag_out: *mut u8,
) -> eki_status {
    // SAFETY: the C caller guarantees C1 to C3 for `key`/`key_len`, `nonce`/`nonce_len` and
    // `aad`/`aad_len` (no maximum), for `pt`/`pt_len` and `ct_out`, which is sized by `pt_len`
    // (each with the maximum `aead::MAX_LEN`), and for the 16-byte `tag_out`, which are the
    // preconditions of `Input::new`, `Output::new` and `Output::fixed`. C1 holds for `pt` and
    // `ct_out` only for a length within the maximum; above it the preconditions require nothing
    // of either pointer, and `bytes` refuses the length before creating a slice. The wrappers are
    // locals of this call, so they do not outlive that guarantee.
    let (key, nonce, aad, pt, ct_out, tag_out) = unsafe {
        (
            Input::new(key, key_len, NO_MAX),
            Input::new(nonce, nonce_len, NO_MAX),
            Input::new(aad, aad_len, NO_MAX),
            Input::new(pt, pt_len, aead::MAX_LEN),
            Output::new(ct_out, pt_len, aead::MAX_LEN),
            Output::fixed::<EKI_AEAD_TAG_LEN>(tag_out),
        )
    };
    barrier([ct_out, tag_out], |[ct_out, tag_out]| {
        check_null(&[&key, &nonce, &aad, &pt, ct_out, tag_out])?;
        aead::seal(
            alg,
            key.bytes()?,
            nonce.bytes()?,
            aad.bytes()?,
            pt.bytes()?,
            ct_out.bytes()?,
            tag_out.bytes()?,
        )
    })
}

/// Verifies the 16-byte `tag` and decrypts `ct` into `pt_out` (`ct_len` bytes). On any failure
/// `pt_out` is zero-filled.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_aead_open(
    alg: eki_aead_alg,
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    ct: *const u8,
    ct_len: usize,
    tag: *const u8,
    pt_out: *mut u8,
) -> eki_status {
    // SAFETY: the C caller guarantees C1 to C3 for `key`/`key_len`, `nonce`/`nonce_len` and
    // `aad`/`aad_len` (no maximum), for `ct`/`ct_len` and `pt_out`, which is sized by `ct_len`
    // (each with the maximum `aead::MAX_LEN`), and for the 16-byte `tag`, which are the
    // preconditions of `Input::new`, `Input::fixed` and `Output::new`. C1 holds for `ct` and
    // `pt_out` only for a length within the maximum; above it the preconditions require nothing
    // of either pointer, and `bytes` refuses the length before creating a slice. The wrappers are
    // locals of this call, so they do not outlive that guarantee.
    let (key, nonce, aad, ct, tag, pt_out) = unsafe {
        (
            Input::new(key, key_len, NO_MAX),
            Input::new(nonce, nonce_len, NO_MAX),
            Input::new(aad, aad_len, NO_MAX),
            Input::new(ct, ct_len, aead::MAX_LEN),
            Input::fixed::<EKI_AEAD_TAG_LEN>(tag),
            Output::new(pt_out, ct_len, aead::MAX_LEN),
        )
    };
    barrier([pt_out], |[pt_out]| {
        check_null(&[&key, &nonce, &aad, &ct, &tag, pt_out])?;
        aead::open(
            alg,
            key.bytes()?,
            nonce.bytes()?,
            aad.bytes()?,
            ct.bytes()?,
            tag.bytes()?,
            pt_out.bytes()?,
        )
    })
}

/// Verifies a 64-byte `r || s` ECDSA P-256 signature over SHA-256 of `msg` against a 65-byte
/// SEC1 uncompressed public key.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_ecdsa_p256_verify(
    public_key: *const u8,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
) -> eki_status {
    // SAFETY: the C caller guarantees C1 and C2 for the 65-byte `public_key`, for `msg`/`msg_len`
    // (no maximum) and for the 64-byte `sig`, which are the preconditions of `Input::fixed` and
    // `Input::new`. The wrappers are locals of this call, so they do not outlive that guarantee.
    let (public_key, msg, sig) = unsafe {
        (
            Input::fixed::<EKI_P256_PUBLIC_KEY_LEN>(public_key),
            Input::new(msg, msg_len, NO_MAX),
            Input::fixed::<EKI_P256_SIGNATURE_LEN>(sig),
        )
    };
    barrier([], |[]| {
        check_null(&[&public_key, &msg, &sig])?;
        ecdsa::p256_verify(public_key.bytes()?, msg.bytes()?, sig.bytes()?)
    })
}

/// Opens a key store as described by `config` and stores the handle in `*out`.
/// `*out` is NULL on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_ks_open(
    config: *const eki_ks_config,
    out: *mut *mut eki_ks,
) -> eki_status {
    eki_status::EKI_ERR_UNSUPPORTED
}

/// Closes the store and frees the handle. Passing NULL is allowed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_ks_close(ks: *mut eki_ks) {}

/// Copies the most recent error message of the handle into `buf` with snprintf semantics and
/// returns its full length, excluding the NUL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_ks_last_error_message(
    ks: *const eki_ks,
    buf: *mut c_char,
    buf_len: usize,
) -> usize {
    0
}

/// Generates a key of algorithm `alg` with a label of 1 to 64 printable bytes and returns its
/// new id in `id_out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_ks_generate(
    ks: *mut eki_ks,
    alg: eki_key_alg,
    label: *const c_char,
    id_out: *mut eki_key_id,
) -> eki_status {
    eki_status::EKI_ERR_UNSUPPORTED
}

/// Reports the algorithm and label of the key with the given id.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_ks_get_info(
    ks: *mut eki_ks,
    id: *const eki_key_id,
    info_out: *mut eki_key_info,
) -> eki_status {
    eki_status::EKI_ERR_UNSUPPORTED
}

/// Writes the 65-byte SEC1 uncompressed public key of an ECDSA P-256 key to `out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_ks_get_public_key(
    ks: *mut eki_ks,
    id: *const eki_key_id,
    out: *mut u8,
) -> eki_status {
    eki_status::EKI_ERR_UNSUPPORTED
}

/// Signs SHA-256 of `msg` with an ECDSA P-256 key and writes the 64-byte `r || s` signature to
/// `sig_out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_ks_sign(
    ks: *mut eki_ks,
    id: *const eki_key_id,
    msg: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
) -> eki_status {
    eki_status::EKI_ERR_UNSUPPORTED
}

/// Computes HMAC-SHA256 of `msg` under a stored HMAC key and writes the 32-byte tag to `out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_ks_hmac_sha256(
    ks: *mut eki_ks,
    id: *const eki_key_id,
    msg: *const u8,
    msg_len: usize,
    out: *mut u8,
) -> eki_status {
    eki_status::EKI_ERR_UNSUPPORTED
}

/// Wraps the AES or HMAC key `key_id` under the AES key `kek_id` (RFC 3394) and writes the
/// 40-byte blob to `out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_ks_wrap(
    ks: *mut eki_ks,
    kek_id: *const eki_key_id,
    key_id: *const eki_key_id,
    out: *mut u8,
) -> eki_status {
    eki_status::EKI_ERR_UNSUPPORTED
}

/// Unwraps the 40-byte `blob` under the AES key `kek_id` and stores the result as a new key with
/// algorithm `alg`, label `label` and id `id`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_ks_unwrap(
    ks: *mut eki_ks,
    kek_id: *const eki_key_id,
    blob: *const u8,
    blob_len: usize,
    alg: eki_key_alg,
    label: *const c_char,
    id: *const eki_key_id,
) -> eki_status {
    eki_status::EKI_ERR_UNSUPPORTED
}

/// Destroys the key with the given id, including both halves of a key pair.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_ks_destroy(ks: *mut eki_ks, id: *const eki_key_id) -> eki_status {
    eki_status::EKI_ERR_UNSUPPORTED
}

/// Generates a hybrid X25519 + ML-KEM-768 key pair. Returns `EKI_ERR_UNSUPPORTED` when the
/// library is built without hybrid support.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_hybrid_kem_keygen(pk_out: *mut u8, sk_out: *mut u8) -> eki_status {
    eki_status::EKI_ERR_UNSUPPORTED
}

/// Encapsulates a fresh shared secret to `pk`: writes the ciphertext to `ct_out` and the shared
/// secret to `ss_out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_hybrid_kem_encap(
    pk: *const u8,
    ct_out: *mut u8,
    ss_out: *mut u8,
) -> eki_status {
    eki_status::EKI_ERR_UNSUPPORTED
}

/// Recovers the shared secret from `ct` with the secret key `sk` and writes it to `ss_out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_hybrid_kem_decap(
    sk: *const u8,
    ct: *const u8,
    ss_out: *mut u8,
) -> eki_status {
    eki_status::EKI_ERR_UNSUPPORTED
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte the test buffers are pre-filled with, so writes and zero-fills are both visible.
    const FILL: u8 = 0xA5;

    #[test]
    fn null_with_length_zero_is_an_empty_input() {
        // SAFETY: the length is 0, so `Input::new` requires nothing of the pointer.
        let input = unsafe { Input::new(core::ptr::null(), 0, NO_MAX) };
        assert_eq!(input.bytes(), Ok(&[][..]));
    }

    #[test]
    fn dangling_with_length_zero_is_an_empty_input() {
        // A non-NULL pointer that points nowhere: with length 0 it must not be used.
        let dangling = core::ptr::NonNull::<u8>::dangling().as_ptr();
        // SAFETY: the length is 0, so `Input::new` requires nothing of the pointer.
        let input = unsafe { Input::new(dangling, 0, NO_MAX) };
        assert_eq!(input.bytes(), Ok(&[][..]));
    }

    #[test]
    fn null_with_non_zero_length_is_null_pointer() {
        // SAFETY: the pointer is NULL, which the preconditions allow; it is never dereferenced.
        let (input, mut output) = unsafe {
            (
                Input::new(core::ptr::null(), 1, NO_MAX),
                Output::new(core::ptr::null_mut(), 1, NO_MAX),
            )
        };
        assert_eq!(input.bytes(), Err(Error::NullPointer));
        assert_eq!(output.bytes(), Err(Error::NullPointer));
        assert_eq!(check_null(&[&input]), Err(Error::NullPointer));
        assert_eq!(check_null(&[&output]), Err(Error::NullPointer));
    }

    #[test]
    fn fixed_input_is_never_empty_and_is_rejected_when_null() {
        let buf = [1_u8, 2, 3, 4];
        // SAFETY: `buf` is a live local array of 4 bytes that nothing writes while `input` exists.
        let input = unsafe { Input::fixed::<4>(buf.as_ptr()) };
        assert_eq!(check_null(&[&input]), Ok(()));
        assert_eq!(input.bytes(), Ok(&buf[..]));

        // SAFETY: the pointer is NULL, which the preconditions allow; it is never dereferenced.
        let null = unsafe { Input::fixed::<4>(core::ptr::null()) };
        assert_eq!(check_null(&[&null]), Err(Error::NullPointer));
        assert_eq!(null.bytes(), Err(Error::NullPointer));
    }

    #[test]
    fn null_with_length_zero_is_an_empty_output() {
        // SAFETY: the length is 0, so `Output::new` requires nothing of the pointer.
        let mut output = unsafe { Output::new(core::ptr::null_mut(), 0, NO_MAX) };
        assert_eq!(output.bytes().map(|b| b.len()), Ok(0));
        assert_eq!(check_null(&[&output]), Ok(()));
    }

    #[test]
    fn null_check_precedes_the_maximum() {
        // A NULL pointer whose length is also above the maximum is reported as NULL.
        // SAFETY: the pointer is NULL and the length above the maximum; neither is used.
        let input = unsafe { Input::new(core::ptr::null(), 9, 8) };
        assert_eq!(input.bytes(), Err(Error::NullPointer));
    }

    #[test]
    fn input_above_its_maximum_is_invalid_without_a_slice() {
        let buf = [FILL; 1];
        // SAFETY: the length exceeds the maximum, so nothing is required of the pointer. The
        // 1-byte buffer is smaller than the declared length; under Miri a slice over it would be
        // reported.
        let input = unsafe { Input::new(buf.as_ptr(), 1000, 100) };
        assert_eq!(check_null(&[&input]), Ok(()));
        assert_eq!(input.bytes(), Err(Error::InvalidArgument));
    }

    #[test]
    fn ok_leaves_outputs_as_written() {
        let mut fixed = [FILL; 4];
        let mut var = [FILL; 6];
        // SAFETY: both pointers come from live local arrays of the lengths passed, which are not
        // otherwise accessed until `barrier` returns.
        let outputs = unsafe {
            [
                Output::fixed::<4>(fixed.as_mut_ptr()),
                Output::new(var.as_mut_ptr(), 6, 8),
            ]
        };
        let status = barrier(outputs, |[a, b]| {
            a.bytes()?.fill(1);
            b.bytes()?.fill(2);
            Ok(())
        });
        assert_eq!(status, eki_status::EKI_OK);
        assert_eq!(fixed, [1; 4]);
        assert_eq!(var, [2; 6]);
    }

    #[test]
    fn error_status_zeroes_outputs() {
        let mut fixed = [FILL; 4];
        let mut var = [FILL; 6];
        // SAFETY: as in `ok_leaves_outputs_as_written`.
        let outputs = unsafe {
            [
                Output::fixed::<4>(fixed.as_mut_ptr()),
                Output::new(var.as_mut_ptr(), 6, 8),
            ]
        };
        let status = barrier(outputs, |[a, b]| {
            a.bytes()?.fill(1);
            b.bytes()?.fill(2);
            Err(Error::AuthFailed)
        });
        assert_eq!(status, eki_status::EKI_ERR_AUTH_FAILED);
        assert_eq!(fixed, [0; 4]);
        assert_eq!(var, [0; 6]);
    }

    #[test]
    fn null_pointer_in_another_parameter_zeroes_outputs() {
        let mut out = [FILL; 4];
        // SAFETY: the input is NULL and never dereferenced; `out` is a live local array of 4
        // bytes, not otherwise accessed until `barrier` returns.
        let (input, out_param) = unsafe {
            (
                Input::new(core::ptr::null(), 3, NO_MAX),
                Output::fixed::<4>(out.as_mut_ptr()),
            )
        };
        let status = barrier([out_param], |[out_param]| {
            check_null(&[&input, out_param])?;
            unreachable!("check_null reports the NULL input");
        });
        assert_eq!(status, eki_status::EKI_ERR_NULL_POINTER);
        assert_eq!(out, [0; 4]);
    }

    #[test]
    fn null_output_is_skipped_on_error() {
        // SAFETY: the pointer is NULL; `Output::zero` must skip it rather than write through it.
        let output = unsafe { Output::fixed::<4>(core::ptr::null_mut()) };
        let status = barrier([output], |[output]| {
            check_null(&[output])?;
            Ok(())
        });
        assert_eq!(status, eki_status::EKI_ERR_NULL_POINTER);
    }

    #[test]
    fn panic_becomes_internal_and_zeroes_outputs() {
        let mut fixed = [FILL; 4];
        let mut var = [FILL; 6];
        // SAFETY: as in `ok_leaves_outputs_as_written`.
        let outputs = unsafe {
            [
                Output::fixed::<4>(fixed.as_mut_ptr()),
                Output::new(var.as_mut_ptr(), 6, 8),
            ]
        };
        let status = barrier(outputs, |[a, b]| {
            a.bytes()?.fill(1);
            b.bytes()?.fill(2);
            panic!("deliberate panic inside a barrier body");
        });
        assert_eq!(status, eki_status::EKI_ERR_INTERNAL);
        assert_eq!(fixed, [0; 4]);
        assert_eq!(var, [0; 6]);
    }

    #[test]
    fn panicking_payload_destructor_is_contained() {
        /// A panic payload whose destructor panics again.
        struct PanicsOnDrop;
        impl Drop for PanicsOnDrop {
            fn drop(&mut self) {
                panic!("deliberate panic in a payload destructor");
            }
        }
        let status = barrier([], |[]| std::panic::panic_any(PanicsOnDrop));
        assert_eq!(status, eki_status::EKI_ERR_INTERNAL);
    }

    #[test]
    fn output_above_its_maximum_is_left_untouched() {
        let mut fixed = [FILL; 4];
        let mut var = [FILL; 4];
        // SAFETY: `fixed` is a live local array of 4 bytes. The variable-length output declares
        // 1000 bytes against a maximum of 100, so nothing is required of its pointer: the buffer
        // behind it has only 4 bytes, and under Miri any slice or write over 1000 bytes would be
        // reported.
        let outputs = unsafe {
            [
                Output::fixed::<4>(fixed.as_mut_ptr()),
                Output::new(var.as_mut_ptr(), 1000, 100),
            ]
        };
        let status = barrier(outputs, |[a, b]| {
            check_null(&[&*a, &*b])?;
            a.bytes()?.fill(1);
            b.bytes()?.fill(2);
            Ok(())
        });
        assert_eq!(status, eki_status::EKI_ERR_INVALID_ARGUMENT);
        assert_eq!(fixed, [0; 4]);
        assert_eq!(var, [FILL; 4]);
    }
}
