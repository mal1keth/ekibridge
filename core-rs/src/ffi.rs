//! The C ABI of `libekicore_rs`.
//!
//! This is the only file in the crate that may contain `unsafe`. The declarations in this file
//! and in the `ekicore-abi` crate are the source of `include/ekicore.h`:
//! `scripts/check-header.sh` regenerates the header from them and fails if the committed copy
//! differs.
//!
//! # State
//!
//! Every function is implemented. The key store functions serve the software backend and, with
//! the `pkcs11` feature (on by default), the PKCS#11 backend; without the feature `eki_ks_open`
//! answers `EKI_ERR_UNSUPPORTED` for `EKI_KS_PKCS11` before it looks at any configuration field.
//! The three hybrid KEM functions are declared in every build and check their pointers in every
//! build. With the `pq` feature (off by default) they then call the `pq` module; without it they
//! answer `EKI_ERR_UNSUPPORTED`, and `barrier` zero-fills their outputs as for any other error.
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
//! - **C4, structs.** A non-NULL pointer to a struct or pointer parameter (`const eki_key_id *`,
//!   `eki_key_id *`, `eki_key_info *`, `const eki_ks_config *`, `eki_ks **`) is aligned for its
//!   type and valid, by C1 and C2, for one value of it: its `sizeof` bytes in one live
//!   allocation, holding an initialised value for an input. The string fields of an
//!   `eki_ks_config` are dereferenced only when its `backend` is `EKI_KS_PKCS11` and the library
//!   has the PKCS#11 backend; otherwise they may hold any value.
//! - **C5, handles.** A non-NULL `eki_ks *` is a value `eki_ks_open` returned that has not been
//!   passed to `eki_ks_close`. Any number of threads may use one handle at the same time;
//!   `eki_ks_close` does not run at the same time as any other call on that handle, and the
//!   handle is not used after it.
//! - **C6, bounded strings.** A non-NULL `label` points to a NUL-terminated string, or to at
//!   least 65 readable bytes; the library reads up to the first NUL or 65 bytes, whichever comes
//!   first, and nothing writes those bytes during the call. The same holds for the
//!   `pkcs11_token_label` (33 bytes: the 32 of the longest label and its NUL) and the
//!   `pkcs11_user_pin` (256 bytes) of a PKCS#11 configuration.
//! - **C7, module path.** A non-NULL `pkcs11_module_path` of a PKCS#11 configuration points to
//!   a NUL-terminated string that nothing writes during the call. The contract sets no maximum
//!   length, so the library scans to the NUL without a bound; the C++ library reads the path the
//!   same way (as a `std::string` built from the C string), so both accept the same paths.
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
//! A key store function differs in step 3 only. `HandleIn::begin` checks `ks` first, then takes
//! the handle's lock and resets the last-error message; `check_null` then covers the remaining
//! pointer parameters in parameter order. The status is the one a single `check_null` over all
//! parameters would give, and a call that fails on a NULL `id` or `label` still resets the
//! message, as plan 4.2 ("Last error") requires of every store call. The body then calls the
//! store logic (`keystore::Store`) with the lock held, and writes the outputs.
//! `eki_ks_last_error_message` and `eki_ks_close` return no status, so they use
//! `contain_panic`, the panic barrier without the status mapping.
//!
//! # Panics
//!
//! A panic in a body is caught by `barrier` (or `contain_panic`) and never unwinds into C. This depends on the panic
//! strategy being `unwind`, which the root `Cargo.toml` sets for the release profile (and which
//! is the default for the others). Under `panic = "abort"`, `catch_unwind` has nothing to catch:
//! a panic terminates the whole host process before `barrier` regains control, so the caller
//! receives neither `EKI_ERR_INTERNAL` nor zeroed outputs.

// The C ABI fixes the argument lists.
#![allow(clippy::too_many_arguments)]
// A `# Safety` section on each exported function would be copied into the generated C header.
// The shared contract is stated once, in the module documentation and in `docs/ffi-contract.md`.
#![allow(clippy::missing_safety_doc)]

use core::ffi::{CStr, c_char};
use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::MutexGuard;

use ekicore_abi::{
    EKI_ABI_VERSION, EKI_AEAD_TAG_LEN, EKI_HKDF_MAX_INPUT_LEN, EKI_HKDF_MAX_OKM_LEN,
    EKI_HMAC_SHA256_LEN, EKI_HYBRID_CT_LEN, EKI_HYBRID_PK_LEN, EKI_HYBRID_SK_LEN,
    EKI_HYBRID_SS_LEN, EKI_LABEL_MAX_LEN, EKI_P256_PUBLIC_KEY_LEN, EKI_P256_SIGNATURE_LEN,
    EKI_WRAPPED_KEY_LEN, eki_aead_alg, eki_key_alg, eki_key_id, eki_key_info, eki_ks,
    eki_ks_config, eki_status,
};
#[cfg(feature = "pq")]
use secrecy::ExposeSecret;

use crate::error::Error;
use crate::keystore::{self, Handle, KeyId, Store};
#[cfg(feature = "pq")]
use crate::pq;
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
}

impl PointerParam for Output {
    fn non_null(&self) -> Result<(), Error> {
        pair_non_null(self.ptr.is_null(), self.len)
    }
}

/// An output parameter, as seen by the "outputs on error" rule.
trait OutputParam: PointerParam {
    /// Zero-fills the output if the rule covers it; otherwise leaves it untouched.
    fn zero(&mut self);
}

impl OutputParam for Output {
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

/// The outputs of a function that has none, for `barrier`.
/// cbindgen:ignore
const NO_OUTPUTS: [Output; 0] = [];

/// Runs the body of an `extern "C"` function and returns its status. This is the panic barrier:
/// nothing but the returned status leaves it.
///
/// `outputs` are all output parameters of the call, of one kind (byte buffers, or one struct
/// output). On any status other than `EKI_OK` each of them is zero-filled by
/// `OutputParam::zero`, after the body has returned or unwound, so the rule also holds when the
/// failure was a NULL pointer in another parameter or a caught panic, and an output the body had
/// partly written is wiped. A panic becomes `EKI_ERR_INTERNAL` through `contain_panic`.
fn barrier<O: OutputParam, const N: usize>(
    mut outputs: [O; N],
    body: impl FnOnce(&mut [O; N]) -> Result<(), Error>,
) -> eki_status {
    let status = contain_panic(eki_status::EKI_ERR_INTERNAL, || {
        body(&mut outputs).map_or_else(eki_status::from, |()| eki_status::EKI_OK)
    });
    if status != eki_status::EKI_OK {
        for output in &mut outputs {
            output.zero();
        }
    }
    status
}

/// Runs `body` and returns its result, or `on_panic` if it panics. Nothing unwinds out of this
/// function: the payload of a caught panic is disposed of by `drop_panic_payload`. `barrier` is
/// built on it; the two functions that return no status use it directly.
///
/// `AssertUnwindSafe` is sound here. Unwind safety is about code observing, after a caught panic,
/// state that the panicking code left half-updated. After a panic, the callers observe only their
/// output parameters: the wrappers' fields are never modified (`bytes`, `write` and `zero` only
/// read them), and the memory they point to, which may be half-written, is overwritten (with
/// zeros by `barrier`, with `""` by `eki_ks_last_error_message`) before the function returns.
/// Everything else a body uses is its own locals, dropped during unwinding (zeroizing types wipe
/// themselves then), caller memory it only reads, or a key store reached through a handle. The
/// store is shared across calls and outlives the panic: it is covered by the argument at
/// `keystore::Handle::lock`, which shows that every point where a store operation can panic
/// leaves the store consistent, so recovering its poisoned lock is sound. The body is not run
/// again.
fn contain_panic<T>(on_panic: T, body: impl FnOnce() -> T) -> T {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(value) => value,
        Err(payload) => {
            drop_panic_payload(payload);
            on_panic
        }
    }
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

// --- Key store helpers ---------------------------------------------------------------------------

/// Number of label bytes the library may read: the 64 of the longest label and its NUL.
/// cbindgen:ignore
const LABEL_SCAN_LEN: usize = EKI_LABEL_MAX_LEN + 1;

/// Number of PKCS#11 token label bytes the library may read: the 32 of the longest label and
/// its NUL.
/// cbindgen:ignore
const TOKEN_LABEL_SCAN_LEN: usize = keystore::PKCS11_TOKEN_LABEL_MAX_LEN + 1;

/// Number of PKCS#11 user PIN bytes the library may read: the 255 of the longest PIN and its
/// NUL.
/// cbindgen:ignore
const USER_PIN_SCAN_LEN: usize = keystore::PKCS11_USER_PIN_MAX_LEN + 1;

/// A key store handle parameter: `eki_ks *`, or `const eki_ks *` for `eki_ks_last_error_message`.
///
/// Holding one dereferences nothing. `get` turns it into a shared reference to the [`Handle`] the
/// pointer really points to, only after the NULL check.
struct HandleIn {
    ptr: *const eki_ks,
}

impl HandleIn {
    /// Wraps the handle pointer `ptr`.
    ///
    /// # Safety
    ///
    /// `ptr` is NULL, or a pointer `eki_ks_open` returned that has not been passed to
    /// `eki_ks_close`, and `eki_ks_close` is not called on it, for as long as the returned value
    /// exists.
    unsafe fn new(ptr: *const eki_ks) -> Self {
        Self { ptr }
    }

    /// The handle, borrowed for no longer than `self`. NULL is `Error::NullPointer`.
    fn get(&self) -> Result<&Handle, Error> {
        if self.ptr.is_null() {
            return Err(Error::NullPointer);
        }
        // SAFETY: `ptr` is non-NULL (checked above), so by the precondition of `HandleIn::new`
        // (from C5) it is the pointer `eki_ks_open` made with `Box::into_raw` from a
        // `Box<Handle>` (cast to `eki_ks`), which is non-dangling and aligned for `Handle`, and
        // the box has not been freed. `eki_ks_close` is the only code that frees it or creates a
        // unique reference to it, and by C5 it does not run during this call. Every other access
        // is through a shared reference like this one, and `Handle`'s mutable state is behind its
        // mutex, so shared references from several threads at once are sound (`Handle` is
        // `Sync`). The reference borrows `self`, a local of the extern call, so it ends before the
        // call returns.
        Ok(unsafe { &*self.ptr.cast::<Handle>() })
    }

    /// Step 1 for `ks`, then the start of a store operation: the NULL check, then the handle's
    /// lock, which also resets the last-error message (`Handle::begin`). The guard keeps the
    /// handle locked until the body ends.
    fn begin(&self) -> Result<MutexGuard<'_, Store>, Error> {
        Ok(self.get()?.begin())
    }
}

impl PointerParam for HandleIn {
    fn non_null(&self) -> Result<(), Error> {
        pair_non_null(self.ptr.is_null(), 1)
    }
}

/// A pointer to one C value the call reads: `const eki_key_id *` or `const eki_ks_config *`.
///
/// Holding one dereferences nothing; `read` copies the value out after the NULL check, so the
/// body works on its own copy.
struct StructIn<T: Copy> {
    ptr: *const T,
}

impl<T: Copy> StructIn<T> {
    /// Wraps the input pointer `ptr`.
    ///
    /// # Safety
    ///
    /// `ptr` is NULL, or aligned for `T` and valid for reads of one initialised `T` within one
    /// allocation that nothing writes, for as long as the returned value exists.
    unsafe fn new(ptr: *const T) -> Self {
        Self { ptr }
    }

    /// A copy of the value. NULL is `Error::NullPointer`.
    fn read(&self) -> Result<T, Error> {
        self.non_null()?;
        // SAFETY: `ptr` is non-NULL (`non_null` above), so by the precondition of
        // `StructIn::new` (from C4, C1 and C2) it is aligned and valid for reads of one
        // initialised `T` with no concurrent writer. The read is a typed copy of a `Copy` value:
        // struct padding is not read as bytes.
        Ok(unsafe { self.ptr.read() })
    }
}

impl<T: Copy> PointerParam for StructIn<T> {
    fn non_null(&self) -> Result<(), Error> {
        pair_non_null(self.ptr.is_null(), 1)
    }
}

/// A C type whose all-zero byte pattern is a valid value, so an output of it can be zero-filled
/// over its whole size, padding included ("outputs on error").
///
/// # Safety
///
/// Every byte of the type may be zero at once and the result is a valid value of the type.
unsafe trait ZeroFill: Copy {}

// SAFETY: `eki_key_id` is `#[repr(C)]` around `[u8; 16]`, and zero is a valid `u8`.
unsafe impl ZeroFill for eki_key_id {}

// SAFETY: `eki_key_info` is `#[repr(C)]` with an `i32` newtype and a `[c_char; 65]`, both valid
// at zero (the selector value 0, an empty label); its padding bytes have no validity requirement.
unsafe impl ZeroFill for eki_key_info {}

// SAFETY: an all-zero raw pointer is the null pointer: `core::ptr::null_mut` is documented as
// equivalent to zero-initialising the pointer. That is the `*out == NULL` that `eki_ks_open`
// leaves on failure.
unsafe impl ZeroFill for *mut eki_ks {}

/// A pointer to one C value the call writes: `eki_key_id *`, `eki_key_info *` or `eki_ks **`.
///
/// `barrier` owns it and zero-fills it when the call fails. On success the body writes one whole
/// value with `write`, a typed write that leaves struct padding unspecified, as the contract
/// allows.
struct StructOut<T: ZeroFill> {
    ptr: *mut T,
}

impl<T: ZeroFill> StructOut<T> {
    /// Wraps the output pointer `ptr`.
    ///
    /// # Safety
    ///
    /// `ptr` is NULL, or aligned for `T` and valid for writes of `size_of::<T>()` bytes within
    /// one allocation that nothing else reads or writes, for as long as the returned value
    /// exists.
    unsafe fn new(ptr: *mut T) -> Self {
        Self { ptr }
    }

    /// Writes `value` to the output. NULL is `Error::NullPointer`.
    fn write(&mut self, value: T) -> Result<(), Error> {
        self.non_null()?;
        // SAFETY: `ptr` is non-NULL (`non_null` above), so by the precondition of
        // `StructOut::new` (from C4, C1 and C2) it is aligned and valid for writes of one `T`
        // that nothing else accesses. `T: Copy`, so overwriting the old bytes drops nothing.
        unsafe { self.ptr.write(value) };
        Ok(())
    }
}

impl StructOut<*mut eki_ks> {
    /// Hands `handle` to the caller in `*out`. The box becomes a raw pointer only after the NULL
    /// check, so a failure here drops the handle instead of leaking it; on success the caller
    /// owns it until `eki_ks_close`.
    fn put_handle(&mut self, handle: Box<Handle>) -> Result<(), Error> {
        self.non_null()?;
        self.write(Box::into_raw(handle).cast())
    }
}

impl<T: ZeroFill> PointerParam for StructOut<T> {
    fn non_null(&self) -> Result<(), Error> {
        pair_non_null(self.ptr.is_null(), 1)
    }
}

impl<T: ZeroFill> OutputParam for StructOut<T> {
    /// Zero-fills all `size_of::<T>()` bytes of a non-NULL output, padding included.
    fn zero(&mut self) {
        if self.ptr.is_null() {
            return;
        }
        // SAFETY: `ptr` is non-NULL (checked above), so by the precondition of `StructOut::new`
        // (from C4, C1 and C2) it is aligned and valid for writes of one `T` that nothing else
        // accesses; `write_bytes` with a count of 1 writes exactly `size_of::<T>()` bytes. The
        // bytes are written, never read, and `T: ZeroFill` makes the all-zero result a valid `T`.
        unsafe { self.ptr.write_bytes(0, 1) };
    }
}

/// A string parameter of which at most `SCAN` bytes are read: a key label (`SCAN` 65), a
/// PKCS#11 token label (33) or a PKCS#11 user PIN (256). `SCAN` is one more than the longest
/// valid text, so a text with no NUL within the bound is read as `SCAN` bytes and fails its
/// length check.
struct TextIn<const SCAN: usize> {
    ptr: *const c_char,
}

/// A key label parameter: at most 65 bytes are read.
type LabelIn = TextIn<LABEL_SCAN_LEN>;

impl<const SCAN: usize> TextIn<SCAN> {
    /// Wraps the string pointer `ptr`.
    ///
    /// # Safety
    ///
    /// `ptr` is NULL, or points to a NUL-terminated string or to at least `SCAN` readable bytes,
    /// all in one allocation that nothing writes, for as long as the returned value exists.
    unsafe fn new(ptr: *const c_char) -> Self {
        Self { ptr }
    }

    /// The bytes before the string's NUL, read with a bounded scan that never reads more than
    /// `SCAN` bytes, as the contract requires. When none of the first `SCAN` bytes is NUL the
    /// result is those `SCAN` bytes, which the format check rejects by length (a label has at
    /// most 64 bytes, a token label 32, a PIN 255). NULL is `Error::NullPointer`.
    /// `CStr::from_ptr` is not used because it scans without a bound.
    fn bytes(&self) -> Result<&[u8], Error> {
        self.non_null()?;
        let start = self.ptr.cast::<u8>();
        let mut len = 0;
        while len < SCAN {
            // SAFETY: `start` is non-NULL (`non_null` above). Bytes `0..len` were read and none is
            // NUL, and `len < SCAN`, so by the precondition of `TextIn::new` (from C6) byte `len`
            // is readable and in the same allocation: the string's NUL is at `len` or later, or
            // the buffer has `SCAN` readable bytes. Nothing writes it (C2), and `u8` has
            // alignment 1.
            if unsafe { start.add(len).read() } == 0 {
                break;
            }
            len += 1;
        }
        // SAFETY: each of the `len <= SCAN` bytes from `start` was read in the loop above, so
        // they are readable and in one allocation (C6), with no concurrent writer (C2); `start`
        // is non-NULL and `u8` has alignment 1. The slice borrows `self`, a local of the extern
        // call, so it ends before the call returns.
        Ok(unsafe { core::slice::from_raw_parts(start, len) })
    }
}

impl<const SCAN: usize> PointerParam for TextIn<SCAN> {
    fn non_null(&self) -> Result<(), Error> {
        pair_non_null(self.ptr.is_null(), 1)
    }
}

/// The PKCS#11 module path: a NUL-terminated string with no maximum length (C7).
struct PathIn {
    ptr: *const c_char,
}

impl PathIn {
    /// Wraps the path pointer `ptr`.
    ///
    /// # Safety
    ///
    /// `ptr` is NULL, or points to a NUL-terminated string in one allocation that nothing
    /// writes, for as long as the returned value exists.
    unsafe fn new(ptr: *const c_char) -> Self {
        Self { ptr }
    }

    /// The bytes before the path's NUL. NULL is `Error::NullPointer`.
    fn bytes(&self) -> Result<&[u8], Error> {
        self.non_null()?;
        // SAFETY: `ptr` is non-NULL (`non_null` above), so by the precondition of `PathIn::new`
        // (from C7) it points to a NUL-terminated string in one allocation with no concurrent
        // writer (C2), which is what `CStr::from_ptr` requires; `c_char` has alignment 1. The
        // returned slice borrows `self`, a local of the extern call, so it ends before the call
        // returns.
        Ok(unsafe { CStr::from_ptr(self.ptr) }.to_bytes())
    }
}

impl PointerParam for PathIn {
    fn non_null(&self) -> Result<(), Error> {
        pair_non_null(self.ptr.is_null(), 1)
    }
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
    barrier(NO_OUTPUTS, |[]| {
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
    barrier(NO_OUTPUTS, |[]| {
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
    // SAFETY: the C caller guarantees C4 (with C1 and C2) for `config`, one `eki_ks_config`, and
    // for `out`, one `eki_ks *`, which are the preconditions of `StructIn::new` and
    // `StructOut::new`. The wrappers are locals of this call, so they do not outlive that
    // guarantee.
    let (config, out) = unsafe { (StructIn::new(config), StructOut::new(out)) };
    barrier([out], |[out]| {
        check_null(&[&config, out])?;
        let config = config.read()?;
        let handle = match keystore::select(config.backend)? {
            keystore::Selected::Software => keystore::open_software(),
            keystore::Selected::Pkcs11 => {
                // SAFETY: the configuration selects the PKCS#11 backend and the library has it
                // (`select` answered `Pkcs11`), so the caller guarantees C7 for the module path
                // and C6 (33 and 256 bytes) for the token label and the PIN, the preconditions of
                // `PathIn::new` and `TextIn::new`. The pointers are the caller's own, copied out
                // of its `eki_ks_config` by `read`. The wrappers are locals of this call, so they
                // do not outlive that guarantee.
                let (module_path, token_label, user_pin) = unsafe {
                    (
                        PathIn::new(config.pkcs11_module_path),
                        TextIn::<TOKEN_LABEL_SCAN_LEN>::new(config.pkcs11_token_label),
                        TextIn::<USER_PIN_SCAN_LEN>::new(config.pkcs11_user_pin),
                    )
                };
                // Step 1 for the three fields, in field order, before any format check.
                check_null(&[&module_path, &token_label, &user_pin])?;
                keystore::open_pkcs11(&keystore::Pkcs11Fields {
                    module_path: module_path.bytes()?,
                    token_label: token_label.bytes()?,
                    user_pin: user_pin.bytes()?,
                })?
            }
        };
        out.put_handle(Box::new(handle))
    })
}

/// Closes the store and frees the handle. Passing NULL is allowed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_ks_close(ks: *mut eki_ks) {
    if ks.is_null() {
        return;
    }
    // SAFETY: by C5 a non-NULL `ks` is the pointer `eki_ks_open` made with `Box::into_raw` from a
    // `Box<Handle>`, not yet closed, and no other call on it runs now or later. Taking the box
    // back is therefore the single release of that allocation, with the type it was made with,
    // and no reference to the handle outlives it.
    let handle = unsafe { Box::from_raw(ks.cast::<Handle>()) };
    // Dropping the handle drops the backend: the software backend wipes every key, the PKCS#11
    // backend closes its session and releases its module, which finalises the module at the last
    // handle. No drop on that path is expected to panic, but a backend's drop calls into other
    // code, and a panic must not unwind into C.
    contain_panic((), move || drop(handle));
}

/// Copies the most recent error message of the handle into `buf` with snprintf semantics and
/// returns its full length, excluding the NUL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_ks_last_error_message(
    ks: *const eki_ks,
    buf: *mut c_char,
    buf_len: usize,
) -> usize {
    // `buf == NULL` is treated as `buf_len == 0` (plan 4.2, "Last error").
    let buf_len = if buf.is_null() { 0 } else { buf_len };
    // SAFETY: the C caller guarantees C5 for `ks` and C1 to C3 for `buf`/`buf_len` (no maximum),
    // which are the preconditions of `HandleIn::new` and `Output::new`; a NULL `buf` comes with
    // length 0, which requires nothing of the pointer. The wrappers are locals of this call, so
    // they do not outlive that guarantee.
    let (ks, mut buf) = unsafe { (HandleIn::new(ks), Output::new(buf.cast(), buf_len, NO_MAX)) };
    let copied = contain_panic(None, || {
        let out = buf.bytes().ok()?;
        // Reading the message does not start an operation, so it is not reset.
        let length = match ks.get() {
            Ok(handle) => keystore::copy_message(handle.lock().last_error().as_bytes(), out),
            Err(_) => keystore::copy_message(b"", out),
        };
        Some(length)
    });
    // After a panic (or a buffer error, which the NULL rule above rules out), the answer is that
    // of an empty message: `""` if there is room, and 0.
    copied.unwrap_or_else(|| {
        buf.bytes()
            .map_or(0, |out| keystore::copy_message(b"", out))
    })
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
    // SAFETY: the C caller guarantees C5 for `ks`, C6 for `label` and C4 for `id_out`, one
    // `eki_key_id`, which are the preconditions of `HandleIn::new`, `LabelIn::new` and
    // `StructOut::new`. The wrappers are locals of this call, so they do not outlive that
    // guarantee.
    let (ks, label, id_out) = unsafe {
        (
            HandleIn::new(ks.cast_const()),
            LabelIn::new(label),
            StructOut::new(id_out),
        )
    };
    barrier([id_out], |[id_out]| {
        let mut store = ks.begin()?;
        check_null(&[&label, id_out])?;
        let id = store.generate(alg, label.bytes()?)?;
        id_out.write(id.into())
    })
}

/// Reports the algorithm and label of the key with the given id.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_ks_get_info(
    ks: *mut eki_ks,
    id: *const eki_key_id,
    info_out: *mut eki_key_info,
) -> eki_status {
    // SAFETY: the C caller guarantees C5 for `ks` and C4 for `id`, one `eki_key_id`, and for
    // `info_out`, one `eki_key_info`, which are the preconditions of `HandleIn::new`,
    // `StructIn::new` and `StructOut::new`. The wrappers are locals of this call, so they do not
    // outlive that guarantee.
    let (ks, id, info_out) = unsafe {
        (
            HandleIn::new(ks.cast_const()),
            StructIn::new(id),
            StructOut::new(info_out),
        )
    };
    barrier([info_out], |[info_out]| {
        let mut store = ks.begin()?;
        check_null(&[&id, info_out])?;
        let info = store.get_info(&KeyId::from(id.read()?))?;
        info_out.write(info.to_abi())
    })
}

/// Writes the 65-byte SEC1 uncompressed public key of an ECDSA P-256 key to `out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_ks_get_public_key(
    ks: *mut eki_ks,
    id: *const eki_key_id,
    out: *mut u8,
) -> eki_status {
    // SAFETY: the C caller guarantees C5 for `ks`, C4 for `id` and C1 to C3 for the 65-byte
    // `out`, which are the preconditions of `HandleIn::new`, `StructIn::new` and
    // `Output::fixed`. The wrappers are locals of this call, so they do not outlive that
    // guarantee.
    let (ks, id, out) = unsafe {
        (
            HandleIn::new(ks.cast_const()),
            StructIn::new(id),
            Output::fixed::<EKI_P256_PUBLIC_KEY_LEN>(out),
        )
    };
    barrier([out], |[out]| {
        let mut store = ks.begin()?;
        check_null(&[&id, out])?;
        let public_key = store.public_key(&KeyId::from(id.read()?))?;
        out.bytes()?.copy_from_slice(&public_key);
        Ok(())
    })
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
    // SAFETY: the C caller guarantees C5 for `ks`, C4 for `id`, and C1 to C3 for `msg`/`msg_len`
    // (no maximum) and the 64-byte `sig_out`, which are the preconditions of `HandleIn::new`,
    // `StructIn::new`, `Input::new` and `Output::fixed`. The wrappers are locals of this call,
    // so they do not outlive that guarantee.
    let (ks, id, msg, sig_out) = unsafe {
        (
            HandleIn::new(ks.cast_const()),
            StructIn::new(id),
            Input::new(msg, msg_len, NO_MAX),
            Output::fixed::<EKI_P256_SIGNATURE_LEN>(sig_out),
        )
    };
    barrier([sig_out], |[sig_out]| {
        let mut store = ks.begin()?;
        check_null(&[&id, &msg, sig_out])?;
        let signature = store.sign(&KeyId::from(id.read()?), msg.bytes()?)?;
        sig_out.bytes()?.copy_from_slice(&signature);
        Ok(())
    })
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
    // SAFETY: the C caller guarantees C5 for `ks`, C4 for `id`, and C1 to C3 for `msg`/`msg_len`
    // (no maximum) and the 32-byte `out`, which are the preconditions of `HandleIn::new`,
    // `StructIn::new`, `Input::new` and `Output::fixed`. The wrappers are locals of this call,
    // so they do not outlive that guarantee.
    let (ks, id, msg, out) = unsafe {
        (
            HandleIn::new(ks.cast_const()),
            StructIn::new(id),
            Input::new(msg, msg_len, NO_MAX),
            Output::fixed::<EKI_HMAC_SHA256_LEN>(out),
        )
    };
    barrier([out], |[out]| {
        let mut store = ks.begin()?;
        check_null(&[&id, &msg, out])?;
        let tag = store.hmac_sha256(&KeyId::from(id.read()?), msg.bytes()?)?;
        out.bytes()?.copy_from_slice(&tag);
        Ok(())
    })
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
    // SAFETY: the C caller guarantees C5 for `ks`, C4 for `kek_id` and `key_id`, and C1 to C3
    // for the 40-byte `out`, which are the preconditions of `HandleIn::new`, `StructIn::new` and
    // `Output::fixed`. The wrappers are locals of this call, so they do not outlive that
    // guarantee.
    let (ks, kek_id, key_id, out) = unsafe {
        (
            HandleIn::new(ks.cast_const()),
            StructIn::new(kek_id),
            StructIn::new(key_id),
            Output::fixed::<EKI_WRAPPED_KEY_LEN>(out),
        )
    };
    barrier([out], |[out]| {
        let mut store = ks.begin()?;
        check_null(&[&kek_id, &key_id, out])?;
        let blob = store.wrap(&KeyId::from(kek_id.read()?), &KeyId::from(key_id.read()?))?;
        out.bytes()?.copy_from_slice(&blob);
        Ok(())
    })
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
    // SAFETY: the C caller guarantees C5 for `ks`, C4 for `kek_id` and `id`, C1 and C2 for
    // `blob`/`blob_len` (no maximum: a length other than 40 is a format error found by the store
    // logic, not a cap) and C6 for `label`, which are the preconditions of `HandleIn::new`,
    // `StructIn::new`, `Input::new` and `LabelIn::new`. The wrappers are locals of this call, so
    // they do not outlive that guarantee.
    let (ks, kek_id, blob, label, id) = unsafe {
        (
            HandleIn::new(ks.cast_const()),
            StructIn::new(kek_id),
            Input::new(blob, blob_len, NO_MAX),
            LabelIn::new(label),
            StructIn::new(id),
        )
    };
    barrier(NO_OUTPUTS, |[]| {
        let mut store = ks.begin()?;
        check_null(&[&kek_id, &blob, &label, &id])?;
        store.unwrap(
            &KeyId::from(kek_id.read()?),
            blob.bytes()?,
            alg,
            label.bytes()?,
            &KeyId::from(id.read()?),
        )
    })
}

/// Destroys the key with the given id, including both halves of a key pair.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_ks_destroy(ks: *mut eki_ks, id: *const eki_key_id) -> eki_status {
    // SAFETY: the C caller guarantees C5 for `ks` and C4 for `id`, which are the preconditions of
    // `HandleIn::new` and `StructIn::new`. The wrappers are locals of this call, so they do not
    // outlive that guarantee.
    let (ks, id) = unsafe { (HandleIn::new(ks.cast_const()), StructIn::new(id)) };
    barrier(NO_OUTPUTS, |[]| {
        let mut store = ks.begin()?;
        check_null(&[&id])?;
        store.destroy(&KeyId::from(id.read()?))
    })
}

/// Generates a hybrid X25519 + ML-KEM-768 key pair. Returns `EKI_ERR_UNSUPPORTED` when the
/// library is built without hybrid support.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_hybrid_kem_keygen(pk_out: *mut u8, sk_out: *mut u8) -> eki_status {
    // SAFETY: the C caller guarantees C1 and C2 for the `EKI_HYBRID_PK_LEN`-byte `pk_out` and the
    // `EKI_HYBRID_SK_LEN`-byte `sk_out`, which are the preconditions of `Output::fixed`. The
    // wrappers are locals of this call, so they do not outlive that guarantee.
    let (pk_out, sk_out) = unsafe {
        (
            Output::fixed::<EKI_HYBRID_PK_LEN>(pk_out),
            Output::fixed::<EKI_HYBRID_SK_LEN>(sk_out),
        )
    };
    barrier([pk_out, sk_out], |[pk_out, sk_out]| {
        check_null(&[pk_out, sk_out])?;
        #[cfg(feature = "pq")]
        {
            let (pk, sk) = pq::keygen()?;
            pk_out.bytes()?.copy_from_slice(&pk);
            sk_out.bytes()?.copy_from_slice(sk.expose_secret());
            Ok(())
        }
        #[cfg(not(feature = "pq"))]
        Err(Error::Unsupported)
    })
}

/// Encapsulates a fresh shared secret to `pk`: writes the ciphertext to `ct_out` and the shared
/// secret to `ss_out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_hybrid_kem_encap(
    pk: *const u8,
    ct_out: *mut u8,
    ss_out: *mut u8,
) -> eki_status {
    // SAFETY: the C caller guarantees C1 and C2 for the `EKI_HYBRID_PK_LEN`-byte `pk`, the
    // `EKI_HYBRID_CT_LEN`-byte `ct_out` and the `EKI_HYBRID_SS_LEN`-byte `ss_out`, which are the
    // preconditions of `Input::fixed` and `Output::fixed`. The wrappers are locals of this call,
    // so they do not outlive that guarantee.
    let (pk, ct_out, ss_out) = unsafe {
        (
            Input::fixed::<EKI_HYBRID_PK_LEN>(pk),
            Output::fixed::<EKI_HYBRID_CT_LEN>(ct_out),
            Output::fixed::<EKI_HYBRID_SS_LEN>(ss_out),
        )
    };
    barrier([ct_out, ss_out], |[ct_out, ss_out]| {
        check_null(&[&pk, ct_out, ss_out])?;
        #[cfg(feature = "pq")]
        {
            // `Input::fixed` made `pk` exactly `EKI_HYBRID_PK_LEN` bytes, the only way the
            // conversion fails.
            let pk: &pq::PublicKey = pk.bytes()?.try_into().map_err(|_| Error::Internal)?;
            let (ct, ss) = pq::encap(pk)?;
            ct_out.bytes()?.copy_from_slice(&ct);
            ss_out.bytes()?.copy_from_slice(ss.expose_secret());
            Ok(())
        }
        #[cfg(not(feature = "pq"))]
        Err(Error::Unsupported)
    })
}

/// Recovers the shared secret from `ct` with the secret key `sk` and writes it to `ss_out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eki_hybrid_kem_decap(
    sk: *const u8,
    ct: *const u8,
    ss_out: *mut u8,
) -> eki_status {
    // SAFETY: the C caller guarantees C1 and C2 for the `EKI_HYBRID_SK_LEN`-byte `sk`, the
    // `EKI_HYBRID_CT_LEN`-byte `ct` and the `EKI_HYBRID_SS_LEN`-byte `ss_out`, which are the
    // preconditions of `Input::fixed` and `Output::fixed`. The wrappers are locals of this call,
    // so they do not outlive that guarantee.
    let (sk, ct, ss_out) = unsafe {
        (
            Input::fixed::<EKI_HYBRID_SK_LEN>(sk),
            Input::fixed::<EKI_HYBRID_CT_LEN>(ct),
            Output::fixed::<EKI_HYBRID_SS_LEN>(ss_out),
        )
    };
    barrier([ss_out], |[ss_out]| {
        check_null(&[&sk, &ct, ss_out])?;
        #[cfg(feature = "pq")]
        {
            // `Input::fixed` made `sk` and `ct` exactly `EKI_HYBRID_SK_LEN` and
            // `EKI_HYBRID_CT_LEN` bytes, the only way the conversions fail.
            let sk: &[u8; EKI_HYBRID_SK_LEN] =
                sk.bytes()?.try_into().map_err(|_| Error::Internal)?;
            let ct: &pq::Ciphertext = ct.bytes()?.try_into().map_err(|_| Error::Internal)?;
            let ss = pq::decap(sk, ct)?;
            ss_out.bytes()?.copy_from_slice(ss.expose_secret());
            Ok(())
        }
        #[cfg(not(feature = "pq"))]
        Err(Error::Unsupported)
    })
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
        let status = barrier(NO_OUTPUTS, |[]| std::panic::panic_any(PanicsOnDrop));
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

    // --- Key store helpers ---

    /// A handle over a scripted backend, as `eki_ks_open` would hand it out; close it with
    /// `eki_ks_close`.
    fn scripted_handle(backend: keystore::scripted::Scripted) -> *mut eki_ks {
        Box::into_raw(Box::new(Handle::new(Box::new(backend)))).cast()
    }

    /// The handle's last-error message, read through the extern function.
    fn message(ks: *const eki_ks) -> String {
        let mut buf = [FILL as c_char; 128];
        // SAFETY: `ks` is an open handle and `buf` a live local of the length passed.
        let len = unsafe { eki_ks_last_error_message(ks, buf.as_mut_ptr(), buf.len()) };
        buf.iter().take(len).map(|&c| c as u8 as char).collect()
    }

    #[test]
    fn null_handle_is_null_pointer() {
        // SAFETY: the pointer is NULL, which the precondition allows; it is never dereferenced.
        let ks = unsafe { HandleIn::new(core::ptr::null()) };
        assert_eq!(check_null(&[&ks]), Err(Error::NullPointer));
        assert!(matches!(ks.get(), Err(Error::NullPointer)));
        assert!(matches!(ks.begin(), Err(Error::NullPointer)));
    }

    #[test]
    fn handle_pointer_reaches_the_handle() {
        let raw = scripted_handle(keystore::scripted::Scripted::default());
        {
            // SAFETY: `raw` came from `Box::into_raw` of a `Box<Handle>` and is closed only after
            // this block, in which `ks` lives.
            let ks = unsafe { HandleIn::new(raw) };
            assert_eq!(check_null(&[&ks]), Ok(()));
            let id = ks
                .begin()
                .expect("non-NULL handle")
                .generate(ekicore_abi::EKI_KEY_AES_256, b"label")
                .expect("generate succeeds");
            let info = ks.begin().expect("non-NULL handle").get_info(&id);
            assert_eq!(
                info.map(|info| info.label.as_bytes().to_vec()),
                Ok(b"label".to_vec())
            );
        }
        // SAFETY: `raw` is an open handle and nothing else uses it.
        unsafe { eki_ks_close(raw) };
    }

    #[test]
    fn struct_input_is_read_by_copy() {
        let id = eki_key_id { bytes: [7; 16] };
        // SAFETY: `id` is a live, aligned, initialised local that nothing writes meanwhile.
        let input = unsafe { StructIn::new(&id) };
        assert_eq!(check_null(&[&input]), Ok(()));
        assert_eq!(input.read(), Ok(id));

        // SAFETY: the pointer is NULL, which the precondition allows; it is never dereferenced.
        let null = unsafe { StructIn::<eki_key_id>::new(core::ptr::null()) };
        assert_eq!(check_null(&[&null]), Err(Error::NullPointer));
        assert_eq!(null.read(), Err(Error::NullPointer));
    }

    /// Storage for an `eki_key_info` that is plain initialised bytes, so a test can inspect every
    /// byte the library wrote, padding included, without reading padding of a typed value.
    #[repr(C, align(4))]
    struct InfoBytes([u8; size_of::<eki_key_info>()]);

    const _: () = assert!(align_of::<InfoBytes>() >= align_of::<eki_key_info>());

    #[test]
    fn struct_output_is_zero_filled_over_its_whole_size() {
        let mut storage = InfoBytes([FILL; size_of::<eki_key_info>()]);
        let ptr = storage.0.as_mut_ptr().cast::<eki_key_info>();
        // SAFETY: `storage` is a live local aligned for `eki_key_info` (assertion above) and of
        // its size, not otherwise accessed until `barrier` returns.
        let output = unsafe { StructOut::new(ptr) };
        let status = barrier([output], |[output]| {
            output.write(eki_key_info {
                alg: ekicore_abi::EKI_KEY_HMAC_SHA256,
                label: [b'x' as c_char; 65],
            })?;
            Err(Error::KeyNotFound)
        });
        assert_eq!(status, eki_status::EKI_ERR_KEY_NOT_FOUND);
        assert_eq!(
            storage.0,
            [0; size_of::<eki_key_info>()],
            "padding included"
        );
    }

    #[test]
    fn struct_output_is_written_on_success() {
        let mut id = eki_key_id { bytes: [FILL; 16] };
        // SAFETY: `id` is a live local, not otherwise accessed until `barrier` returns.
        let output = unsafe { StructOut::new(&mut id) };
        let status = barrier([output], |[output]| {
            output.write(eki_key_id { bytes: [3; 16] })
        });
        assert_eq!(status, eki_status::EKI_OK);
        assert_eq!(id.bytes, [3; 16]);
    }

    #[test]
    fn null_struct_output_is_skipped_on_error() {
        // SAFETY: the pointer is NULL; `zero` must skip it rather than write through it.
        let output = unsafe { StructOut::<eki_key_id>::new(core::ptr::null_mut()) };
        let status = barrier([output], |[output]| {
            check_null(&[&*output])?;
            Ok(())
        });
        assert_eq!(status, eki_status::EKI_ERR_NULL_POINTER);
    }

    #[test]
    fn failed_handle_output_is_null() {
        let mut handle: *mut eki_ks = core::ptr::dangling_mut();
        // SAFETY: `handle` is a live local, not otherwise accessed until `barrier` returns.
        let output = unsafe { StructOut::new(&mut handle) };
        let status = barrier([output], |[_]| Err(Error::InvalidArgument));
        assert_eq!(status, eki_status::EKI_ERR_INVALID_ARGUMENT);
        assert!(handle.is_null());
    }

    #[test]
    fn handle_put_into_null_output_is_dropped() {
        // SAFETY: the pointer is NULL, which the precondition allows; it is never written.
        let mut output = unsafe { StructOut::<*mut eki_ks>::new(core::ptr::null_mut()) };
        let handle = Box::new(Handle::new(Box::new(
            keystore::scripted::Scripted::default(),
        )));
        // Under Miri a leaked handle would be reported at the end of the test.
        assert_eq!(output.put_handle(handle), Err(Error::NullPointer));
    }

    #[test]
    fn null_label_is_null_pointer() {
        // SAFETY: the pointer is NULL, which the precondition allows; it is never dereferenced.
        let label = unsafe { LabelIn::new(core::ptr::null()) };
        assert_eq!(check_null(&[&label]), Err(Error::NullPointer));
        assert_eq!(label.bytes(), Err(Error::NullPointer));
    }

    #[test]
    fn label_ends_at_its_first_nul() {
        for (text, expected) in [
            (&b"\0"[..], &b""[..]),
            (b"abc\0", b"abc"),
            (b"ab\0cd\0", b"ab"),
        ] {
            // SAFETY: `text` is a live NUL-terminated byte string that nothing writes.
            let label = unsafe { LabelIn::new(text.as_ptr().cast()) };
            assert_eq!(label.bytes(), Ok(expected));
        }
    }

    #[test]
    fn label_of_64_bytes_and_its_nul_is_read_whole() {
        let mut text = vec![b'a'; 64];
        text.push(0);
        let text = text.into_boxed_slice();
        // SAFETY: `text` is a live 65-byte allocation ending in NUL that nothing writes.
        let label = unsafe { LabelIn::new(text.as_ptr().cast()) };
        assert_eq!(label.bytes(), Ok(&[b'a'; 64][..]));
    }

    #[test]
    fn unterminated_label_scan_stops_at_65_bytes() {
        // Exactly 65 bytes with no NUL: reading byte 66 would be outside the allocation, which
        // Miri reports.
        let text = vec![b'x'; LABEL_SCAN_LEN].into_boxed_slice();
        // SAFETY: `text` is a live allocation of 65 readable bytes that nothing writes.
        let label = unsafe { LabelIn::new(text.as_ptr().cast()) };
        let bytes = label.bytes().expect("non-NULL");
        assert_eq!(bytes.len(), LABEL_SCAN_LEN);
        assert_eq!(keystore::Label::parse(bytes), None, "rejected by length");
    }

    #[test]
    fn contained_panic_gives_the_fallback() {
        assert_eq!(contain_panic(0, || 5), 5);
        assert_eq!(contain_panic(0, || panic!("deliberate panic")), 0);
    }

    #[test]
    fn backend_failure_message_reaches_the_caller_and_is_reset() {
        let ks = scripted_handle(keystore::scripted::Scripted {
            fail_with: Some("module said no".to_owned()),
            ..Default::default()
        });
        let text = c"label";
        let mut id = eki_key_id { bytes: [FILL; 16] };
        let aes = ekicore_abi::EKI_KEY_AES_256;
        // SAFETY: `ks` is an open handle; `text` is NUL-terminated; `id` is a live local.
        let status = unsafe { eki_ks_generate(ks, aes, text.as_ptr(), &mut id) };
        assert_eq!(status, eki_status::EKI_ERR_BACKEND);
        assert_eq!(id.bytes, [0; 16], "id_out zero-filled");
        assert_eq!(message(ks), "module said no");
        // A call that fails on a NULL pointer other than `ks` still starts an operation.
        // SAFETY: `ks` is an open handle; the NULL id is the case under test.
        let status = unsafe { eki_ks_destroy(ks, core::ptr::null()) };
        assert_eq!(status, eki_status::EKI_ERR_NULL_POINTER);
        assert_eq!(message(ks), "");
        // SAFETY: `ks` is an open handle and nothing else uses it.
        unsafe { eki_ks_close(ks) };
    }

    #[test]
    fn panic_in_a_store_operation_is_internal_and_the_handle_recovers() {
        let ec = keystore::KeyId([3; 16]);
        let mut backend = keystore::scripted::Scripted {
            panic_in_sign: true,
            ..Default::default()
        };
        let label = keystore::Label::parse(b"ec").expect("valid label");
        backend.add(keystore::KeyAlg::EcdsaP256, &label, &ec);
        let ks = scripted_handle(backend);
        let id = eki_key_id::from(ec);
        let mut sig = [FILL; EKI_P256_SIGNATURE_LEN];
        // SAFETY: `ks` is an open handle; `id` and `sig` are live locals; the message is empty.
        let status = unsafe { eki_ks_sign(ks, &id, core::ptr::null(), 0, sig.as_mut_ptr()) };
        assert_eq!(status, eki_status::EKI_ERR_INTERNAL);
        assert_eq!(sig, [0; EKI_P256_SIGNATURE_LEN]);
        let mut storage = InfoBytes([FILL; size_of::<eki_key_info>()]);
        // SAFETY: `ks` is an open handle, its lock now poisoned; `id` is a live local; `storage`
        // is aligned for and of the size of `eki_key_info`.
        let status = unsafe { eki_ks_get_info(ks, &id, storage.0.as_mut_ptr().cast()) };
        assert_eq!(status, eki_status::EKI_OK, "the poisoned lock is recovered");
        assert_eq!(message(ks), "");
        // SAFETY: `ks` is an open handle and nothing else uses it.
        unsafe { eki_ks_close(ks) };
    }
}
