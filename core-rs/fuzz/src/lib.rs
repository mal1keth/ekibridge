//! Input decoding, buffers and checks shared by the cargo-fuzz targets of `ekicore-rs` and by the
//! seed generator (`examples/seeds.rs`).
//!
//! Every target calls the C ABI (`ekicore_rs::ffi::eki_*`) as a hostile C caller could: pointers
//! into exactly sized heap buffers (so AddressSanitizer reports an access one byte past the end),
//! NULL wherever the input asks for it, lengths within and beyond the documented caps, any
//! selector value. Statuses are read back as plain `i32`.
//!
//! # Input layout
//!
//! [`Reader`] reads the layout that `core-cpp/fuzz/fuzz_input.hpp` reads, so one seed file means
//! the same calls to both libraries and one generator writes both corpora. Integers are
//! little-endian; a fixed-size array is its bytes; a byte string is a 2-byte little-endian length
//! followed by that many bytes. A field cut short by the end of the input reads as zero bytes
//! (integers, arrays) or is shortened (byte strings), so every input decodes. The composite
//! fields below ([`InBuf`], [`read_capped_len`], [`read_label`], [`read_key_ref`],
//! [`read_audit_path`], [`Config`]) are documented with the bytes they consume.
//!
//! # Scratch files
//!
//! Audit logs are written to the system temporary directory, under names that carry the target
//! and the process id ([`Scratch`]), so parallel fuzzing jobs never share a file. The PKCS#11
//! backend is never given a module that exists: the module path a configuration can carry names
//! a file that is not there, so no token is ever opened.

use core::ffi::{CStr, c_char};
use core::marker::PhantomData;
use core::ptr::NonNull;
use std::alloc::{Layout, alloc, dealloc};
use std::ffi::CString;
use std::path::PathBuf;

use ekicore_abi::{
    EKI_APPROVERS_MAX, EKI_AUDIT_HASH_LEN, EKI_AUDIT_PATH_MAX_LEN, EKI_KEY_ECDSA_P256,
    EKI_KEY_ID_LEN, EKI_KS_PKCS11, EKI_KS_SOFTWARE, EKI_LABEL_MAX_LEN, EKI_P256_PUBLIC_KEY_LEN,
    EKI_P256_SIGNATURE_LEN, eki_key_alg, eki_key_id, eki_ks, eki_ks_backend, eki_ks_config,
    eki_ks_config_v2, eki_status,
};
use ekicore_rs::ffi::{
    eki_ks_close, eki_ks_generate, eki_ks_get_public_key, eki_ks_open, eki_ks_sign,
};
use sha2::{Digest, Sha256};

// --- Statuses ----------------------------------------------------------------------------------

/// `EKI_OK`.
pub const OK: i32 = eki_status::EKI_OK as i32;
/// `EKI_ERR_NULL_POINTER`.
pub const NULL_POINTER: i32 = eki_status::EKI_ERR_NULL_POINTER as i32;
/// `EKI_ERR_INVALID_ARGUMENT`.
pub const INVALID_ARGUMENT: i32 = eki_status::EKI_ERR_INVALID_ARGUMENT as i32;
/// `EKI_ERR_UNSUPPORTED`.
pub const UNSUPPORTED: i32 = eki_status::EKI_ERR_UNSUPPORTED as i32;
/// `EKI_ERR_AUTH_FAILED`.
pub const AUTH_FAILED: i32 = eki_status::EKI_ERR_AUTH_FAILED as i32;
/// `EKI_ERR_KEY_NOT_FOUND`.
pub const KEY_NOT_FOUND: i32 = eki_status::EKI_ERR_KEY_NOT_FOUND as i32;
/// `EKI_ERR_KEY_EXISTS`.
pub const KEY_EXISTS: i32 = eki_status::EKI_ERR_KEY_EXISTS as i32;
/// `EKI_ERR_BACKEND`.
pub const BACKEND: i32 = eki_status::EKI_ERR_BACKEND as i32;
/// `EKI_ERR_INTERNAL`.
pub const INTERNAL: i32 = eki_status::EKI_ERR_INTERNAL as i32;
/// `EKI_ERR_APPROVAL_REQUIRED`, the largest status of ABI version 2.
pub const STATUS_MAX: i32 = eki_status::EKI_ERR_APPROVAL_REQUIRED as i32;

/// Whether the library was built with the PKCS#11 backend (`pkcs11` feature of this crate).
pub const WITH_PKCS11: bool = cfg!(feature = "pkcs11");
/// Whether the library was built with the hybrid KEM (`pq` feature of this crate).
pub const WITH_PQ: bool = cfg!(feature = "pq");

/// Panics unless `status` is a value ABI version 2 defines, and is not `EKI_ERR_INTERNAL`: a
/// caught panic or a violated invariant is a bug whatever the input was.
pub fn check_status(function: &str, status: i32) {
    assert!(
        (OK..=STATUS_MAX).contains(&status),
        "{function} returned {status}, outside 0..={STATUS_MAX}"
    );
    assert_ne!(status, INTERNAL, "{function} returned EKI_ERR_INTERNAL");
}

// --- Reading the input -------------------------------------------------------------------------

/// Reads typed fields from the front of a libFuzzer input.
pub struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    /// A reader over `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Self { rest: data }
    }

    /// True when every byte has been read.
    pub fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// One byte; 0 past the end.
    pub fn u8(&mut self) -> u8 {
        match self.rest.split_first() {
            Some((&byte, rest)) => {
                self.rest = rest;
                byte
            }
            None => 0,
        }
    }

    /// The low bit of one byte.
    pub fn boolean(&mut self) -> bool {
        self.u8() & 1 == 1
    }

    /// Two bytes, little-endian.
    pub fn u16(&mut self) -> u16 {
        u16::from_le_bytes(self.array())
    }

    /// Four bytes, little-endian.
    pub fn i32(&mut self) -> i32 {
        i32::from_le_bytes(self.array())
    }

    /// `N` bytes, zero-padded past the end.
    pub fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0; N];
        for byte in &mut out {
            *byte = self.u8();
        }
        out
    }

    /// A byte string: a [`Reader::u16`] length, then that many bytes (fewer at the end).
    pub fn bytes(&mut self) -> Vec<u8> {
        let len = usize::from(self.u16()).min(self.rest.len());
        let (bytes, rest) = self.rest.split_at(len);
        self.rest = rest;
        bytes.to_vec()
    }

    /// Every byte that is left.
    pub fn rest(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.rest).to_vec()
    }
}

/// A caller-supplied input buffer: [`Reader::boolean`] (pass NULL), then [`Reader::bytes`].
///
/// The length argument is the buffer's length either way: the contract defines NULL with
/// length 0 (an empty buffer) and NULL with a non-zero length (`EKI_ERR_NULL_POINTER`). An empty
/// buffer that is not NULL is passed as a dangling, non-NULL pointer, which the library must
/// never dereference.
#[derive(Clone, Debug, Default)]
pub struct InBuf {
    /// Pass NULL instead of the buffer's address.
    pub null: bool,
    /// The bytes; exactly allocated.
    pub data: Vec<u8>,
}

impl InBuf {
    /// Reads one from `r`.
    pub fn read(r: &mut Reader<'_>) -> Self {
        let null = r.boolean();
        Self {
            null,
            data: r.bytes(),
        }
    }

    /// The pointer argument.
    pub fn ptr(&self) -> *const u8 {
        if self.null {
            core::ptr::null()
        } else {
            self.data.as_ptr()
        }
    }

    /// The length of the bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// True when there are no bytes.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Whether `(ptr, len)` breaks the pointer rule: NULL with a non-zero length.
    pub fn null_with(&self, len: usize) -> bool {
        self.null && len > 0
    }
}

/// The length argument for a parameter with a documented maximum `cap`: one byte whose low two
/// bits choose the real length of the buffer (0 and 1), `cap + 1` (2) or `usize::MAX` (3).
///
/// Above the cap the contract says the call fails without reading or writing the buffer, so the
/// buffer stays at its real, smaller size and AddressSanitizer reports any access.
pub fn read_capped_len(r: &mut Reader<'_>, actual: usize, cap: usize) -> usize {
    match r.u8() & 3 {
        2 => cap + 1,
        3 => usize::MAX,
        _ => actual,
    }
}

/// A key id argument: one byte whose low two bits choose NULL (0), 16 raw bytes that follow (1),
/// or (2, 3) one of `known` picked by the next byte (an all-zero id when `known` is empty).
pub fn read_key_ref(r: &mut Reader<'_>, known: &[eki_key_id]) -> Option<eki_key_id> {
    match r.u8() & 3 {
        0 => None,
        1 => Some(eki_key_id { bytes: r.array() }),
        _ => {
            let pick = usize::from(r.u8());
            Some(if known.is_empty() {
                eki_key_id {
                    bytes: [0; EKI_KEY_ID_LEN],
                }
            } else {
                known[pick % known.len()]
            })
        }
    }
}

/// A pointer to `id`, or NULL.
pub fn id_ptr(id: &Option<eki_key_id>) -> *const eki_key_id {
    id.as_ref()
        .map_or(core::ptr::null(), |id| id as *const eki_key_id)
}

// --- Strings -----------------------------------------------------------------------------------

/// A string argument: NULL, a NUL-terminated string, or bytes without a terminator.
#[derive(Clone, Debug)]
pub struct Text {
    null: bool,
    bytes: Vec<u8>,
}

impl Text {
    /// The NULL pointer.
    pub fn null() -> Self {
        Self {
            null: true,
            bytes: Vec::new(),
        }
    }

    /// `text` with a NUL appended.
    pub fn terminated(text: &[u8]) -> Self {
        let mut bytes = Vec::with_capacity(text.len() + 1);
        bytes.extend_from_slice(text);
        bytes.push(0);
        Self { null: false, bytes }
    }

    /// Exactly `bytes`, with no terminator added: the library may read all of them and not one
    /// more.
    pub fn unterminated(bytes: Vec<u8>) -> Self {
        Self { null: false, bytes }
    }

    /// The pointer argument.
    pub fn ptr(&self) -> *const c_char {
        if self.null {
            core::ptr::null()
        } else {
            self.bytes.as_ptr().cast()
        }
    }

    /// True for NULL.
    pub fn is_null(&self) -> bool {
        self.null
    }

    /// The text the library reads with a bound of `scan` bytes: up to the first NUL, at most
    /// `scan` bytes. `None` for NULL.
    pub fn seen(&self, scan: usize) -> Option<&[u8]> {
        if self.null {
            return None;
        }
        let end = self
            .bytes
            .iter()
            .take(scan)
            .position(|&b| b == 0)
            .unwrap_or(self.bytes.len().min(scan));
        Some(&self.bytes[..end])
    }
}

/// Longest label the targets pass before its NUL; longer than `EKI_LABEL_MAX_LEN` (64).
pub const LABEL_FUZZ_MAX: usize = 80;

/// A label argument: one byte modulo 3 chooses NULL (0), [`Reader::bytes`] cut to
/// [`LABEL_FUZZ_MAX`] with a NUL appended (1), or [`Reader::bytes`] padded with `a` or cut to
/// exactly 65 bytes and passed without a NUL (2), the largest unterminated label the contract
/// allows.
pub fn read_label(r: &mut Reader<'_>) -> Text {
    match r.u8() % 3 {
        0 => Text::null(),
        1 => {
            let mut text = r.bytes();
            text.truncate(LABEL_FUZZ_MAX);
            Text::terminated(&text)
        }
        _ => Text::unterminated(exact(&r.bytes(), EKI_LABEL_MAX_LEN + 1, b'a')),
    }
}

/// Whether the library must accept `label` (the bytes before its NUL): 1 to 64 bytes, each in
/// `0x20..=0x7E`.
pub fn label_is_valid(label: &[u8]) -> bool {
    (1..=EKI_LABEL_MAX_LEN).contains(&label.len())
        && label.iter().all(|b| (0x20..=0x7E).contains(b))
}

/// The scratch paths of one target in this process.
pub struct Scratch {
    /// The audit log a run may create, as a path; removed by [`Scratch::reset`].
    pub log_path: PathBuf,
    /// The same, as the C string the targets pass.
    pub log: CString,
    /// The temporary directory itself: a path that exists and is not a regular file.
    pub dir: CString,
    /// A file in a directory that does not exist.
    pub missing: CString,
}

impl Scratch {
    /// The paths for `target`.
    pub fn new(target: &str) -> Self {
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let c = |path: &std::path::Path| {
            CString::new(path.as_os_str().as_encoded_bytes()).expect("no NUL in a path")
        };
        let log_path = dir.join(format!("ekibridge-fuzz-{target}-{pid}.log"));
        Self {
            log: c(&log_path),
            missing: c(&dir.join(format!("ekibridge-fuzz-{target}-{pid}.d/audit.log"))),
            dir: c(&dir),
            log_path,
        }
    }

    /// Removes the log file, so a run starts without one.
    pub fn reset(&self) {
        // A missing file is the normal case.
        let _ = std::fs::remove_file(&self.log_path);
    }
}

/// `bytes` cut or padded with `pad` to exactly `len` bytes, in an allocation of exactly `len`
/// bytes, so AddressSanitizer reports a read of byte `len`.
pub fn exact(bytes: &[u8], len: usize, pad: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    out.extend(
        bytes
            .iter()
            .copied()
            .chain(core::iter::repeat(pad))
            .take(len),
    );
    out
}

/// An audit log path argument: one byte modulo 6 chooses NULL (0), the run's log file (1), the
/// empty string (2), 4097 bytes with no NUL, one more than the longest path (3), the temporary
/// directory (4) or a file in a directory that does not exist (5).
pub fn read_audit_path(r: &mut Reader<'_>, scratch: &Scratch) -> Text {
    match r.u8() % 6 {
        0 => Text::null(),
        1 => Text::terminated(scratch.log.as_bytes()),
        2 => Text::terminated(b""),
        3 => Text::unterminated(exact(b"", EKI_AUDIT_PATH_MAX_LEN + 1, b'a')),
        4 => Text::terminated(scratch.dir.as_bytes()),
        _ => Text::terminated(scratch.missing.as_bytes()),
    }
}

// --- Outputs -----------------------------------------------------------------------------------

/// The byte every output is filled with before a call, so that both a missing zero-fill and a
/// write to an output that must stay untouched are visible.
pub const FILL: u8 = 0xA5;

/// What the contract requires of a non-NULL output after a failed call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OnError {
    /// Zero-filled over its whole size.
    Zero,
    /// Left as it was: its length argument is above the parameter's maximum.
    Untouched,
}

/// The state of one output after a call, for [`Call::check`].
#[derive(Debug)]
pub struct Seen {
    /// The output was passed as NULL.
    pub null: bool,
    /// The rule for a failed call.
    pub on_error: OnError,
    /// Its bytes after the call.
    pub bytes: Vec<u8>,
}

/// A byte output, exactly allocated and pre-filled with [`FILL`].
pub struct OutBuf {
    null: bool,
    on_error: OnError,
    bytes: Vec<u8>,
}

impl OutBuf {
    /// An output of `len` bytes that a failed call zero-fills.
    pub fn new(null: bool, len: usize) -> Self {
        Self {
            null,
            on_error: OnError::Zero,
            bytes: vec![FILL; len],
        }
    }

    /// An output of `len` bytes passed with a length argument above its maximum, which a call
    /// never touches.
    pub fn untouched(null: bool, len: usize) -> Self {
        Self {
            on_error: OnError::Untouched,
            ..Self::new(null, len)
        }
    }

    /// The pointer argument.
    pub fn ptr(&mut self) -> *mut u8 {
        if self.null {
            core::ptr::null_mut()
        } else {
            self.bytes.as_mut_ptr()
        }
    }

    /// True when passed as NULL.
    pub fn is_null(&self) -> bool {
        self.null
    }

    /// The bytes after the call.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The state for [`Call::check`].
    pub fn seen(&self) -> Seen {
        Seen {
            null: self.null,
            on_error: self.on_error,
            bytes: self.bytes.clone(),
        }
    }
}

/// A C value whose every bit pattern is valid, so a [`Slot`] of it can be read whatever the
/// library wrote.
///
/// # Safety
///
/// Every byte pattern of `size_of::<Self>()` bytes is a valid value of the type.
pub unsafe trait AnyBits: Copy {}

// SAFETY: `#[repr(C)]` around `[u8; 16]`.
unsafe impl AnyBits for eki_key_id {}
// SAFETY: `#[repr(C)]` with an `i32` newtype and `[c_char; 65]`; padding has no validity rule.
unsafe impl AnyBits for ekicore_abi::eki_key_info {}
// SAFETY: `#[repr(C)]` with two `i32` newtypes and `[c_char; 65]`; padding has no validity rule.
unsafe impl AnyBits for ekicore_abi::eki_key_info_v2 {}
// SAFETY: every bit pattern of an integer is valid.
unsafe impl AnyBits for u32 {}
// SAFETY: every bit pattern of an integer is valid.
unsafe impl AnyBits for u64 {}
// SAFETY: every bit pattern of a raw pointer is a valid raw pointer value.
unsafe impl AnyBits for *mut eki_ks {}

/// A struct or integer output (`eki_key_id *`, `eki_key_info *`, `eki_ks **`, `uint64_t *`, ...)
/// in a heap allocation of exactly its size and alignment, pre-filled with [`FILL`], so its
/// bytes, padding included, can be checked after a failed call.
pub struct Slot<T: AnyBits> {
    null: bool,
    ptr: NonNull<T>,
    _owns: PhantomData<T>,
}

impl<T: AnyBits> Slot<T> {
    /// A slot, passed as NULL when `null` is set.
    pub fn new(null: bool) -> Self {
        let layout = Layout::new::<T>();
        // SAFETY: every `T` used here has a non-zero size, which is what `alloc` requires.
        let raw = unsafe { alloc(layout) };
        let ptr = NonNull::new(raw.cast::<T>()).expect("allocation succeeded");
        // SAFETY: `raw` is a fresh allocation of `size_of::<T>()` bytes.
        unsafe { raw.write_bytes(FILL, layout.size()) };
        Self {
            null,
            ptr,
            _owns: PhantomData,
        }
    }

    /// The pointer argument.
    pub fn ptr(&mut self) -> *mut T {
        if self.null {
            core::ptr::null_mut()
        } else {
            self.ptr.as_ptr()
        }
    }

    /// True when passed as NULL.
    pub fn is_null(&self) -> bool {
        self.null
    }

    /// The bytes of the slot.
    pub fn bytes(&self) -> &[u8] {
        // SAFETY: the allocation holds `size_of::<T>()` bytes, all initialised: `new` filled them
        // and the library writes either a whole value or zeros over them.
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr().cast::<u8>(), size_of::<T>()) }
    }

    /// The value in the slot.
    pub fn get(&self) -> T {
        // SAFETY: the allocation is aligned for `T` and holds `size_of::<T>()` initialised bytes,
        // and `T: AnyBits` makes any of them a valid value.
        unsafe { self.ptr.as_ptr().read() }
    }

    /// The state for [`Call::check`]; a failed call zero-fills the whole value.
    pub fn seen(&self) -> Seen {
        Seen {
            null: self.null,
            on_error: OnError::Zero,
            bytes: self.bytes().to_vec(),
        }
    }
}

impl<T: AnyBits> Drop for Slot<T> {
    fn drop(&mut self) {
        // SAFETY: `ptr` came from `alloc` with this layout in `new` and is freed only here.
        unsafe { dealloc(self.ptr.as_ptr().cast(), Layout::new::<T>()) };
    }
}

// --- Checking a call ---------------------------------------------------------------------------

/// One finished call and what the contract says about it.
#[derive(Debug)]
pub struct Call {
    /// The function's name, for the panic message.
    pub function: &'static str,
    /// The status it returned.
    pub status: i32,
    /// A pointer parameter broke the pointer rule (NULL where a pointer is required).
    pub null_param: bool,
    /// A configuration field the contract checks for NULL was NULL.
    pub null_field: bool,
    /// A length argument was above its parameter's maximum.
    pub over_cap: bool,
    /// The outputs after the call.
    pub outputs: Vec<Seen>,
}

impl Call {
    /// A call with no outputs and nothing NULL.
    pub fn new(function: &'static str, status: i32) -> Self {
        Self {
            function,
            status,
            null_param: false,
            null_field: false,
            over_cap: false,
            outputs: Vec::new(),
        }
    }

    /// Panics unless the call kept the contract:
    /// * the status is defined and not `EKI_ERR_INTERNAL`;
    /// * a NULL pointer parameter gives `EKI_ERR_NULL_POINTER` (step 1 comes first), and that
    ///   status comes from nothing else than a NULL parameter or configuration field;
    /// * a length above its maximum fails (`EKI_ERR_INVALID_ARGUMENT` unless a pointer was NULL);
    /// * after a failure every non-NULL output is zero-filled, or untouched when its length was
    ///   above the maximum.
    pub fn check(&self) {
        let f = self.function;
        check_status(f, self.status);
        if self.null_param {
            assert_eq!(
                self.status, NULL_POINTER,
                "{f} with a NULL pointer parameter"
            );
        }
        if self.status == NULL_POINTER {
            assert!(
                self.null_param || self.null_field,
                "{f} returned EKI_ERR_NULL_POINTER with no NULL argument"
            );
        }
        if self.over_cap && !self.null_param {
            assert_eq!(
                self.status, INVALID_ARGUMENT,
                "{f} with a length above its maximum"
            );
        }
        if self.status == OK {
            return;
        }
        for (index, out) in self.outputs.iter().enumerate() {
            if out.null {
                continue;
            }
            let want = match out.on_error {
                OnError::Zero => 0,
                OnError::Untouched => FILL,
            };
            assert!(
                out.bytes.iter().all(|&b| b == want),
                "{f} returned {} but output #{index} is not {:?}: {:02x?}",
                self.status,
                out.on_error,
                out.bytes
            );
        }
    }
}

// --- Key stores --------------------------------------------------------------------------------

/// An open key store handle, closed when dropped, so a failed assertion still releases it (and
/// the lock on its audit log).
pub struct Store(*mut eki_ks);

impl Store {
    /// Takes ownership of `handle`, which `eki_ks_open` or `eki_ks_open_v2` returned with
    /// `EKI_OK`.
    pub fn from_raw(handle: *mut eki_ks) -> Self {
        assert!(!handle.is_null(), "a store opened with EKI_OK has a handle");
        Self(handle)
    }

    /// Opens a software store with `eki_ks_open`.
    pub fn software() -> Self {
        let config = eki_ks_config {
            backend: EKI_KS_SOFTWARE,
            pkcs11_module_path: core::ptr::null(),
            pkcs11_token_label: core::ptr::null(),
            pkcs11_user_pin: core::ptr::null(),
        };
        let mut handle = core::ptr::null_mut();
        // SAFETY: `config` is a live, initialised struct (the software backend ignores the NULL
        // PKCS#11 fields); `handle` is a live, writable pointer slot.
        let status = unsafe { eki_ks_open(&config, &mut handle) } as i32;
        assert_eq!(status, OK, "opening a software store failed");
        Self::from_raw(handle)
    }

    /// The handle argument.
    pub fn ptr(&self) -> *mut eki_ks {
        self.0
    }

    /// Generates a key of `alg` labelled `label`; panics if that fails.
    pub fn generate(&self, alg: eki_key_alg, label: &CStr) -> eki_key_id {
        let mut id = eki_key_id {
            bytes: [FILL; EKI_KEY_ID_LEN],
        };
        // SAFETY: `self.0` is an open handle; `label` is NUL-terminated and outlives the call;
        // `id` is a live, writable `eki_key_id`.
        let status = unsafe { eki_ks_generate(self.0, alg, label.as_ptr(), &mut id) } as i32;
        assert_eq!(status, OK, "eki_ks_generate failed in an open store");
        id
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from a successful open and is closed exactly once, here, with no
        // other call on it in flight.
        unsafe { eki_ks_close(self.0) };
    }
}

/// Number of approver keys a target can pick from.
pub const APPROVER_POOL: usize = 4;

/// The domain prefix of a destroy approval message.
pub const APPROVAL_DOMAIN: &[u8; 20] = b"ekibridge-destroy-v1";

/// An approver key: its id in the approvers' store and its public key.
type ApproverKey = (eki_key_id, [u8; EKI_P256_PUBLIC_KEY_LEN]);

/// ECDSA P-256 keys in a software store of their own, for dual control: their public keys go
/// into a configuration, their signatures approve destroy requests. Made on first use.
#[derive(Default)]
pub struct Approvers {
    pool: Option<(Store, Vec<ApproverKey>)>,
}

impl Approvers {
    fn pool(&mut self) -> &(Store, Vec<ApproverKey>) {
        self.pool.get_or_insert_with(|| {
            let store = Store::software();
            let keys = (0..APPROVER_POOL)
                .map(|_| {
                    let id = store.generate(EKI_KEY_ECDSA_P256, c"approver");
                    let mut public_key = [FILL; EKI_P256_PUBLIC_KEY_LEN];
                    // SAFETY: `store` is open; `id` is a live struct; `public_key` is a
                    // writable 65-byte buffer.
                    let status =
                        unsafe { eki_ks_get_public_key(store.ptr(), &id, public_key.as_mut_ptr()) }
                            as i32;
                    assert_eq!(status, OK, "reading an approver's public key failed");
                    (id, public_key)
                })
                .collect();
            (store, keys)
        })
    }

    /// The public key of approver `index % APPROVER_POOL`.
    pub fn public_key(&mut self, index: u8) -> [u8; EKI_P256_PUBLIC_KEY_LEN] {
        self.pool().1[usize::from(index) % APPROVER_POOL].1
    }

    /// The approval of `request` for key `id` by approver `index % APPROVER_POOL`.
    pub fn approve(
        &mut self,
        index: u8,
        request: &[u8; 32],
        id: &eki_key_id,
    ) -> [u8; EKI_P256_SIGNATURE_LEN] {
        let (store, keys) = self.pool();
        let signer = keys[usize::from(index) % APPROVER_POOL].0;
        let mut message = Vec::with_capacity(68);
        message.extend_from_slice(APPROVAL_DOMAIN);
        message.extend_from_slice(request);
        message.extend_from_slice(&id.bytes);
        let mut sig = [FILL; EKI_P256_SIGNATURE_LEN];
        // SAFETY: `store` is open; `signer` is a live struct; `message` is a live Vec of the
        // stated length; `sig` is a writable 64-byte buffer.
        let status = unsafe {
            eki_ks_sign(
                store.ptr(),
                &signer,
                message.as_ptr(),
                message.len(),
                sig.as_mut_ptr(),
            )
        } as i32;
        assert_eq!(status, OK, "an approver failed to sign");
        sig
    }
}

/// A PKCS#11 module path that names no file, so a configuration that reaches the module load
/// fails there (`EKI_ERR_BACKEND`) and no token is opened.
pub const NO_MODULE: &CStr = c"/nonexistent/ekibridge-fuzz/no-pkcs11-module.so";

/// Longest token label and PIN the targets pass before the NUL: longer than the 32 and 255
/// bytes the contract allows.
pub const TOKEN_LABEL_FUZZ_MAX: usize = 40;
/// See [`TOKEN_LABEL_FUZZ_MAX`].
pub const PIN_FUZZ_MAX: usize = 300;

/// A store configuration, owning every buffer its pointers point into.
///
/// Bytes read: `backend` ([`Reader::i32`]); one byte of NULL flags for the PKCS#11 fields (bit 0
/// set: `pkcs11_module_path` is [`NO_MODULE`]; bit 1: `pkcs11_token_label` is given; bit 2:
/// `pkcs11_user_pin` is given); the token label ([`Reader::bytes`], cut to
/// [`TOKEN_LABEL_FUZZ_MAX`], NUL appended); the PIN (the same, [`PIN_FUZZ_MAX`]); the audit log
/// path ([`read_audit_path`]); the approver count (one byte: 255 is `usize::MAX`, any other value
/// is taken modulo 12); the approver keys source (one byte modulo 3: NULL; raw bytes from
/// [`Reader::bytes`], resized to `count * 65` when the count is valid; or keys of [`Approvers`],
/// one index byte per key, for a valid count) and their bytes.
pub struct Config {
    backend: i32,
    module_path: Option<&'static CStr>,
    token_label: Text,
    pin: Text,
    audit: Text,
    approver_count: usize,
    approver_keys: Option<Vec<u8>>,
    /// The approver keys came from [`Approvers`], so they are valid points.
    approvers_generated: bool,
    /// Two of the generated approver keys are the same.
    approvers_repeat: bool,
}

impl Config {
    /// Reads a configuration.
    pub fn read(r: &mut Reader<'_>, scratch: &Scratch, approvers: &mut Approvers) -> Self {
        let backend = r.i32();
        let flags = r.u8();
        let mut token_label = r.bytes();
        token_label.truncate(TOKEN_LABEL_FUZZ_MAX);
        let mut pin = r.bytes();
        pin.truncate(PIN_FUZZ_MAX);
        let audit = read_audit_path(r, scratch);
        let approver_count = match r.u8() {
            255 => usize::MAX,
            n => usize::from(n % 12),
        };
        let valid_count = (2..=EKI_APPROVERS_MAX).contains(&approver_count);
        let source = r.u8() % 3;
        let mut picks = Vec::new();
        let approver_keys = match source {
            0 => None,
            1 => {
                let keys = r.bytes();
                Some(if valid_count {
                    exact(&keys, approver_count * EKI_P256_PUBLIC_KEY_LEN, 0)
                } else {
                    keys
                })
            }
            _ => {
                let count = if valid_count { approver_count } else { 1 };
                let mut keys = Vec::with_capacity(count * EKI_P256_PUBLIC_KEY_LEN);
                for _ in 0..count {
                    let pick = r.u8();
                    picks.push(usize::from(pick) % APPROVER_POOL);
                    keys.extend_from_slice(&approvers.public_key(pick));
                }
                Some(keys)
            }
        };
        let text = |given: bool, bytes: &[u8]| {
            if given {
                Text::terminated(bytes)
            } else {
                Text::null()
            }
        };
        Self {
            backend,
            module_path: (flags & 1 != 0).then_some(NO_MODULE),
            token_label: text(flags & 2 != 0, &token_label),
            pin: text(flags & 4 != 0, &pin),
            audit,
            approver_count,
            approver_keys,
            approvers_generated: source == 2,
            approvers_repeat: (1..picks.len()).any(|i| picks[..i].contains(&picks[i])),
        }
    }

    /// The software backend with nothing else: what `eki_ks_open` gets in the common case.
    pub fn software() -> Self {
        Self {
            backend: EKI_KS_SOFTWARE.0,
            module_path: None,
            token_label: Text::null(),
            pin: Text::null(),
            audit: Text::null(),
            approver_count: 0,
            approver_keys: None,
            approvers_generated: false,
            approvers_repeat: false,
        }
    }

    /// The `eki_ks_config` view: the backend and the PKCS#11 fields.
    pub fn v1(&self) -> eki_ks_config {
        eki_ks_config {
            backend: eki_ks_backend(self.backend),
            pkcs11_module_path: self.module_path.map_or(core::ptr::null(), CStr::as_ptr),
            pkcs11_token_label: self.token_label.ptr(),
            pkcs11_user_pin: self.pin.ptr(),
        }
    }

    /// The `eki_ks_config_v2` view.
    pub fn v2(&self) -> eki_ks_config_v2 {
        let v1 = self.v1();
        eki_ks_config_v2 {
            backend: v1.backend,
            pkcs11_module_path: v1.pkcs11_module_path,
            pkcs11_token_label: v1.pkcs11_token_label,
            pkcs11_user_pin: v1.pkcs11_user_pin,
            audit_log_path: self.audit.ptr(),
            approver_public_keys: self
                .approver_keys
                .as_ref()
                .map_or(core::ptr::null(), |keys| keys.as_ptr()),
            approver_count: self.approver_count,
        }
    }

    /// Whether a field that `eki_ks_open` checks for NULL is NULL.
    pub fn null_field_v1(&self) -> bool {
        self.backend == EKI_KS_PKCS11.0
            && WITH_PKCS11
            && (self.module_path.is_none() || self.token_label.is_null() || self.pin.is_null())
    }

    /// Whether a field that `eki_ks_open_v2` checks for NULL is NULL.
    pub fn null_field_v2(&self) -> bool {
        self.null_field_v1() || (self.approver_count != 0 && self.approver_keys.is_none())
    }

    /// Whether `eki_ks_open_v2` gets the run's log file as its audit log.
    pub fn uses_log(&self, scratch: &Scratch) -> bool {
        self.audit.seen(EKI_AUDIT_PATH_MAX_LEN + 1) == Some(scratch.log.as_bytes())
    }

    /// Whether the configuration has dual control, if it opens.
    pub fn has_approvers(&self) -> bool {
        self.approver_count != 0
    }

    /// Makes the run's log file the audit log.
    pub fn set_audit_log(&mut self, scratch: &Scratch) {
        self.audit = Text::terminated(scratch.log.as_bytes());
    }

    /// Whether the configuration has an audit log, if it opens.
    pub fn has_audit_log(&self) -> bool {
        !self.audit.is_null()
    }

    /// The statuses `eki_ks_open` (`v2` false) or `eki_ks_open_v2` may return for this
    /// configuration when `config` and `out` are not NULL, step by step in the contract's order:
    /// the backend selector; every NULL field; the token label, the PIN, the audit path, the
    /// approver count and the approver keys; opening the backend (a PKCS#11 module that does not
    /// exist fails); opening the log (`log_locked`: another handle holds the run's log).
    ///
    /// Raw approver keys may or may not be valid points, so for them both outcomes are allowed.
    pub fn expected_open(&self, v2: bool, scratch: &Scratch, log_locked: bool) -> Vec<i32> {
        let pkcs11 = self.backend == EKI_KS_PKCS11.0;
        if self.backend != EKI_KS_SOFTWARE.0 && !pkcs11 {
            return vec![INVALID_ARGUMENT];
        }
        if pkcs11 && !WITH_PKCS11 {
            return vec![UNSUPPORTED];
        }
        if (v2 && self.null_field_v2()) || (!v2 && self.null_field_v1()) {
            return vec![NULL_POINTER];
        }
        let printable = |b: &u8| (0x20..=0x7E).contains(b);
        if pkcs11 {
            let label = self
                .token_label
                .seen(TOKEN_LABEL_MAX + 1)
                .unwrap_or_default();
            let pin = self.pin.seen(PIN_MAX + 1).unwrap_or_default();
            if !(1..=TOKEN_LABEL_MAX).contains(&label.len())
                || !label.iter().all(printable)
                || !(1..=PIN_MAX).contains(&pin.len())
            {
                return vec![INVALID_ARGUMENT];
            }
        }
        let mut allowed = Vec::new();
        if v2 {
            let path = self.audit.seen(EKI_AUDIT_PATH_MAX_LEN + 1);
            if path.is_some_and(|p| !(1..=EKI_AUDIT_PATH_MAX_LEN).contains(&p.len())) {
                return vec![INVALID_ARGUMENT];
            }
            let count = self.approver_count;
            if count != 0 && !(2..=EKI_APPROVERS_MAX).contains(&count) {
                return vec![INVALID_ARGUMENT];
            }
            if count != 0 {
                if !self.approvers_generated {
                    allowed.push(INVALID_ARGUMENT);
                } else if self.approvers_repeat {
                    return vec![INVALID_ARGUMENT];
                }
            }
        }
        if pkcs11 {
            allowed.push(BACKEND);
            return allowed;
        }
        let log_fails = v2
            && match self.audit.seen(EKI_AUDIT_PATH_MAX_LEN + 1) {
                None => false,
                Some(path) if path == scratch.log.as_bytes() => log_locked,
                Some(_) => true,
            };
        allowed.push(if log_fails { BACKEND } else { OK });
        allowed
    }
}

/// Longest PKCS#11 token label the contract accepts.
pub const TOKEN_LABEL_MAX: usize = 32;
/// Longest PKCS#11 user PIN the contract accepts.
pub const PIN_MAX: usize = 255;

// --- Audit logs --------------------------------------------------------------------------------

/// The fourteen `op` names of an audit record.
pub const AUDIT_OPS: [&str; 14] = [
    "open",
    "close",
    "generate",
    "unwrap",
    "rotate",
    "revoke",
    "destroy",
    "destroy_request",
    "destroy_approve",
    "sign",
    "hmac",
    "hmac_verify",
    "wrap",
    "get_public_key",
];

/// The end of a valid audit log: its number of records and the hash of the last one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditHead {
    /// The number of records.
    pub records: u64,
    /// The hash of the last record; zeros for an empty log.
    pub hash: [u8; EKI_AUDIT_HASH_LEN],
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Whether `text` is `YYYY-MM-DDTHH:MM:SSZ` naming a real UTC second from 1970 on.
fn audit_time_is_valid(text: &[u8]) -> bool {
    let shape = b"dddd-dd-ddTdd:dd:ddZ";
    if text.len() != shape.len()
        || !text.iter().zip(shape).all(|(&t, &s)| {
            if s == b'd' {
                t.is_ascii_digit()
            } else {
                t == s
            }
        })
    {
        return false;
    }
    let num = |range: core::ops::Range<usize>| {
        text[range]
            .iter()
            .fold(0_u32, |n, &d| n * 10 + u32::from(d - b'0'))
    };
    let (year, month, day) = (num(0..4), num(5..7), num(8..10));
    let (hour, minute, second) = (num(11..13), num(14..16), num(17..19));
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let month_days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    year >= 1970 && (1..=month_days).contains(&day) && hour < 24 && minute < 60 && second < 60
}

/// Whether `text` is a canonical decimal (no sign, no leading zero) of `value`.
fn audit_number_is(text: &[u8], value: u64) -> bool {
    text == value.to_string().as_bytes()
}

/// An independent strict reading of an audit log, written from the ABI 2 contract (section 5
/// and amendments 6, 12 and 15) rather than from either library: the head of `log` if every
/// line is exactly a record that continues the chain, `None` otherwise.
pub fn audit_rebuild(log: &[u8]) -> Option<AuditHead> {
    let mut head = AuditHead {
        records: 0,
        hash: [0; EKI_AUDIT_HASH_LEN],
    };
    if log.is_empty() {
        return Some(head);
    }
    let body = log.strip_suffix(b"\n")?;
    for line in body.split(|&b| b == b'\n') {
        let rest = line.strip_prefix(b"{\"seq\":")?;
        let (seq, rest) = split_at_byte(rest, b',')?;
        if !audit_number_is(seq, head.records + 1) {
            return None;
        }
        let rest = rest.strip_prefix(b"\"time\":\"")?;
        let (time, rest) = split_at_byte(rest, b'"')?;
        let rest = rest.strip_prefix(b",\"op\":\"")?;
        let (op, rest) = split_at_byte(rest, b'"')?;
        let rest = rest.strip_prefix(b",\"key\":\"")?;
        let (key, rest) = split_at_byte(rest, b'"')?;
        let rest = rest.strip_prefix(b",\"key2\":\"")?;
        let (key2, rest) = split_at_byte(rest, b'"')?;
        let rest = rest.strip_prefix(b",\"status\":")?;
        let (status, rest) = split_at_byte(rest, b',')?;
        let rest = rest.strip_prefix(b"\"prev\":\"")?;
        let (prev, rest) = split_at_byte(rest, b'"')?;
        let rest = rest.strip_prefix(b",\"hash\":\"")?;
        let (hash, rest) = split_at_byte(rest, b'"')?;
        let key_ok = |k: &[u8]| {
            k.is_empty() || (k.len() == 32 && k.iter().all(|b| b"0123456789abcdef".contains(b)))
        };
        let status_ok = (0..=STATUS_MAX as u64).any(|s| audit_number_is(status, s));
        let covered = &line[..line.len() - rest.len() - hash.len() - b",\"hash\":\"\"".len()];
        let digest: [u8; EKI_AUDIT_HASH_LEN] = Sha256::digest(covered).into();
        let valid = rest == b"}"
            && audit_time_is_valid(time)
            && AUDIT_OPS.iter().any(|name| name.as_bytes() == op)
            && key_ok(key)
            && key_ok(key2)
            && status_ok
            && prev == lower_hex(&head.hash).as_bytes()
            && hash == lower_hex(&digest).as_bytes();
        if !valid {
            return None;
        }
        head = AuditHead {
            records: head.records + 1,
            hash: digest,
        };
    }
    Some(head)
}

/// `text` split before the first `byte`, with that byte dropped.
fn split_at_byte(text: &[u8], byte: u8) -> Option<(&[u8], &[u8])> {
    let at = text.iter().position(|&b| b == byte)?;
    Some((&text[..at], &text[at + 1..]))
}
