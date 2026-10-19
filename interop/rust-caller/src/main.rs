//! rust-caller: Rust code that uses the ekicore C ABI without linking either implementation.
//!
//! The binary loads the library named on the command line at run time, so the same build drives
//! libekicore (C++, OpenSSL) and libekicore_rs (Rust, RustCrypto): the runtime-selection switch of
//! the migration plan in miniature. It sees the libraries exactly as a C program would, through
//! the symbols of `include/ekicore.h`; the `ekicore-abi` crate supplies the matching types.
//!
//! ```text
//! interop-rust-caller <path to libekicore.{so,dylib} or libekicore_rs.{so,dylib}>
//! ```
//!
//! It runs a fixed script (version, hkdf, hmac, aead, keystore) and prints one line per step:
//! `PASS <step>` or `FAIL <step> (<status name>): <what failed>`. Status names come from the
//! loaded library's `eki_status_name`. Exit status: 0 if every step passed, 1 if a step failed,
//! 2 on a usage or loading error.
//!
//! Statuses cross the boundary as raw `i32`, never as the `eki_status` enum: a Rust enum holding
//! a value outside its variants is undefined behaviour, and nothing stops a library from returning
//! one. All `unsafe` sits in the thin wrappers of [`Api`] and [`Store`], each with the reason it
//! holds.

#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::{CStr, c_char};
use std::process::ExitCode;
use std::ptr::{self, NonNull};

use ekicore_abi::{
    EKI_ABI_VERSION, EKI_AEAD_AES_256_GCM, EKI_AEAD_CHACHA20_POLY1305, EKI_AEAD_KEY_LEN,
    EKI_AEAD_NONCE_LEN, EKI_AEAD_TAG_LEN, EKI_HMAC_SHA256_LEN, EKI_KEY_AES_256, EKI_KEY_ECDSA_P256,
    EKI_KEY_HMAC_SHA256, EKI_KEY_ID_LEN, EKI_KS_SOFTWARE, EKI_P256_PUBLIC_KEY_LEN,
    EKI_P256_SIGNATURE_LEN, EKI_WRAPPED_KEY_LEN, eki_aead_alg, eki_key_alg, eki_key_id,
    eki_key_info, eki_ks, eki_ks_config, eki_status,
};
use libloading::{Library, Symbol};

const OK: i32 = eki_status::EKI_OK as i32;
const AUTH_FAILED: i32 = eki_status::EKI_ERR_AUTH_FAILED as i32;
const KEY_NOT_FOUND: i32 = eki_status::EKI_ERR_KEY_NOT_FOUND as i32;

// ---- the C functions, typed as include/ekicore.h declares them ---------------------------------

// Parameter names and order follow the header; `eki_status` results are read as plain `i32`.
type AbiVersionFn = unsafe extern "C" fn() -> u32;
type VersionFn = unsafe extern "C" fn() -> *const c_char;
type StatusNameFn = unsafe extern "C" fn(status: i32) -> *const c_char;
type HmacFn = unsafe extern "C" fn(
    key: *const u8,
    key_len: usize,
    msg: *const u8,
    msg_len: usize,
    out: *mut u8,
) -> i32;
type HmacVerifyFn = unsafe extern "C" fn(
    key: *const u8,
    key_len: usize,
    msg: *const u8,
    msg_len: usize,
    tag: *const u8,
    tag_len: usize,
) -> i32;
type HkdfFn = unsafe extern "C" fn(
    ikm: *const u8,
    ikm_len: usize,
    salt: *const u8,
    salt_len: usize,
    info: *const u8,
    info_len: usize,
    okm: *mut u8,
    okm_len: usize,
) -> i32;
type AeadSealFn = unsafe extern "C" fn(
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
) -> i32;
type AeadOpenFn = unsafe extern "C" fn(
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
) -> i32;
type EcdsaVerifyFn = unsafe extern "C" fn(
    public_key: *const u8,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
) -> i32;
type KsOpenFn = unsafe extern "C" fn(config: *const eki_ks_config, out: *mut *mut eki_ks) -> i32;
type KsCloseFn = unsafe extern "C" fn(ks: *mut eki_ks);
type KsLastErrorFn =
    unsafe extern "C" fn(ks: *const eki_ks, buf: *mut c_char, buf_len: usize) -> usize;
type KsGenerateFn = unsafe extern "C" fn(
    ks: *mut eki_ks,
    alg: eki_key_alg,
    label: *const c_char,
    id_out: *mut eki_key_id,
) -> i32;
type KsGetInfoFn = unsafe extern "C" fn(
    ks: *mut eki_ks,
    id: *const eki_key_id,
    info_out: *mut eki_key_info,
) -> i32;
type KsGetPublicKeyFn =
    unsafe extern "C" fn(ks: *mut eki_ks, id: *const eki_key_id, out: *mut u8) -> i32;
type KsSignFn = unsafe extern "C" fn(
    ks: *mut eki_ks,
    id: *const eki_key_id,
    msg: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
) -> i32;
type KsHmacFn = unsafe extern "C" fn(
    ks: *mut eki_ks,
    id: *const eki_key_id,
    msg: *const u8,
    msg_len: usize,
    out: *mut u8,
) -> i32;
type KsWrapFn = unsafe extern "C" fn(
    ks: *mut eki_ks,
    kek_id: *const eki_key_id,
    key_id: *const eki_key_id,
    out: *mut u8,
) -> i32;
type KsUnwrapFn = unsafe extern "C" fn(
    ks: *mut eki_ks,
    kek_id: *const eki_key_id,
    blob: *const u8,
    blob_len: usize,
    alg: eki_key_alg,
    label: *const c_char,
    id: *const eki_key_id,
) -> i32;
type KsDestroyFn = unsafe extern "C" fn(ks: *mut eki_ks, id: *const eki_key_id) -> i32;

// ---- loading -----------------------------------------------------------------------------------

/// The functions of the ABI this program uses, resolved from one loaded library. Each `Symbol`
/// borrows the `Library`, so no function pointer can outlive the code it points into.
struct Api<'lib> {
    abi_version: Symbol<'lib, AbiVersionFn>,
    version: Symbol<'lib, VersionFn>,
    status_name: Symbol<'lib, StatusNameFn>,
    hmac_sha256: Symbol<'lib, HmacFn>,
    hmac_sha256_verify: Symbol<'lib, HmacVerifyFn>,
    hkdf_sha256: Symbol<'lib, HkdfFn>,
    aead_seal: Symbol<'lib, AeadSealFn>,
    aead_open: Symbol<'lib, AeadOpenFn>,
    ecdsa_p256_verify: Symbol<'lib, EcdsaVerifyFn>,
    ks_open: Symbol<'lib, KsOpenFn>,
    ks_close: Symbol<'lib, KsCloseFn>,
    ks_last_error_message: Symbol<'lib, KsLastErrorFn>,
    ks_generate: Symbol<'lib, KsGenerateFn>,
    ks_get_info: Symbol<'lib, KsGetInfoFn>,
    ks_get_public_key: Symbol<'lib, KsGetPublicKeyFn>,
    ks_sign: Symbol<'lib, KsSignFn>,
    ks_hmac_sha256: Symbol<'lib, KsHmacFn>,
    ks_wrap: Symbol<'lib, KsWrapFn>,
    ks_unwrap: Symbol<'lib, KsUnwrapFn>,
    ks_destroy: Symbol<'lib, KsDestroyFn>,
}

/// Looks up `name` in `lib` as a function of type `F`.
///
/// # Safety
///
/// `F` must be the function pointer type that `include/ekicore.h` declares for `name`.
unsafe fn symbol<'lib, F>(lib: &'lib Library, name: &CStr) -> Result<Symbol<'lib, F>, String> {
    // SAFETY: the caller guarantees that `F` matches the C declaration of `name`.
    unsafe { lib.get::<F>(name) }
        .map_err(|e| format!("{}: {}", name.to_string_lossy(), error_chain(&e)))
}

impl<'lib> Api<'lib> {
    fn load(lib: &'lib Library) -> Result<Self, String> {
        // SAFETY: each type alias above is transcribed from the declaration of the same name in
        // include/ekicore.h, with `eki_status` returns read as `i32` (same size and ABI, since
        // the enum is `int32_t`-backed) and the selectors as the `repr(transparent)` newtypes of
        // `ekicore-abi`.
        unsafe {
            Ok(Self {
                abi_version: symbol(lib, c"eki_abi_version")?,
                version: symbol(lib, c"eki_version")?,
                status_name: symbol(lib, c"eki_status_name")?,
                hmac_sha256: symbol(lib, c"eki_hmac_sha256")?,
                hmac_sha256_verify: symbol(lib, c"eki_hmac_sha256_verify")?,
                hkdf_sha256: symbol(lib, c"eki_hkdf_sha256")?,
                aead_seal: symbol(lib, c"eki_aead_seal")?,
                aead_open: symbol(lib, c"eki_aead_open")?,
                ecdsa_p256_verify: symbol(lib, c"eki_ecdsa_p256_verify")?,
                ks_open: symbol(lib, c"eki_ks_open")?,
                ks_close: symbol(lib, c"eki_ks_close")?,
                ks_last_error_message: symbol(lib, c"eki_ks_last_error_message")?,
                ks_generate: symbol(lib, c"eki_ks_generate")?,
                ks_get_info: symbol(lib, c"eki_ks_get_info")?,
                ks_get_public_key: symbol(lib, c"eki_ks_get_public_key")?,
                ks_sign: symbol(lib, c"eki_ks_sign")?,
                ks_hmac_sha256: symbol(lib, c"eki_ks_hmac_sha256")?,
                ks_wrap: symbol(lib, c"eki_ks_wrap")?,
                ks_unwrap: symbol(lib, c"eki_ks_unwrap")?,
                ks_destroy: symbol(lib, c"eki_ks_destroy")?,
            })
        }
    }
}

/// Copies a static C string returned by the library, tolerating NULL.
///
/// # Safety
///
/// `p` must be NULL or point to a NUL-terminated string that stays valid during the call.
unsafe fn c_string(p: *const c_char) -> String {
    if p.is_null() {
        return "(null)".to_owned();
    }
    // SAFETY: `p` is non-NULL and, by the caller's guarantee, NUL-terminated and valid.
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

/// The inputs `eki_aead_seal` and `eki_aead_open` share.
struct AeadParams<'a> {
    alg: eki_aead_alg,
    key: &'a [u8],
    nonce: &'a [u8],
    aad: &'a [u8],
}

// Safe wrappers over the stateless functions. Every pointer passed below comes from a live Rust
// slice or array with the exact length passed next to it (an empty slice yields a dangling but
// non-NULL pointer with length 0, which the contract never dereferences), outputs are distinct
// `&mut` borrows and so never overlap an input, and the library keeps no pointer after returning.
impl Api<'_> {
    fn abi_version(&self) -> u32 {
        // SAFETY: no arguments; the function only returns a constant.
        unsafe { (self.abi_version)() }
    }

    fn version(&self) -> Option<String> {
        // SAFETY: no arguments; the result is static storage or, from a broken library, NULL.
        let p = unsafe { (self.version)() };
        // SAFETY: `p` is NULL or the library's static NUL-terminated version string.
        (!p.is_null()).then(|| unsafe { c_string(p) })
    }

    fn status_name(&self, status: i32) -> String {
        // SAFETY: any `int32_t` is a valid argument; the result is a static string.
        let p = unsafe { (self.status_name)(status) };
        // SAFETY: `p` is NULL or the library's static NUL-terminated status name.
        unsafe { c_string(p) }
    }

    fn hkdf_sha256(&self, ikm: &[u8], salt: &[u8], info: &[u8], okm: &mut [u8]) -> i32 {
        // SAFETY: see the comment on this impl block.
        unsafe {
            (self.hkdf_sha256)(
                ikm.as_ptr(),
                ikm.len(),
                salt.as_ptr(),
                salt.len(),
                info.as_ptr(),
                info.len(),
                okm.as_mut_ptr(),
                okm.len(),
            )
        }
    }

    fn hmac_sha256(&self, key: &[u8], msg: &[u8], out: &mut [u8; EKI_HMAC_SHA256_LEN]) -> i32 {
        // SAFETY: see the comment on this impl block; `out` is the fixed 32 bytes.
        unsafe {
            (self.hmac_sha256)(
                key.as_ptr(),
                key.len(),
                msg.as_ptr(),
                msg.len(),
                out.as_mut_ptr(),
            )
        }
    }

    fn hmac_sha256_verify(&self, key: &[u8], msg: &[u8], tag: &[u8]) -> i32 {
        // SAFETY: see the comment on this impl block.
        unsafe {
            (self.hmac_sha256_verify)(
                key.as_ptr(),
                key.len(),
                msg.as_ptr(),
                msg.len(),
                tag.as_ptr(),
                tag.len(),
            )
        }
    }

    /// Seals `pt` into `ct`, which must have the same length.
    fn aead_seal(
        &self,
        p: &AeadParams,
        pt: &[u8],
        ct: &mut [u8],
        tag: &mut [u8; EKI_AEAD_TAG_LEN],
    ) -> i32 {
        assert_eq!(ct.len(), pt.len(), "ct_out must hold pt_len bytes");
        // SAFETY: see the comment on this impl block; `ct` holds `pt.len()` bytes as the
        // contract requires (checked above) and `tag` is the fixed 16 bytes.
        unsafe {
            (self.aead_seal)(
                p.alg,
                p.key.as_ptr(),
                p.key.len(),
                p.nonce.as_ptr(),
                p.nonce.len(),
                p.aad.as_ptr(),
                p.aad.len(),
                pt.as_ptr(),
                pt.len(),
                ct.as_mut_ptr(),
                tag.as_mut_ptr(),
            )
        }
    }

    /// Opens `ct` into `pt`, which must have the same length.
    fn aead_open(
        &self,
        p: &AeadParams,
        ct: &[u8],
        tag: &[u8; EKI_AEAD_TAG_LEN],
        pt: &mut [u8],
    ) -> i32 {
        assert_eq!(pt.len(), ct.len(), "pt_out must hold ct_len bytes");
        // SAFETY: see the comment on this impl block; `pt` holds `ct.len()` bytes as the
        // contract requires (checked above) and `tag` is the fixed 16 bytes.
        unsafe {
            (self.aead_open)(
                p.alg,
                p.key.as_ptr(),
                p.key.len(),
                p.nonce.as_ptr(),
                p.nonce.len(),
                p.aad.as_ptr(),
                p.aad.len(),
                ct.as_ptr(),
                ct.len(),
                tag.as_ptr(),
                pt.as_mut_ptr(),
            )
        }
    }

    fn ecdsa_p256_verify(
        &self,
        public_key: &[u8; EKI_P256_PUBLIC_KEY_LEN],
        msg: &[u8],
        sig: &[u8; EKI_P256_SIGNATURE_LEN],
    ) -> i32 {
        // SAFETY: see the comment on this impl block; `public_key` and `sig` are the fixed 65
        // and 64 bytes.
        unsafe {
            (self.ecdsa_p256_verify)(public_key.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr())
        }
    }
}

// ---- the key store handle ----------------------------------------------------------------------

/// An open `eki_ks` handle, closed on drop whatever path the step takes.
///
/// The methods take `&self`: the library serialises operations on a handle internally, and the
/// pointer itself is never changed after `open`. The same pointer rules as for [`Api`] apply.
struct Store<'a, 'lib> {
    api: &'a Api<'lib>,
    ks: NonNull<eki_ks>,
}

impl<'a, 'lib> Store<'a, 'lib> {
    /// Opens an in-memory software store; the PKCS#11 fields are ignored by that backend.
    fn open_software(api: &'a Api<'lib>) -> Result<Self, i32> {
        let config = eki_ks_config {
            backend: EKI_KS_SOFTWARE,
            pkcs11_module_path: ptr::null(),
            pkcs11_token_label: ptr::null(),
            pkcs11_user_pin: ptr::null(),
        };
        let mut ks: *mut eki_ks = ptr::null_mut();
        // SAFETY: `config` and `ks` are live locals; the library copies what it needs from
        // `config` and writes only the handle pointer to `ks`.
        let status = unsafe { (api.ks_open)(&config, &mut ks) };
        match NonNull::new(ks) {
            Some(ks) if status == OK => Ok(Self { api, ks }),
            Some(ks) => {
                // The contract sets *out = NULL on failure; release a handle anyway if one leaked.
                // SAFETY: `ks` was produced by this library's eki_ks_open and is closed only here.
                unsafe { (api.ks_close)(ks.as_ptr()) };
                Err(status)
            }
            None if status == OK => Err(eki_status::EKI_ERR_INTERNAL as i32),
            None => Err(status),
        }
    }

    /// The handle's last error message, or "" if there is none.
    fn last_error(&self) -> String {
        let mut buf = [0u8; 256];
        // SAFETY: `ks` is open; `buf` is writable for `buf.len()` bytes and the library writes
        // at most that many, NUL included.
        unsafe {
            (self.api.ks_last_error_message)(self.ks.as_ptr(), buf.as_mut_ptr().cast(), buf.len())
        };
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..end]).into_owned()
    }

    /// Like [`expect`], adding the handle's last error message to a failure.
    fn expect(&self, got: i32, want: i32, what: &str) -> StepResult {
        expect(got, want, what).map_err(|mut failure| {
            let message = self.last_error();
            if !message.is_empty() {
                failure.what = format!("{} [{message}]", failure.what);
            }
            failure
        })
    }

    fn generate(&self, alg: eki_key_alg, label: &CStr, id: &mut eki_key_id) -> i32 {
        // SAFETY: `ks` is open; `label` is NUL-terminated; `id` is a live, writable key id.
        unsafe { (self.api.ks_generate)(self.ks.as_ptr(), alg, label.as_ptr(), id) }
    }

    fn get_info(&self, id: &eki_key_id, info: &mut eki_key_info) -> i32 {
        // SAFETY: `ks` is open; `id` and `info` are live, and `info` is writable.
        unsafe { (self.api.ks_get_info)(self.ks.as_ptr(), id, info) }
    }

    fn get_public_key(&self, id: &eki_key_id, out: &mut [u8; EKI_P256_PUBLIC_KEY_LEN]) -> i32 {
        // SAFETY: `ks` is open; `out` is the fixed 65 bytes.
        unsafe { (self.api.ks_get_public_key)(self.ks.as_ptr(), id, out.as_mut_ptr()) }
    }

    fn sign(&self, id: &eki_key_id, msg: &[u8], sig: &mut [u8; EKI_P256_SIGNATURE_LEN]) -> i32 {
        // SAFETY: `ks` is open; `msg` is a live slice of `msg.len()` bytes; `sig` is the fixed 64
        // bytes.
        unsafe {
            (self.api.ks_sign)(
                self.ks.as_ptr(),
                id,
                msg.as_ptr(),
                msg.len(),
                sig.as_mut_ptr(),
            )
        }
    }

    fn hmac_sha256(&self, id: &eki_key_id, msg: &[u8], out: &mut [u8; EKI_HMAC_SHA256_LEN]) -> i32 {
        // SAFETY: `ks` is open; `msg` is a live slice of `msg.len()` bytes; `out` is the fixed 32
        // bytes.
        unsafe {
            (self.api.ks_hmac_sha256)(
                self.ks.as_ptr(),
                id,
                msg.as_ptr(),
                msg.len(),
                out.as_mut_ptr(),
            )
        }
    }

    fn wrap(&self, kek: &eki_key_id, key: &eki_key_id, out: &mut [u8; EKI_WRAPPED_KEY_LEN]) -> i32 {
        // SAFETY: `ks` is open; both ids are live; `out` is the fixed 40 bytes.
        unsafe { (self.api.ks_wrap)(self.ks.as_ptr(), kek, key, out.as_mut_ptr()) }
    }

    fn unwrap(
        &self,
        kek: &eki_key_id,
        blob: &[u8],
        alg: eki_key_alg,
        label: &CStr,
        id: &eki_key_id,
    ) -> i32 {
        // SAFETY: `ks` is open; `blob` is a live slice of `blob.len()` bytes; `label` is
        // NUL-terminated; both ids are live.
        unsafe {
            (self.api.ks_unwrap)(
                self.ks.as_ptr(),
                kek,
                blob.as_ptr(),
                blob.len(),
                alg,
                label.as_ptr(),
                id,
            )
        }
    }

    fn destroy(&self, id: &eki_key_id) -> i32 {
        // SAFETY: `ks` is open; `id` is live.
        unsafe { (self.api.ks_destroy)(self.ks.as_ptr(), id) }
    }
}

impl Drop for Store<'_, '_> {
    fn drop(&mut self) {
        // SAFETY: `ks` came from this library's eki_ks_open, is closed exactly once (here), and
        // no other reference to the handle outlives the `Store`.
        unsafe { (self.api.ks_close)(self.ks.as_ptr()) }
    }
}

// ---- step results ------------------------------------------------------------------------------

/// Why a step failed: the status the library returned (`EKI_OK` when the call succeeded but its
/// output was wrong) and a description of the call or check.
struct Failure {
    status: i32,
    what: String,
}

type StepResult = Result<(), Failure>;

/// A failure unless `got == want`.
fn expect(got: i32, want: i32, what: &str) -> StepResult {
    if got == want {
        Ok(())
    } else {
        Err(Failure {
            status: got,
            what: what.to_owned(),
        })
    }
}

/// A failure (reported with `EKI_OK`: the call itself succeeded) unless `ok` holds.
fn check(ok: bool, what: &str) -> StepResult {
    if ok {
        Ok(())
    } else {
        Err(Failure {
            status: OK,
            what: what.to_owned(),
        })
    }
}

// ---- helpers -----------------------------------------------------------------------------------

/// Decodes a hex literal from a published test vector.
fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("test vector literals are valid hex")
}

/// An error and its sources on one line: libloading puts the `dlerror()` text in the source.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut text = e.to_string();
    let mut source = e.source();
    while let Some(inner) = source {
        text = format!("{text}: {inner}");
        source = inner.source();
    }
    text
}

/// Random test inputs from the operating system. They only feed a self-test; the library makes
/// its own keys.
fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).expect("the operating system random source is available");
    out
}

// ---- steps -------------------------------------------------------------------------------------

fn step_version(api: &Api) -> StepResult {
    let version = api.version();
    let abi = api.abi_version();
    println!(
        "  library {}, ABI {abi}",
        version.as_deref().unwrap_or("(null)")
    );
    check(version.is_some(), "eki_version returned NULL")?;
    check(
        abi == EKI_ABI_VERSION,
        &format!("eki_abi_version is not {EKI_ABI_VERSION}"),
    )
}

/// RFC 5869 A.1.
fn step_hkdf(api: &Api) -> StepResult {
    let ikm = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = unhex("000102030405060708090a0b0c");
    let info = unhex("f0f1f2f3f4f5f6f7f8f9");
    let want = unhex(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    );
    let mut okm = vec![0u8; want.len()];
    expect(
        api.hkdf_sha256(&ikm, &salt, &info, &mut okm),
        OK,
        "eki_hkdf_sha256 on RFC 5869 A.1",
    )?;
    check(okm == want, "OKM differs from RFC 5869 A.1")
}

/// RFC 4231 test case 2.
fn step_hmac(api: &Api) -> StepResult {
    let key = b"Jefe";
    let msg = b"what do ya want for nothing?";
    let want = unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    let mut tag = [0u8; EKI_HMAC_SHA256_LEN];
    expect(
        api.hmac_sha256(key, msg, &mut tag),
        OK,
        "eki_hmac_sha256 on RFC 4231 case 2",
    )?;
    check(tag[..] == want[..], "tag differs from RFC 4231 case 2")?;
    expect(
        api.hmac_sha256_verify(key, msg, &tag),
        OK,
        "eki_hmac_sha256_verify on the correct tag",
    )?;
    tag[0] ^= 0x01;
    expect(
        api.hmac_sha256_verify(key, msg, &tag),
        AUTH_FAILED,
        "eki_hmac_sha256_verify on a flipped tag",
    )
}

fn aead_round_trip(api: &Api, alg: eki_aead_alg, name: &str) -> StepResult {
    let key: [u8; EKI_AEAD_KEY_LEN] = random_bytes();
    let nonce: [u8; EKI_AEAD_NONCE_LEN] = random_bytes();
    let aad: [u8; 16] = random_bytes();
    let pt: [u8; 1024] = random_bytes();
    let mut ct = [0u8; 1024];
    let mut tag = [0u8; EKI_AEAD_TAG_LEN];

    let params = AeadParams {
        alg,
        key: &key,
        nonce: &nonce,
        aad: &aad,
    };

    let status = api.aead_seal(&params, &pt, &mut ct, &mut tag);
    expect(status, OK, &format!("eki_aead_seal {name}"))?;

    let mut opened = [0xA5u8; 1024];
    let status = api.aead_open(&params, &ct, &tag, &mut opened);
    expect(status, OK, &format!("eki_aead_open {name}"))?;
    check(
        opened == pt,
        &format!("eki_aead_open {name} returned other plaintext"),
    )?;

    tag[EKI_AEAD_TAG_LEN - 1] ^= 0x80;
    opened.fill(0xA5);
    let status = api.aead_open(&params, &ct, &tag, &mut opened);
    expect(
        status,
        AUTH_FAILED,
        &format!("eki_aead_open {name} with a tampered tag"),
    )?;
    check(
        opened.iter().all(|&b| b == 0),
        &format!("eki_aead_open {name} left plaintext after a failure"),
    )
}

fn step_aead(api: &Api) -> StepResult {
    aead_round_trip(api, EKI_AEAD_AES_256_GCM, "AES-256-GCM")?;
    aead_round_trip(api, EKI_AEAD_CHACHA20_POLY1305, "ChaCha20-Poly1305")
}

/// A key the keystore step creates, with the metadata `get_info` must report back.
struct NamedKey {
    alg: eki_key_alg,
    label: &'static CStr,
    id: eki_key_id,
}

impl NamedKey {
    fn new(alg: eki_key_alg, label: &'static CStr) -> Self {
        Self {
            alg,
            label,
            id: eki_key_id {
                bytes: [0; EKI_KEY_ID_LEN],
            },
        }
    }

    fn name(&self) -> String {
        self.label.to_string_lossy().into_owned()
    }
}

/// `get_info` must report the algorithm and the label, NUL-padded through byte 64.
fn check_info(store: &Store, key: &NamedKey) -> StepResult {
    let mut info = eki_key_info {
        alg: eki_key_alg(0),
        label: [0; 65],
    };
    store.expect(
        store.get_info(&key.id, &mut info),
        OK,
        &format!("eki_ks_get_info {}", key.name()),
    )?;
    let mut want = [0u8; 65];
    let label = key.label.to_bytes();
    want[..label.len()].copy_from_slice(label);
    // `c_char` is `i8` on some targets and `u8` on others; compare the raw bytes.
    let got = info.label.map(|c| c.to_ne_bytes()[0]);
    check(
        info.alg == key.alg && got == want,
        &format!("eki_ks_get_info {} reported other alg or label", key.name()),
    )
}

/// Software store: generate, inspect, use, wrap, unwrap, destroy, close.
fn step_keystore(api: &Api) -> StepResult {
    let store = Store::open_software(api).map_err(|status| Failure {
        status,
        what: "eki_ks_open software".to_owned(),
    })?;

    let mut kek = NamedKey::new(EKI_KEY_AES_256, c"interop-kek");
    let mut mac = NamedKey::new(EKI_KEY_HMAC_SHA256, c"interop-hmac");
    let mut signer = NamedKey::new(EKI_KEY_ECDSA_P256, c"interop-signer");
    for key in [&mut kek, &mut mac, &mut signer] {
        let status = store.generate(key.alg, key.label, &mut key.id);
        store.expect(status, OK, &format!("eki_ks_generate {}", key.name()))?;
    }
    for key in [&kek, &mac, &signer] {
        check_info(&store, key)?;
    }

    let msg = b"interop message signed and authenticated by the key store";

    let mut tag = [0u8; EKI_HMAC_SHA256_LEN];
    store.expect(
        store.hmac_sha256(&mac.id, msg, &mut tag),
        OK,
        "eki_ks_hmac_sha256 interop-hmac",
    )?;

    let mut sig = [0u8; EKI_P256_SIGNATURE_LEN];
    let mut public_key = [0u8; EKI_P256_PUBLIC_KEY_LEN];
    store.expect(
        store.sign(&signer.id, msg, &mut sig),
        OK,
        "eki_ks_sign interop-signer",
    )?;
    store.expect(
        store.get_public_key(&signer.id, &mut public_key),
        OK,
        "eki_ks_get_public_key interop-signer",
    )?;
    expect(
        api.ecdsa_p256_verify(&public_key, msg, &sig),
        OK,
        "eki_ecdsa_p256_verify of the store's signature",
    )?;

    let mut blob = [0u8; EKI_WRAPPED_KEY_LEN];
    store.expect(
        store.wrap(&kek.id, &mac.id, &mut blob),
        OK,
        "eki_ks_wrap interop-hmac under interop-kek",
    )?;
    let mut copy = NamedKey::new(EKI_KEY_HMAC_SHA256, c"interop-hmac-unwrapped");
    copy.id.bytes = random_bytes();
    store.expect(
        store.unwrap(&kek.id, &blob, copy.alg, copy.label, &copy.id),
        OK,
        "eki_ks_unwrap as interop-hmac-unwrapped",
    )?;
    check_info(&store, &copy)?;
    let mut tag_copy = [0u8; EKI_HMAC_SHA256_LEN];
    store.expect(
        store.hmac_sha256(&copy.id, msg, &mut tag_copy),
        OK,
        "eki_ks_hmac_sha256 interop-hmac-unwrapped",
    )?;
    check(
        tag_copy == tag,
        "the unwrapped key computes a different HMAC",
    )?;

    for key in [&kek, &mac, &signer, &copy] {
        store.expect(
            store.destroy(&key.id),
            OK,
            &format!("eki_ks_destroy {}", key.name()),
        )?;
    }
    for key in [&kek, &mac, &signer, &copy] {
        let mut info = eki_key_info {
            alg: eki_key_alg(0),
            label: [0; 65],
        };
        store.expect(
            store.get_info(&key.id, &mut info),
            KEY_NOT_FOUND,
            &format!("eki_ks_get_info after destroying {}", key.name()),
        )?;
    }
    drop(store); // eki_ks_close
    Ok(())
}

// ---- driver ------------------------------------------------------------------------------------

type Step = (&'static str, fn(&Api) -> StepResult);

const STEPS: [Step; 5] = [
    ("version", step_version),   // stop here on an ABI mismatch
    ("hkdf", step_hkdf),         // RFC 5869 A.1
    ("hmac", step_hmac),         // RFC 4231 test case 2
    ("aead", step_aead),         // both algorithms, random inputs
    ("keystore", step_keystore), // software backend, full key lifecycle
];

fn run(path: &str) -> ExitCode {
    // SAFETY: loading a library runs its initialisers. The path names an ekicore build, whose
    // initialisers (Rust std, or the C++ runtime and OpenSSL) are sound to run in any process.
    let lib = match unsafe { Library::new(path) } {
        Ok(lib) => lib,
        Err(e) => {
            eprintln!("rust-caller: cannot load {path}: {}", error_chain(&e));
            return ExitCode::from(2);
        }
    };
    let api = match Api::load(&lib) {
        Ok(api) => api,
        Err(e) => {
            eprintln!("rust-caller: {path} does not export {e}");
            return ExitCode::from(2);
        }
    };

    println!("rust-caller: {path}");
    let mut failed = 0;
    for (name, step) in STEPS {
        match step(&api) {
            Ok(()) => println!("PASS {name}"),
            Err(failure) => {
                failed += 1;
                println!(
                    "FAIL {name} ({}): {}",
                    api.status_name(failure.status),
                    failure.what
                );
                // Nothing else can be trusted from a library that implements a different ABI.
                if name == "version" {
                    break;
                }
            }
        }
    }
    if failed == 0 {
        println!("rust-caller: all steps passed");
        ExitCode::SUCCESS
    } else {
        println!("rust-caller: {failed} step(s) failed");
        ExitCode::from(1)
    }
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().collect();
    match args.as_slice() {
        [_, path] => match path.to_str() {
            Some(path) => run(path),
            None => {
                eprintln!("rust-caller: the library path is not valid UTF-8");
                ExitCode::from(2)
            }
        },
        _ => {
            eprintln!("usage: interop-rust-caller <path to libekicore or libekicore_rs>");
            ExitCode::from(2)
        }
    }
}
