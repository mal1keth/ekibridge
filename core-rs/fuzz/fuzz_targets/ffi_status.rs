//! Every exported function of the ABI, called in arbitrary sequences with arbitrary buffers,
//! lengths within and beyond their caps, NULL flags and selectors, on a software key store.
//!
//! Input: the session's store (one byte modulo 3: none, `eki_ks_open`, `eki_ks_open_v2`; then a
//! `Config` for the last two), then calls until the input ends (at most [`MAX_CALLS`]): one byte
//! modulo [`OPS`] picks the function, and its arguments follow in parameter order (see `step`).
//! A store call gets the session's handle, or NULL when its first byte says so or no store is
//! open. Key ids are raw bytes or ids the session made (`read_key_ref`). The run's audit log, the
//! approver keys and their signatures, the last wrapped key, KEM key pair and ciphertext and
//! destroy request are carried from call to call, so the success paths are reachable.
//!
//! Properties of every call (`Call::check` in the shared library):
//! * the status is a defined value, never `EKI_ERR_INTERNAL`;
//! * a NULL pointer parameter gives `EKI_ERR_NULL_POINTER`, and that status has no other cause
//!   than a NULL parameter or configuration field;
//! * a length above its maximum gives `EKI_ERR_INVALID_ARGUMENT`;
//! * after any failure every non-NULL output is all zero, with no exception for
//!   `EKI_ERR_UNSUPPORTED`, except an output whose length was above its maximum, which is left
//!   untouched;
//! * `EKI_ERR_BACKEND` only where the contract allows it here (opening a store or a log, reading
//!   a log), and `EKI_ERR_UNSUPPORTED` only for a feature that is off or a handle without the
//!   audit log or approvers the call needs.
//!
//! Exact oracles where the status is fully determined: opening a store (`Config::expected_open`),
//! generating a key, reading an audit log, the metadata functions. At the end the store is
//! closed; if it had the run's audit log, the log verifies and opens again (the lock was
//! released).

#![no_main]

use core::ffi::{CStr, c_char};

use ekicore_abi::{
    EKI_ABI_VERSION, EKI_AEAD_MAX_LEN, EKI_AEAD_TAG_LEN, EKI_AUDIT_HASH_LEN,
    EKI_AUDIT_PATH_MAX_LEN, EKI_DESTROY_REQUEST_LEN, EKI_HKDF_MAX_INPUT_LEN, EKI_HKDF_MAX_OKM_LEN,
    EKI_HMAC_SHA256_LEN, EKI_HYBRID_CT_LEN, EKI_HYBRID_PK_LEN, EKI_HYBRID_SK_LEN,
    EKI_HYBRID_SS_LEN, EKI_KEY_ID_LEN, EKI_LABEL_MAX_LEN, EKI_P256_PUBLIC_KEY_LEN,
    EKI_P256_SIGNATURE_LEN, EKI_WRAPPED_KEY_LEN, eki_aead_alg, eki_key_alg, eki_key_id,
    eki_key_info, eki_key_info_v2, eki_ks,
};
use ekicore_rs::ffi::{
    eki_abi_version, eki_aead_open, eki_aead_seal, eki_audit_verify, eki_ecdsa_p256_verify,
    eki_hkdf_sha256, eki_hmac_sha256, eki_hmac_sha256_verify, eki_hybrid_kem_decap,
    eki_hybrid_kem_encap, eki_hybrid_kem_keygen, eki_ks_audit_head, eki_ks_destroy,
    eki_ks_destroy_approve, eki_ks_destroy_request, eki_ks_generate, eki_ks_get_info,
    eki_ks_get_info_v2, eki_ks_get_public_key, eki_ks_hmac_sha256, eki_ks_hmac_sha256_verify,
    eki_ks_last_error_message, eki_ks_open, eki_ks_open_v2, eki_ks_revoke, eki_ks_rotate,
    eki_ks_sign, eki_ks_unwrap, eki_ks_wrap, eki_status_name, eki_version,
};
use ekicore_rs_fuzz::{
    Approvers, BACKEND, Call, Config, INVALID_ARGUMENT, InBuf, OK, OutBuf, Reader, Scratch, Slot,
    Store, UNSUPPORTED, WITH_PKCS11, WITH_PQ, exact, id_ptr, label_is_valid, read_audit_path,
    read_capped_len, read_key_ref, read_label,
};
use libfuzzer_sys::fuzz_target;

/// Calls made from one input at most.
const MAX_CALLS: usize = 24;

/// Number of functions `step` can call.
const OPS: u8 = 29;

/// Names of the status values, for `eki_status_name`.
const STATUS_NAMES: [&str; 13] = [
    "EKI_OK",
    "EKI_ERR_NULL_POINTER",
    "EKI_ERR_INVALID_ARGUMENT",
    "EKI_ERR_BUFFER_TOO_SMALL",
    "EKI_ERR_UNSUPPORTED",
    "EKI_ERR_AUTH_FAILED",
    "EKI_ERR_KEY_NOT_FOUND",
    "EKI_ERR_KEY_EXISTS",
    "EKI_ERR_WRONG_KEY_TYPE",
    "EKI_ERR_BACKEND",
    "EKI_ERR_INTERNAL",
    "EKI_ERR_KEY_STATE",
    "EKI_ERR_APPROVAL_REQUIRED",
];

/// What a session carries from call to call.
struct Session {
    scratch: Scratch,
    approvers: Approvers,
    store: Option<Store>,
    /// The store has approvers.
    dual: bool,
    /// The store has the run's audit log.
    audited: bool,
    /// Ids of keys the session made.
    known: Vec<eki_key_id>,
    wrapped: [u8; EKI_WRAPPED_KEY_LEN],
    request: Option<([u8; EKI_DESTROY_REQUEST_LEN], eki_key_id)>,
    head: [u8; EKI_AUDIT_HASH_LEN],
    kem_pk: Vec<u8>,
    kem_sk: Vec<u8>,
    kem_ct: Vec<u8>,
}

impl Session {
    /// The handle argument of a store call: NULL when the input's byte says so or no store is
    /// open.
    fn ks(&self, r: &mut Reader<'_>) -> *mut eki_ks {
        let null = r.boolean();
        match &self.store {
            Some(store) if !null => store.ptr(),
            _ => core::ptr::null_mut(),
        }
    }

    /// Whether `eki_ks_open_v2` must find the run's log locked.
    fn log_locked(&self) -> bool {
        self.store.is_some() && self.audited
    }
}

/// An output of `n` bytes for a parameter with maximum `max`, passed with length argument `len`.
fn sized_out(null: bool, n: usize, len: usize, max: usize) -> OutBuf {
    if len > max {
        OutBuf::untouched(null, n)
    } else {
        OutBuf::new(null, n)
    }
}

/// A fixed-size input with its NULL flag: [`Reader::boolean`], then `N` bytes.
fn fixed<const N: usize>(r: &mut Reader<'_>) -> (bool, [u8; N]) {
    let null = r.boolean();
    (null, r.array())
}

fn ptr_or_null<T>(null: bool, value: &T) -> *const T {
    if null { core::ptr::null() } else { value }
}

/// One call; its arguments are read from `r` in parameter order.
#[allow(clippy::too_many_lines)]
fn step(op: u8, s: &mut Session, r: &mut Reader<'_>) -> Call {
    match op {
        0 => {
            let key = InBuf::read(r);
            let msg = InBuf::read(r);
            let mut out = OutBuf::new(r.boolean(), EKI_HMAC_SHA256_LEN);
            // SAFETY: inputs are NULL or live Vecs of their stated length; `out` is NULL or a
            // distinct 32-byte allocation.
            let status =
                unsafe { eki_hmac_sha256(key.ptr(), key.len(), msg.ptr(), msg.len(), out.ptr()) };
            let mut call = Call::new("eki_hmac_sha256", status as i32);
            call.null_param = key.null_with(key.len()) || msg.null_with(msg.len()) || out.is_null();
            call.outputs.push(out.seen());
            call
        }
        1 => {
            let key = InBuf::read(r);
            let msg = InBuf::read(r);
            let tag = InBuf::read(r);
            // SAFETY: inputs are NULL or live Vecs of their stated length.
            let status = unsafe {
                eki_hmac_sha256_verify(
                    key.ptr(),
                    key.len(),
                    msg.ptr(),
                    msg.len(),
                    tag.ptr(),
                    tag.len(),
                )
            };
            let mut call = Call::new("eki_hmac_sha256_verify", status as i32);
            call.null_param =
                key.null_with(key.len()) || msg.null_with(msg.len()) || tag.null_with(tag.len());
            call
        }
        2 => {
            let ikm = InBuf::read(r);
            let ikm_len = read_capped_len(r, ikm.len(), EKI_HKDF_MAX_INPUT_LEN);
            let salt = InBuf::read(r);
            let salt_len = read_capped_len(r, salt.len(), EKI_HKDF_MAX_INPUT_LEN);
            let info = InBuf::read(r);
            let info_len = read_capped_len(r, info.len(), EKI_HKDF_MAX_INPUT_LEN);
            let okm_null = r.boolean();
            let okm_size = usize::from(r.u16() % 9001);
            let okm_len = read_capped_len(r, okm_size, EKI_HKDF_MAX_OKM_LEN);
            let mut okm = sized_out(okm_null, okm_size, okm_len, EKI_HKDF_MAX_OKM_LEN);
            // SAFETY: each input is NULL or a live Vec; a length argument above its cap is never
            // used to access the buffer (the contract's exception), otherwise it is the Vec's
            // length; `okm` is NULL or a distinct allocation of `okm_size` bytes, which equals
            // `okm_len` whenever `okm_len` is within the cap.
            let status = unsafe {
                eki_hkdf_sha256(
                    ikm.ptr(),
                    ikm_len,
                    salt.ptr(),
                    salt_len,
                    info.ptr(),
                    info_len,
                    okm.ptr(),
                    okm_len,
                )
            };
            let mut call = Call::new("eki_hkdf_sha256", status as i32);
            call.null_param = ikm.null_with(ikm_len)
                || salt.null_with(salt_len)
                || info.null_with(info_len)
                || (okm_null && okm_len > 0);
            call.over_cap = [ikm_len, salt_len, info_len]
                .iter()
                .any(|&n| n > EKI_HKDF_MAX_INPUT_LEN)
                || okm_len > EKI_HKDF_MAX_OKM_LEN;
            call.outputs.push(okm.seen());
            call
        }
        3 => {
            let alg = eki_aead_alg(r.i32());
            let key = InBuf::read(r);
            let nonce = InBuf::read(r);
            let aad = InBuf::read(r);
            let pt = InBuf::read(r);
            let max = EKI_AEAD_MAX_LEN as usize;
            let pt_len = read_capped_len(r, pt.len(), max);
            let mut ct = sized_out(r.boolean(), pt.len(), pt_len, max);
            let mut tag = OutBuf::new(r.boolean(), EKI_AEAD_TAG_LEN);
            // SAFETY: as for HKDF; `ct` is NULL or a distinct allocation of `pt.len()` bytes,
            // which is `pt_len` whenever `pt_len` is within the cap; `tag` is NULL or a distinct
            // 16-byte allocation.
            let status = unsafe {
                eki_aead_seal(
                    alg,
                    key.ptr(),
                    key.len(),
                    nonce.ptr(),
                    nonce.len(),
                    aad.ptr(),
                    aad.len(),
                    pt.ptr(),
                    pt_len,
                    ct.ptr(),
                    tag.ptr(),
                )
            };
            let mut call = Call::new("eki_aead_seal", status as i32);
            call.null_param = key.null_with(key.len())
                || nonce.null_with(nonce.len())
                || aad.null_with(aad.len())
                || pt.null_with(pt_len)
                || (ct.is_null() && pt_len > 0)
                || tag.is_null();
            call.over_cap = pt_len > max;
            call.outputs.extend([ct.seen(), tag.seen()]);
            call
        }
        4 => {
            let alg = eki_aead_alg(r.i32());
            let key = InBuf::read(r);
            let nonce = InBuf::read(r);
            let aad = InBuf::read(r);
            let ct = InBuf::read(r);
            let max = EKI_AEAD_MAX_LEN as usize;
            let ct_len = read_capped_len(r, ct.len(), max);
            let (tag_null, tag) = fixed::<EKI_AEAD_TAG_LEN>(r);
            let mut pt = sized_out(r.boolean(), ct.len(), ct_len, max);
            // SAFETY: as for seal; `tag` is NULL or a live 16-byte array; `pt` is NULL or a
            // distinct allocation of `ct.len()` bytes.
            let status = unsafe {
                eki_aead_open(
                    alg,
                    key.ptr(),
                    key.len(),
                    nonce.ptr(),
                    nonce.len(),
                    aad.ptr(),
                    aad.len(),
                    ct.ptr(),
                    ct_len,
                    ptr_or_null(tag_null, &tag).cast(),
                    pt.ptr(),
                )
            };
            let mut call = Call::new("eki_aead_open", status as i32);
            call.null_param = key.null_with(key.len())
                || nonce.null_with(nonce.len())
                || aad.null_with(aad.len())
                || ct.null_with(ct_len)
                || tag_null
                || (pt.is_null() && ct_len > 0);
            call.over_cap = ct_len > max;
            call.outputs.push(pt.seen());
            call
        }
        5 => {
            let (pk_null, pk) = fixed::<EKI_P256_PUBLIC_KEY_LEN>(r);
            let msg = InBuf::read(r);
            let (sig_null, sig) = fixed::<EKI_P256_SIGNATURE_LEN>(r);
            // SAFETY: `pk` and `sig` are NULL or live arrays of 65 and 64 bytes; `msg` is NULL or
            // a live Vec of its stated length.
            let status = unsafe {
                eki_ecdsa_p256_verify(
                    ptr_or_null(pk_null, &pk).cast(),
                    msg.ptr(),
                    msg.len(),
                    ptr_or_null(sig_null, &sig).cast(),
                )
            };
            let mut call = Call::new("eki_ecdsa_p256_verify", status as i32);
            call.null_param = pk_null || msg.null_with(msg.len()) || sig_null;
            call
        }
        6 => {
            let mut pk = OutBuf::new(r.boolean(), EKI_HYBRID_PK_LEN);
            let mut sk = OutBuf::new(r.boolean(), EKI_HYBRID_SK_LEN);
            // SAFETY: `pk` and `sk` are NULL or distinct allocations of 1216 and 96 bytes.
            let status = unsafe { eki_hybrid_kem_keygen(pk.ptr(), sk.ptr()) } as i32;
            if status == OK {
                s.kem_pk = pk.bytes().to_vec();
                s.kem_sk = sk.bytes().to_vec();
            }
            let mut call = Call::new("eki_hybrid_kem_keygen", status);
            call.null_param = pk.is_null() || sk.is_null();
            call.outputs.extend([pk.seen(), sk.seen()]);
            call
        }
        7 => {
            let pk_null = r.boolean();
            let from_session = r.boolean();
            let raw = r.bytes();
            let pk = exact(
                if from_session { &s.kem_pk } else { &raw },
                EKI_HYBRID_PK_LEN,
                0,
            );
            let mut ct = OutBuf::new(r.boolean(), EKI_HYBRID_CT_LEN);
            let mut ss = OutBuf::new(r.boolean(), EKI_HYBRID_SS_LEN);
            // SAFETY: `pk` is NULL or a live 1216-byte Vec; `ct` and `ss` are NULL or distinct
            // allocations of 1120 and 32 bytes.
            let status =
                unsafe { eki_hybrid_kem_encap(ptr_or_null(pk_null, &pk[0]), ct.ptr(), ss.ptr()) }
                    as i32;
            if status == OK {
                s.kem_ct = ct.bytes().to_vec();
            }
            let mut call = Call::new("eki_hybrid_kem_encap", status);
            call.null_param = pk_null || ct.is_null() || ss.is_null();
            call.outputs.extend([ct.seen(), ss.seen()]);
            call
        }
        8 => {
            let sk_null = r.boolean();
            let sk_from_session = r.boolean();
            let sk_raw = r.bytes();
            let sk = exact(
                if sk_from_session { &s.kem_sk } else { &sk_raw },
                EKI_HYBRID_SK_LEN,
                0,
            );
            let ct_null = r.boolean();
            let ct_from_session = r.boolean();
            let ct_raw = r.bytes();
            let ct = exact(
                if ct_from_session { &s.kem_ct } else { &ct_raw },
                EKI_HYBRID_CT_LEN,
                0,
            );
            let mut ss = OutBuf::new(r.boolean(), EKI_HYBRID_SS_LEN);
            // SAFETY: `sk` and `ct` are NULL or live Vecs of 96 and 1120 bytes; `ss` is NULL or
            // a distinct 32-byte allocation.
            let status = unsafe {
                eki_hybrid_kem_decap(
                    ptr_or_null(sk_null, &sk[0]),
                    ptr_or_null(ct_null, &ct[0]),
                    ss.ptr(),
                )
            } as i32;
            let mut call = Call::new("eki_hybrid_kem_decap", status);
            call.null_param = sk_null || ct_null || ss.is_null();
            call.outputs.push(ss.seen());
            call
        }
        9 => {
            let path = read_audit_path(r, &s.scratch);
            let head = match r.u8() % 3 {
                0 => None,
                1 => Some(r.array::<EKI_AUDIT_HASH_LEN>()),
                _ => Some(s.head),
            };
            let mut records = Slot::<u64>::new(r.boolean());
            // SAFETY: `path` is NULL, NUL-terminated or 4097 readable bytes; `head` is NULL or a
            // live 32-byte array; `records` is NULL or a live, aligned `uint64_t`.
            let status = unsafe {
                eki_audit_verify(
                    path.ptr(),
                    head.as_ref().map_or(core::ptr::null(), |h| h.as_ptr()),
                    records.ptr(),
                )
            } as i32;
            let mut call = Call::new("eki_audit_verify", status);
            call.null_param = path.is_null() || records.is_null();
            call.outputs.push(records.seen());
            if !call.null_param {
                let seen = path.seen(EKI_AUDIT_PATH_MAX_LEN + 1).unwrap_or_default();
                let expected: &[i32] = if !(1..=EKI_AUDIT_PATH_MAX_LEN).contains(&seen.len()) {
                    &[INVALID_ARGUMENT]
                } else if seen != s.scratch.log.as_bytes() || !s.scratch.log_path.is_file() {
                    &[BACKEND]
                } else if head.is_none() {
                    &[OK]
                } else {
                    &[OK, ekicore_rs_fuzz::AUTH_FAILED]
                };
                assert!(
                    expected.contains(&status),
                    "eki_audit_verify returned {status}"
                );
            }
            call
        }
        10 => {
            let value = r.i32();
            // SAFETY: the metadata functions take no pointer; each returned string has static
            // storage and is NUL-terminated.
            let (abi, version, name) = unsafe {
                (
                    eki_abi_version(),
                    CStr::from_ptr(eki_version()),
                    CStr::from_ptr(eki_status_name(value)),
                )
            };
            assert_eq!(abi, EKI_ABI_VERSION, "eki_abi_version");
            assert!(
                version.to_bytes().starts_with(b"ekicore-rs "),
                "eki_version"
            );
            let expected = usize::try_from(value)
                .ok()
                .and_then(|i| STATUS_NAMES.get(i))
                .copied()
                .unwrap_or("EKI_STATUS_UNKNOWN");
            assert_eq!(
                name.to_bytes(),
                expected.as_bytes(),
                "eki_status_name({value})"
            );
            Call::new("eki_status_name", OK)
        }
        11 | 12 => {
            let v2 = op == 12;
            let config_null = r.boolean();
            let mut out = Slot::<*mut eki_ks>::new(r.boolean());
            let config = Config::read(r, &s.scratch, &mut s.approvers);
            let (raw1, raw2) = (config.v1(), config.v2());
            // SAFETY: the config is NULL or a live struct whose pointers point into buffers
            // `config` owns (approver keys sized to a valid count); `out` is NULL or a live,
            // aligned `eki_ks *`.
            let status = unsafe {
                if v2 {
                    eki_ks_open_v2(ptr_or_null(config_null, &raw2), out.ptr())
                } else {
                    eki_ks_open(ptr_or_null(config_null, &raw1), out.ptr())
                }
            } as i32;
            let function = if v2 { "eki_ks_open_v2" } else { "eki_ks_open" };
            let mut call = Call::new(function, status);
            call.null_param = config_null || out.is_null();
            call.null_field = if v2 {
                config.null_field_v2()
            } else {
                config.null_field_v1()
            };
            call.outputs.push(out.seen());
            if !call.null_param {
                let expected = config.expected_open(v2, &s.scratch, s.log_locked());
                assert!(
                    expected.contains(&status),
                    "{function} returned {status}, expected one of {expected:?}"
                );
            }
            if status == OK {
                // Closed at once: the session keeps its own store.
                drop(Store::from_raw(out.get()));
            }
            call
        }
        13 => {
            let ks = s.ks(r);
            let buf_null = r.boolean();
            let buf_len = usize::from(r.u16() % 300);
            let mut buf = OutBuf::new(buf_null, buf_len);
            // SAFETY: `ks` is NULL or the session's open handle; `buf` is NULL or a writable
            // allocation of `buf_len` bytes.
            let n = unsafe { eki_ks_last_error_message(ks, buf.ptr().cast::<c_char>(), buf_len) };
            if ks.is_null() {
                assert_eq!(n, 0, "eki_ks_last_error_message(NULL) returned {n}");
            }
            if !buf_null && buf_len > 0 {
                let written = n.min(buf_len - 1);
                let bytes = buf.bytes();
                assert_eq!(bytes[written], 0, "message not NUL-terminated at {written}");
                assert!(
                    !bytes[..written].contains(&0),
                    "message shorter than reported"
                );
            }
            Call::new("eki_ks_last_error_message", OK)
        }
        14 => {
            let ks = s.ks(r);
            let alg = eki_key_alg(r.i32());
            let label = read_label(r);
            let mut id = Slot::<eki_key_id>::new(r.boolean());
            // SAFETY: `ks` is NULL or the session's open handle; `label` is NULL,
            // NUL-terminated or 65 readable bytes; `id` is NULL or a live, aligned `eki_key_id`.
            let status = unsafe { eki_ks_generate(ks, alg, label.ptr(), id.ptr()) } as i32;
            let mut call = Call::new("eki_ks_generate", status);
            call.null_param = ks.is_null() || label.is_null() || id.is_null();
            call.outputs.push(id.seen());
            if !call.null_param {
                let valid = (1..=3).contains(&alg.0)
                    && label
                        .seen(EKI_LABEL_MAX_LEN + 1)
                        .is_some_and(label_is_valid);
                assert_eq!(
                    status,
                    if valid { OK } else { INVALID_ARGUMENT },
                    "eki_ks_generate"
                );
            }
            if status == OK {
                s.known.push(id.get());
            }
            call
        }
        15 => {
            let ks = s.ks(r);
            let id = read_key_ref(r, &s.known);
            let mut info = Slot::<eki_key_info>::new(r.boolean());
            // SAFETY: `ks` is NULL or the session's open handle; `id` is NULL or a live struct;
            // `info` is NULL or a live, aligned `eki_key_info`.
            let status = unsafe { eki_ks_get_info(ks, id_ptr(&id), info.ptr()) } as i32;
            let mut call = Call::new("eki_ks_get_info", status);
            call.null_param = ks.is_null() || id.is_none() || info.is_null();
            call.outputs.push(info.seen());
            call
        }
        16 => {
            let ks = s.ks(r);
            let id = read_key_ref(r, &s.known);
            let mut info = Slot::<eki_key_info_v2>::new(r.boolean());
            // SAFETY: as for `eki_ks_get_info`, with an `eki_key_info_v2`.
            let status = unsafe { eki_ks_get_info_v2(ks, id_ptr(&id), info.ptr()) } as i32;
            let mut call = Call::new("eki_ks_get_info_v2", status);
            call.null_param = ks.is_null() || id.is_none() || info.is_null();
            call.outputs.push(info.seen());
            call
        }
        17 => {
            let ks = s.ks(r);
            let id = read_key_ref(r, &s.known);
            let mut out = OutBuf::new(r.boolean(), EKI_P256_PUBLIC_KEY_LEN);
            // SAFETY: `ks` is NULL or the session's open handle; `id` is NULL or a live struct;
            // `out` is NULL or a distinct 65-byte allocation.
            let status = unsafe { eki_ks_get_public_key(ks, id_ptr(&id), out.ptr()) } as i32;
            let mut call = Call::new("eki_ks_get_public_key", status);
            call.null_param = ks.is_null() || id.is_none() || out.is_null();
            call.outputs.push(out.seen());
            call
        }
        18 | 19 => {
            let ks = s.ks(r);
            let id = read_key_ref(r, &s.known);
            let msg = InBuf::read(r);
            let len = if op == 18 {
                EKI_P256_SIGNATURE_LEN
            } else {
                EKI_HMAC_SHA256_LEN
            };
            let mut out = OutBuf::new(r.boolean(), len);
            // SAFETY: `ks` is NULL or the session's open handle; `id` is NULL or a live struct;
            // `msg` is NULL or a live Vec of its stated length; `out` is NULL or a distinct
            // allocation of the 64 or 32 bytes the function writes.
            let (function, status) = unsafe {
                if op == 18 {
                    let s = eki_ks_sign(ks, id_ptr(&id), msg.ptr(), msg.len(), out.ptr());
                    ("eki_ks_sign", s)
                } else {
                    let s = eki_ks_hmac_sha256(ks, id_ptr(&id), msg.ptr(), msg.len(), out.ptr());
                    ("eki_ks_hmac_sha256", s)
                }
            };
            let mut call = Call::new(function, status as i32);
            call.null_param =
                ks.is_null() || id.is_none() || msg.null_with(msg.len()) || out.is_null();
            call.outputs.push(out.seen());
            call
        }
        20 => {
            let ks = s.ks(r);
            let id = read_key_ref(r, &s.known);
            let msg = InBuf::read(r);
            let tag = InBuf::read(r);
            // SAFETY: `ks` is NULL or the session's open handle; `id` is NULL or a live struct;
            // `msg` and `tag` are NULL or live Vecs of their stated lengths.
            let status = unsafe {
                eki_ks_hmac_sha256_verify(
                    ks,
                    id_ptr(&id),
                    msg.ptr(),
                    msg.len(),
                    tag.ptr(),
                    tag.len(),
                )
            } as i32;
            let mut call = Call::new("eki_ks_hmac_sha256_verify", status);
            call.null_param = ks.is_null()
                || id.is_none()
                || msg.null_with(msg.len())
                || tag.null_with(tag.len());
            call
        }
        21 => {
            let ks = s.ks(r);
            let kek = read_key_ref(r, &s.known);
            let key = read_key_ref(r, &s.known);
            let mut out = OutBuf::new(r.boolean(), EKI_WRAPPED_KEY_LEN);
            // SAFETY: `ks` is NULL or the session's open handle; the ids are NULL or live
            // structs; `out` is NULL or a distinct 40-byte allocation.
            let status = unsafe { eki_ks_wrap(ks, id_ptr(&kek), id_ptr(&key), out.ptr()) } as i32;
            if status == OK {
                s.wrapped.copy_from_slice(out.bytes());
            }
            let mut call = Call::new("eki_ks_wrap", status);
            call.null_param = ks.is_null() || kek.is_none() || key.is_none() || out.is_null();
            call.outputs.push(out.seen());
            call
        }
        22 => {
            let ks = s.ks(r);
            let kek = read_key_ref(r, &s.known);
            let from_session = r.boolean();
            let mut blob = InBuf::read(r);
            if from_session {
                // The last wrapped key, with the input's bytes XORed over it.
                let mask = core::mem::take(&mut blob.data);
                blob.data = s.wrapped.to_vec();
                blob.null = false;
                for (byte, m) in blob.data.iter_mut().zip(&mask) {
                    *byte ^= m;
                }
            }
            let alg = eki_key_alg(r.i32());
            let label = read_label(r);
            let id = read_key_ref(r, &s.known);
            // SAFETY: `ks` is NULL or the session's open handle; the ids are NULL or live
            // structs; `blob` is NULL or a live Vec of its stated length; `label` is NULL,
            // NUL-terminated or 65 readable bytes.
            let status = unsafe {
                eki_ks_unwrap(
                    ks,
                    id_ptr(&kek),
                    blob.ptr(),
                    blob.len(),
                    alg,
                    label.ptr(),
                    id_ptr(&id),
                )
            } as i32;
            if status == OK {
                s.known.extend(id);
            }
            let mut call = Call::new("eki_ks_unwrap", status);
            call.null_param = ks.is_null()
                || kek.is_none()
                || blob.null_with(blob.len())
                || label.is_null()
                || id.is_none();
            call
        }
        23 | 25 => {
            let ks = s.ks(r);
            let id = read_key_ref(r, &s.known);
            // SAFETY: `ks` is NULL or the session's open handle; `id` is NULL or a live struct.
            let (function, status) = unsafe {
                if op == 23 {
                    ("eki_ks_destroy", eki_ks_destroy(ks, id_ptr(&id)))
                } else {
                    ("eki_ks_revoke", eki_ks_revoke(ks, id_ptr(&id)))
                }
            };
            let mut call = Call::new(function, status as i32);
            call.null_param = ks.is_null() || id.is_none();
            call
        }
        24 => {
            let ks = s.ks(r);
            let id = read_key_ref(r, &s.known);
            let mut new_id = Slot::<eki_key_id>::new(r.boolean());
            // SAFETY: `ks` is NULL or the session's open handle; `id` is NULL or a live struct;
            // `new_id` is NULL or a live, aligned `eki_key_id`.
            let status = unsafe { eki_ks_rotate(ks, id_ptr(&id), new_id.ptr()) } as i32;
            if status == OK {
                s.known.push(new_id.get());
            }
            let mut call = Call::new("eki_ks_rotate", status);
            call.null_param = ks.is_null() || id.is_none() || new_id.is_null();
            call.outputs.push(new_id.seen());
            call
        }
        26 => {
            let ks = s.ks(r);
            let id = read_key_ref(r, &s.known);
            let mut out = OutBuf::new(r.boolean(), EKI_DESTROY_REQUEST_LEN);
            // SAFETY: `ks` is NULL or the session's open handle; `id` is NULL or a live struct;
            // `out` is NULL or a distinct 32-byte allocation.
            let status = unsafe { eki_ks_destroy_request(ks, id_ptr(&id), out.ptr()) } as i32;
            if let (OK, Some(id)) = (status, id) {
                let request = out.bytes().try_into().expect("32 bytes");
                s.request = Some((request, id));
            }
            let mut call = Call::new("eki_ks_destroy_request", status);
            call.null_param = ks.is_null() || id.is_none() || out.is_null();
            call.outputs.push(out.seen());
            if !call.null_param {
                assert_eq!(
                    status == UNSUPPORTED,
                    !s.dual,
                    "destroy_request and dual control"
                );
            }
            call
        }
        27 => {
            let ks = s.ks(r);
            let (request_null, raw_request) = fixed::<EKI_DESTROY_REQUEST_LEN>(r);
            let from_session = r.boolean();
            let (request, target) = match s.request {
                Some(pending) if from_session => pending,
                _ => (
                    raw_request,
                    eki_key_id {
                        bytes: [0; EKI_KEY_ID_LEN],
                    },
                ),
            };
            let (pk_null, raw_pk) = fixed::<EKI_P256_PUBLIC_KEY_LEN>(r);
            let pk_generated = r.boolean();
            let pk_pick = r.u8();
            let pk = if pk_generated {
                s.approvers.public_key(pk_pick)
            } else {
                raw_pk
            };
            let (sig_null, raw_sig) = fixed::<EKI_P256_SIGNATURE_LEN>(r);
            let sig_generated = r.boolean();
            let sig_pick = r.u8();
            let sig = if sig_generated {
                s.approvers.approve(sig_pick, &request, &target)
            } else {
                raw_sig
            };
            let mut remaining = Slot::<u32>::new(r.boolean());
            // SAFETY: `ks` is NULL or the session's open handle; `request`, `pk` and `sig` are
            // NULL or live arrays of 32, 65 and 64 bytes; `remaining` is NULL or a live, aligned
            // `uint32_t`.
            let status = unsafe {
                eki_ks_destroy_approve(
                    ks,
                    ptr_or_null(request_null, &request).cast(),
                    ptr_or_null(pk_null, &pk).cast(),
                    ptr_or_null(sig_null, &sig).cast(),
                    remaining.ptr(),
                )
            } as i32;
            let mut call = Call::new("eki_ks_destroy_approve", status);
            call.null_param =
                ks.is_null() || request_null || pk_null || sig_null || remaining.is_null();
            call.outputs.push(remaining.seen());
            if !call.null_param {
                assert_eq!(
                    status == UNSUPPORTED,
                    !s.dual,
                    "destroy_approve and dual control"
                );
            }
            call
        }
        _ => {
            let ks = s.ks(r);
            let mut hash = OutBuf::new(r.boolean(), EKI_AUDIT_HASH_LEN);
            let mut seq = Slot::<u64>::new(r.boolean());
            // SAFETY: `ks` is NULL or the session's open handle; `hash` is NULL or a distinct
            // 32-byte allocation; `seq` is NULL or a live, aligned `uint64_t`.
            let status = unsafe { eki_ks_audit_head(ks, hash.ptr(), seq.ptr()) } as i32;
            if status == OK {
                s.head.copy_from_slice(hash.bytes());
            }
            let mut call = Call::new("eki_ks_audit_head", status);
            call.null_param = ks.is_null() || hash.is_null() || seq.is_null();
            call.outputs.extend([hash.seen(), seq.seen()]);
            if !call.null_param {
                assert_eq!(
                    status == UNSUPPORTED,
                    !s.audited,
                    "audit_head and the audit log"
                );
            }
            call
        }
    }
}

/// The statuses that only some functions may return here: `EKI_ERR_BACKEND` needs a store or a
/// log to open or a log to read (a software store and a scratch file never fail otherwise), and
/// `EKI_ERR_UNSUPPORTED` a feature that is off or a handle without the log or approvers.
fn check_rare_statuses(op: u8, call: &Call) {
    let f = call.function;
    if call.status == BACKEND {
        assert!(matches!(op, 9 | 11 | 12), "{f} returned EKI_ERR_BACKEND");
    }
    if call.status == UNSUPPORTED {
        let allowed = match op {
            6..=8 => !WITH_PQ,
            11 | 12 => !WITH_PKCS11,
            26..=28 => true,
            _ => false,
        };
        assert!(allowed, "{f} returned EKI_ERR_UNSUPPORTED");
    }
}

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    let mut s = Session {
        scratch: Scratch::new("ffi_status"),
        approvers: Approvers::default(),
        store: None,
        dual: false,
        audited: false,
        known: Vec::new(),
        wrapped: [0; EKI_WRAPPED_KEY_LEN],
        request: None,
        head: [0; EKI_AUDIT_HASH_LEN],
        kem_pk: Vec::new(),
        kem_sk: Vec::new(),
        kem_ct: Vec::new(),
    };
    s.scratch.reset();

    let kind = r.u8() % 3;
    if kind != 0 {
        let config = Config::read(&mut r, &s.scratch, &mut s.approvers);
        let v2 = kind == 2;
        let mut out = Slot::<*mut eki_ks>::new(false);
        // SAFETY: the config views point into buffers `config` owns; `out` is a live, aligned
        // `eki_ks *`.
        let status = unsafe {
            if v2 {
                eki_ks_open_v2(&config.v2(), out.ptr())
            } else {
                eki_ks_open(&config.v1(), out.ptr())
            }
        } as i32;
        let mut call = Call::new("open the session's store", status);
        call.null_field = if v2 {
            config.null_field_v2()
        } else {
            config.null_field_v1()
        };
        call.outputs.push(out.seen());
        call.check();
        let expected = config.expected_open(v2, &s.scratch, false);
        assert!(
            expected.contains(&status),
            "opening the session's store returned {status}"
        );
        if status == OK {
            s.store = Some(Store::from_raw(out.get()));
            s.dual = v2 && config.has_approvers();
            s.audited = v2 && config.has_audit_log();
        }
    }

    let mut calls = 0;
    while !r.is_empty() && calls < MAX_CALLS {
        let op = r.u8() % OPS;
        let call = step(op, &mut s, &mut r);
        call.check();
        check_rare_statuses(op, &call);
        calls += 1;
    }

    let audited = s.store.is_some() && s.audited;
    drop(s.store.take());
    if audited {
        let mut records = Slot::<u64>::new(false);
        // SAFETY: the log path is NUL-terminated and outlives the call; `expected_head` is NULL;
        // `records` is a live, aligned `uint64_t`.
        let status =
            unsafe { eki_audit_verify(s.scratch.log.as_ptr(), core::ptr::null(), records.ptr()) }
                as i32;
        assert_eq!(
            status, OK,
            "the audit log of a closed store does not verify"
        );
        assert!(records.get() >= 2, "open and close were not both logged");
        let mut config = Config::software();
        config.set_audit_log(&s.scratch);
        let mut out = Slot::<*mut eki_ks>::new(false);
        // SAFETY: as for the session's store.
        let status = unsafe { eki_ks_open_v2(&config.v2(), out.ptr()) } as i32;
        assert_eq!(
            status, OK,
            "the log of a closed store cannot be opened again"
        );
        drop(Store::from_raw(out.get()));
    }
    s.scratch.reset();
});
