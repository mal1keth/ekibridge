//! ABI version 2 call wrappers and the scenarios shared by the software and PKCS#11 suites: the
//! state table, rotate, revoke, HMAC verification, dual control of destroy and the format rows
//! of `eki_ks_open_v2` (docs/ffi-contract.md: "Key states", "Opening a store with ABI 2", "Dual
//! control", "Per-function contract").

use core::ffi::c_char;
use std::ffi::CString;

use ekicore_abi::{
    EKI_KEY_AES_256, EKI_KEY_ECDSA_P256, EKI_KEY_HMAC_SHA256, EKI_KEY_STATE_ACTIVE,
    EKI_KEY_STATE_RETIRED, EKI_KEY_STATE_REVOKED, eki_key_alg, eki_key_id, eki_key_info_v2,
    eki_key_state, eki_ks, eki_ks_config, eki_ks_config_v2, eki_status,
};
use ekicore_rs::ffi::{
    eki_audit_verify, eki_ks_audit_head, eki_ks_destroy_approve, eki_ks_destroy_request,
    eki_ks_get_info_v2, eki_ks_hmac_sha256_verify, eki_ks_open_v2, eki_ks_revoke, eki_ks_rotate,
};

use super::ks::{self, unknown_id};
use super::{
    FILL, In, Store, assert_info, assert_open_v2_fails, assert_zero, config_v2, fixed_id, label,
    prefilled_id, prefilled_info, try_open_v2,
};

use eki_status::{
    EKI_ERR_APPROVAL_REQUIRED, EKI_ERR_AUTH_FAILED, EKI_ERR_INVALID_ARGUMENT,
    EKI_ERR_KEY_NOT_FOUND, EKI_ERR_KEY_STATE, EKI_ERR_NULL_POINTER, EKI_ERR_UNSUPPORTED, EKI_OK,
};

/// A `uint32_t` or `uint64_t` output pre-filled with the pattern.
pub const FILL_U32: u32 = u32::from_ne_bytes([FILL; 4]);
pub const FILL_U64: u64 = u64::from_ne_bytes([FILL; 8]);

/// The 20 bytes an approval message starts with.
pub const DOMAIN: &[u8] = b"ekibridge-destroy-v1";

// ---------------------------------------------------------------------------------------------
// Raw wrappers: `None` passes NULL, every `Some` is a live object of the size the ABI requires.
// ---------------------------------------------------------------------------------------------

fn id_ptr(id: Option<&eki_key_id>) -> *const eki_key_id {
    id.map_or(core::ptr::null(), |i| i as *const eki_key_id)
}

fn in_ptr<const N: usize>(input: Option<&[u8; N]>) -> *const u8 {
    input.map_or(core::ptr::null(), |i| i.as_ptr())
}

fn out_ptr<const N: usize>(out: Option<&mut [u8; N]>) -> *mut u8 {
    out.map_or(core::ptr::null_mut(), |o| o.as_mut_ptr())
}

fn mut_ptr<T>(out: Option<&mut T>) -> *mut T {
    out.map_or(core::ptr::null_mut(), |o| o as *mut T)
}

/// `eki_ks_open_v2`.
pub fn open_v2(cfg: Option<&eki_ks_config_v2>, out: Option<&mut *mut eki_ks>) -> eki_status {
    let cfg = cfg.map_or(core::ptr::null(), |c| c as *const eki_ks_config_v2);
    // SAFETY: `cfg` is NULL or a live configuration whose pointers are NULL or live; `out` is
    // NULL or a live `eki_ks *`.
    unsafe { eki_ks_open_v2(cfg, mut_ptr(out)) }
}

/// `eki_ks_get_info_v2`.
pub fn get_info_v2(
    ks: *mut eki_ks,
    id: Option<&eki_key_id>,
    info_out: Option<&mut eki_key_info_v2>,
) -> eki_status {
    // SAFETY: `ks` is NULL or an open handle; `id` and `info_out` are NULL or live objects.
    unsafe { eki_ks_get_info_v2(ks, id_ptr(id), mut_ptr(info_out)) }
}

/// `eki_ks_rotate`.
pub fn rotate(
    ks: *mut eki_ks,
    old: Option<&eki_key_id>,
    new_out: Option<&mut eki_key_id>,
) -> eki_status {
    // SAFETY: `ks` is NULL or an open handle; `old` and `new_out` are NULL or live ids.
    unsafe { eki_ks_rotate(ks, id_ptr(old), mut_ptr(new_out)) }
}

/// `eki_ks_revoke`.
pub fn revoke(ks: *mut eki_ks, id: Option<&eki_key_id>) -> eki_status {
    // SAFETY: `ks` is NULL or an open handle; `id` is NULL or a live id.
    unsafe { eki_ks_revoke(ks, id_ptr(id)) }
}

/// `eki_ks_hmac_sha256_verify`.
pub fn hmac_verify(ks: *mut eki_ks, id: Option<&eki_key_id>, msg: In, tag: In) -> eki_status {
    // SAFETY: `ks` is NULL or an open handle; `id` is NULL or a live id; `msg` and `tag` are
    // NULL or live slices of the lengths passed.
    unsafe { eki_ks_hmac_sha256_verify(ks, id_ptr(id), msg.ptr(), msg.len(), tag.ptr(), tag.len()) }
}

/// `eki_ks_destroy_request`.
pub fn destroy_request(
    ks: *mut eki_ks,
    id: Option<&eki_key_id>,
    request_out: Option<&mut [u8; 32]>,
) -> eki_status {
    // SAFETY: `ks` is NULL or an open handle; `id` is NULL or a live id; the output is NULL or a
    // live 32-byte array.
    unsafe { eki_ks_destroy_request(ks, id_ptr(id), out_ptr(request_out)) }
}

/// `eki_ks_destroy_approve`.
pub fn destroy_approve(
    ks: *mut eki_ks,
    request: Option<&[u8; 32]>,
    approver: Option<&[u8; 65]>,
    sig: Option<&[u8; 64]>,
    remaining_out: Option<&mut u32>,
) -> eki_status {
    // SAFETY: `ks` is NULL or an open handle; the inputs are NULL or live arrays of the fixed
    // sizes the ABI requires; `remaining_out` is NULL or a live `u32`.
    unsafe {
        eki_ks_destroy_approve(
            ks,
            in_ptr(request),
            in_ptr(approver),
            in_ptr(sig),
            mut_ptr(remaining_out),
        )
    }
}

/// `eki_ks_audit_head`.
pub fn audit_head(
    ks: *mut eki_ks,
    hash_out: Option<&mut [u8; 32]>,
    seq_out: Option<&mut u64>,
) -> eki_status {
    // SAFETY: `ks` is NULL or an open handle; the outputs are NULL or a live 32-byte array and a
    // live `u64`.
    unsafe { eki_ks_audit_head(ks, out_ptr(hash_out), mut_ptr(seq_out)) }
}

/// `eki_audit_verify` with a raw path pointer.
pub fn audit_verify(
    path: *const c_char,
    expected_head: Option<&[u8; 32]>,
    records_out: Option<&mut u64>,
) -> eki_status {
    // SAFETY: `path` is NULL, a NUL-terminated string or at least 4097 readable bytes;
    // `expected_head` is NULL or a live 32-byte array; `records_out` is NULL or a live `u64`.
    unsafe { eki_audit_verify(path, in_ptr(expected_head), mut_ptr(records_out)) }
}

// ---------------------------------------------------------------------------------------------
// Key info version 2.
// ---------------------------------------------------------------------------------------------

/// An [`eki_key_info_v2`] with every field set to the pre-fill pattern.
pub fn prefilled_info_v2() -> eki_key_info_v2 {
    eki_key_info_v2 {
        alg: eki_key_alg(i32::from_ne_bytes([FILL; 4])),
        state: eki_key_state(i32::from_ne_bytes([FILL; 4])),
        label: [FILL as c_char; 65],
    }
}

/// Asserts that a version 2 key info was zero-filled after an error.
#[track_caller]
pub fn assert_info_v2_zero(info: &eki_key_info_v2) {
    assert_eq!(info.alg, eki_key_alg(0), "info_out.alg not zeroed");
    assert_eq!(info.state, eki_key_state(0), "info_out.state not zeroed");
    assert_zero(&info.label.map(|c| c as u8));
}

/// Asserts that a version 2 key info names `alg`, `state` and `text`, NUL-padded.
#[track_caller]
pub fn assert_info_v2(info: &eki_key_info_v2, alg: eki_key_alg, state: eki_key_state, text: &str) {
    assert_eq!(info.alg, alg, "info_out.alg");
    assert_eq!(info.state, state, "info_out.state");
    let bytes = info.label.map(|c| c as u8);
    assert_eq!(&bytes[..text.len()], text.as_bytes(), "info_out.label");
    assert_zero(&bytes[text.len()..]);
}

impl Store {
    /// Version 2 key info of `id`; asserts success.
    #[track_caller]
    pub fn info_v2(&self, id: &eki_key_id) -> eki_key_info_v2 {
        let mut info = prefilled_info_v2();
        assert_eq!(get_info_v2(self.ptr(), Some(id), Some(&mut info)), EKI_OK);
        info
    }

    /// The lifecycle state of `id`; asserts success.
    #[track_caller]
    pub fn state(&self, id: &eki_key_id) -> eki_key_state {
        self.info_v2(id).state
    }

    /// Rotates `id`; asserts success and tracks the new key for cleanup.
    #[track_caller]
    pub fn rotate(&self, id: &eki_key_id) -> eki_key_id {
        let mut new = prefilled_id();
        assert_eq!(
            rotate(self.ptr(), Some(id), Some(&mut new)),
            EKI_OK,
            "rotate"
        );
        self.track(new);
        new
    }

    /// Revokes `id`; asserts success.
    #[track_caller]
    pub fn revoke(&self, id: &eki_key_id) {
        assert_eq!(revoke(self.ptr(), Some(id)), EKI_OK, "revoke");
    }

    /// A destroy request for `id`; asserts success.
    #[track_caller]
    pub fn request(&self, id: &eki_key_id) -> [u8; 32] {
        let mut request = [FILL; 32];
        assert_eq!(
            destroy_request(self.ptr(), Some(id), Some(&mut request)),
            EKI_OK,
            "destroy_request"
        );
        request
    }

    /// The approval of `request` by approver `index`; returns the status and the remaining
    /// count it wrote.
    pub fn approve(
        &self,
        approvers: &Approvers,
        index: usize,
        request: &[u8; 32],
        id: &eki_key_id,
    ) -> (eki_status, u32) {
        let sig = approvers.sign(index, request, id);
        let mut remaining = FILL_U32;
        let status = destroy_approve(
            self.ptr(),
            Some(request),
            Some(&approvers.public[index]),
            Some(&sig),
            Some(&mut remaining),
        );
        (status, remaining)
    }

    /// The hash and `seq` of the last audit record; asserts success.
    #[track_caller]
    pub fn audit_head(&self) -> ([u8; 32], u64) {
        let mut hash = [FILL; 32];
        let mut seq = FILL_U64;
        assert_eq!(
            audit_head(self.ptr(), Some(&mut hash), Some(&mut seq)),
            EKI_OK,
            "audit_head"
        );
        (hash, seq)
    }
}

// ---------------------------------------------------------------------------------------------
// Approvers: ECDSA keys in a software store of their own, signing through `eki_ks_sign`.
// ---------------------------------------------------------------------------------------------

/// `n` approver keys. Their private halves stay in a software store; the library under test
/// only ever sees the public keys and the signatures.
pub struct Approvers {
    store: Store,
    keys: Vec<eki_key_id>,
    /// The SEC1 uncompressed public keys, in order.
    pub public: Vec<[u8; 65]>,
}

impl Approvers {
    pub fn new(n: usize) -> Approvers {
        let store = Store::software();
        let keys: Vec<eki_key_id> = (0..n)
            .map(|i| store.generate(EKI_KEY_ECDSA_P256, &format!("eki-test approver {i}")))
            .collect();
        let public = keys.iter().map(|id| store.public_key(id)).collect();
        Approvers {
            store,
            keys,
            public,
        }
    }

    /// The first `n` public keys, back to back.
    pub fn bytes(&self, n: usize) -> Vec<u8> {
        self.public[..n].concat()
    }

    /// The signature of approver `index` over the approval message of `request` for `id`.
    pub fn sign(&self, index: usize, request: &[u8; 32], id: &eki_key_id) -> [u8; 64] {
        let message = [DOMAIN, request, &id.bytes].concat();
        assert_eq!(message.len(), 68);
        self.store.sign(&self.keys[index], In::Bytes(&message))
    }
}

/// A public key that is not a point of the curve: the last byte of a valid one flipped.
pub fn off_curve(key: &[u8; 65]) -> [u8; 65] {
    let mut bad = *key;
    bad[64] ^= 0x01;
    bad
}

// ---------------------------------------------------------------------------------------------
// Scenarios shared by both backends.
// ---------------------------------------------------------------------------------------------

/// Every row of the state table for RETIRED and REVOKED keys of each algorithm (ACTIVE is the
/// ABI 1 behaviour), with zero-filled outputs on `KEY_STATE`.
pub fn state_table_rows(store: &Store) {
    let ks = store.ptr();
    let kek = store.generate(EKI_KEY_AES_256, "eki-test kek");
    let active_kek = store.generate(EKI_KEY_AES_256, "eki-test active kek");
    let mac = store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac");
    let ec = store.generate(EKI_KEY_ECDSA_P256, "eki-test ecdsa");
    let tag = store.hmac(&mac, b"m");
    let blob = store.wrap(&kek, &mac);
    let public_key = store.public_key(&ec);
    for id in [kek, mac, ec] {
        assert_eq!(store.state(&id), EKI_KEY_STATE_ACTIVE);
        store.rotate(&id);
        assert_eq!(store.state(&id), EKI_KEY_STATE_RETIRED);
    }
    assert_info(&store.info(&mac), EKI_KEY_HMAC_SHA256, "eki-test hmac");

    // RETIRED: may check and recover, may not protect anything new.
    assert_state_refused(store, &kek, &mac, &ec);
    assert_eq!(
        hmac_verify(ks, Some(&mac), In::Bytes(b"m"), In::Bytes(&tag)),
        EKI_OK
    );
    let mut wrong = tag;
    wrong[0] ^= 1;
    assert_eq!(
        hmac_verify(ks, Some(&mac), In::Bytes(b"m"), In::Bytes(&wrong)),
        EKI_ERR_AUTH_FAILED
    );
    assert_eq!(store.public_key(&ec), public_key, "RETIRED key, public key");
    let mut out = [FILL; 40];
    assert_eq!(
        ks::wrap(ks, Some(&kek), Some(&mac), Some(&mut out)),
        EKI_ERR_KEY_STATE
    );
    assert_zero(&out);
    let _ = store.wrap(&active_kek, &mac);
    let copy = fixed_id(0x31);
    store.unwrap(&kek, &blob, EKI_KEY_HMAC_SHA256, "eki-test copy", &copy);
    assert_eq!(
        store.state(&copy),
        EKI_KEY_STATE_ACTIVE,
        "an unwrapped key is ACTIVE"
    );
    assert_eq!(store.hmac(&copy, b"m"), tag, "RETIRED kek, unwrap");
    let mut new = prefilled_id();
    assert_eq!(rotate(ks, Some(&mac), Some(&mut new)), EKI_ERR_KEY_STATE);
    assert_zero(&new.bytes);

    // REVOKED: only describe, revoke and destroy.
    for id in [kek, mac, ec] {
        store.revoke(&id);
        assert_eq!(store.state(&id), EKI_KEY_STATE_REVOKED);
        store.revoke(&id);
        assert_eq!(
            store.state(&id),
            EKI_KEY_STATE_REVOKED,
            "revoke is idempotent"
        );
    }
    assert_state_refused(store, &kek, &mac, &ec);
    let mut pk = [FILL; 65];
    assert_eq!(
        ks::get_public_key(ks, Some(&ec), Some(&mut pk)),
        EKI_ERR_KEY_STATE
    );
    assert_zero(&pk);
    assert_eq!(
        hmac_verify(ks, Some(&mac), In::Bytes(b"m"), In::Bytes(&tag)),
        EKI_ERR_KEY_STATE
    );
    let mut out = [FILL; 40];
    assert_eq!(
        ks::wrap(ks, Some(&active_kek), Some(&mac), Some(&mut out)),
        EKI_ERR_KEY_STATE,
        "REVOKED key under an ACTIVE kek"
    );
    assert_zero(&out);
    let text = label("eki-test revoked kek");
    for (id, row) in [(fixed_id(0x32), "fresh id"), (mac, "id in use")] {
        let status = ks::unwrap(
            ks,
            Some(&kek),
            In::Bytes(&blob),
            EKI_KEY_HMAC_SHA256,
            text.as_ptr(),
            Some(&id),
        );
        assert_eq!(status, EKI_ERR_KEY_STATE, "REVOKED kek, {row}");
    }
    let mut new = prefilled_id();
    assert_eq!(rotate(ks, Some(&ec), Some(&mut new)), EKI_ERR_KEY_STATE);
    assert_zero(&new.bytes);
    assert_info(&store.info(&ec), EKI_KEY_ECDSA_P256, "eki-test ecdsa");
    for id in [kek, mac, ec] {
        store.destroy(&id);
    }
}

/// The rows a RETIRED and a REVOKED key share: sign, make a tag, wrap as the kek.
#[track_caller]
fn assert_state_refused(store: &Store, kek: &eki_key_id, mac: &eki_key_id, ec: &eki_key_id) {
    let ks = store.ptr();
    let mut sig = [FILL; 64];
    assert_eq!(
        ks::sign(ks, Some(ec), In::Bytes(b"m"), Some(&mut sig)),
        EKI_ERR_KEY_STATE
    );
    assert_zero(&sig);
    let mut tag = [FILL; 32];
    assert_eq!(
        ks::hmac(ks, Some(mac), In::Bytes(b"m"), Some(&mut tag)),
        EKI_ERR_KEY_STATE
    );
    assert_zero(&tag);
    let mut out = [FILL; 40];
    assert_eq!(
        ks::wrap(ks, Some(kek), Some(kek), Some(&mut out)),
        EKI_ERR_KEY_STATE
    );
    assert_zero(&out);
}

/// `eki_ks_rotate`: every algorithm, fresh material, the state rows and the NULL rows.
pub fn rotate_rows(store: &Store) {
    let ks = store.ptr();
    for (alg, text) in [
        (EKI_KEY_AES_256, "eki-test rotate aes"),
        (EKI_KEY_HMAC_SHA256, "eki-test rotate hmac"),
        (EKI_KEY_ECDSA_P256, "eki-test rotate ecdsa"),
    ] {
        let old = store.generate(alg, text);
        // What the old key computes, taken while it is ACTIVE.
        let mac = store.generate(EKI_KEY_HMAC_SHA256, "eki-test wrapped");
        let before = match alg {
            EKI_KEY_HMAC_SHA256 => store.hmac(&old, b"m").to_vec(),
            EKI_KEY_AES_256 => store.wrap(&old, &mac).to_vec(),
            _ => store.public_key(&old).to_vec(),
        };
        let new = store.rotate(&old);
        assert_ne!(new, old);
        assert_info_v2(&store.info_v2(&new), alg, EKI_KEY_STATE_ACTIVE, text);
        assert_info_v2(&store.info_v2(&old), alg, EKI_KEY_STATE_RETIRED, text);
        let after = match alg {
            EKI_KEY_HMAC_SHA256 => store.hmac(&new, b"m").to_vec(),
            EKI_KEY_AES_256 => store.wrap(&new, &mac).to_vec(),
            _ => store.public_key(&new).to_vec(),
        };
        assert_ne!(before, after, "{text}: fresh key material");
    }

    let unknown = unknown_id();
    let mut new = prefilled_id();
    assert_eq!(
        rotate(ks, Some(&unknown), Some(&mut new)),
        EKI_ERR_KEY_NOT_FOUND
    );
    assert_zero(&new.bytes);

    let mac = store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac");
    let mut new = prefilled_id();
    assert_eq!(
        rotate(core::ptr::null_mut(), Some(&mac), Some(&mut new)),
        EKI_ERR_NULL_POINTER
    );
    assert_zero(&new.bytes);
    let mut new = prefilled_id();
    assert_eq!(rotate(ks, None, Some(&mut new)), EKI_ERR_NULL_POINTER);
    assert_zero(&new.bytes);
    assert_eq!(
        rotate(ks, Some(&unknown), None),
        EKI_ERR_NULL_POINTER,
        "before existence"
    );
    assert_eq!(rotate(ks, Some(&mac), None), EKI_ERR_NULL_POINTER);
    assert_eq!(
        store.state(&mac),
        EKI_KEY_STATE_ACTIVE,
        "a NULL row changes nothing"
    );
}

/// `eki_ks_revoke`: from ACTIVE and from RETIRED, idempotent, missing, NULL rows.
pub fn revoke_rows(store: &Store) {
    let ks = store.ptr();
    let active = store.generate(EKI_KEY_HMAC_SHA256, "eki-test active");
    let retired = store.generate(EKI_KEY_ECDSA_P256, "eki-test retired");
    store.rotate(&retired);
    for id in [active, retired] {
        assert_eq!(revoke(ks, Some(&id)), EKI_OK);
        assert_eq!(store.state(&id), EKI_KEY_STATE_REVOKED);
        assert_eq!(revoke(ks, Some(&id)), EKI_OK, "REVOKED key");
        assert_eq!(store.state(&id), EKI_KEY_STATE_REVOKED);
    }
    assert_eq!(revoke(ks, Some(&unknown_id())), EKI_ERR_KEY_NOT_FOUND);
    let mac = store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac");
    assert_eq!(
        revoke(core::ptr::null_mut(), Some(&mac)),
        EKI_ERR_NULL_POINTER
    );
    assert_eq!(revoke(ks, None), EKI_ERR_NULL_POINTER);
    assert_eq!(store.state(&mac), EKI_KEY_STATE_ACTIVE);
}

/// `eki_ks_hmac_sha256_verify`: the tag rows, the check order and the NULL rows.
pub fn hmac_verify_rows(store: &Store) {
    let ks = store.ptr();
    let unknown = unknown_id();
    let mac = store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac");
    let aes = store.generate(EKI_KEY_AES_256, "eki-test aes");
    let ec = store.generate(EKI_KEY_ECDSA_P256, "eki-test ecdsa");
    let tag = store.hmac(&mac, b"message");
    let empty_tag = store.hmac(&mac, &[]);

    assert_eq!(
        hmac_verify(ks, Some(&mac), In::Bytes(b"message"), In::Bytes(&tag)),
        EKI_OK
    );
    for msg in [In::Null(0), In::Bytes(&[])] {
        assert_eq!(
            hmac_verify(ks, Some(&mac), msg, In::Bytes(&empty_tag)),
            EKI_OK,
            "empty message {msg:?}"
        );
    }
    for index in [0, 17, 31] {
        let mut wrong = tag;
        wrong[index] ^= 0x80;
        assert_eq!(
            hmac_verify(ks, Some(&mac), In::Bytes(b"message"), In::Bytes(&wrong)),
            EKI_ERR_AUTH_FAILED,
            "byte {index}"
        );
    }
    assert_eq!(
        hmac_verify(ks, Some(&mac), In::Bytes(b"messagE"), In::Bytes(&tag)),
        EKI_ERR_AUTH_FAILED
    );

    // The tag length is a format check: before existence and type.
    let long = [tag.as_slice(), &[0]].concat();
    for (row, tag_arg) in [
        ("tag_len 31", In::Bytes(&tag[..31])),
        ("tag_len 33", In::Bytes(&long)),
        ("tag_len 0", In::Bytes(&[])),
        ("tag NULL, tag_len 0", In::Null(0)),
    ] {
        for id in [&mac, &unknown, &aes] {
            assert_eq!(
                hmac_verify(ks, Some(id), In::Bytes(b"message"), tag_arg),
                EKI_ERR_INVALID_ARGUMENT,
                "{row}"
            );
        }
    }
    assert_eq!(
        hmac_verify(ks, Some(&unknown), In::Bytes(b"m"), In::Bytes(&tag)),
        EKI_ERR_KEY_NOT_FOUND
    );
    for id in [&aes, &ec] {
        assert_eq!(
            hmac_verify(ks, Some(id), In::Bytes(b"m"), In::Bytes(&tag)),
            eki_status::EKI_ERR_WRONG_KEY_TYPE
        );
    }

    // NULL rows, and NULL before every other check.
    let null_rows: [(&str, *mut eki_ks, Option<&eki_key_id>, In, In); 5] = [
        (
            "ks",
            core::ptr::null_mut(),
            Some(&mac),
            In::Bytes(b"m"),
            In::Bytes(&tag),
        ),
        ("id", ks, None, In::Bytes(b"m"), In::Bytes(&tag)),
        ("msg", ks, Some(&mac), In::Null(1), In::Bytes(&tag)),
        ("tag", ks, Some(&mac), In::Bytes(b"m"), In::Null(32)),
        (
            "tag with tag_len 31",
            ks,
            Some(&unknown),
            In::Bytes(b"m"),
            In::Null(31),
        ),
    ];
    for (row, ks_arg, id, msg, tag_arg) in null_rows {
        assert_eq!(
            hmac_verify(ks_arg, id, msg, tag_arg),
            EKI_ERR_NULL_POINTER,
            "{row} NULL"
        );
    }
}

/// `eki_ks_get_info_v2`: each algorithm, missing key, NULL rows, zero-filled output.
pub fn get_info_v2_rows(store: &Store) {
    let ks = store.ptr();
    for (alg, text) in [
        (EKI_KEY_AES_256, "eki-test aes"),
        (EKI_KEY_HMAC_SHA256, "eki-test hmac"),
        (EKI_KEY_ECDSA_P256, "eki-test ecdsa"),
    ] {
        let id = store.generate(alg, text);
        assert_info_v2(&store.info_v2(&id), alg, EKI_KEY_STATE_ACTIVE, text);
        let mut info = prefilled_info();
        assert_eq!(ks::get_info(ks, Some(&id), Some(&mut info)), EKI_OK);
        assert_info(&info, alg, text);
    }
    let unknown = unknown_id();
    let mut info = prefilled_info_v2();
    assert_eq!(
        get_info_v2(ks, Some(&unknown), Some(&mut info)),
        EKI_ERR_KEY_NOT_FOUND
    );
    assert_info_v2_zero(&info);
    let mac = store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac");
    let mut info = prefilled_info_v2();
    assert_eq!(
        get_info_v2(core::ptr::null_mut(), Some(&mac), Some(&mut info)),
        EKI_ERR_NULL_POINTER
    );
    assert_info_v2_zero(&info);
    let mut info = prefilled_info_v2();
    assert_eq!(get_info_v2(ks, None, Some(&mut info)), EKI_ERR_NULL_POINTER);
    assert_info_v2_zero(&info);
    assert_eq!(get_info_v2(ks, Some(&unknown), None), EKI_ERR_NULL_POINTER);
}

/// A handle without approvers and without an audit log: plain destroy works, the dual-control
/// functions and `audit_head` are `UNSUPPORTED` before any other check, outputs zero-filled.
pub fn no_approver_rows(store: &Store) {
    let ks = store.ptr();
    let mac = store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac");
    for id in [mac, unknown_id()] {
        let mut request = [FILL; 32];
        assert_eq!(
            destroy_request(ks, Some(&id), Some(&mut request)),
            EKI_ERR_UNSUPPORTED
        );
        assert_zero(&request);
    }
    for key in [[0; 65], [4; 65]] {
        let mut remaining = FILL_U32;
        assert_eq!(
            destroy_approve(
                ks,
                Some(&[7; 32]),
                Some(&key),
                Some(&[1; 64]),
                Some(&mut remaining)
            ),
            EKI_ERR_UNSUPPORTED,
            "even with an invalid approver key"
        );
        assert_eq!(remaining, 0);
    }
    let mut hash = [FILL; 32];
    let mut seq = FILL_U64;
    assert_eq!(
        audit_head(ks, Some(&mut hash), Some(&mut seq)),
        EKI_ERR_UNSUPPORTED
    );
    assert_zero(&hash);
    assert_eq!(seq, 0);
    store.destroy(&mac);

    // NULL rows come first.
    let mac = store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac");
    let null_ks: *mut eki_ks = core::ptr::null_mut();
    let mut request = [FILL; 32];
    assert_eq!(
        destroy_request(null_ks, Some(&mac), Some(&mut request)),
        EKI_ERR_NULL_POINTER
    );
    assert_zero(&request);
    let mut request = [FILL; 32];
    assert_eq!(
        destroy_request(ks, None, Some(&mut request)),
        EKI_ERR_NULL_POINTER
    );
    assert_zero(&request);
    assert_eq!(destroy_request(ks, Some(&mac), None), EKI_ERR_NULL_POINTER);
    approve_null_rows(store, &[7; 32], &[4; 65], &[1; 64]);
    let mut seq = FILL_U64;
    assert_eq!(
        audit_head(null_ks, Some(&mut [FILL; 32]), Some(&mut seq)),
        EKI_ERR_NULL_POINTER
    );
    assert_eq!(seq, 0);
    let mut hash = [FILL; 32];
    assert_eq!(audit_head(ks, Some(&mut hash), None), EKI_ERR_NULL_POINTER);
    assert_zero(&hash);
    let mut seq = FILL_U64;
    assert_eq!(audit_head(ks, None, Some(&mut seq)), EKI_ERR_NULL_POINTER);
    assert_eq!(seq, 0);
}

/// The NULL rows of `eki_ks_destroy_approve` with otherwise valid arguments.
pub fn approve_null_rows(store: &Store, request: &[u8; 32], key: &[u8; 65], sig: &[u8; 64]) {
    let ks = store.ptr();
    type Row<'a> = (
        &'a str,
        *mut eki_ks,
        Option<&'a [u8; 32]>,
        Option<&'a [u8; 65]>,
        Option<&'a [u8; 64]>,
    );
    let rows: [Row; 4] = [
        (
            "ks",
            core::ptr::null_mut(),
            Some(request),
            Some(key),
            Some(sig),
        ),
        ("request", ks, None, Some(key), Some(sig)),
        ("approver_public_key", ks, Some(request), None, Some(sig)),
        ("sig", ks, Some(request), Some(key), None),
    ];
    for (row, ks_arg, request, key, sig) in rows {
        let mut remaining = FILL_U32;
        assert_eq!(
            destroy_approve(ks_arg, request, key, sig, Some(&mut remaining)),
            EKI_ERR_NULL_POINTER,
            "{row} NULL"
        );
        assert_eq!(remaining, 0, "{row} NULL: remaining_out zeroed");
    }
    assert_eq!(
        destroy_approve(ks, Some(request), Some(key), Some(sig), None),
        EKI_ERR_NULL_POINTER,
        "remaining_out NULL"
    );
}

/// Dual control on a handle opened with approvers 0, 1 and 2 of `approvers` (approver 3 is an
/// outsider). Every key the scenario creates ends destroyed by approvals.
pub fn dual_control_rows(store: &Store, approvers: &Approvers) {
    let ks = store.ptr();
    let unknown = unknown_id();
    let target = store.generate(EKI_KEY_HMAC_SHA256, "eki-test doomed");
    store.forget(&target);

    // Plain destroy needs approvals; a missing key is still KEY_NOT_FOUND.
    assert_eq!(ks::destroy(ks, Some(&target)), EKI_ERR_APPROVAL_REQUIRED);
    assert_eq!(
        store.state(&target),
        EKI_KEY_STATE_ACTIVE,
        "nothing changed"
    );
    assert_eq!(ks::destroy(ks, Some(&unknown)), EKI_ERR_KEY_NOT_FOUND);
    let mut request = [FILL; 32];
    assert_eq!(
        destroy_request(ks, Some(&unknown), Some(&mut request)),
        EKI_ERR_KEY_NOT_FOUND
    );
    assert_zero(&request);

    let request = store.request(&target);
    let sig0 = approvers.sign(0, &request, &target);
    let fail = |request: &[u8; 32], key: &[u8; 65], sig: &[u8; 64], expected, row: &str| {
        let mut remaining = FILL_U32;
        assert_eq!(
            destroy_approve(
                ks,
                Some(request),
                Some(key),
                Some(sig),
                Some(&mut remaining)
            ),
            expected,
            "{row}"
        );
        assert_eq!(remaining, 0, "{row}: remaining_out zeroed");
    };
    let invalid = EKI_ERR_INVALID_ARGUMENT;
    let mut compressed = approvers.public[0];
    compressed[0] = 0x02;
    fail(
        &request,
        &off_curve(&approvers.public[0]),
        &sig0,
        invalid,
        "approver off the curve",
    );
    fail(
        &request,
        &compressed,
        &sig0,
        invalid,
        "approver not uncompressed",
    );
    fail(&request, &[0; 65], &sig0, invalid, "approver all zero");
    fail(
        &[0x5A; 32],
        &[0; 65],
        &sig0,
        invalid,
        "key format before request lookup",
    );
    let not_found = EKI_ERR_KEY_NOT_FOUND;
    fail(
        &[0x5A; 32],
        &approvers.public[0],
        &sig0,
        not_found,
        "unknown request",
    );
    fail(
        &[0x5A; 32],
        &approvers.public[3],
        &sig0,
        not_found,
        "lookup before membership",
    );
    let auth = EKI_ERR_AUTH_FAILED;
    let outsider = approvers.sign(3, &request, &target);
    fail(
        &request,
        &approvers.public[3],
        &outsider,
        auth,
        "signature by a non-approver",
    );
    let other_request = approvers.sign(0, &[0x5A; 32], &target);
    fail(
        &request,
        &approvers.public[0],
        &other_request,
        auth,
        "signature over another request",
    );
    let other_key = approvers.sign(0, &request, &unknown);
    fail(
        &request,
        &approvers.public[0],
        &other_key,
        auth,
        "signature over another key id",
    );
    let by_1 = approvers.sign(1, &request, &target);
    fail(
        &request,
        &approvers.public[0],
        &by_1,
        auth,
        "signature by another approver",
    );
    fail(
        &request,
        &approvers.public[0],
        &[0; 64],
        auth,
        "signature all zero",
    );
    approve_null_rows(store, &request, &approvers.public[0], &sig0);

    assert_eq!(store.approve(approvers, 0, &request, &target), (EKI_OK, 1));
    assert_eq!(
        store.approve(approvers, 0, &request, &target),
        (EKI_OK, 1),
        "same approver twice"
    );

    // A new request replaces the old one and drops its approval.
    let renewed = store.request(&target);
    assert_ne!(renewed, request);
    assert_eq!(
        store.approve(approvers, 1, &request, &target),
        (EKI_ERR_KEY_NOT_FOUND, 0),
        "the replaced request"
    );
    assert_eq!(store.approve(approvers, 1, &renewed, &target), (EKI_OK, 1));
    assert_eq!(store.state(&target), EKI_KEY_STATE_ACTIVE);
    assert_eq!(
        store.approve(approvers, 2, &renewed, &target),
        (EKI_OK, 0),
        "second distinct approver"
    );
    let mut info = prefilled_info_v2();
    assert_eq!(
        get_info_v2(ks, Some(&target), Some(&mut info)),
        EKI_ERR_KEY_NOT_FOUND,
        "the key is gone"
    );
    assert_eq!(
        store.approve(approvers, 0, &renewed, &target),
        (EKI_ERR_KEY_NOT_FOUND, 0),
        "the request is gone"
    );

    // Any state can be destroyed, and requests for two keys are independent.
    let revoked = store.generate(EKI_KEY_ECDSA_P256, "eki-test revoked");
    store.forget(&revoked);
    let retired = store.generate(EKI_KEY_AES_256, "eki-test retired");
    store.forget(&retired);
    let successor = store.rotate(&retired);
    store.forget(&successor);
    store.revoke(&revoked);
    let first = store.request(&revoked);
    let second = store.request(&retired);
    let third = store.request(&successor);
    assert_eq!(store.approve(approvers, 2, &first, &revoked), (EKI_OK, 1));
    assert_eq!(store.approve(approvers, 0, &second, &retired), (EKI_OK, 1));
    assert_eq!(store.approve(approvers, 1, &first, &revoked), (EKI_OK, 0));
    assert_eq!(store.approve(approvers, 1, &second, &retired), (EKI_OK, 0));
    assert_eq!(store.approve(approvers, 0, &third, &successor), (EKI_OK, 1));
    assert_eq!(store.approve(approvers, 2, &third, &successor), (EKI_OK, 0));
    for id in [revoked, retired, successor] {
        let mut info = prefilled_info_v2();
        assert_eq!(
            get_info_v2(ks, Some(&id), Some(&mut info)),
            EKI_ERR_KEY_NOT_FOUND
        );
    }
}

/// The format and NULL rows of `eki_ks_open_v2` that need no audit log file, on top of the
/// backend fields of `base`, which must be a configuration that opens.
pub fn open_v2_rows(base: &eki_ks_config, approvers: &Approvers) {
    let keys = approvers.bytes(approvers.public.len());
    let two = approvers.bytes(2);

    // `config` and `out` NULL.
    let cfg = config_v2(base, None, None, 0);
    let mut handle: *mut eki_ks = core::ptr::dangling_mut();
    assert_eq!(open_v2(None, Some(&mut handle)), EKI_ERR_NULL_POINTER);
    assert!(handle.is_null(), "*out NULL");
    assert_eq!(open_v2(Some(&cfg), None), EKI_ERR_NULL_POINTER);

    // Approver keys: NULL before format, then count, distinctness and validity.
    for count in [1, 2, 8, 9, usize::MAX] {
        assert_open_v2_fails(&config_v2(base, None, None, count), EKI_ERR_NULL_POINTER);
    }
    let empty = CString::default();
    assert_open_v2_fails(
        &config_v2(base, Some(&empty), None, 1),
        EKI_ERR_NULL_POINTER,
    );
    let duplicate = [approvers.public[0], approvers.public[0]].concat();
    let bad_point = [approvers.public[0], off_curve(&approvers.public[1])].concat();
    let mut compressed = approvers.public[1];
    compressed[0] = 0x03;
    let not_uncompressed = [approvers.public[0], compressed].concat();
    let zero = [approvers.public[0], [0; 65]].concat();
    let invalid: [(&str, &[u8], usize); 7] = [
        ("approver_count 1", &keys, 1),
        ("approver_count 9", &keys, 9),
        ("approver_count usize::MAX", &keys, usize::MAX),
        ("duplicate approver", &duplicate, 2),
        ("approver off the curve", &bad_point, 2),
        ("approver not uncompressed", &not_uncompressed, 2),
        ("approver all zero", &zero, 2),
    ];
    for (row, bytes, count) in invalid {
        let opened = try_open_v2(&config_v2(base, None, Some(bytes), count));
        assert_eq!(opened.status, EKI_ERR_INVALID_ARGUMENT, "{row}");
        assert!(opened.out_is_null, "{row}: *out NULL");
    }
    // Field order: the audit path before the approver count.
    let long_path = CString::new(vec![b'a'; 4097]).expect("no NUL");
    for path in [&empty, &long_path] {
        assert_open_v2_fails(
            &config_v2(base, Some(path), Some(&keys), 1),
            EKI_ERR_INVALID_ARGUMENT,
        );
        assert_open_v2_fails(
            &config_v2(base, Some(path), Some(&two), 2),
            EKI_ERR_INVALID_ARGUMENT,
        );
    }

    // Count 0 ignores the array; 2 and 8 keys open a handle with dual control.
    let garbage = [0xFF_u8; 3];
    let store = Store::open_v2(&config_v2(base, None, Some(&garbage), 0));
    let mac = store.generate(EKI_KEY_HMAC_SHA256, "eki-test single control");
    store.destroy(&mac);
    drop(store);
    for n in [2, 8] {
        let bytes = approvers.bytes(n);
        let store = Store::open_v2(&config_v2(base, None, Some(&bytes), n));
        let mut request = [FILL; 32];
        assert_eq!(
            destroy_request(store.ptr(), Some(&unknown_id()), Some(&mut request)),
            EKI_ERR_KEY_NOT_FOUND,
            "{n} approvers"
        );
        let mut hash = [FILL; 32];
        let mut seq = FILL_U64;
        assert_eq!(
            audit_head(store.ptr(), Some(&mut hash), Some(&mut seq)),
            EKI_ERR_UNSUPPORTED,
            "no audit log"
        );
    }
}
