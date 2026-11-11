//! Key store call wrappers and the scenarios shared by the software and PKCS#11 suites.
//!
//! Every scenario takes an open [`Store`] and checks behaviour that docs/ffi-contract.md
//! ("Validation order", "Per-function contract") requires of both backends. Backend-specific
//! rows live in the test files themselves.

use core::ffi::c_char;

use ekicore_abi::{
    EKI_KEY_AES_256, EKI_KEY_ECDSA_P256, EKI_KEY_HMAC_SHA256, EKI_P256_PUBLIC_KEY_LEN,
    EKI_P256_SIGNATURE_LEN, EKI_WRAPPED_KEY_LEN, eki_key_alg, eki_key_id, eki_key_info, eki_ks,
    eki_status,
};
use ekicore_rs::ffi::{
    eki_ecdsa_p256_verify, eki_ks_destroy, eki_ks_generate, eki_ks_get_info, eki_ks_get_public_key,
    eki_ks_hmac_sha256, eki_ks_last_error_message, eki_ks_sign, eki_ks_unwrap, eki_ks_wrap,
};

use super::{
    FILL, In, Store, assert_info, assert_info_zero, assert_untouched, assert_zero, fixed_id, label,
    label_of_len, last_error, prefilled_id, prefilled_info, unterminated_label,
};

use eki_status::{
    EKI_ERR_AUTH_FAILED, EKI_ERR_INVALID_ARGUMENT, EKI_ERR_KEY_EXISTS, EKI_ERR_KEY_NOT_FOUND,
    EKI_ERR_NULL_POINTER, EKI_ERR_WRONG_KEY_TYPE, EKI_OK,
};

// ---------------------------------------------------------------------------------------------
// Raw wrappers: `None` passes NULL, every `Some` is a live object of the size the ABI requires.
// ---------------------------------------------------------------------------------------------

fn id_ptr(id: Option<&eki_key_id>) -> *const eki_key_id {
    id.map_or(core::ptr::null(), |i| i as *const eki_key_id)
}

fn out_ptr<const N: usize>(out: Option<&mut [u8; N]>) -> *mut u8 {
    out.map_or(core::ptr::null_mut(), |o| o.as_mut_ptr())
}

/// `eki_ks_generate` with a raw label pointer.
pub fn generate(
    ks: *mut eki_ks,
    alg: eki_key_alg,
    label: *const c_char,
    id_out: Option<&mut eki_key_id>,
) -> eki_status {
    let id_out = id_out.map_or(core::ptr::null_mut(), |i| i as *mut eki_key_id);
    // SAFETY: `ks` is NULL or an open handle; `label` is NULL or points to at least 65 readable
    // bytes or a NUL-terminated string; `id_out` is NULL or a live `eki_key_id`.
    unsafe { eki_ks_generate(ks, alg, label, id_out) }
}

/// `eki_ks_get_info`.
pub fn get_info(
    ks: *mut eki_ks,
    id: Option<&eki_key_id>,
    info_out: Option<&mut eki_key_info>,
) -> eki_status {
    let info_out = info_out.map_or(core::ptr::null_mut(), |i| i as *mut eki_key_info);
    // SAFETY: `ks` is NULL or an open handle; `id` and `info_out` are NULL or live objects.
    unsafe { eki_ks_get_info(ks, id_ptr(id), info_out) }
}

/// `eki_ks_get_public_key`.
pub fn get_public_key(
    ks: *mut eki_ks,
    id: Option<&eki_key_id>,
    out: Option<&mut [u8; EKI_P256_PUBLIC_KEY_LEN]>,
) -> eki_status {
    // SAFETY: `ks` is NULL or an open handle; `id` is NULL or a live id; the output is NULL or
    // a live 65-byte array.
    unsafe { eki_ks_get_public_key(ks, id_ptr(id), out_ptr(out)) }
}

/// `eki_ks_sign`.
pub fn sign(
    ks: *mut eki_ks,
    id: Option<&eki_key_id>,
    msg: In,
    sig_out: Option<&mut [u8; EKI_P256_SIGNATURE_LEN]>,
) -> eki_status {
    // SAFETY: `ks` is NULL or an open handle; `id` is NULL or a live id; `msg` is NULL or a
    // live slice of the length passed; the output is NULL or a live 64-byte array.
    unsafe { eki_ks_sign(ks, id_ptr(id), msg.ptr(), msg.len(), out_ptr(sig_out)) }
}

/// `eki_ks_hmac_sha256`.
pub fn hmac(
    ks: *mut eki_ks,
    id: Option<&eki_key_id>,
    msg: In,
    out: Option<&mut [u8; 32]>,
) -> eki_status {
    // SAFETY: `ks` is NULL or an open handle; `id` is NULL or a live id; `msg` is NULL or a
    // live slice of the length passed; the output is NULL or a live 32-byte array.
    unsafe { eki_ks_hmac_sha256(ks, id_ptr(id), msg.ptr(), msg.len(), out_ptr(out)) }
}

/// `eki_ks_wrap`.
pub fn wrap(
    ks: *mut eki_ks,
    kek_id: Option<&eki_key_id>,
    key_id: Option<&eki_key_id>,
    out: Option<&mut [u8; EKI_WRAPPED_KEY_LEN]>,
) -> eki_status {
    // SAFETY: `ks` is NULL or an open handle; the ids are NULL or live ids; the output is NULL
    // or a live 40-byte array.
    unsafe { eki_ks_wrap(ks, id_ptr(kek_id), id_ptr(key_id), out_ptr(out)) }
}

/// `eki_ks_unwrap` with a raw label pointer.
pub fn unwrap(
    ks: *mut eki_ks,
    kek_id: Option<&eki_key_id>,
    blob: In,
    alg: eki_key_alg,
    label: *const c_char,
    id: Option<&eki_key_id>,
) -> eki_status {
    // SAFETY: `ks` is NULL or an open handle; `kek_id` and `id` are NULL or live ids; `blob` is
    // NULL or a live slice of the length passed; `label` is NULL, a NUL-terminated string, or
    // at least 65 readable bytes.
    unsafe {
        eki_ks_unwrap(
            ks,
            id_ptr(kek_id),
            blob.ptr(),
            blob.len(),
            alg,
            label,
            id_ptr(id),
        )
    }
}

/// `eki_ks_destroy`.
pub fn destroy(ks: *mut eki_ks, id: Option<&eki_key_id>) -> eki_status {
    // SAFETY: `ks` is NULL or an open handle; `id` is NULL or a live id.
    unsafe { eki_ks_destroy(ks, id_ptr(id)) }
}

/// `eki_ks_last_error_message` with a raw buffer.
pub fn last_error_raw(ks: *const eki_ks, buf: Option<&mut [c_char]>, buf_len: usize) -> usize {
    let buf = buf.map_or(core::ptr::null_mut(), |b| {
        assert!(b.len() >= buf_len, "test bug: buffer shorter than buf_len");
        b.as_mut_ptr()
    });
    // SAFETY: `ks` is NULL or an open handle; `buf` is NULL or a live buffer of at least
    // `buf_len` bytes.
    unsafe { eki_ks_last_error_message(ks, buf, buf_len) }
}

// ---------------------------------------------------------------------------------------------
// Convenience helpers on an open store that assert success.
// ---------------------------------------------------------------------------------------------

impl Store {
    /// Key info of `id`; asserts success.
    #[track_caller]
    pub fn info(&self, id: &eki_key_id) -> eki_key_info {
        let mut info = prefilled_info();
        assert_eq!(
            get_info(self.ptr(), Some(id), Some(&mut info)),
            EKI_OK,
            "get_info"
        );
        info
    }

    /// HMAC of `msg` under the stored key `id`; asserts success.
    #[track_caller]
    pub fn hmac(&self, id: &eki_key_id, msg: &[u8]) -> [u8; 32] {
        let mut out = [FILL; 32];
        assert_eq!(
            hmac(self.ptr(), Some(id), In::Bytes(msg), Some(&mut out)),
            EKI_OK,
            "ks_hmac"
        );
        out
    }

    /// Public key of the ECDSA key `id`; asserts success.
    #[track_caller]
    pub fn public_key(&self, id: &eki_key_id) -> [u8; 65] {
        let mut out = [FILL; 65];
        assert_eq!(
            get_public_key(self.ptr(), Some(id), Some(&mut out)),
            EKI_OK,
            "get_public_key"
        );
        out
    }

    /// Signature over `msg` with the ECDSA key `id`; asserts success.
    #[track_caller]
    pub fn sign(&self, id: &eki_key_id, msg: In) -> [u8; 64] {
        let mut sig = [FILL; 64];
        assert_eq!(
            sign(self.ptr(), Some(id), msg, Some(&mut sig)),
            EKI_OK,
            "ks_sign"
        );
        sig
    }

    /// Wraps `key` under `kek`; asserts success.
    #[track_caller]
    pub fn wrap(&self, kek: &eki_key_id, key: &eki_key_id) -> [u8; 40] {
        let mut out = [FILL; 40];
        assert_eq!(
            wrap(self.ptr(), Some(kek), Some(key), Some(&mut out)),
            EKI_OK,
            "ks_wrap"
        );
        out
    }

    /// Unwraps `blob` under `kek` as a new key; asserts success and tracks the id for cleanup.
    #[track_caller]
    pub fn unwrap(
        &self,
        kek: &eki_key_id,
        blob: &[u8],
        alg: eki_key_alg,
        text: &str,
        id: &eki_key_id,
    ) {
        let text = label(text);
        let status = unwrap(
            self.ptr(),
            Some(kek),
            In::Bytes(blob),
            alg,
            text.as_ptr(),
            Some(id),
        );
        assert_eq!(status, EKI_OK, "ks_unwrap");
        self.track(*id);
    }

    /// Destroys `id`; asserts success.
    #[track_caller]
    pub fn destroy(&self, id: &eki_key_id) {
        assert_eq!(destroy(self.ptr(), Some(id)), EKI_OK, "ks_destroy");
        self.forget(id);
    }
}

/// Stateless verification of a store signature.
pub fn verify(public_key: &[u8; 65], msg: In, sig: &[u8; 64]) -> eki_status {
    // SAFETY: both arrays are live and of the fixed sizes the ABI requires; `msg` is NULL or a
    // live slice of the length passed.
    unsafe { eki_ecdsa_p256_verify(public_key.as_ptr(), msg.ptr(), msg.len(), sig.as_ptr()) }
}

/// An id no store has generated (generated ids are random; this one is fixed).
pub fn unknown_id() -> eki_key_id {
    fixed_id(0x5A)
}

// ---------------------------------------------------------------------------------------------
// Scenarios shared by both backends.
// ---------------------------------------------------------------------------------------------

/// Generate one key of each algorithm, read it back, use it, destroy it.
pub fn lifecycle(store: &Store) {
    let aes = store.generate(EKI_KEY_AES_256, "eki-test aes");
    let mac = store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac");
    let ec = store.generate(EKI_KEY_ECDSA_P256, "eki-test ecdsa");
    assert!(aes != mac && mac != ec && aes != ec, "ids are distinct");

    assert_info(&store.info(&aes), EKI_KEY_AES_256, "eki-test aes");
    assert_info(&store.info(&mac), EKI_KEY_HMAC_SHA256, "eki-test hmac");
    assert_info(&store.info(&ec), EKI_KEY_ECDSA_P256, "eki-test ecdsa");

    // HMAC is deterministic per key and differs between keys.
    let mac2 = store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac 2");
    let tag = store.hmac(&mac, b"message");
    assert_eq!(tag, store.hmac(&mac, b"message"));
    assert_ne!(tag, store.hmac(&mac, b"message!"));
    assert_ne!(tag, store.hmac(&mac2, b"message"));

    // Sign, then verify with the stateless function (signature bytes are never compared: "Known
    // limitations" in docs/ffi-contract.md).
    let pk = store.public_key(&ec);
    assert_eq!(pk[0], 0x04, "SEC1 uncompressed");
    assert_eq!(pk, store.public_key(&ec), "public key is stable");
    let sig = store.sign(&ec, In::Bytes(b"message"));
    assert_eq!(verify(&pk, In::Bytes(b"message"), &sig), EKI_OK);
    assert_eq!(verify(&pk, In::Bytes(b"other"), &sig), EKI_ERR_AUTH_FAILED);
    let sig2 = store.sign(&ec, In::Bytes(b"message"));
    assert_eq!(verify(&pk, In::Bytes(b"message"), &sig2), EKI_OK);

    for id in [aes, mac, mac2, ec] {
        store.destroy(&id);
        let mut info = prefilled_info();
        assert_eq!(
            get_info(store.ptr(), Some(&id), Some(&mut info)),
            EKI_ERR_KEY_NOT_FOUND
        );
        assert_info_zero(&info);
    }
}

/// Wrap an HMAC key and an AES key, unwrap them under new ids, and check the copies behave
/// like the originals.
pub fn wrap_unwrap_round_trip(store: &Store) {
    let kek = store.generate(EKI_KEY_AES_256, "eki-test kek");
    let mac = store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac");
    let aes = store.generate(EKI_KEY_AES_256, "eki-test aes");

    let blob = store.wrap(&kek, &mac);
    assert_eq!(
        blob,
        store.wrap(&kek, &mac),
        "RFC 3394 wrapping is deterministic"
    );
    let copy = fixed_id(0x11);
    store.unwrap(
        &kek,
        &blob,
        EKI_KEY_HMAC_SHA256,
        "eki-test hmac copy",
        &copy,
    );
    assert_info(
        &store.info(&copy),
        EKI_KEY_HMAC_SHA256,
        "eki-test hmac copy",
    );
    assert_eq!(store.hmac(&copy, b"message"), store.hmac(&mac, b"message"));
    assert_eq!(store.hmac(&copy, &[]), store.hmac(&mac, &[]));

    // An unwrapped AES key wraps exactly like the original.
    let aes_blob = store.wrap(&kek, &aes);
    let aes_copy = fixed_id(0x12);
    store.unwrap(
        &kek,
        &aes_blob,
        EKI_KEY_AES_256,
        "eki-test aes copy",
        &aes_copy,
    );
    assert_info(&store.info(&aes_copy), EKI_KEY_AES_256, "eki-test aes copy");
    assert_eq!(store.wrap(&aes, &mac), store.wrap(&aes_copy, &mac));

    // Self-wrap is allowed (`kek_id == key_id` (AES) → OK).
    let self_blob = store.wrap(&kek, &kek);
    assert_ne!(self_blob, [FILL; 40]);

    // Destroying the copy leaves the original.
    store.destroy(&copy);
    assert_info(&store.info(&mac), EKI_KEY_HMAC_SHA256, "eki-test hmac");
}

/// `ks_generate` rows and the label rules ("Labels" in docs/ffi-contract.md).
pub fn generate_rows(store: &Store) {
    let ks = store.ptr();
    let good = label("eki-test");

    for alg in [0, 4, -1, i32::MIN, i32::MAX] {
        let mut id = prefilled_id();
        let status = generate(ks, eki_key_alg(alg), good.as_ptr(), Some(&mut id));
        assert_eq!(status, EKI_ERR_INVALID_ARGUMENT, "alg {alg}");
        assert_zero(&id.bytes);
    }

    let bad_labels: [(&str, Vec<u8>); 7] = [
        ("empty", vec![0]),
        ("65 bytes", label_of_len(65).into_bytes_with_nul()),
        ("0x01", b"eki\x01test\0".to_vec()),
        ("0x1f", b"\x1f\0".to_vec()),
        ("0x7f", b"eki\x7f\0".to_vec()),
        ("0x80", b"eki\x80\0".to_vec()),
        ("0xff", b"\xff\0".to_vec()),
    ];
    for alg in [EKI_KEY_AES_256, EKI_KEY_HMAC_SHA256, EKI_KEY_ECDSA_P256] {
        for (name, bytes) in &bad_labels {
            let mut id = prefilled_id();
            let status = generate(ks, alg, bytes.as_ptr().cast(), Some(&mut id));
            assert_eq!(status, EKI_ERR_INVALID_ARGUMENT, "alg {alg:?} label {name}");
            assert_zero(&id.bytes);
        }
        // No NUL within 65 bytes: rejected after reading at most 65 bytes.
        let unterminated = unterminated_label();
        let mut id = prefilled_id();
        let status = generate(ks, alg, unterminated.as_ptr().cast(), Some(&mut id));
        assert_eq!(
            status, EKI_ERR_INVALID_ARGUMENT,
            "alg {alg:?} unterminated label"
        );
        assert_zero(&id.bytes);
    }

    // Boundary labels that are valid: 1 byte, 64 bytes, the printable extremes.
    for text in [
        " ".to_owned(),
        "~".to_owned(),
        " !\"#$%&'()*+,-./0123456789:;<=>?@AZ[\\]^_`az{|}~".to_owned(),
        String::from_utf8(label_of_len(64).into_bytes()).unwrap(),
    ] {
        let id = store.generate(EKI_KEY_HMAC_SHA256, &text);
        assert_info(&store.info(&id), EKI_KEY_HMAC_SHA256, &text);
    }

    // Labels need not be unique.
    let a = store.generate(EKI_KEY_AES_256, "eki-test same");
    let b = store.generate(EKI_KEY_AES_256, "eki-test same");
    assert_ne!(a, b);
}

/// NULL rows of `ks_generate`, including NULL taking precedence over selector and label checks.
pub fn generate_null_rows(store: &Store) {
    let ks = store.ptr();
    let good = label("eki-test");
    let empty = label("");

    let mut id = prefilled_id();
    let status = generate(
        core::ptr::null_mut(),
        EKI_KEY_AES_256,
        good.as_ptr(),
        Some(&mut id),
    );
    assert_eq!(status, EKI_ERR_NULL_POINTER, "ks NULL");
    assert_zero(&id.bytes);

    let mut id = prefilled_id();
    let status = generate(ks, EKI_KEY_AES_256, core::ptr::null(), Some(&mut id));
    assert_eq!(status, EKI_ERR_NULL_POINTER, "label NULL");
    assert_zero(&id.bytes);

    assert_eq!(
        generate(ks, EKI_KEY_AES_256, good.as_ptr(), None),
        EKI_ERR_NULL_POINTER,
        "id_out NULL"
    );
    assert_eq!(
        generate(core::ptr::null_mut(), eki_key_alg(0), empty.as_ptr(), None),
        EKI_ERR_NULL_POINTER,
        "ks NULL, alg 0, empty label"
    );
    let mut id = prefilled_id();
    assert_eq!(
        generate(ks, eki_key_alg(0), core::ptr::null(), Some(&mut id)),
        EKI_ERR_NULL_POINTER,
        "label NULL, alg 0"
    );
    // Selector before label format (step 2 before step 3 of "Validation order"): both
    // INVALID_ARGUMENT.
    let mut id = prefilled_id();
    assert_eq!(
        generate(ks, eki_key_alg(0), empty.as_ptr(), Some(&mut id)),
        EKI_ERR_INVALID_ARGUMENT
    );
}

/// Rows for `get_info`, `destroy`, `get_public_key`, `sign` and `ks_hmac`.
pub fn lookup_rows(store: &Store) {
    let ks = store.ptr();
    let unknown = unknown_id();
    let aes = store.generate(EKI_KEY_AES_256, "eki-test aes");
    let mac = store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac");
    let ec = store.generate(EKI_KEY_ECDSA_P256, "eki-test ecdsa");

    // get_info / destroy: unknown id; destroy twice.
    let mut info = prefilled_info();
    assert_eq!(
        get_info(ks, Some(&unknown), Some(&mut info)),
        EKI_ERR_KEY_NOT_FOUND
    );
    assert_info_zero(&info);
    assert_eq!(destroy(ks, Some(&unknown)), EKI_ERR_KEY_NOT_FOUND);
    let doomed = store.generate(EKI_KEY_HMAC_SHA256, "eki-test doomed");
    store.destroy(&doomed);
    assert_eq!(
        destroy(ks, Some(&doomed)),
        EKI_ERR_KEY_NOT_FOUND,
        "destroy twice"
    );
    let mut out = [FILL; 32];
    assert_eq!(
        hmac(ks, Some(&doomed), In::Bytes(b"m"), Some(&mut out)),
        EKI_ERR_KEY_NOT_FOUND
    );
    assert_zero(&out);

    // get_public_key / sign: missing → KEY_NOT_FOUND; not ECDSA → WRONG_KEY_TYPE.
    for (id, expected) in [
        (&unknown, EKI_ERR_KEY_NOT_FOUND),
        (&aes, EKI_ERR_WRONG_KEY_TYPE),
        (&mac, EKI_ERR_WRONG_KEY_TYPE),
    ] {
        let mut pk = [FILL; 65];
        assert_eq!(
            get_public_key(ks, Some(id), Some(&mut pk)),
            expected,
            "get_public_key"
        );
        assert_zero(&pk);
        let mut sig = [FILL; 64];
        assert_eq!(
            sign(ks, Some(id), In::Bytes(b"m"), Some(&mut sig)),
            expected,
            "sign"
        );
        assert_zero(&sig);
    }

    // ks_hmac: missing → KEY_NOT_FOUND; not HMAC → WRONG_KEY_TYPE.
    for (id, expected) in [
        (&unknown, EKI_ERR_KEY_NOT_FOUND),
        (&ec, EKI_ERR_WRONG_KEY_TYPE),
        (&aes, EKI_ERR_WRONG_KEY_TYPE),
    ] {
        let mut out = [FILL; 32];
        assert_eq!(
            hmac(ks, Some(id), In::Bytes(b"m"), Some(&mut out)),
            expected,
            "ks_hmac"
        );
        assert_zero(&out);
    }

    // Empty messages are fine for ks_hmac and ks_sign, with NULL or non-NULL pointers.
    let tag = store.hmac(&mac, &[]);
    let mut out = [FILL; 32];
    assert_eq!(hmac(ks, Some(&mac), In::Null(0), Some(&mut out)), EKI_OK);
    assert_eq!(out, tag);
    let pk = store.public_key(&ec);
    for msg in [In::Null(0), In::Bytes(&[])] {
        let sig = store.sign(&ec, msg);
        assert_eq!(verify(&pk, In::Null(0), &sig), EKI_OK, "{msg:?}");
    }
}

/// NULL rows of every per-key function; NULL takes precedence over store state.
pub fn lookup_null_rows(store: &Store) {
    let ks = store.ptr();
    let null_ks: *mut eki_ks = core::ptr::null_mut();
    let unknown = unknown_id();
    let mac = store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac");
    let ec = store.generate(EKI_KEY_ECDSA_P256, "eki-test ecdsa");

    let mut info = prefilled_info();
    assert_eq!(
        get_info(null_ks, Some(&mac), Some(&mut info)),
        EKI_ERR_NULL_POINTER
    );
    assert_info_zero(&info);
    let mut info = prefilled_info();
    assert_eq!(get_info(ks, None, Some(&mut info)), EKI_ERR_NULL_POINTER);
    assert_info_zero(&info);
    assert_eq!(get_info(ks, Some(&unknown), None), EKI_ERR_NULL_POINTER);

    assert_eq!(destroy(null_ks, Some(&mac)), EKI_ERR_NULL_POINTER);
    assert_eq!(destroy(ks, None), EKI_ERR_NULL_POINTER);

    let mut pk = [FILL; 65];
    assert_eq!(
        get_public_key(null_ks, Some(&ec), Some(&mut pk)),
        EKI_ERR_NULL_POINTER
    );
    assert_zero(&pk);
    assert_eq!(
        get_public_key(ks, None, Some(&mut [FILL; 65])),
        EKI_ERR_NULL_POINTER
    );
    assert_eq!(
        get_public_key(ks, Some(&mac), None),
        EKI_ERR_NULL_POINTER,
        "before type"
    );

    let mut sig = [FILL; 64];
    assert_eq!(
        sign(null_ks, Some(&ec), In::Bytes(b"m"), Some(&mut sig)),
        EKI_ERR_NULL_POINTER
    );
    assert_zero(&sig);
    assert_eq!(
        sign(ks, None, In::Bytes(b"m"), Some(&mut [FILL; 64])),
        EKI_ERR_NULL_POINTER
    );
    let mut sig = [FILL; 64];
    assert_eq!(
        sign(ks, Some(&ec), In::Null(1), Some(&mut sig)),
        EKI_ERR_NULL_POINTER
    );
    assert_zero(&sig);
    assert_eq!(
        sign(ks, Some(&unknown), In::Bytes(b"m"), None),
        EKI_ERR_NULL_POINTER
    );

    let mut out = [FILL; 32];
    assert_eq!(
        hmac(null_ks, Some(&mac), In::Bytes(b"m"), Some(&mut out)),
        EKI_ERR_NULL_POINTER
    );
    assert_zero(&out);
    assert_eq!(
        hmac(ks, None, In::Bytes(b"m"), Some(&mut [FILL; 32])),
        EKI_ERR_NULL_POINTER
    );
    let mut out = [FILL; 32];
    assert_eq!(
        hmac(ks, Some(&mac), In::Null(5), Some(&mut out)),
        EKI_ERR_NULL_POINTER
    );
    assert_zero(&out);
    assert_eq!(
        hmac(ks, Some(&ec), In::Bytes(b"m"), None),
        EKI_ERR_NULL_POINTER,
        "before type"
    );
}

/// `ks_wrap` rows, including the multi-fault rows that pin the check order
/// (kek exists → key exists → kek is AES → key is AES or HMAC).
pub fn wrap_rows(store: &Store) {
    let ks = store.ptr();
    let unknown = unknown_id();
    let kek = store.generate(EKI_KEY_AES_256, "eki-test kek");
    let mac = store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac");
    let ec = store.generate(EKI_KEY_ECDSA_P256, "eki-test ecdsa");

    let rows: [(&str, &eki_key_id, &eki_key_id, eki_status); 9] = [
        (
            "kek is HMAC, key missing",
            &mac,
            &unknown,
            EKI_ERR_KEY_NOT_FOUND,
        ),
        (
            "kek is HMAC, key exists",
            &mac,
            &kek,
            EKI_ERR_WRONG_KEY_TYPE,
        ),
        (
            "kek is ECDSA, key exists",
            &ec,
            &mac,
            EKI_ERR_WRONG_KEY_TYPE,
        ),
        ("key is ECDSA", &kek, &ec, EKI_ERR_WRONG_KEY_TYPE),
        ("kek missing", &unknown, &mac, EKI_ERR_KEY_NOT_FOUND),
        (
            "kek missing, key is ECDSA",
            &unknown,
            &ec,
            EKI_ERR_KEY_NOT_FOUND,
        ),
        (
            "kek missing, key missing",
            &unknown,
            &unknown,
            EKI_ERR_KEY_NOT_FOUND,
        ),
        ("key missing", &kek, &unknown, EKI_ERR_KEY_NOT_FOUND),
        (
            "kek is HMAC, key is ECDSA",
            &mac,
            &ec,
            EKI_ERR_WRONG_KEY_TYPE,
        ),
    ];
    for (name, kek_id, key_id, expected) in rows {
        let mut out = [FILL; 40];
        assert_eq!(
            wrap(ks, Some(kek_id), Some(key_id), Some(&mut out)),
            expected,
            "{name}"
        );
        assert_zero(&out);
    }

    let mut out = [FILL; 40];
    assert_eq!(
        wrap(ks, Some(&kek), Some(&kek), Some(&mut out)),
        EKI_OK,
        "self-wrap"
    );
    assert_ne!(out, [0; 40]);

    // NULL rows, and NULL before store state.
    let mut out = [FILL; 40];
    assert_eq!(
        wrap(
            core::ptr::null_mut(),
            Some(&kek),
            Some(&mac),
            Some(&mut out)
        ),
        EKI_ERR_NULL_POINTER
    );
    assert_zero(&out);
    let mut out = [FILL; 40];
    assert_eq!(
        wrap(ks, None, Some(&mac), Some(&mut out)),
        EKI_ERR_NULL_POINTER
    );
    assert_zero(&out);
    let mut out = [FILL; 40];
    assert_eq!(
        wrap(ks, Some(&kek), None, Some(&mut out)),
        EKI_ERR_NULL_POINTER
    );
    assert_zero(&out);
    assert_eq!(
        wrap(ks, Some(&unknown), Some(&unknown), None),
        EKI_ERR_NULL_POINTER
    );
}

/// A NULL row of `ks_unwrap`: name, `ks`, `kek_id`, `blob`, `label`, `id`.
type UnwrapNullRow<'a> = (
    &'a str,
    *mut eki_ks,
    Option<&'a eki_key_id>,
    In<'a>,
    *const c_char,
    Option<&'a eki_key_id>,
);

/// `ks_unwrap` rows, including the multi-fault rows that pin the check order
/// (alg → blob_len → not ECDSA → label → kek exists → kek is AES → id free → integrity).
pub fn unwrap_rows(store: &Store) {
    let ks = store.ptr();
    let unknown = unknown_id();
    let kek = store.generate(EKI_KEY_AES_256, "eki-test kek");
    let mac = store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac");
    let ec = store.generate(EKI_KEY_ECDSA_P256, "eki-test ecdsa");
    let blob = store.wrap(&kek, &mac);
    let mut flipped = blob;
    flipped[20] ^= 0x01;
    let fresh = fixed_id(0x21);
    let good = label("eki-test unwrapped");
    let empty = label("");
    let long = label_of_len(65);
    let ctrl = label("eki\x01");
    let unterminated = unterminated_label();
    let hmac_alg = EKI_KEY_HMAC_SHA256;

    let invalid: [(&str, In, eki_key_alg, *const c_char, &eki_key_id); 12] = [
        (
            "blob_len 39",
            In::Bytes(&blob[..39]),
            hmac_alg,
            good.as_ptr(),
            &fresh,
        ),
        (
            "blob_len 41",
            In::Bytes(&[0; 41]),
            hmac_alg,
            good.as_ptr(),
            &fresh,
        ),
        (
            "blob NULL, blob_len 0",
            In::Null(0),
            hmac_alg,
            good.as_ptr(),
            &fresh,
        ),
        (
            "alg ECDSA_P256",
            In::Bytes(&blob),
            EKI_KEY_ECDSA_P256,
            good.as_ptr(),
            &fresh,
        ),
        (
            "alg 0",
            In::Bytes(&blob),
            eki_key_alg(0),
            good.as_ptr(),
            &fresh,
        ),
        (
            "alg 4",
            In::Bytes(&blob),
            eki_key_alg(4),
            good.as_ptr(),
            &fresh,
        ),
        (
            "label empty",
            In::Bytes(&blob),
            hmac_alg,
            empty.as_ptr(),
            &fresh,
        ),
        (
            "label 65 bytes",
            In::Bytes(&blob),
            hmac_alg,
            long.as_ptr(),
            &fresh,
        ),
        (
            "label 0x01",
            In::Bytes(&blob),
            hmac_alg,
            ctrl.as_ptr(),
            &fresh,
        ),
        (
            "label unterminated",
            In::Bytes(&blob),
            hmac_alg,
            unterminated.as_ptr().cast(),
            &fresh,
        ),
        // Format checks come before store state: the id is taken, still INVALID_ARGUMENT.
        (
            "blob_len 39, id taken",
            In::Bytes(&blob[..39]),
            hmac_alg,
            good.as_ptr(),
            &ec,
        ),
        (
            "alg ECDSA_P256, id taken",
            In::Bytes(&blob),
            EKI_KEY_ECDSA_P256,
            good.as_ptr(),
            &kek,
        ),
    ];
    for (name, blob_arg, alg, label_ptr, id) in invalid {
        let status = unwrap(ks, Some(&kek), blob_arg, alg, label_ptr, Some(id));
        assert_eq!(status, EKI_ERR_INVALID_ARGUMENT, "{name}");
        // Format checks also precede the kek lookup.
        let status = unwrap(ks, Some(&unknown), blob_arg, alg, label_ptr, Some(id));
        assert_eq!(status, EKI_ERR_INVALID_ARGUMENT, "{name}, kek missing");
    }

    let state: [(&str, &eki_key_id, &[u8; 40], &eki_key_id, eki_status); 10] = [
        (
            "kek missing",
            &unknown,
            &blob,
            &fresh,
            EKI_ERR_KEY_NOT_FOUND,
        ),
        (
            "kek missing, id taken",
            &unknown,
            &blob,
            &ec,
            EKI_ERR_KEY_NOT_FOUND,
        ),
        ("kek is HMAC", &mac, &blob, &fresh, EKI_ERR_WRONG_KEY_TYPE),
        ("kek is ECDSA", &ec, &blob, &fresh, EKI_ERR_WRONG_KEY_TYPE),
        (
            "kek is HMAC, id taken",
            &mac,
            &blob,
            &ec,
            EKI_ERR_WRONG_KEY_TYPE,
        ),
        (
            "kek is HMAC, blob flipped",
            &mac,
            &flipped,
            &fresh,
            EKI_ERR_WRONG_KEY_TYPE,
        ),
        (
            "id used by an EC key pair",
            &kek,
            &blob,
            &ec,
            EKI_ERR_KEY_EXISTS,
        ),
        ("id used by the kek", &kek, &blob, &kek, EKI_ERR_KEY_EXISTS),
        (
            "id taken, blob flipped",
            &kek,
            &flipped,
            &mac,
            EKI_ERR_KEY_EXISTS,
        ),
        (
            "blob byte flipped",
            &kek,
            &flipped,
            &fresh,
            EKI_ERR_AUTH_FAILED,
        ),
    ];
    for (name, kek_id, blob_arg, id, expected) in state {
        let status = unwrap(
            ks,
            Some(kek_id),
            In::Bytes(blob_arg),
            hmac_alg,
            good.as_ptr(),
            Some(id),
        );
        assert_eq!(status, expected, "{name}");
    }
    // A failed unwrap creates nothing, and the keys whose ids were offered are unchanged.
    let mut info = prefilled_info();
    assert_eq!(
        get_info(ks, Some(&fresh), Some(&mut info)),
        EKI_ERR_KEY_NOT_FOUND
    );
    assert_info(&store.info(&ec), EKI_KEY_ECDSA_P256, "eki-test ecdsa");
    assert_info(&store.info(&kek), EKI_KEY_AES_256, "eki-test kek");

    // Every blob byte is covered by the integrity check.
    for index in 0..40 {
        let mut bad = blob;
        bad[index] ^= 0x80;
        let status = unwrap(
            ks,
            Some(&kek),
            In::Bytes(&bad),
            hmac_alg,
            good.as_ptr(),
            Some(&fresh),
        );
        assert_eq!(status, EKI_ERR_AUTH_FAILED, "byte {index}");
    }

    // NULL rows, and NULL before everything else.
    let null_rows: [UnwrapNullRow; 6] = [
        (
            "ks",
            core::ptr::null_mut(),
            Some(&kek),
            In::Bytes(&blob),
            good.as_ptr(),
            Some(&fresh),
        ),
        (
            "kek_id",
            ks,
            None,
            In::Bytes(&blob),
            good.as_ptr(),
            Some(&fresh),
        ),
        (
            "blob",
            ks,
            Some(&kek),
            In::Null(40),
            good.as_ptr(),
            Some(&fresh),
        ),
        (
            "label",
            ks,
            Some(&kek),
            In::Bytes(&blob),
            core::ptr::null(),
            Some(&fresh),
        ),
        ("id", ks, Some(&kek), In::Bytes(&blob), good.as_ptr(), None),
        (
            "blob NULL with blob_len 39",
            ks,
            Some(&kek),
            In::Null(39),
            good.as_ptr(),
            Some(&fresh),
        ),
    ];
    for (name, ks_arg, kek_id, blob_arg, label_ptr, id) in null_rows {
        let status = unwrap(ks_arg, kek_id, blob_arg, hmac_alg, label_ptr, id);
        assert_eq!(status, EKI_ERR_NULL_POINTER, "{name} NULL");
    }
    let status = unwrap(
        ks,
        Some(&kek),
        In::Bytes(&blob),
        eki_key_alg(0),
        core::ptr::null(),
        Some(&fresh),
    );
    assert_eq!(status, EKI_ERR_NULL_POINTER, "label NULL, alg 0");

    // The original blob still unwraps after all of the above.
    store.unwrap(&kek, &blob, hmac_alg, "eki-test unwrapped", &fresh);
    assert_eq!(store.hmac(&fresh, b"m"), store.hmac(&mac, b"m"));
}

/// `eki_ks_last_error_message` conventions ("Last error message" in docs/ffi-contract.md).
pub fn last_error_rows(store: &Store) {
    let ks = store.ptr();

    // NULL handle: "" if there is room, return 0.
    let mut buf = [FILL as c_char; 8];
    assert_eq!(last_error_raw(core::ptr::null(), Some(&mut buf), 8), 0);
    assert_eq!(buf[0], 0, "NUL written");
    assert_untouched(&buf[1..].iter().map(|&c| c as u8).collect::<Vec<_>>());
    let mut buf = [FILL as c_char; 8];
    assert_eq!(last_error_raw(core::ptr::null(), Some(&mut buf), 0), 0);
    assert_untouched(&buf.iter().map(|&c| c as u8).collect::<Vec<_>>());
    assert_eq!(last_error_raw(core::ptr::null(), None, 0), 0);
    assert_eq!(
        last_error_raw(core::ptr::null(), None, 8),
        0,
        "buf NULL is buf_len 0"
    );

    // A successful call leaves "".
    let mac = store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac");
    assert_eq!(last_error(ks), "");

    // A failure may leave text; whatever it is, the snprintf convention holds.
    assert_eq!(destroy(ks, Some(&unknown_id())), EKI_ERR_KEY_NOT_FOUND);
    let full = last_error(ks);
    let n = full.len();
    assert_eq!(
        last_error_raw(ks, None, 0),
        n,
        "buf NULL returns the full length"
    );
    assert_eq!(last_error_raw(ks, None, 64), n, "buf NULL is buf_len 0");
    let mut buf = [FILL as c_char; 4];
    assert_eq!(last_error_raw(ks, Some(&mut buf), 0), n);
    assert_untouched(&buf.iter().map(|&c| c as u8).collect::<Vec<_>>());
    let mut buf = [FILL as c_char; 4];
    assert_eq!(last_error_raw(ks, Some(&mut buf), 1), n);
    assert_eq!(buf[0], 0, "buf_len 1 writes only the NUL");
    let mut buf = [FILL as c_char; 4];
    assert_eq!(last_error_raw(ks, Some(&mut buf), 4), n);
    let written = n.min(3);
    let bytes: Vec<u8> = buf.iter().map(|&c| c as u8).collect();
    assert_eq!(
        &bytes[..written],
        &full.as_bytes()[..written],
        "truncated prefix"
    );
    assert_eq!(bytes[written], 0, "NUL after the truncated prefix");

    // The next call resets the message on entry.
    let _ = store.info(&mac);
    assert_eq!(last_error(ks), "", "reset by a successful call");
    assert_eq!(last_error_raw(ks, None, 0), 0);
}
