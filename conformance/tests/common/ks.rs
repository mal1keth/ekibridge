//! Key-store helpers shared by `ks_software` and `ks_pkcs11`: flow helpers that stop a scenario
//! at the first failed step, the store rows of docs/ffi-contract.md ("Per-function contract", run
//! on any open store), and the ECDSA cross-verification.

use std::ffi::CString;

use ekicore_conformance::sel::{KEY_AES_256 as AES, KEY_ECDSA_P256 as EC, KEY_HMAC_SHA256 as HMAC};
use ekicore_conformance::status::*;
use ekicore_conformance::{
    In, KeyInfo, KsConfig, Lib, Store, describe, eki_key_id, prefill_array, prefill_key_id,
    prefill_key_info,
};

use super::{Report, cstr, unique_label};

/// (row, store, alg, label, pass id_out, expected status)
type GenRow<'a> = (
    &'static str,
    &'a Store<'a>,
    i32,
    Option<&'a CString>,
    bool,
    i32,
);

/// A scenario step that failed; the message names the library, the call and the status.
pub type Flow<T> = Result<T, String>;

/// Runs `body`, records an early stop as a failure, then reports.
pub fn run(name: &str, body: impl FnOnce(&mut Report) -> Flow<()>) {
    let mut r = Report::new(name);
    if let Err(e) = body(&mut r) {
        r.check(false, || format!("scenario stopped: {e}"));
    }
    r.finish();
}

/// `Ok` when `s` is `EKI_OK`; otherwise a failed step naming the library and the call.
pub fn step(lib: &Lib, call: &str, s: i32) -> Flow<()> {
    if s == EKI_OK {
        Ok(())
    } else {
        Err(format!("{}: {call} returned {}", lib.name(), describe(s)))
    }
}

pub fn open<'l>(lib: &'l Lib, cfg: &KsConfig) -> Flow<Store<'l>> {
    match lib.ks_open(cfg) {
        (EKI_OK, Some(st)) => Ok(st),
        (EKI_OK, None) => Err(format!(
            "{}: eki_ks_open returned EKI_OK without a handle",
            lib.name()
        )),
        (s, _) => Err(format!(
            "{}: eki_ks_open(backend {}) returned {}",
            lib.name(),
            cfg.backend,
            describe(s)
        )),
    }
}

pub fn generate(st: &Store, alg: i32, label: &CString) -> Flow<eki_key_id> {
    let mut id = prefill_key_id();
    step(
        st.lib(),
        &format!("eki_ks_generate(alg {alg}, {label:?})"),
        st.generate(alg, Some(label), Some(&mut id)),
    )?;
    Ok(id)
}

pub fn info(st: &Store, id: &eki_key_id) -> Flow<KeyInfo> {
    let mut info = prefill_key_info();
    step(
        st.lib(),
        "eki_ks_get_info",
        st.get_info(Some(id), Some(&mut info)),
    )?;
    Ok(KeyInfo::from_raw(&info))
}

pub fn public_key(st: &Store, id: &eki_key_id) -> Flow<[u8; 65]> {
    let mut pk = prefill_array::<65>();
    step(
        st.lib(),
        "eki_ks_get_public_key",
        st.get_public_key(Some(id), Some(&mut pk)),
    )?;
    Ok(pk)
}

pub fn sign(st: &Store, id: &eki_key_id, msg: &[u8]) -> Flow<[u8; 64]> {
    let mut sig = prefill_array::<64>();
    step(
        st.lib(),
        "eki_ks_sign",
        st.sign(Some(id), In::from(msg), Some(&mut sig)),
    )?;
    Ok(sig)
}

pub fn hmac(st: &Store, id: &eki_key_id, msg: &[u8]) -> Flow<[u8; 32]> {
    let mut out = prefill_array::<32>();
    step(
        st.lib(),
        "eki_ks_hmac_sha256",
        st.hmac_sha256(Some(id), In::from(msg), Some(&mut out)),
    )?;
    Ok(out)
}

pub fn wrap(st: &Store, kek: &eki_key_id, key: &eki_key_id) -> Flow<[u8; 40]> {
    let mut blob = prefill_array::<40>();
    step(
        st.lib(),
        "eki_ks_wrap",
        st.wrap(Some(kek), Some(key), Some(&mut blob)),
    )?;
    Ok(blob)
}

pub fn unwrap(
    st: &Store,
    kek: &eki_key_id,
    blob: &[u8],
    alg: i32,
    label: &CString,
    id: &eki_key_id,
) -> Flow<()> {
    step(
        st.lib(),
        "eki_ks_unwrap",
        st.unwrap(Some(kek), In::from(blob), alg, Some(label), Some(id)),
    )
}

pub fn destroy(st: &Store, id: &eki_key_id) -> Flow<()> {
    step(st.lib(), "eki_ks_destroy", st.destroy(Some(id)))
}

/// An id no store has seen: process id, clock and a counter, spread over 16 bytes with the
/// splitmix64 finaliser. Test ids only need to be unique, not secret.
pub fn fresh_id() -> eki_key_id {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static N: AtomicU64 = AtomicU64::new(0);
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let mut x = t ^ (u64::from(std::process::id()) << 32) ^ n.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let mut bytes = [0u8; 16];
    for chunk in bytes.chunks_mut(8) {
        // splitmix64
        x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        chunk.copy_from_slice(&(z ^ (z >> 31)).to_be_bytes());
    }
    eki_key_id { bytes }
}

/// The store rows of docs/ffi-contract.md ("Per-function contract"), run on one open store.
/// Creates its keys with unique labels and destroys them again.
pub fn store_error_rows(r: &mut Report, st: &Store) -> Flow<()> {
    let lib = st.lib();
    let null = lib.null_store();
    let kek_label = unique_label("kek");
    let hmac_label = unique_label("hmac");
    let ec_label = unique_label("ec");
    let kek = generate(st, AES, &kek_label)?;
    let hk = generate(st, HMAC, &hmac_label)?;
    let ec = generate(st, EC, &ec_label)?;
    let missing = fresh_id();
    let msg = b"conformance message".to_vec();

    // --- generate ---------------------------------------------------------------------------
    let long = cstr(&"x".repeat(65));
    // A unique label padded with '-' to exactly 64 bytes.
    let exact64 = cstr(&format!(
        "{:-<64}",
        unique_label("max").to_str().unwrap_or("conf")
    ));
    let ctl = cstr("bad\u{1}label");
    let del = cstr("bad\u{7f}label");
    let edges = cstr(&format!(
        " ~{}",
        unique_label("edge").to_str().unwrap_or("e")
    ));
    let ok_label = unique_label("gen");
    let rows: [GenRow; 11] = [
        (
            "generate ks NULL",
            &null,
            HMAC,
            Some(&ok_label),
            true,
            EKI_ERR_NULL_POINTER,
        ),
        (
            "generate label NULL",
            st,
            HMAC,
            None,
            true,
            EKI_ERR_NULL_POINTER,
        ),
        (
            "generate id_out NULL",
            st,
            HMAC,
            Some(&ok_label),
            false,
            EKI_ERR_NULL_POINTER,
        ),
        (
            "generate label \"\"",
            st,
            HMAC,
            Some(&cstr("")),
            true,
            EKI_ERR_INVALID_ARGUMENT,
        ),
        (
            "generate 65-byte label",
            st,
            HMAC,
            Some(&long),
            true,
            EKI_ERR_INVALID_ARGUMENT,
        ),
        (
            "generate label with 0x01",
            st,
            HMAC,
            Some(&ctl),
            true,
            EKI_ERR_INVALID_ARGUMENT,
        ),
        (
            "generate label with 0x7f",
            st,
            HMAC,
            Some(&del),
            true,
            EKI_ERR_INVALID_ARGUMENT,
        ),
        (
            "generate alg 0",
            st,
            0,
            Some(&ok_label),
            true,
            EKI_ERR_INVALID_ARGUMENT,
        ),
        (
            "generate alg 4",
            st,
            4,
            Some(&ok_label),
            true,
            EKI_ERR_INVALID_ARGUMENT,
        ),
        (
            "generate 64-byte label",
            st,
            HMAC,
            Some(&exact64),
            true,
            EKI_OK,
        ),
        (
            "generate label with 0x20 and 0x7e",
            st,
            AES,
            Some(&edges),
            true,
            EKI_OK,
        ),
    ];
    for (row, s, alg, label, with_out, want) in rows {
        let mut id = prefill_key_id();
        let got = s.generate(
            alg,
            label.map(|c| c.as_c_str()),
            with_out.then_some(&mut id),
        );
        if r.status(lib, row, got, want) {
            if want == EKI_OK {
                if let Ok(i) = info(st, &id) {
                    r.check(
                        Some(i.label_str().as_str()) == label.and_then(|c| c.to_str().ok()),
                        || format!("{}: {row}: get_info label {:?}", lib.name(), i.label_str()),
                    );
                }
                destroy(st, &id)?;
            } else if with_out {
                r.zeroed(lib, row, "id_out", &id.bytes);
            }
        }
    }

    // --- get_info ---------------------------------------------------------------------------
    for (id, alg, label) in [
        (&kek, AES, &kek_label),
        (&hk, HMAC, &hmac_label),
        (&ec, EC, &ec_label),
    ] {
        let i = info(st, id)?;
        let row = format!("get_info alg {alg}");
        r.check(i.alg == alg, || {
            format!("{}: {row}: alg {}", lib.name(), i.alg)
        });
        r.check(Some(i.label_str().as_str()) == label.to_str().ok(), || {
            format!(
                "{}: {row}: label {:?}, want {label:?}",
                lib.name(),
                i.label_str()
            )
        });
        r.check(i.label_nul_padded(), || {
            format!("{}: {row}: label not NUL-padded: {i:?}", lib.name())
        });
    }
    r.check(last_error_is_empty(st), || {
        format!(
            "{}: last error not reset to \"\" by a successful get_info: {:?}",
            lib.name(),
            st.last_error()
        )
    });
    let mut infob = prefill_key_info();
    let s = st.get_info(Some(&missing), Some(&mut infob));
    if r.status(lib, "get_info unknown id", s, EKI_ERR_KEY_NOT_FOUND) {
        r.check(KeyInfo::from_raw(&infob).is_zero(), || {
            format!(
                "{}: get_info unknown id: info_out not zero-filled",
                lib.name()
            )
        });
    }
    r.status(
        lib,
        "get_info id NULL",
        st.get_info(None, Some(&mut prefill_key_info())),
        EKI_ERR_NULL_POINTER,
    );
    r.status(
        lib,
        "get_info info_out NULL",
        st.get_info(Some(&kek), None),
        EKI_ERR_NULL_POINTER,
    );
    r.status(
        lib,
        "get_info ks NULL",
        null.get_info(Some(&kek), Some(&mut prefill_key_info())),
        EKI_ERR_NULL_POINTER,
    );

    // --- get_public_key / sign / hmac -------------------------------------------------------
    for (row, id, want) in [
        ("get_public_key AES key", &kek, EKI_ERR_WRONG_KEY_TYPE),
        ("get_public_key HMAC key", &hk, EKI_ERR_WRONG_KEY_TYPE),
        ("get_public_key unknown id", &missing, EKI_ERR_KEY_NOT_FOUND),
    ] {
        let mut pk = prefill_array::<65>();
        if r.status(lib, row, st.get_public_key(Some(id), Some(&mut pk)), want) {
            r.zeroed(lib, row, "out", &pk);
        }
    }
    let pk = public_key(st, &ec)?;
    r.check(pk[0] == 0x04, || {
        format!("{}: public key does not start with 0x04", lib.name())
    });
    r.status(
        lib,
        "get_public_key out NULL",
        st.get_public_key(Some(&ec), None),
        EKI_ERR_NULL_POINTER,
    );

    for (row, id, want) in [
        ("sign AES key", &kek, EKI_ERR_WRONG_KEY_TYPE),
        ("sign HMAC key", &hk, EKI_ERR_WRONG_KEY_TYPE),
        ("sign unknown id", &missing, EKI_ERR_KEY_NOT_FOUND),
    ] {
        let mut sig = prefill_array::<64>();
        if r.status(
            lib,
            row,
            st.sign(Some(id), In::from(&msg), Some(&mut sig)),
            want,
        ) {
            r.zeroed(lib, row, "sig_out", &sig);
        }
    }
    let mut sig = prefill_array::<64>();
    let s = st.sign(Some(&ec), In::Null { len: 4 }, Some(&mut sig));
    if r.status(lib, "sign msg NULL, msg_len 4", s, EKI_ERR_NULL_POINTER) {
        r.zeroed(lib, "sign msg NULL, msg_len 4", "sig_out", &sig);
    }
    r.status(
        lib,
        "sign sig_out NULL",
        st.sign(Some(&ec), In::from(&msg), None),
        EKI_ERR_NULL_POINTER,
    );
    let mut sig = prefill_array::<64>();
    if r.status(
        lib,
        "sign msg_len 0",
        st.sign(Some(&ec), In::NULL, Some(&mut sig)),
        EKI_OK,
    ) {
        let s = lib.ecdsa_p256_verify(Some(&pk), In::NULL, Some(&sig));
        r.status(lib, "verify of the msg_len 0 signature", s, EKI_OK);
    }

    for (row, id, want) in [
        ("ks_hmac ECDSA key", &ec, EKI_ERR_WRONG_KEY_TYPE),
        ("ks_hmac AES key", &kek, EKI_ERR_WRONG_KEY_TYPE),
        ("ks_hmac unknown id", &missing, EKI_ERR_KEY_NOT_FOUND),
    ] {
        let mut out = prefill_array::<32>();
        if r.status(
            lib,
            row,
            st.hmac_sha256(Some(id), In::from(&msg), Some(&mut out)),
            want,
        ) {
            r.zeroed(lib, row, "out", &out);
        }
    }
    let mut out = prefill_array::<32>();
    r.status(
        lib,
        "ks_hmac msg_len 0",
        st.hmac_sha256(Some(&hk), In::NULL, Some(&mut out)),
        EKI_OK,
    );
    r.status(
        lib,
        "ks_hmac out NULL",
        st.hmac_sha256(Some(&hk), In::from(&msg), None),
        EKI_ERR_NULL_POINTER,
    );

    // --- wrap ----------------------------------------------------------------------------------
    for (row, kek_id, key_id, want) in [
        (
            "wrap kek is HMAC, key missing (existence before type)",
            &hk,
            &missing,
            EKI_ERR_KEY_NOT_FOUND,
        ),
        (
            "wrap kek is HMAC, key exists",
            &hk,
            &kek,
            EKI_ERR_WRONG_KEY_TYPE,
        ),
        ("wrap key is ECDSA", &kek, &ec, EKI_ERR_WRONG_KEY_TYPE),
        ("wrap kek missing", &missing, &hk, EKI_ERR_KEY_NOT_FOUND),
        ("wrap kek_id == key_id (AES)", &kek, &kek, EKI_OK),
        ("wrap HMAC key under AES kek", &kek, &hk, EKI_OK),
    ] {
        let mut blob = prefill_array::<40>();
        if r.status(
            lib,
            row,
            st.wrap(Some(kek_id), Some(key_id), Some(&mut blob)),
            want,
        ) && want != EKI_OK
        {
            r.zeroed(lib, row, "out", &blob);
        }
    }
    r.status(
        lib,
        "wrap out NULL",
        st.wrap(Some(&kek), Some(&hk), None),
        EKI_ERR_NULL_POINTER,
    );
    r.status(
        lib,
        "wrap kek_id NULL",
        st.wrap(None, Some(&hk), Some(&mut prefill_array())),
        EKI_ERR_NULL_POINTER,
    );

    // --- unwrap --------------------------------------------------------------------------------
    let blob = wrap(st, &kek, &hk)?;
    let mut flipped = blob;
    flipped[20] ^= 0x01;
    let new_id = fresh_id();
    let new_label = unique_label("unwrapped");
    let bad_label = cstr("tab\tlabel");
    let rows: [(&str, &eki_key_id, In, i32, &CString, &eki_key_id, i32); 10] = [
        (
            "unwrap blob NULL, blob_len 40",
            &kek,
            In::Null { len: 40 },
            HMAC,
            &new_label,
            &new_id,
            EKI_ERR_NULL_POINTER,
        ),
        (
            "unwrap blob_len 39",
            &kek,
            In::Bytes(&blob[..39]),
            HMAC,
            &new_label,
            &new_id,
            EKI_ERR_INVALID_ARGUMENT,
        ),
        (
            "unwrap alg ECDSA_P256",
            &kek,
            In::from(&blob),
            EC,
            &new_label,
            &new_id,
            EKI_ERR_INVALID_ARGUMENT,
        ),
        (
            "unwrap alg 0",
            &kek,
            In::from(&blob),
            0,
            &new_label,
            &new_id,
            EKI_ERR_INVALID_ARGUMENT,
        ),
        (
            "unwrap bad label",
            &kek,
            In::from(&blob),
            HMAC,
            &bad_label,
            &new_id,
            EKI_ERR_INVALID_ARGUMENT,
        ),
        (
            "unwrap kek is HMAC",
            &hk,
            In::from(&blob),
            HMAC,
            &new_label,
            &new_id,
            EKI_ERR_WRONG_KEY_TYPE,
        ),
        (
            "unwrap kek missing",
            &missing,
            In::from(&blob),
            HMAC,
            &new_label,
            &new_id,
            EKI_ERR_KEY_NOT_FOUND,
        ),
        (
            "unwrap id already used by an EC key pair",
            &kek,
            In::from(&blob),
            HMAC,
            &new_label,
            &ec,
            EKI_ERR_KEY_EXISTS,
        ),
        (
            "unwrap id already used by an HMAC key",
            &kek,
            In::from(&blob),
            HMAC,
            &new_label,
            &hk,
            EKI_ERR_KEY_EXISTS,
        ),
        (
            "unwrap blob byte flipped",
            &kek,
            In::from(&flipped),
            HMAC,
            &new_label,
            &new_id,
            EKI_ERR_AUTH_FAILED,
        ),
    ];
    for (row, kek_id, b, alg, label, id, want) in rows {
        r.status(
            lib,
            row,
            st.unwrap(Some(kek_id), b, alg, Some(label), Some(id)),
            want,
        );
    }
    let s = st.unwrap(Some(&kek), In::from(&blob), HMAC, None, Some(&new_id));
    r.status(lib, "unwrap label NULL", s, EKI_ERR_NULL_POINTER);
    // A failed unwrap must not have created the id.
    let s = st.get_info(Some(&new_id), Some(&mut prefill_key_info()));
    r.status(
        lib,
        "get_info after failed unwraps",
        s,
        EKI_ERR_KEY_NOT_FOUND,
    );

    // Round trip inside this store: the unwrapped key computes the same HMAC as the original.
    unwrap(st, &kek, &blob, HMAC, &new_label, &new_id)?;
    let h1 = hmac(st, &hk, &msg)?;
    let h2 = hmac(st, &new_id, &msg)?;
    r.check(h1 == h2, || {
        format!(
            "{}: unwrapped HMAC key computes a different tag",
            lib.name()
        )
    });
    let i = info(st, &new_id)?;
    r.check(
        i.alg == HMAC && Some(i.label_str().as_str()) == new_label.to_str().ok(),
        || format!("{}: get_info of the unwrapped key: {i:?}", lib.name()),
    );

    // --- destroy -------------------------------------------------------------------------------
    r.status(
        lib,
        "destroy unknown id",
        st.destroy(Some(&missing)),
        EKI_ERR_KEY_NOT_FOUND,
    );
    r.status(
        lib,
        "destroy id NULL",
        st.destroy(None),
        EKI_ERR_NULL_POINTER,
    );
    r.status(
        lib,
        "destroy ks NULL",
        null.destroy(Some(&hk)),
        EKI_ERR_NULL_POINTER,
    );
    for id in [&new_id, &hk, &ec, &kek] {
        r.status(lib, "destroy", st.destroy(Some(id)), EKI_OK);
        r.status(
            lib,
            "destroy twice",
            st.destroy(Some(id)),
            EKI_ERR_KEY_NOT_FOUND,
        );
        let s = st.get_info(Some(id), Some(&mut prefill_key_info()));
        r.status(lib, "get_info after destroy", s, EKI_ERR_KEY_NOT_FOUND);
    }
    Ok(())
}

fn last_error_is_empty(st: &Store) -> bool {
    st.last_error().is_empty()
}

/// `eki_ks_last_error_message` rows that need no key: NULL handle, NULL buffer, tiny buffer.
pub fn last_error_rows(r: &mut Report, st: &Store) {
    let lib = st.lib();
    let null = lib.null_store();
    let mut buf = [0xA5u8; 8];
    let n = null.last_error_message_raw(Some(&mut buf), 0);
    r.check(n == 0 && buf[0] == 0, || {
        format!(
            "{}: last_error_message(ks NULL) returned {n}, buf[0] = {:#x}; want 0 and \"\"",
            lib.name(),
            buf[0]
        )
    });
    let n = null.last_error_message_raw(None, 0);
    r.check(n == 0, || {
        format!(
            "{}: last_error_message(NULL, NULL, 0) returned {n}",
            lib.name()
        )
    });

    // Provoke a failure so there may be text, then check the snprintf convention.
    let _ = st.get_info(Some(&fresh_id()), Some(&mut prefill_key_info()));
    let full = st.last_error_message_raw(None, 16); // buf NULL is treated as buf_len 0
    let mut one = [0xA5u8; 1];
    let n1 = st.last_error_message_raw(Some(&mut one), 0);
    r.check(n1 == full && one[0] == 0, || {
        format!(
            "{}: buf_len 1: returned {n1} (want {full}), buf[0] = {:#x} (want NUL)",
            lib.name(),
            one[0]
        )
    });
    let mut big = vec![0xA5u8; full + 1];
    let n2 = st.last_error_message_raw(Some(&mut big), 0);
    r.check(n2 == full && big[full] == 0, || {
        format!(
            "{}: buf_len full+1: returned {n2}, terminator {:#x}",
            lib.name(),
            big[full]
        )
    });
}

/// ECDSA cross-verification: generate and sign in `x`, verify with `y`'s stateless verify (and
/// `x`'s own), and check that a different message fails in both.
pub fn ecdsa_cross(r: &mut Report, x: &Store, y: &Lib) -> Flow<()> {
    let lib = x.lib();
    let id = generate(x, EC, &unique_label("ec-cross"))?;
    let pk = public_key(x, &id)?;
    for msg in [b"".as_slice(), b"abc", &[0x5a; 1000]] {
        let sig = sign(x, &id, msg)?;
        let ctx = format!("sign in {}, {}-byte message", lib.name(), msg.len());
        r.status(
            y,
            &format!("{ctx}, verify in {}", y.name()),
            y.ecdsa_p256_verify(Some(&pk), In::from(msg), Some(&sig)),
            EKI_OK,
        );
        r.status(
            lib,
            &format!("{ctx}, verify in {}", lib.name()),
            lib.ecdsa_p256_verify(Some(&pk), In::from(msg), Some(&sig)),
            EKI_OK,
        );
        let s = y.ecdsa_p256_verify(Some(&pk), In::from(b"another message"), Some(&sig));
        r.status(
            y,
            &format!("{ctx}, verify other message in {}", y.name()),
            s,
            EKI_ERR_AUTH_FAILED,
        );
    }
    destroy(x, &id)
}
