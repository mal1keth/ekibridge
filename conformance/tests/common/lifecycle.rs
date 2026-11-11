//! Helpers for the ABI 2 modules (`ks_lifecycle`, `audit`, `ks_pkcs11_lifecycle`): flow helpers
//! for the new calls, approver keys held in a separate software store, keys brought into a given
//! state, and the state table of docs/ffi-contract.md ("Key states") run on the handles of one
//! library.

use std::ffi::CString;

use ekicore_conformance::sel::{
    KEY_AES_256 as AES, KEY_ECDSA_P256 as EC, KEY_HMAC_SHA256 as HMAC, KEY_STATE_ACTIVE as ACTIVE,
    KEY_STATE_RETIRED as RETIRED, KEY_STATE_REVOKED as REVOKED,
};
use ekicore_conformance::status::*;
use ekicore_conformance::{
    In, KeyInfoV2, KsConfig, KsConfigV2, Lib, PREFILL_U32, PREFILL_U64, Store, describe,
    eki_key_id, is_zero, prefill_array, prefill_key_id, prefill_key_info, prefill_key_info_v2,
};

use super::ks::{self, Flow, step};
use super::{Report, unique_label};

/// The three key states, in the order of the state table's columns.
pub const STATES: [i32; 3] = [ACTIVE, RETIRED, REVOKED];

/// The 20 ASCII bytes an approval message starts with (docs/ffi-contract.md, "Dual control").
pub const DESTROY_DOMAIN: &[u8; 20] = b"ekibridge-destroy-v1";

/// Name of a key state for messages.
pub fn state_name(state: i32) -> &'static str {
    match state {
        ACTIVE => "ACTIVE",
        RETIRED => "RETIRED",
        REVOKED => "REVOKED",
        _ => "not a state",
    }
}

/// Name of a key algorithm for messages.
pub fn alg_name(alg: i32) -> &'static str {
    match alg {
        AES => "AES-256",
        HMAC => "HMAC-SHA256",
        EC => "ECDSA-P256",
        _ => "not an algorithm",
    }
}

/// The status a state-table row expects in `state`: `EKI_OK` where `allowed` says so for that
/// column (ACTIVE, RETIRED, REVOKED), `EKI_ERR_KEY_STATE` otherwise.
pub fn expect_in(state: i32, allowed: [bool; 3]) -> i32 {
    let column = STATES.iter().position(|&s| s == state).unwrap_or(0);
    if allowed[column] {
        EKI_OK
    } else {
        EKI_ERR_KEY_STATE
    }
}

// ---------------------------------------------------------------------------------------------
// Flow helpers for the ABI 2 calls
// ---------------------------------------------------------------------------------------------

pub fn open_v2<'l>(lib: &'l Lib, cfg: &KsConfigV2) -> Flow<Store<'l>> {
    match lib.ks_open_v2(cfg) {
        (EKI_OK, Some(st)) => Ok(st),
        (EKI_OK, None) => Err(format!(
            "{}: eki_ks_open_v2 returned EKI_OK without a handle",
            lib.name()
        )),
        (s, _) => Err(format!(
            "{}: eki_ks_open_v2(backend {}, audit log {}, {} approvers) returned {}",
            lib.name(),
            cfg.backend,
            if cfg.audit_log_path.is_some() {
                "set"
            } else {
                "NULL"
            },
            cfg.approver_count,
            describe(s)
        )),
    }
}

pub fn info_v2(st: &Store, id: &eki_key_id) -> Flow<KeyInfoV2> {
    let mut info = prefill_key_info_v2();
    step(
        st.lib(),
        "eki_ks_get_info_v2",
        st.get_info_v2(Some(id), Some(&mut info)),
    )?;
    Ok(KeyInfoV2::from_raw(&info))
}

pub fn rotate(st: &Store, id: &eki_key_id) -> Flow<eki_key_id> {
    let mut new_id = prefill_key_id();
    step(
        st.lib(),
        "eki_ks_rotate",
        st.rotate(Some(id), Some(&mut new_id)),
    )?;
    Ok(new_id)
}

pub fn revoke(st: &Store, id: &eki_key_id) -> Flow<()> {
    step(st.lib(), "eki_ks_revoke", st.revoke(Some(id)))
}

pub fn destroy_request(st: &Store, id: &eki_key_id) -> Flow<[u8; 32]> {
    let mut request = prefill_array::<32>();
    step(
        st.lib(),
        "eki_ks_destroy_request",
        st.destroy_request(Some(id), Some(&mut request)),
    )?;
    Ok(request)
}

/// One approval; returns `remaining_out`.
pub fn approve(st: &Store, request: &[u8; 32], key: &[u8; 65], sig: &[u8; 64]) -> Flow<u32> {
    let mut remaining = PREFILL_U32;
    step(
        st.lib(),
        "eki_ks_destroy_approve",
        st.destroy_approve(Some(request), Some(key), Some(sig), Some(&mut remaining)),
    )?;
    Ok(remaining)
}

/// `eki_ks_audit_head`: the hash and sequence number of the last record.
pub fn audit_head(st: &Store) -> Flow<([u8; 32], u64)> {
    let mut hash = prefill_array::<32>();
    let mut seq = PREFILL_U64;
    step(
        st.lib(),
        "eki_ks_audit_head",
        st.audit_head(Some(&mut hash), Some(&mut seq)),
    )?;
    Ok((hash, seq))
}

/// The message an approver signs for `request` and the key `id` ("Dual control").
pub fn approval_message(request: &[u8; 32], id: &eki_key_id) -> Vec<u8> {
    let mut msg = DESTROY_DOMAIN.to_vec();
    msg.extend_from_slice(request);
    msg.extend_from_slice(&id.bytes);
    msg
}

// ---------------------------------------------------------------------------------------------
// Approvers
// ---------------------------------------------------------------------------------------------

/// ECDSA P-256 approver keys in a software store of one library, outside the store under test:
/// approver private keys never enter the library through the ABI 2 interface ("Dual control" in
/// docs/ffi-contract.md). Approvals are signed with that library's `eki_ks_sign`.
pub struct Approvers<'l> {
    store: Store<'l>,
    ids: Vec<eki_key_id>,
    /// The public keys, in generation order.
    pub keys: Vec<[u8; 65]>,
}

impl<'l> Approvers<'l> {
    /// `n` approver keys in a new software store of `lib`, opened with `eki_ks_open`.
    pub fn new(lib: &'l Lib, n: usize) -> Flow<Self> {
        let store = ks::open(lib, &KsConfig::software())?;
        let mut ids = Vec::with_capacity(n);
        let mut keys = Vec::with_capacity(n);
        for _ in 0..n {
            let id = ks::generate(&store, EC, &unique_label("approver"))?;
            keys.push(ks::public_key(&store, &id)?);
            ids.push(id);
        }
        Ok(Approvers { store, ids, keys })
    }

    /// The library holding the approver keys.
    pub fn lib(&self) -> &'l Lib {
        self.store.lib()
    }

    /// Approver `i`'s signature over the approval message of `request` and `id`.
    pub fn sign(&self, i: usize, request: &[u8; 32], id: &eki_key_id) -> Flow<[u8; 64]> {
        ks::sign(&self.store, &self.ids[i], &approval_message(request, id))
    }

    /// Approver `i`'s signature over an arbitrary message.
    pub fn sign_raw(&self, i: usize, msg: &[u8]) -> Flow<[u8; 64]> {
        ks::sign(&self.store, &self.ids[i], msg)
    }

    /// The first `n` public keys.
    pub fn first(&self, n: usize) -> Vec<[u8; 65]> {
        self.keys[..n].to_vec()
    }
}

/// A public key that is not a P-256 point: a valid key with the last byte of Y changed.
pub fn off_curve(key: &[u8; 65]) -> [u8; 65] {
    let mut k = *key;
    k[64] ^= 0x01;
    k
}

// ---------------------------------------------------------------------------------------------
// Keys in a given state
// ---------------------------------------------------------------------------------------------

/// Brings the ACTIVE key `id` into `state`: RETIRED through `eki_ks_rotate`, REVOKED through
/// `eki_ks_revoke`. The key `eki_ks_rotate` creates is pushed onto `made`.
pub fn set_state(st: &Store, id: &eki_key_id, state: i32, made: &mut Vec<eki_key_id>) -> Flow<()> {
    match state {
        RETIRED => {
            made.push(rotate(st, id)?);
            Ok(())
        }
        REVOKED => revoke(st, id),
        _ => Ok(()),
    }
}

/// A new key of `alg` in `state`. Every id created is pushed onto `made`.
pub fn key_in_state(
    st: &Store,
    alg: i32,
    state: i32,
    made: &mut Vec<eki_key_id>,
) -> Flow<eki_key_id> {
    let id = ks::generate(st, alg, &unique_label(state_name(state)))?;
    made.push(id);
    set_state(st, &id, state, made)?;
    Ok(id)
}

/// Destroys every id of `made` through `st`, a handle without approvers. An id that is already
/// gone is fine; any other failure is reported. Used to leave a PKCS#11 token as it was found.
pub fn destroy_all(r: &mut Report, st: &Store, made: &[eki_key_id]) {
    for id in made {
        let s = st.destroy(Some(id));
        r.status_in(
            st.lib(),
            "cleanup destroy",
            s,
            &[EKI_OK, EKI_ERR_KEY_NOT_FOUND],
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The state table ("Key states" in docs/ffi-contract.md)
// ---------------------------------------------------------------------------------------------

/// Every row of the state table, for each of the three states, on the handles of one library:
/// `plain` has no approvers, `dual` has approvers and serves the `destroy_request` row, which a
/// handle without approvers answers with `EKI_ERR_UNSUPPORTED`. Each row uses fresh keys; the
/// outputs of a failed call must be zero-filled. Every id created is pushed onto `made`.
pub fn state_table_rows(
    r: &mut Report,
    plain: &Store,
    dual: &Store,
    made: &mut Vec<eki_key_id>,
) -> Flow<()> {
    let lib = plain.lib();
    let msg = b"state table message".to_vec();
    for state in STATES {
        let sn = state_name(state);

        // get_info, get_info_v2, revoke and destroy: allowed in every state, for every type.
        for alg in [AES, HMAC, EC] {
            let ctx = |row: &str| format!("{row}, {} key {sn}", alg_name(alg));
            let label = unique_label("table");
            let id = ks::generate(plain, alg, &label)?;
            made.push(id);
            set_state(plain, &id, state, made)?;
            let mut info = prefill_key_info();
            if r.status(
                lib,
                &ctx("get_info"),
                plain.get_info(Some(&id), Some(&mut info)),
                EKI_OK,
            ) {
                let i = ekicore_conformance::KeyInfo::from_raw(&info);
                r.check(i.alg == alg && label_is(&i.label, &label), || {
                    format!("{}: {}: {i:?}", lib.name(), ctx("get_info"))
                });
            }
            let mut info = prefill_key_info_v2();
            if r.status(
                lib,
                &ctx("get_info_v2"),
                plain.get_info_v2(Some(&id), Some(&mut info)),
                EKI_OK,
            ) {
                let i = KeyInfoV2::from_raw(&info);
                r.check(
                    i.alg == alg && i.state == state && label_is(&i.label, &label),
                    || format!("{}: {}: {i:?}", lib.name(), ctx("get_info_v2")),
                );
                r.check(i.v1().label_nul_padded(), || {
                    format!(
                        "{}: {}: label not NUL-padded",
                        lib.name(),
                        ctx("get_info_v2")
                    )
                });
            }
            if r.status(lib, &ctx("revoke"), plain.revoke(Some(&id)), EKI_OK) {
                let i = info_v2(plain, &id)?;
                r.check(i.state == REVOKED, || {
                    format!(
                        "{}: {}: state {} after revoke",
                        lib.name(),
                        ctx("revoke"),
                        i.state
                    )
                });
            }
            let other = key_in_state(plain, alg, state, made)?;
            if r.status(lib, &ctx("destroy"), plain.destroy(Some(&other)), EKI_OK) {
                let s = plain.get_info(Some(&other), Some(&mut prefill_key_info()));
                r.status(
                    lib,
                    &ctx("get_info after destroy"),
                    s,
                    EKI_ERR_KEY_NOT_FOUND,
                );
            }
            let on_dual = key_in_state(dual, alg, state, made)?;
            let mut request = prefill_array::<32>();
            if r.status(
                lib,
                &ctx("destroy_request on a handle with approvers"),
                dual.destroy_request(Some(&on_dual), Some(&mut request)),
                EKI_OK,
            ) {
                r.check(request != [ekicore_conformance::PREFILL; 32], || {
                    format!(
                        "{}: {}: request_out not written",
                        lib.name(),
                        ctx("destroy_request")
                    )
                });
            }
        }

        // get_public_key: ok, ok, KEY_STATE.
        let ec = ks::generate(plain, EC, &unique_label("table-ec"))?;
        made.push(ec);
        let pk_active = ks::public_key(plain, &ec)?;
        set_state(plain, &ec, state, made)?;
        let row = format!("get_public_key, ECDSA key {sn}");
        let want = expect_in(state, [true, true, false]);
        let mut pk = prefill_array::<65>();
        if r.status(
            lib,
            &row,
            plain.get_public_key(Some(&ec), Some(&mut pk)),
            want,
        ) {
            if want == EKI_OK {
                r.bytes(lib, &row, "public key", &pk, &pk_active);
            } else {
                r.zeroed(lib, &row, "out", &pk);
            }
        }

        // sign: ok, KEY_STATE, KEY_STATE.
        let row = format!("sign, ECDSA key {sn}");
        let want = expect_in(state, [true, false, false]);
        let mut sig = prefill_array::<64>();
        if r.status(
            lib,
            &row,
            plain.sign(Some(&ec), In::from(&msg), Some(&mut sig)),
            want,
        ) {
            if want == EKI_OK {
                let s = lib.ecdsa_p256_verify(Some(&pk_active), In::from(&msg), Some(&sig));
                r.status(lib, &format!("{row}: verify the signature"), s, EKI_OK);
            } else {
                r.zeroed(lib, &row, "sig_out", &sig);
            }
        }

        // hmac: ok, KEY_STATE, KEY_STATE. hmac_verify with the right tag: ok, ok, KEY_STATE.
        let hk = ks::generate(plain, HMAC, &unique_label("table-hmac"))?;
        made.push(hk);
        let tag = ks::hmac(plain, &hk, &msg)?;
        set_state(plain, &hk, state, made)?;
        let row = format!("hmac_sha256, HMAC key {sn}");
        let want = expect_in(state, [true, false, false]);
        let mut out = prefill_array::<32>();
        if r.status(
            lib,
            &row,
            plain.hmac_sha256(Some(&hk), In::from(&msg), Some(&mut out)),
            want,
        ) {
            if want == EKI_OK {
                r.bytes(lib, &row, "tag", &out, &tag);
            } else {
                r.zeroed(lib, &row, "out", &out);
            }
        }
        let row = format!("hmac_sha256_verify with the right tag, HMAC key {sn}");
        r.status(
            lib,
            &row,
            plain.hmac_sha256_verify(Some(&hk), In::from(&msg), In::from(&tag)),
            expect_in(state, [true, true, false]),
        );

        // wrap, as the kek: ok, KEY_STATE, KEY_STATE.
        let kek = key_in_state(plain, AES, state, made)?;
        let key = ks::generate(plain, HMAC, &unique_label("table-wrapped"))?;
        made.push(key);
        let row = format!("wrap, kek {sn}, ACTIVE HMAC key");
        let want = expect_in(state, [true, false, false]);
        let mut blob = prefill_array::<40>();
        if r.status(
            lib,
            &row,
            plain.wrap(Some(&kek), Some(&key), Some(&mut blob)),
            want,
        ) && want != EKI_OK
        {
            r.zeroed(lib, &row, "out", &blob);
        }

        // wrap, as the key being wrapped: ok, ok, KEY_STATE (AES and HMAC keys).
        let active_kek = ks::generate(plain, AES, &unique_label("table-kek"))?;
        made.push(active_kek);
        for alg in [AES, HMAC] {
            let key = key_in_state(plain, alg, state, made)?;
            let row = format!("wrap, ACTIVE kek, {} key {sn}", alg_name(alg));
            let want = expect_in(state, [true, true, false]);
            let mut blob = prefill_array::<40>();
            if r.status(
                lib,
                &row,
                plain.wrap(Some(&active_kek), Some(&key), Some(&mut blob)),
                want,
            ) && want != EKI_OK
            {
                r.zeroed(lib, &row, "out", &blob);
            }
        }

        // unwrap, as the kek: ok, ok, KEY_STATE. The blob is made while the kek is ACTIVE.
        let kek = ks::generate(plain, AES, &unique_label("table-unwrap-kek"))?;
        made.push(kek);
        let wrapped = ks::generate(plain, HMAC, &unique_label("table-unwrap-src"))?;
        made.push(wrapped);
        let blob = ks::wrap(plain, &kek, &wrapped)?;
        let reference = ks::hmac(plain, &wrapped, &msg)?;
        set_state(plain, &kek, state, made)?;
        let new_id = ks::fresh_id();
        made.push(new_id);
        let row = format!("unwrap, kek {sn}");
        let want = expect_in(state, [true, true, false]);
        let label = unique_label("table-unwrapped");
        let s = plain.unwrap(
            Some(&kek),
            In::from(&blob),
            HMAC,
            Some(&label),
            Some(&new_id),
        );
        if r.status(lib, &row, s, want) {
            if want == EKI_OK {
                let i = info_v2(plain, &new_id)?;
                r.check(i.state == ACTIVE && i.alg == HMAC, || {
                    format!("{}: {row}: the unwrapped key is {i:?}", lib.name())
                });
                let h = ks::hmac(plain, &new_id, &msg)?;
                r.bytes(lib, &row, "HMAC of the unwrapped key", &h, &reference);
            } else {
                let s = plain.get_info(Some(&new_id), Some(&mut prefill_key_info()));
                r.status(
                    lib,
                    &format!("{row}: no key created"),
                    s,
                    EKI_ERR_KEY_NOT_FOUND,
                );
            }
        }

        // rotate, as the old key: ok, KEY_STATE, KEY_STATE (every key type).
        for alg in [AES, HMAC, EC] {
            let label = unique_label("table-rotate");
            let old = ks::generate(plain, alg, &label)?;
            made.push(old);
            set_state(plain, &old, state, made)?;
            let row = format!("rotate, {} key {sn}", alg_name(alg));
            let want = expect_in(state, [true, false, false]);
            let mut new_id = prefill_key_id();
            let s = plain.rotate(Some(&old), Some(&mut new_id));
            if s == EKI_OK {
                made.push(new_id);
            }
            if !r.status(lib, &row, s, want) {
                continue;
            }
            if want != EKI_OK {
                r.zeroed(lib, &row, "new_id_out", &new_id.bytes);
                continue;
            }
            r.check(new_id != old, || {
                format!("{}: {row}: the new id equals the old one", lib.name())
            });
            let new_info = info_v2(plain, &new_id)?;
            r.check(
                new_info.alg == alg
                    && new_info.state == ACTIVE
                    && label_is(&new_info.label, &label),
                || format!("{}: {row}: the new key is {new_info:?}", lib.name()),
            );
            let old_info = info_v2(plain, &old)?;
            r.check(old_info.state == RETIRED, || {
                format!("{}: {row}: the old key is {old_info:?}", lib.name())
            });
        }
    }
    Ok(())
}

/// True when the NUL-padded `label` holds exactly the text of `want`.
pub fn label_is(label: &[u8; 65], want: &CString) -> bool {
    let text = want.as_bytes();
    text.len() <= 64 && label[..text.len()] == *text && is_zero(&label[text.len()..])
}
