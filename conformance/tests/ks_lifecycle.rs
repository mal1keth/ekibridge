//! Key lifecycle and dual control of destroy (ABI 2 contract §3, §4, §6, §7) on the software
//! backend of both libraries: the state table, the position of the state check in each
//! validation sequence, the `eki_ks_open_v2` rows, the NULL rows of the nine ABI 2 functions and
//! dual control with approver keys held in a software store of the other library.
//!
//! Every expected status comes from the contract, so a row that passes in both libraries also
//! gives the same status in both. The audit log has its own module (`audit`); the PKCS#11 rows
//! are in `ks_pkcs11_lifecycle`.

mod common;

use std::ptr::NonNull;

use common::ks::{self, Flow, run};
use common::lifecycle::{
    self as lc, Approvers, approval_message, approve, destroy_request, info_v2, key_in_state,
    off_curve, open_v2, set_state,
};
use common::{Report, cstr, unique_label};
use ekicore_conformance::sel::{
    KEY_AES_256 as AES, KEY_ECDSA_P256 as EC, KEY_HMAC_SHA256 as HMAC, KEY_STATE_ACTIVE as ACTIVE,
    KEY_STATE_RETIRED as RETIRED, KEY_STATE_REVOKED as REVOKED, KS_PKCS11,
};
use ekicore_conformance::status::*;
use ekicore_conformance::{
    In, KeyInfoV2, KsConfig, KsConfigV2, Lib, PREFILL_U32, PREFILL_U64, Store, eki_key_id, eki_ks,
    prefill_array, prefill_key_id, prefill_key_info, prefill_key_info_v2,
};

/// The state table of §3 on two kinds of plain handle (`eki_ks_open`, and `eki_ks_open_v2`
/// without log or approvers), with a dual-control handle for the `destroy_request` row.
#[test]
fn state_table() {
    let Some((a, b)) = common::setup("ks_lifecycle::state_table") else {
        return;
    };
    run("ks_lifecycle::state_table", |r| {
        for lib in [a, b] {
            let approvers = Approvers::new(lib, 2)?;
            let dual = open_v2(lib, &KsConfigV2::software().with_approvers(&approvers.keys))?;
            let mut made = Vec::new();
            let plain = ks::open(lib, &KsConfig::software())?;
            lc::state_table_rows(r, &plain, &dual, &mut made)?;
            let plain_v2 = open_v2(lib, &KsConfigV2::software())?;
            lc::state_table_rows(r, &plain_v2, &dual, &mut made)?;
        }
        Ok(())
    });
}

/// The state check comes after the existence and type checks of the same key and before every
/// later check (§3, the per-function sequences), plus the rotate, revoke and get_info_v2 rows of
/// §7. Uses an `eki_ks_open` handle, to which the state rules apply as well (§1).
#[test]
fn state_check_order() {
    let Some((a, b)) = common::setup("ks_lifecycle::state_check_order") else {
        return;
    };
    run("ks_lifecycle::state_check_order", |r| {
        for lib in [a, b] {
            let st = ks::open(lib, &KsConfig::software())?;
            order_rows(r, lib, &st)?;
        }
        Ok(())
    });
}

fn order_rows(r: &mut Report, lib: &Lib, st: &Store) -> Flow<()> {
    let mut made = Vec::new();
    let msg = b"order message".to_vec();
    let missing = ks::fresh_id();

    // sign, get_public_key, hmac: missing, wrong type, state.
    let retired_aes = key_in_state(st, AES, RETIRED, &mut made)?;
    let revoked_hmac = key_in_state(st, HMAC, REVOKED, &mut made)?;
    let revoked_ec = key_in_state(st, EC, REVOKED, &mut made)?;
    let retired_ec = key_in_state(st, EC, RETIRED, &mut made)?;
    let mut sig = prefill_array::<64>();
    let s = st.sign(Some(&retired_aes), In::from(&msg), Some(&mut sig));
    if r.status(
        lib,
        "sign, RETIRED AES key (type before state)",
        s,
        EKI_ERR_WRONG_KEY_TYPE,
    ) {
        r.zeroed(lib, "sign, RETIRED AES key", "sig_out", &sig);
    }
    let s = st.sign(Some(&missing), In::from(&msg), Some(&mut prefill_array()));
    r.status(lib, "sign, missing key", s, EKI_ERR_KEY_NOT_FOUND);
    let mut pk = prefill_array::<65>();
    let s = st.get_public_key(Some(&revoked_hmac), Some(&mut pk));
    if r.status(
        lib,
        "get_public_key, REVOKED HMAC key (type before state)",
        s,
        EKI_ERR_WRONG_KEY_TYPE,
    ) {
        r.zeroed(lib, "get_public_key, REVOKED HMAC key", "out", &pk);
    }
    let s = st.get_public_key(Some(&retired_ec), Some(&mut prefill_array()));
    r.status(lib, "get_public_key, RETIRED key", s, EKI_OK);
    let mut pk = prefill_array::<65>();
    let s = st.get_public_key(Some(&revoked_ec), Some(&mut pk));
    if r.status(lib, "get_public_key, REVOKED key", s, EKI_ERR_KEY_STATE) {
        r.zeroed(lib, "get_public_key, REVOKED key", "out", &pk);
    }
    let s = st.hmac_sha256(
        Some(&revoked_ec),
        In::from(&msg),
        Some(&mut prefill_array()),
    );
    r.status(
        lib,
        "hmac_sha256, REVOKED ECDSA key (type before state)",
        s,
        EKI_ERR_WRONG_KEY_TYPE,
    );
    for (row, id) in [
        ("sign, RETIRED key", &retired_ec),
        ("sign, REVOKED key", &revoked_ec),
    ] {
        let mut sig = prefill_array::<64>();
        if r.status(
            lib,
            row,
            st.sign(Some(id), In::from(&msg), Some(&mut sig)),
            EKI_ERR_KEY_STATE,
        ) {
            r.zeroed(lib, row, "sig_out", &sig);
        }
    }

    // hmac_sha256_verify: tag_len, missing, not HMAC, state, mismatch.
    let active = ks::generate(st, HMAC, &unique_label("order-hmac"))?;
    made.push(active);
    let retired = ks::generate(st, HMAC, &unique_label("order-hmac-r"))?;
    made.push(retired);
    let revoked = ks::generate(st, HMAC, &unique_label("order-hmac-v"))?;
    made.push(revoked);
    let tag_active = ks::hmac(st, &active, &msg)?;
    let tag_empty = ks::hmac(st, &active, b"")?;
    let tag_retired = ks::hmac(st, &retired, &msg)?;
    let tag_revoked = ks::hmac(st, &revoked, &msg)?;
    set_state(st, &retired, RETIRED, &mut made)?;
    set_state(st, &revoked, REVOKED, &mut made)?;
    let mut wrong = tag_active;
    wrong[0] ^= 0x01;
    let short = &tag_active[..31];
    let long = [tag_active.as_slice(), &[0]].concat();
    let rows: [(&str, &eki_key_id, In, i32); 13] = [
        (
            "tag_len 31",
            &active,
            In::Bytes(short),
            EKI_ERR_INVALID_ARGUMENT,
        ),
        (
            "tag_len 33",
            &active,
            In::from(&long),
            EKI_ERR_INVALID_ARGUMENT,
        ),
        (
            "tag NULL, tag_len 0",
            &active,
            In::NULL,
            EKI_ERR_INVALID_ARGUMENT,
        ),
        (
            "tag_len 31, REVOKED key (length before state)",
            &revoked,
            In::Bytes(short),
            EKI_ERR_INVALID_ARGUMENT,
        ),
        (
            "tag_len 31, missing key (length before existence)",
            &missing,
            In::Bytes(short),
            EKI_ERR_INVALID_ARGUMENT,
        ),
        (
            "missing key",
            &missing,
            In::from(&tag_active),
            EKI_ERR_KEY_NOT_FOUND,
        ),
        (
            "AES key",
            &retired_aes,
            In::from(&tag_active),
            EKI_ERR_WRONG_KEY_TYPE,
        ),
        (
            "REVOKED ECDSA key (type before state)",
            &revoked_ec,
            In::from(&tag_active),
            EKI_ERR_WRONG_KEY_TYPE,
        ),
        (
            "REVOKED key, right tag",
            &revoked,
            In::from(&tag_revoked),
            EKI_ERR_KEY_STATE,
        ),
        (
            "REVOKED key, wrong tag (state before comparison)",
            &revoked,
            In::from(&wrong),
            EKI_ERR_KEY_STATE,
        ),
        (
            "ACTIVE key, wrong tag",
            &active,
            In::from(&wrong),
            EKI_ERR_AUTH_FAILED,
        ),
        (
            "RETIRED key, wrong tag",
            &retired,
            In::from(&wrong),
            EKI_ERR_AUTH_FAILED,
        ),
        (
            "RETIRED key, right tag",
            &retired,
            In::from(&tag_retired),
            EKI_OK,
        ),
    ];
    for (row, id, tag, want) in rows {
        let s = st.hmac_sha256_verify(Some(id), In::from(&msg), tag);
        r.status(lib, &format!("hmac_sha256_verify, {row}"), s, want);
    }
    let s = st.hmac_sha256_verify(Some(&active), In::from(&msg), In::from(&tag_active));
    r.status(lib, "hmac_sha256_verify, ACTIVE key, right tag", s, EKI_OK);
    let s = st.hmac_sha256_verify(Some(&active), In::NULL, In::from(&tag_empty));
    r.status(lib, "hmac_sha256_verify, msg NULL, msg_len 0", s, EKI_OK);

    // wrap: kek exists, key exists, kek AES-256, key AES-256 or HMAC, kek state, key state.
    let active_kek = ks::generate(st, AES, &unique_label("order-kek"))?;
    made.push(active_kek);
    let retired_kek = key_in_state(st, AES, RETIRED, &mut made)?;
    let revoked_key = key_in_state(st, HMAC, REVOKED, &mut made)?;
    let retired_key = key_in_state(st, HMAC, RETIRED, &mut made)?;
    let rows: [(&str, &eki_key_id, &eki_key_id, i32); 8] = [
        (
            "RETIRED kek, missing key (existence before state)",
            &retired_kek,
            &missing,
            EKI_ERR_KEY_NOT_FOUND,
        ),
        (
            "missing kek, REVOKED key",
            &missing,
            &revoked_key,
            EKI_ERR_KEY_NOT_FOUND,
        ),
        (
            "RETIRED kek, ECDSA key (type before state)",
            &retired_kek,
            &retired_ec,
            EKI_ERR_WRONG_KEY_TYPE,
        ),
        (
            "REVOKED HMAC key as kek (type before state)",
            &revoked_hmac,
            &active,
            EKI_ERR_WRONG_KEY_TYPE,
        ),
        (
            "ACTIVE kek, REVOKED ECDSA key (type before state)",
            &active_kek,
            &revoked_ec,
            EKI_ERR_WRONG_KEY_TYPE,
        ),
        ("RETIRED kek", &retired_kek, &active, EKI_ERR_KEY_STATE),
        (
            "RETIRED kek, REVOKED key",
            &retired_kek,
            &revoked_key,
            EKI_ERR_KEY_STATE,
        ),
        (
            "RETIRED key under an ACTIVE kek",
            &active_kek,
            &retired_key,
            EKI_OK,
        ),
    ];
    for (row, kek, key, want) in rows {
        let mut blob = prefill_array::<40>();
        let row = format!("wrap, {row}");
        if r.status(
            lib,
            &row,
            st.wrap(Some(kek), Some(key), Some(&mut blob)),
            want,
        ) && want != EKI_OK
        {
            r.zeroed(lib, &row, "out", &blob);
        }
    }
    let s = st.wrap(
        Some(&active_kek),
        Some(&revoked_key),
        Some(&mut prefill_array()),
    );
    r.status(
        lib,
        "wrap, REVOKED key under an ACTIVE kek",
        s,
        EKI_ERR_KEY_STATE,
    );

    // unwrap: the ABI 1 sequence with the kek state after "kek is AES-256".
    let kek_r = ks::generate(st, AES, &unique_label("order-kek-r"))?;
    made.push(kek_r);
    let kek_v = ks::generate(st, AES, &unique_label("order-kek-v"))?;
    made.push(kek_v);
    let src = ks::generate(st, HMAC, &unique_label("order-src"))?;
    made.push(src);
    let blob_r = ks::wrap(st, &kek_r, &src)?;
    let blob_v = ks::wrap(st, &kek_v, &src)?;
    set_state(st, &kek_r, RETIRED, &mut made)?;
    set_state(st, &kek_v, REVOKED, &mut made)?;
    let mut flipped_r = blob_r;
    flipped_r[20] ^= 0x01;
    let mut flipped_v = blob_v;
    flipped_v[20] ^= 0x01;
    let fresh = ks::fresh_id();
    let label = unique_label("order-unwrapped");
    let bad_label = cstr("bad\u{1}label");
    let rows: [(&str, &eki_key_id, In, &std::ffi::CString, &eki_key_id, i32); 10] = [
        (
            "REVOKED kek, blob_len 39 (format before state)",
            &kek_v,
            In::Bytes(&blob_v[..39]),
            &label,
            &fresh,
            EKI_ERR_INVALID_ARGUMENT,
        ),
        (
            "REVOKED kek, bad label",
            &kek_v,
            In::from(&blob_v),
            &bad_label,
            &fresh,
            EKI_ERR_INVALID_ARGUMENT,
        ),
        (
            "missing kek",
            &missing,
            In::from(&blob_v),
            &label,
            &fresh,
            EKI_ERR_KEY_NOT_FOUND,
        ),
        (
            "REVOKED HMAC key as kek (type before state)",
            &revoked_hmac,
            In::from(&blob_v),
            &label,
            &fresh,
            EKI_ERR_WRONG_KEY_TYPE,
        ),
        (
            "REVOKED kek, id in use (state before id check)",
            &kek_v,
            In::from(&blob_v),
            &label,
            &src,
            EKI_ERR_KEY_STATE,
        ),
        (
            "REVOKED kek, blob byte flipped (state before integrity)",
            &kek_v,
            In::from(&flipped_v),
            &label,
            &fresh,
            EKI_ERR_KEY_STATE,
        ),
        (
            "REVOKED kek",
            &kek_v,
            In::from(&blob_v),
            &label,
            &fresh,
            EKI_ERR_KEY_STATE,
        ),
        (
            "RETIRED kek, id in use",
            &kek_r,
            In::from(&blob_r),
            &label,
            &src,
            EKI_ERR_KEY_EXISTS,
        ),
        (
            "RETIRED kek, blob byte flipped",
            &kek_r,
            In::from(&flipped_r),
            &label,
            &fresh,
            EKI_ERR_AUTH_FAILED,
        ),
        (
            "RETIRED kek",
            &kek_r,
            In::from(&blob_r),
            &label,
            &fresh,
            EKI_OK,
        ),
    ];
    for (row, kek, blob, label, id, want) in rows {
        let s = st.unwrap(Some(kek), blob, HMAC, Some(label), Some(id));
        r.status(lib, &format!("unwrap, {row}"), s, want);
    }
    made.push(fresh);
    let i = info_v2(st, &fresh)?;
    r.check(i.state == ACTIVE && i.alg == HMAC, || {
        format!("{}: unwrap under a RETIRED kek made {i:?}", lib.name())
    });
    r.bytes(
        lib,
        "unwrap under a RETIRED kek",
        "HMAC of the unwrapped key",
        &ks::hmac(st, &fresh, &msg)?,
        &ks::hmac(st, &src, &msg)?,
    );

    // rotate: missing, old ACTIVE.
    for (row, id, want) in [
        ("missing key", &missing, EKI_ERR_KEY_NOT_FOUND),
        ("RETIRED key", &retired_aes, EKI_ERR_KEY_STATE),
        ("REVOKED key", &revoked_ec, EKI_ERR_KEY_STATE),
    ] {
        let mut new_id = prefill_key_id();
        let row = format!("rotate, {row}");
        if r.status(lib, &row, st.rotate(Some(id), Some(&mut new_id)), want) {
            r.zeroed(lib, &row, "new_id_out", &new_id.bytes);
        }
    }
    // The new key of a rotation can itself be rotated; the HMAC key it holds is a new key.
    let first = ks::generate(st, HMAC, &unique_label("order-chain"))?;
    made.push(first);
    let h0 = ks::hmac(st, &first, &msg)?;
    let second = lc::rotate(st, &first)?;
    made.push(second);
    let third = lc::rotate(st, &second)?;
    made.push(third);
    r.check(first != second && second != third && first != third, || {
        format!("{}: rotate chain repeated an id", lib.name())
    });
    let h1 = ks::hmac(st, &third, &msg)?;
    r.check(h0 != h1, || {
        format!(
            "{}: the key made by rotate computes the old key's HMAC",
            lib.name()
        )
    });

    // revoke: exists; idempotent; no transition leads back.
    let s = st.revoke(Some(&missing));
    r.status(lib, "revoke, missing key", s, EKI_ERR_KEY_NOT_FOUND);
    r.status(
        lib,
        "revoke, REVOKED key",
        st.revoke(Some(&revoked)),
        EKI_OK,
    );
    r.status(lib, "revoke, RETIRED key", st.revoke(Some(&first)), EKI_OK);
    for (row, id) in [
        ("REVOKED twice", &revoked),
        ("RETIRED, then REVOKED", &first),
    ] {
        let i = info_v2(st, id)?;
        r.check(i.state == REVOKED, || {
            format!("{}: get_info_v2 after revoke ({row}): {i:?}", lib.name())
        });
    }
    let s = st.rotate(Some(&first), Some(&mut prefill_key_id()));
    r.status(lib, "rotate after revoke", s, EKI_ERR_KEY_STATE);

    // get_info_v2 of a missing key.
    let mut info = prefill_key_info_v2();
    let s = st.get_info_v2(Some(&missing), Some(&mut info));
    if r.status(lib, "get_info_v2, missing key", s, EKI_ERR_KEY_NOT_FOUND) {
        r.check(KeyInfoV2::from_raw(&info).is_zero(), || {
            format!(
                "{}: get_info_v2, missing key: info_out not zero-filled",
                lib.name()
            )
        });
    }
    Ok(())
}

/// Step 1 of every ABI 2 function: each pointer parameter NULL in turn, with the outputs
/// zero-filled; and a NULL pointer beats a bad selector, length or key. These rows hold for a
/// placeholder that checks its pointers too.
#[test]
fn null_pointer_rows() {
    let Some((a, b)) = common::setup("ks_lifecycle::null_pointer_rows") else {
        return;
    };
    run("ks_lifecycle::null_pointer_rows", |r| {
        for lib in [a, b] {
            let st = ks::open(lib, &KsConfig::software())?;
            let null = lib.null_store();
            let id = ks::generate(&st, HMAC, &unique_label("null"))?;
            let missing = ks::fresh_id();
            let msg = b"msg".to_vec();
            let tag = [0u8; 32];
            let request = [7u8; 32];
            let pk = [4u8; 65];
            let sig = [1u8; 64];

            // eki_ks_open_v2
            let cfg = KsConfigV2::software();
            let bad = KsConfigV2 {
                backend: 99,
                ..KsConfigV2::default()
            };
            open_v2_row(
                r,
                lib,
                "open_v2 config NULL",
                None,
                true,
                EKI_ERR_NULL_POINTER,
            );
            open_v2_row(
                r,
                lib,
                "open_v2 out NULL",
                Some(&cfg),
                false,
                EKI_ERR_NULL_POINTER,
            );
            open_v2_row(
                r,
                lib,
                "open_v2 config NULL, out NULL",
                None,
                false,
                EKI_ERR_NULL_POINTER,
            );
            open_v2_row(
                r,
                lib,
                "open_v2 backend 99, out NULL (NULL before selector)",
                Some(&bad),
                false,
                EKI_ERR_NULL_POINTER,
            );

            // eki_ks_get_info_v2
            for (row, s, i, with_out) in [
                ("get_info_v2 ks NULL", &null, Some(&id), true),
                ("get_info_v2 id NULL", &st, None, true),
                ("get_info_v2 info_out NULL", &st, Some(&id), false),
            ] {
                let mut info = prefill_key_info_v2();
                let got = s.get_info_v2(i, with_out.then_some(&mut info));
                if r.status(lib, row, got, EKI_ERR_NULL_POINTER) && with_out {
                    r.check(KeyInfoV2::from_raw(&info).is_zero(), || {
                        format!("{}: {row}: info_out not zero-filled", lib.name())
                    });
                }
            }
            let s = st.get_info_v2(Some(&missing), None);
            r.status(
                lib,
                "get_info_v2 missing key, info_out NULL (NULL before store state)",
                s,
                EKI_ERR_NULL_POINTER,
            );

            // eki_ks_rotate
            for (row, s, i, with_out) in [
                ("rotate ks NULL", &null, Some(&id), true),
                ("rotate old_id NULL", &st, None, true),
                ("rotate new_id_out NULL", &st, Some(&id), false),
            ] {
                let mut new_id = prefill_key_id();
                let got = s.rotate(i, with_out.then_some(&mut new_id));
                if r.status(lib, row, got, EKI_ERR_NULL_POINTER) && with_out {
                    r.zeroed(lib, row, "new_id_out", &new_id.bytes);
                }
            }

            // eki_ks_revoke
            r.status(
                lib,
                "revoke ks NULL",
                null.revoke(Some(&id)),
                EKI_ERR_NULL_POINTER,
            );
            r.status(lib, "revoke id NULL", st.revoke(None), EKI_ERR_NULL_POINTER);

            // eki_ks_hmac_sha256_verify
            for (row, s, i, m, t) in [
                ("ks NULL", &null, Some(&id), In::from(&msg), In::from(&tag)),
                ("id NULL", &st, None, In::from(&msg), In::from(&tag)),
                (
                    "msg NULL, msg_len 4",
                    &st,
                    Some(&id),
                    In::Null { len: 4 },
                    In::from(&tag),
                ),
                (
                    "tag NULL, tag_len 32",
                    &st,
                    Some(&id),
                    In::from(&msg),
                    In::Null { len: 32 },
                ),
                (
                    "tag NULL, tag_len 31 (NULL before length)",
                    &st,
                    Some(&id),
                    In::from(&msg),
                    In::Null { len: 31 },
                ),
                (
                    "id NULL, tag_len 31",
                    &st,
                    None,
                    In::from(&msg),
                    In::Bytes(&tag[..31]),
                ),
            ] {
                let got = s.hmac_sha256_verify(i, m, t);
                r.status(
                    lib,
                    &format!("ks_hmac_sha256_verify {row}"),
                    got,
                    EKI_ERR_NULL_POINTER,
                );
            }

            // eki_ks_destroy_request
            for (row, s, i, with_out) in [
                ("destroy_request ks NULL", &null, Some(&id), true),
                ("destroy_request id NULL", &st, None, true),
                ("destroy_request request_out NULL", &st, Some(&id), false),
            ] {
                let mut out = prefill_array::<32>();
                let got = s.destroy_request(i, with_out.then_some(&mut out));
                if r.status(lib, row, got, EKI_ERR_NULL_POINTER) && with_out {
                    r.zeroed(lib, row, "request_out", &out);
                }
            }

            // eki_ks_destroy_approve
            type ApproveRow<'x> = (
                &'static str,
                &'x Store<'x>,
                Option<&'x [u8; 32]>,
                Option<&'x [u8; 65]>,
                Option<&'x [u8; 64]>,
                bool,
            );
            let rows: [ApproveRow; 5] = [
                (
                    "destroy_approve ks NULL",
                    &null,
                    Some(&request),
                    Some(&pk),
                    Some(&sig),
                    true,
                ),
                (
                    "destroy_approve request NULL",
                    &st,
                    None,
                    Some(&pk),
                    Some(&sig),
                    true,
                ),
                (
                    "destroy_approve approver_public_key NULL",
                    &st,
                    Some(&request),
                    None,
                    Some(&sig),
                    true,
                ),
                (
                    "destroy_approve sig NULL",
                    &st,
                    Some(&request),
                    Some(&pk),
                    None,
                    true,
                ),
                (
                    "destroy_approve remaining_out NULL",
                    &st,
                    Some(&request),
                    Some(&pk),
                    Some(&sig),
                    false,
                ),
            ];
            for (row, s, q, k, g, with_out) in rows {
                let mut remaining = PREFILL_U32;
                let got = s.destroy_approve(q, k, g, with_out.then_some(&mut remaining));
                if r.status(lib, row, got, EKI_ERR_NULL_POINTER) && with_out {
                    r.check(remaining == 0, || {
                        format!("{}: {row}: remaining_out = {remaining:#x}", lib.name())
                    });
                }
            }

            // eki_ks_audit_head
            for (row, s, with_hash, with_seq) in [
                ("audit_head ks NULL", &null, true, true),
                ("audit_head hash_out NULL", &st, false, true),
                ("audit_head seq_out NULL", &st, true, false),
            ] {
                let mut hash = prefill_array::<32>();
                let mut seq = PREFILL_U64;
                let got =
                    s.audit_head(with_hash.then_some(&mut hash), with_seq.then_some(&mut seq));
                if r.status(lib, row, got, EKI_ERR_NULL_POINTER) {
                    if with_hash {
                        r.zeroed(lib, row, "hash_out", &hash);
                    }
                    if with_seq {
                        r.check(seq == 0, || {
                            format!("{}: {row}: seq_out = {seq:#x}", lib.name())
                        });
                    }
                }
            }

            // eki_audit_verify (expected_head may be NULL; it is not a NULL row).
            let path = cstr("/nonexistent/ekibridge-audit.log");
            let head = [0u8; 32];
            for (row, p, h, with_out) in [
                ("audit_verify path NULL", None, Some(&head), true),
                (
                    "audit_verify path NULL, expected_head NULL",
                    None,
                    None,
                    true,
                ),
                (
                    "audit_verify records_out NULL",
                    Some(path.as_c_str()),
                    None,
                    false,
                ),
            ] {
                let mut records = PREFILL_U64;
                let got = lib.audit_verify(p, h, with_out.then_some(&mut records));
                if r.status(lib, row, got, EKI_ERR_NULL_POINTER) && with_out {
                    r.check(records == 0, || {
                        format!("{}: {row}: records_out = {records:#x}", lib.name())
                    });
                }
            }
            ks::destroy(&st, &id)?;
        }
        Ok(())
    });
}

/// Calls `eki_ks_open_v2` with `*out` pre-set to a non-NULL sentinel; checks the status and that
/// a failure leaves `*out == NULL`. A handle returned on success is closed.
fn open_v2_row(
    r: &mut Report,
    lib: &Lib,
    row: &str,
    cfg: Option<&KsConfigV2>,
    with_out: bool,
    want: i32,
) {
    let raw_cfg = cfg.map(KsConfigV2::as_raw);
    let sentinel = NonNull::<eki_ks>::dangling().as_ptr();
    let mut out = sentinel;
    let s = lib.ks_open_v2_raw(raw_cfg.as_ref(), with_out.then_some(&mut out));
    if r.status(lib, row, s, want) && with_out && want != EKI_OK {
        r.check(out.is_null(), || {
            format!("{}: {row}: *out is {out:?}, want NULL", lib.name())
        });
    }
    if s == EKI_OK && with_out && !out.is_null() && out != sentinel {
        // SAFETY: the library just returned this handle from eki_ks_open_v2 and nothing else
        // owns it.
        drop(unsafe { lib.adopt(out) });
    }
}

/// The `eki_ks_open_v2` rows of §4 and §7 that need no file: selectors, the approver fields, the
/// audit path length and the order of NULL and format checks across fields.
#[test]
fn open_v2_error_matrix() {
    let Some((a, b)) = common::setup("ks_lifecycle::open_v2_error_matrix") else {
        return;
    };
    run("ks_lifecycle::open_v2_error_matrix", |r| {
        for lib in [a, b] {
            let approvers = Approvers::new(lib, 9)?;
            let keys = &approvers.keys;
            let sw = KsConfigV2::software();
            let with_keys = |count: usize, bytes: Vec<u8>| KsConfigV2 {
                approver_public_keys: Some(bytes),
                approver_count: count,
                ..KsConfigV2::software()
            };
            let null_keys = |count: usize| KsConfigV2 {
                approver_public_keys: None,
                approver_count: count,
                ..KsConfigV2::software()
            };
            let mut compressed = keys[1];
            compressed[0] = 0x02;
            let path = |p: &str| Some(cstr(p));
            let long_path = format!("/{}", "a".repeat(4096));
            let max_path = format!("/nonexistent-ekibridge/{}", "a".repeat(4096 - 23));
            assert_eq!(max_path.len(), 4096, "harness: path of the maximum length");
            let nomod = "/nonexistent/ekibridge-test-module.so";
            let p11 = |m: Option<&str>, l: Option<&str>, p: Option<&str>| KsConfigV2 {
                backend: KS_PKCS11,
                module_path: m.map(cstr),
                token_label: l.map(cstr),
                user_pin: p.map(cstr),
                ..KsConfigV2::default()
            };
            let rows: Vec<(&str, KsConfigV2, i32)> = vec![
                ("software, no log, no approvers", sw.clone(), EKI_OK),
                (
                    "backend 0",
                    KsConfigV2 {
                        backend: 0,
                        ..sw.clone()
                    },
                    EKI_ERR_INVALID_ARGUMENT,
                ),
                (
                    "backend 99",
                    KsConfigV2 {
                        backend: 99,
                        ..sw.clone()
                    },
                    EKI_ERR_INVALID_ARGUMENT,
                ),
                (
                    "approver_count 1",
                    with_keys(1, keys[..1].concat()),
                    EKI_ERR_INVALID_ARGUMENT,
                ),
                (
                    "approver_count 9",
                    with_keys(9, keys[..9].concat()),
                    EKI_ERR_INVALID_ARGUMENT,
                ),
                (
                    "duplicate approver",
                    with_keys(2, [keys[0], keys[0]].concat()),
                    EKI_ERR_INVALID_ARGUMENT,
                ),
                (
                    "approver off the curve",
                    with_keys(2, [keys[0], off_curve(&keys[1])].concat()),
                    EKI_ERR_INVALID_ARGUMENT,
                ),
                (
                    "approver with prefix 0x02",
                    with_keys(2, [keys[0], compressed].concat()),
                    EKI_ERR_INVALID_ARGUMENT,
                ),
                (
                    "approver all zero",
                    with_keys(2, [keys[0], [0u8; 65]].concat()),
                    EKI_ERR_INVALID_ARGUMENT,
                ),
                (
                    "approver_count 2, approver_public_keys NULL",
                    null_keys(2),
                    EKI_ERR_NULL_POINTER,
                ),
                (
                    "approver_count 1, approver_public_keys NULL (NULL before format)",
                    null_keys(1),
                    EKI_ERR_NULL_POINTER,
                ),
                (
                    "approver_count 9, approver_public_keys NULL (NULL before format)",
                    null_keys(9),
                    EKI_ERR_NULL_POINTER,
                ),
                (
                    "approver_count 0, approver_public_keys NULL",
                    null_keys(0),
                    EKI_OK,
                ),
                (
                    "approver_count 0, approver_public_keys not NULL (not read)",
                    with_keys(0, vec![0xEE; 65]),
                    EKI_OK,
                ),
                (
                    "two approvers",
                    KsConfigV2::software().with_approvers(&approvers.first(2)),
                    EKI_OK,
                ),
                (
                    "eight approvers",
                    KsConfigV2::software().with_approvers(&approvers.first(8)),
                    EKI_OK,
                ),
                (
                    "audit_log_path \"\"",
                    KsConfigV2 {
                        audit_log_path: path(""),
                        ..sw.clone()
                    },
                    EKI_ERR_INVALID_ARGUMENT,
                ),
                (
                    "audit_log_path of 4097 bytes",
                    KsConfigV2 {
                        audit_log_path: path(&long_path),
                        ..sw.clone()
                    },
                    EKI_ERR_INVALID_ARGUMENT,
                ),
                (
                    "audit_log_path of 4096 bytes that cannot be created",
                    KsConfigV2 {
                        audit_log_path: path(&max_path),
                        ..sw.clone()
                    },
                    EKI_ERR_BACKEND,
                ),
                (
                    "audit_log_path \"\", approver_count 2, keys NULL (NULL field first)",
                    KsConfigV2 {
                        audit_log_path: path(""),
                        ..null_keys(2)
                    },
                    EKI_ERR_NULL_POINTER,
                ),
                (
                    "audit_log_path \"\", approver off the curve (field order)",
                    KsConfigV2 {
                        audit_log_path: path(""),
                        ..with_keys(2, [keys[0], off_curve(&keys[1])].concat())
                    },
                    EKI_ERR_INVALID_ARGUMENT,
                ),
                (
                    "software with malformed PKCS#11 fields",
                    KsConfigV2 {
                        module_path: path("/nonexistent/module.so"),
                        token_label: path(""),
                        user_pin: path(""),
                        ..KsConfigV2::software().with_approvers(&approvers.first(2))
                    },
                    EKI_OK,
                ),
                (
                    "PKCS#11 module_path NULL, audit_log_path \"\"",
                    KsConfigV2 {
                        audit_log_path: path(""),
                        ..p11(None, Some("ekibridge"), Some("1234"))
                    },
                    EKI_ERR_NULL_POINTER,
                ),
                (
                    "PKCS#11 token_label \"\", approver_count 2, keys NULL (NULL field first)",
                    KsConfigV2 {
                        approver_count: 2,
                        ..p11(Some(nomod), Some(""), Some("1234"))
                    },
                    EKI_ERR_NULL_POINTER,
                ),
                (
                    "PKCS#11 module that does not exist, audit_log_path \"\" (format first)",
                    KsConfigV2 {
                        audit_log_path: path(""),
                        ..p11(Some(nomod), Some("ekibridge"), Some("1234"))
                    },
                    EKI_ERR_INVALID_ARGUMENT,
                ),
                (
                    "PKCS#11 module that does not exist, approver off the curve (format first)",
                    KsConfigV2 {
                        approver_public_keys: Some([keys[0], off_curve(&keys[1])].concat()),
                        approver_count: 2,
                        ..p11(Some(nomod), Some("ekibridge"), Some("1234"))
                    },
                    EKI_ERR_INVALID_ARGUMENT,
                ),
                (
                    "PKCS#11 module that does not exist, valid approvers",
                    KsConfigV2 {
                        approver_public_keys: Some(approvers.first(2).concat()),
                        approver_count: 2,
                        ..p11(Some(nomod), Some("ekibridge"), Some("1234"))
                    },
                    EKI_ERR_BACKEND,
                ),
            ];
            for (row, cfg, want) in &rows {
                open_v2_row(r, lib, row, Some(cfg), true, *want);
            }
        }
        Ok(())
    });
}

/// A handle without approvers: destroy works as in ABI 1, `destroy_request` and
/// `destroy_approve` are UNSUPPORTED before any other check (§6, §7). Run on an `eki_ks_open`
/// handle and on an `eki_ks_open_v2` handle without approvers.
#[test]
fn dual_control_needs_approvers() {
    let Some((a, b)) = common::setup("ks_lifecycle::dual_control_needs_approvers") else {
        return;
    };
    run("ks_lifecycle::dual_control_needs_approvers", |r| {
        for lib in [a, b] {
            let v1 = ks::open(lib, &KsConfig::software())?;
            single_control_rows(r, lib, &v1, "eki_ks_open handle")?;
            let v2 = open_v2(lib, &KsConfigV2::software())?;
            single_control_rows(r, lib, &v2, "eki_ks_open_v2 handle")?;
        }
        Ok(())
    });
}

fn single_control_rows(r: &mut Report, lib: &Lib, st: &Store, kind: &str) -> Flow<()> {
    let id = ks::generate(st, EC, &unique_label("single"))?;
    let pk = ks::public_key(st, &id)?;
    let missing = ks::fresh_id();
    for (row, key) in [("existing key", &id), ("missing key", &missing)] {
        let row = format!("{kind}: destroy_request, {row}");
        let mut out = prefill_array::<32>();
        if r.status(
            lib,
            &row,
            st.destroy_request(Some(key), Some(&mut out)),
            EKI_ERR_UNSUPPORTED,
        ) {
            r.zeroed(lib, &row, "request_out", &out);
        }
    }
    let mut compressed = pk;
    compressed[0] = 0x02;
    for (row, key) in [("valid key", &pk), ("key with prefix 0x02", &compressed)] {
        let row = format!("{kind}: destroy_approve, {row}");
        let mut remaining = PREFILL_U32;
        let s = st.destroy_approve(
            Some(&[3; 32]),
            Some(key),
            Some(&[1; 64]),
            Some(&mut remaining),
        );
        if r.status(lib, &row, s, EKI_ERR_UNSUPPORTED) {
            r.check(remaining == 0, || {
                format!("{}: {row}: remaining_out = {remaining:#x}", lib.name())
            });
        }
    }
    r.status(
        lib,
        &format!("{kind}: destroy without approvers"),
        st.destroy(Some(&id)),
        EKI_OK,
    );
    Ok(())
}

/// Dual control (§6, §7) on a software handle of library `x` whose approver keys live in a
/// software store of the other library `y`, so every approval is signed by `y`'s `eki_ks_sign`
/// and checked by `x`; run in both directions, with two and with three configured approvers.
#[test]
fn dual_control_cross_library() {
    let Some((a, b)) = common::setup("ks_lifecycle::dual_control_cross_library") else {
        return;
    };
    run("ks_lifecycle::dual_control_cross_library", |r| {
        for (x, y) in [(a, b), (b, a)] {
            // Keys 0..3 may be configured; key 3 never is.
            let approvers = Approvers::new(y, 4)?;
            for count in [2, 3] {
                let cfg = KsConfigV2::software().with_approvers(&approvers.first(count));
                let st = open_v2(x, &cfg)?;
                dual_control_rows(r, x, &st, &approvers, count)?;
            }
        }
        Ok(())
    });
}

/// (row, request, approver_public_key, sig, expected status)
type ApprovalRow<'a> = (&'a str, &'a [u8; 32], &'a [u8; 65], &'a [u8; 64], i32);

fn dual_control_rows(
    r: &mut Report,
    lib: &Lib,
    st: &Store,
    ap: &Approvers,
    count: usize,
) -> Flow<()> {
    let ctx = |row: &str| format!("{count} approvers in {}: {row}", ap.lib().name());
    let outsider = 3;
    let missing = ks::fresh_id();

    // destroy needs approvals; a missing key is still KEY_NOT_FOUND.
    let key = ks::generate(st, EC, &unique_label("dual"))?;
    r.status(
        lib,
        &ctx("destroy, existing key"),
        st.destroy(Some(&key)),
        EKI_ERR_APPROVAL_REQUIRED,
    );
    ks::info(st, &key).map_err(|e| format!("{e} (the key must survive APPROVAL_REQUIRED)"))?;
    r.status(
        lib,
        &ctx("destroy, missing key"),
        st.destroy(Some(&missing)),
        EKI_ERR_KEY_NOT_FOUND,
    );
    let mut out = prefill_array::<32>();
    if r.status(
        lib,
        &ctx("destroy_request, missing key"),
        st.destroy_request(Some(&missing), Some(&mut out)),
        EKI_ERR_KEY_NOT_FOUND,
    ) {
        r.zeroed(
            lib,
            &ctx("destroy_request, missing key"),
            "request_out",
            &out,
        );
    }

    // A new request replaces the earlier one.
    let old = destroy_request(st, &key)?;
    let req = destroy_request(st, &key)?;
    r.check(old != req, || {
        format!(
            "{}: {}",
            lib.name(),
            ctx("two requests returned the same bytes")
        )
    });
    let sig_old = ap.sign(0, &old, &key)?;
    let sig0 = ap.sign(0, &req, &key)?;
    let sig1 = ap.sign(1, &req, &key)?;
    let mut compressed = ap.keys[0];
    compressed[0] = 0x02;
    let unknown = [0x5A; 32];
    let sig_unknown = ap.sign(0, &unknown, &key)?;
    let sig_outsider = ap.sign(outsider, &req, &key)?;
    let sig_other_id = ap.sign(0, &req, &missing)?;
    let sig_no_domain = ap.sign_raw(0, &[req.as_slice(), &key.bytes].concat())?;
    let rows: [ApprovalRow; 9] = [
        (
            "replaced request",
            &old,
            &ap.keys[0],
            &sig_old,
            EKI_ERR_KEY_NOT_FOUND,
        ),
        (
            "unknown request",
            &unknown,
            &ap.keys[0],
            &sig_unknown,
            EKI_ERR_KEY_NOT_FOUND,
        ),
        (
            "approver key with prefix 0x02 (format before lookup)",
            &unknown,
            &compressed,
            &sig_unknown,
            EKI_ERR_INVALID_ARGUMENT,
        ),
        (
            "approver key off the curve",
            &req,
            &off_curve(&ap.keys[0]),
            &sig0,
            EKI_ERR_INVALID_ARGUMENT,
        ),
        (
            "signature by a non-approver",
            &req,
            &ap.keys[outsider],
            &sig_outsider,
            EKI_ERR_AUTH_FAILED,
        ),
        (
            "signature over another request",
            &req,
            &ap.keys[0],
            &sig_old,
            EKI_ERR_AUTH_FAILED,
        ),
        (
            "signature by another approver than the key given",
            &req,
            &ap.keys[0],
            &sig1,
            EKI_ERR_AUTH_FAILED,
        ),
        (
            "signature over another key id",
            &req,
            &ap.keys[0],
            &sig_other_id,
            EKI_ERR_AUTH_FAILED,
        ),
        (
            "signature without the domain prefix",
            &req,
            &ap.keys[0],
            &sig_no_domain,
            EKI_ERR_AUTH_FAILED,
        ),
    ];
    for (row, q, k, g, want) in rows {
        let mut remaining = PREFILL_U32;
        let row = ctx(&format!("destroy_approve, {row}"));
        if r.status(
            lib,
            &row,
            st.destroy_approve(Some(q), Some(k), Some(g), Some(&mut remaining)),
            want,
        ) {
            r.check(remaining == 0, || {
                format!("{}: {row}: remaining_out = {remaining:#x}", lib.name())
            });
        }
    }

    // First approval, then the same approver again: OK, one more needed, the key still exists.
    let rem = approve(st, &req, &ap.keys[0], &sig0)?;
    r.check(rem == 1, || {
        format!("{}: {}: remaining {rem}", lib.name(), ctx("first approval"))
    });
    let again = ap.sign(0, &req, &key)?;
    let rem = approve(st, &req, &ap.keys[0], &again)?;
    r.check(rem == 1, || {
        format!(
            "{}: {}: remaining {rem}",
            lib.name(),
            ctx("same approver twice")
        )
    });
    ks::info(st, &key).map_err(|e| format!("{e} (after one approver)"))?;
    r.status(
        lib,
        &ctx("destroy after one approval"),
        st.destroy(Some(&key)),
        EKI_ERR_APPROVAL_REQUIRED,
    );

    // Second distinct approver: OK, remaining 0, key gone, request removed.
    let rem = approve(st, &req, &ap.keys[1], &sig1)?;
    r.check(rem == 0, || {
        format!(
            "{}: {}: remaining {rem}",
            lib.name(),
            ctx("second approver")
        )
    });
    let s = st.get_info(Some(&key), Some(&mut prefill_key_info()));
    r.status(
        lib,
        &ctx("get_info after two approvals"),
        s,
        EKI_ERR_KEY_NOT_FOUND,
    );
    let mut remaining = PREFILL_U32;
    let s = st.destroy_approve(
        Some(&req),
        Some(&ap.keys[1]),
        Some(&sig1),
        Some(&mut remaining),
    );
    r.status(
        lib,
        &ctx("approval of a completed request"),
        s,
        EKI_ERR_KEY_NOT_FOUND,
    );

    // Approvals belong to their request: after a new request for the key, an approval of the
    // replaced one does not count.
    let key2 = ks::generate(st, HMAC, &unique_label("dual-2"))?;
    let first = destroy_request(st, &key2)?;
    let last_approver = count - 1;
    approve(
        st,
        &first,
        &ap.keys[last_approver],
        &ap.sign(last_approver, &first, &key2)?,
    )?;
    let second = destroy_request(st, &key2)?;
    let rem = approve(st, &second, &ap.keys[0], &ap.sign(0, &second, &key2)?)?;
    r.check(rem == 1, || {
        format!(
            "{}: {}: remaining {rem}",
            lib.name(),
            ctx("first approval of a request that replaced an approved one")
        )
    });
    let rem = approve(
        st,
        &second,
        &ap.keys[last_approver],
        &ap.sign(last_approver, &second, &key2)?,
    )?;
    r.check(rem == 0, || {
        format!(
            "{}: {}: remaining {rem}",
            lib.name(),
            ctx("HMAC key, second approver")
        )
    });
    let s = st.get_info(Some(&key2), Some(&mut prefill_key_info()));
    r.status(lib, &ctx("HMAC key gone"), s, EKI_ERR_KEY_NOT_FOUND);

    // The approval message is exactly domain || request || id: the harness's own message,
    // signed by the approver store, was accepted above. Check its length once.
    r.check(approval_message(&req, &key).len() == 68, || {
        "harness: approval message is not 68 bytes".to_owned()
    });
    Ok(())
}
