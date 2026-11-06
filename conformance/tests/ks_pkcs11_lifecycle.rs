//! Key lifecycle and dual control on the PKCS#11 backend (ABI 2 contract §3, §6, §8) against the
//! SoftHSM2 token both libraries share: the state table, a state set through one library seen
//! through the other, and dual control where a key disappears through another handle or a
//! request outlives its handle.
//!
//! Needs `EKI_PKCS11_MODULE`, `EKI_PKCS11_TOKEN_LABEL` and `EKI_PKCS11_PIN`
//! (`source scripts/softhsm-init.sh`); every test skips with a message otherwise. As in
//! `ks_pkcs11`, the two libraries never hold a PKCS#11 store open at the same time, a static
//! mutex serialises the tests, and every store is closed before the test returns. Every key a
//! test creates is destroyed again through a handle without approvers, also when the scenario
//! stops early, so the token is left as it was found.
//!
//! §8 also asks that the token itself refuse what the state forbids. Both libraries check the
//! state before they call the token (§3), so no call through the ABI reaches the token with a
//! forbidden operation; that half is not checkable here. What is checked is the consequence the
//! ABI shows: the state lives in the token, so the other library reads it back.

mod common;

use std::sync::{Mutex, MutexGuard};

use common::Report;
use common::ks::{self, Flow, run};
use common::lifecycle::{
    self as lc, Approvers, approve, destroy_all, destroy_request, info_v2, open_v2, set_state,
};
use common::unique_label;
use ekicore_conformance::sel::{
    KEY_AES_256 as AES, KEY_ECDSA_P256 as EC, KEY_HMAC_SHA256 as HMAC, KEY_STATE_ACTIVE as ACTIVE,
    KEY_STATE_RETIRED as RETIRED, KEY_STATE_REVOKED as REVOKED,
};
use ekicore_conformance::status::*;
use ekicore_conformance::{
    In, KsConfig, KsConfigV2, Lib, PREFILL_U32, eki_key_id, prefill_array, prefill_key_id,
    prefill_key_info,
};

static SERIAL: Mutex<()> = Mutex::new(());

/// The libraries, the token config and the serialisation guard; `None` (after a skip message)
/// when either the libraries or the token are not configured.
fn setup(
    test: &str,
) -> Option<(
    &'static Lib,
    &'static Lib,
    KsConfig,
    MutexGuard<'static, ()>,
)> {
    let (a, b) = common::setup(test)?;
    let Some(cfg) = KsConfig::pkcs11_from_env() else {
        eprintln!(
            "skipping {test}: EKI_PKCS11_MODULE, EKI_PKCS11_TOKEN_LABEL and EKI_PKCS11_PIN are not \
             set (source scripts/softhsm-init.sh, then scripts/run-conformance.sh --with-pkcs11)"
        );
        return None;
    };
    let guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    Some((a, b, cfg, guard))
}

/// Runs `body`, which must close every store it opens before it returns, then destroys every id
/// it recorded in `made` through a fresh handle of `cleaner` without approvers, whether the body
/// finished or stopped early.
fn run_with_cleanup(
    name: &str,
    cleaner: &Lib,
    cfg: &KsConfig,
    body: impl FnOnce(&mut Report, &mut Vec<eki_key_id>) -> Flow<()>,
) {
    run(name, |r| {
        let mut made = Vec::new();
        let result = body(r, &mut made);
        if !made.is_empty() {
            let st = ks::open(cleaner, cfg)?;
            destroy_all(r, &st, &made);
        }
        result
    });
}

/// The state table of §3 on the token, in each library: a plain handle (`eki_ks_open`) and a
/// dual-control handle (`eki_ks_open_v2` with approvers in a software store) on the same token.
#[test]
fn state_table() {
    let Some((a, b, cfg, _guard)) = setup("ks_pkcs11_lifecycle::state_table") else {
        return;
    };
    for lib in [a, b] {
        let name = format!("ks_pkcs11_lifecycle::state_table ({})", lib.name());
        run_with_cleanup(&name, lib, &cfg, |r, made| {
            let approvers = Approvers::new(lib, 2)?;
            let dual = open_v2(
                lib,
                &KsConfigV2::from_v1(&cfg).with_approvers(&approvers.keys),
            )?;
            let plain = ks::open(lib, &cfg)?;
            lc::state_table_rows(r, &plain, &dual, made)
        });
    }
}

/// §8: keys retired or revoked through library x are RETIRED or REVOKED through library y on the
/// same token, y's operations obey those states, the new key of a rotation is ACTIVE with the old
/// key's algorithm and label, and a key y revokes is REVOKED for x. Both directions.
#[test]
fn state_visible_across_libraries() {
    let Some((a, b, cfg, _guard)) = setup("ks_pkcs11_lifecycle::state_visible_across_libraries")
    else {
        return;
    };
    for (x, y) in [(a, b), (b, a)] {
        let name = format!(
            "ks_pkcs11_lifecycle::state_visible_across_libraries ({} -> {})",
            x.name(),
            y.name()
        );
        run_with_cleanup(&name, x, &cfg, |r, made| cross_states(r, x, y, &cfg, made));
    }
}

fn cross_states(
    r: &mut Report,
    x: &Lib,
    y: &Lib,
    cfg: &KsConfig,
    made: &mut Vec<eki_key_id>,
) -> Flow<()> {
    let dir = format!("{} -> {}", x.name(), y.name());
    let msg = b"lifecycle across libraries".to_vec();

    // Phase 1: x creates keys, records reference values while they are ACTIVE, then changes
    // their states.
    let st = ks::open(x, cfg)?;
    let mut make = |alg: i32, tag: &str| -> Flow<eki_key_id> {
        let id = ks::generate(&st, alg, &unique_label(tag))?;
        made.push(id);
        Ok(id)
    };
    let kek_r = make(AES, "x-kek-retired")?;
    let kek_v = make(AES, "x-kek-revoked")?;
    let hk_r = make(HMAC, "x-hmac-retired")?;
    let hk_v = make(HMAC, "x-hmac-revoked")?;
    let ec_r = make(EC, "x-ec-retired")?;
    let ec_v = make(EC, "x-ec-revoked")?;
    let src = make(HMAC, "x-src")?;
    let active_kek = make(AES, "x-kek-active")?;
    let blob_r = ks::wrap(&st, &kek_r, &src)?;
    let blob_v = ks::wrap(&st, &kek_v, &src)?;
    let src_tag = ks::hmac(&st, &src, &msg)?;
    let tag_r = ks::hmac(&st, &hk_r, &msg)?;
    let tag_v = ks::hmac(&st, &hk_v, &msg)?;
    let pk_r = ks::public_key(&st, &ec_r)?;
    let info_hk_r = ks::info(&st, &hk_r)?;
    let mut rotated = Vec::new();
    for id in [&kek_r, &hk_r, &ec_r] {
        let new_id = lc::rotate(&st, id)?;
        made.push(new_id);
        rotated.push((*id, new_id));
    }
    for id in [&kek_v, &hk_v, &ec_v] {
        lc::revoke(&st, id)?;
    }
    drop(st);

    // Phase 2: y sees the states and obeys them.
    let st = ks::open(y, cfg)?;
    for (id, want) in [
        (&kek_r, RETIRED),
        (&hk_r, RETIRED),
        (&ec_r, RETIRED),
        (&kek_v, REVOKED),
        (&hk_v, REVOKED),
        (&ec_v, REVOKED),
        (&src, ACTIVE),
    ] {
        let i = info_v2(&st, id)?;
        r.check(i.state == want, || {
            format!(
                "{dir}: get_info_v2 in {} reports state {} ({}), want {}",
                y.name(),
                i.state,
                lc::state_name(i.state),
                lc::state_name(want)
            )
        });
    }
    for (old, new_id) in &rotated {
        let old_info = info_v2(&st, old)?;
        let new_info = info_v2(&st, new_id)?;
        r.check(
            new_info.state == ACTIVE
                && new_info.alg == old_info.alg
                && new_info.label == old_info.label,
            || format!("{dir}: rotated key {old_info:?} -> {new_info:?}"),
        );
    }
    r.check(info_v2(&st, &hk_r)?.v1() == info_hk_r, || {
        format!("{dir}: alg or label of a retired key changed")
    });

    // RETIRED: verify, public key and unwrap are allowed; sign, hmac, wrap as kek and rotate
    // are not.
    let s = st.hmac_sha256_verify(Some(&hk_r), In::from(&msg), In::from(&tag_r));
    r.status(y, &format!("{dir}: hmac_verify, RETIRED key"), s, EKI_OK);
    let mut pk = prefill_array::<65>();
    let s = st.get_public_key(Some(&ec_r), Some(&mut pk));
    if r.status(y, &format!("{dir}: get_public_key, RETIRED key"), s, EKI_OK) {
        r.bytes(y, &dir, "public key of the RETIRED key", &pk, &pk_r);
    }
    let unwrapped = ks::fresh_id();
    made.push(unwrapped);
    let label = unique_label("y-unwrapped");
    let s = st.unwrap(
        Some(&kek_r),
        In::from(&blob_r),
        HMAC,
        Some(&label),
        Some(&unwrapped),
    );
    if r.status(y, &format!("{dir}: unwrap, RETIRED kek"), s, EKI_OK) {
        let h = ks::hmac(&st, &unwrapped, &msg)?;
        r.bytes(
            y,
            &dir,
            "HMAC of the key unwrapped under a RETIRED kek",
            &h,
            &src_tag,
        );
    }
    let s = st.wrap(Some(&active_kek), Some(&hk_r), Some(&mut prefill_array()));
    r.status(
        y,
        &format!("{dir}: wrap, RETIRED key under an ACTIVE kek"),
        s,
        EKI_OK,
    );
    for (row, s) in [
        (
            "sign, RETIRED key",
            st.sign(Some(&ec_r), In::from(&msg), Some(&mut prefill_array())),
        ),
        (
            "hmac_sha256, RETIRED key",
            st.hmac_sha256(Some(&hk_r), In::from(&msg), Some(&mut prefill_array())),
        ),
        (
            "wrap, RETIRED kek",
            st.wrap(Some(&kek_r), Some(&src), Some(&mut prefill_array())),
        ),
        (
            "rotate, RETIRED key",
            st.rotate(Some(&hk_r), Some(&mut prefill_key_id())),
        ),
    ] {
        r.status(y, &format!("{dir}: {row}"), s, EKI_ERR_KEY_STATE);
    }

    // REVOKED: only description, revoke and destroy.
    let fresh = ks::fresh_id();
    made.push(fresh);
    for (row, s) in [
        (
            "hmac_verify, REVOKED key",
            st.hmac_sha256_verify(Some(&hk_v), In::from(&msg), In::from(&tag_v)),
        ),
        (
            "get_public_key, REVOKED key",
            st.get_public_key(Some(&ec_v), Some(&mut prefill_array())),
        ),
        (
            "sign, REVOKED key",
            st.sign(Some(&ec_v), In::from(&msg), Some(&mut prefill_array())),
        ),
        (
            "hmac_sha256, REVOKED key",
            st.hmac_sha256(Some(&hk_v), In::from(&msg), Some(&mut prefill_array())),
        ),
        (
            "unwrap, REVOKED kek",
            st.unwrap(
                Some(&kek_v),
                In::from(&blob_v),
                HMAC,
                Some(&label),
                Some(&fresh),
            ),
        ),
        (
            "wrap, REVOKED key under an ACTIVE kek",
            st.wrap(Some(&active_kek), Some(&hk_v), Some(&mut prefill_array())),
        ),
        (
            "rotate, REVOKED key",
            st.rotate(Some(&ec_v), Some(&mut prefill_key_id())),
        ),
    ] {
        r.status(y, &format!("{dir}: {row}"), s, EKI_ERR_KEY_STATE);
    }
    r.status(
        y,
        &format!("{dir}: revoke, REVOKED key"),
        st.revoke(Some(&hk_v)),
        EKI_OK,
    );

    // y revokes a key x retired.
    lc::revoke(&st, &ec_r)?;
    drop(st);

    // Phase 3: x sees y's revocation.
    let st = ks::open(x, cfg)?;
    let i = info_v2(&st, &ec_r)?;
    r.check(i.state == REVOKED, || {
        format!(
            "{dir}: key revoked by {} is {i:?} in {}",
            y.name(),
            x.name()
        )
    });
    let s = st.get_public_key(Some(&ec_r), Some(&mut prefill_array()));
    r.status(
        x,
        &format!("{dir}: get_public_key of the key y revoked"),
        s,
        EKI_ERR_KEY_STATE,
    );
    let i = info_v2(&st, &unwrapped)?;
    r.check(i.state == ACTIVE && i.alg == HMAC, || {
        format!(
            "{dir}: key unwrapped by {} is {i:?} in {}",
            y.name(),
            x.name()
        )
    });
    drop(st);
    Ok(())
}

/// Dual control on the token (§6): a key destroyed through another handle while a request for it
/// is pending ends that request with KEY_NOT_FOUND, and a request does not outlive its handle.
/// Approver keys live in a software store of the other library.
#[test]
fn dual_control_on_the_token() {
    let Some((a, b, cfg, _guard)) = setup("ks_pkcs11_lifecycle::dual_control_on_the_token") else {
        return;
    };
    for (x, y) in [(a, b), (b, a)] {
        let name = format!(
            "ks_pkcs11_lifecycle::dual_control_on_the_token ({} with approvers in {})",
            x.name(),
            y.name()
        );
        run_with_cleanup(&name, x, &cfg, |r, made| {
            let ap = Approvers::new(y, 2)?;
            let dual_cfg = KsConfigV2::from_v1(&cfg).with_approvers(&ap.keys);
            let plain = ks::open(x, &cfg)?;
            let dual = open_v2(x, &dual_cfg)?;

            // Destroyed through another handle between the two approvals.
            let key = ks::generate(&dual, EC, &unique_label("dual-gone"))?;
            made.push(key);
            r.status(
                x,
                "destroy on the handle with approvers",
                dual.destroy(Some(&key)),
                EKI_ERR_APPROVAL_REQUIRED,
            );
            let req = destroy_request(&dual, &key)?;
            let rem = approve(&dual, &req, &ap.keys[0], &ap.sign(0, &req, &key)?)?;
            r.check(rem == 1, || {
                format!("{}: first approval: remaining {rem}", x.name())
            });
            ks::destroy(&plain, &key)?;
            let mut remaining = PREFILL_U32;
            let sig1 = ap.sign(1, &req, &key)?;
            let s = dual.destroy_approve(
                Some(&req),
                Some(&ap.keys[1]),
                Some(&sig1),
                Some(&mut remaining),
            );
            if r.status(
                x,
                "second approval after the key was destroyed elsewhere",
                s,
                EKI_ERR_KEY_NOT_FOUND,
            ) {
                r.check(remaining == 0, || {
                    format!("{}: remaining_out = {remaining:#x}", x.name())
                });
            }

            // A request vanishes with its handle; the key survives.
            let key = ks::generate(&plain, HMAC, &unique_label("dual-closed"))?;
            made.push(key);
            let req = destroy_request(&dual, &key)?;
            approve(&dual, &req, &ap.keys[0], &ap.sign(0, &req, &key)?)?;
            drop(dual);
            let dual = open_v2(x, &dual_cfg)?;
            let s = dual.destroy_approve(
                Some(&req),
                Some(&ap.keys[1]),
                Some(&ap.sign(1, &req, &key)?),
                Some(&mut remaining),
            );
            r.status(
                x,
                "approval of a request made by a closed handle",
                s,
                EKI_ERR_KEY_NOT_FOUND,
            );
            let s = plain.get_info(Some(&key), Some(&mut prefill_key_info()));
            r.status(
                x,
                "the key of the forgotten request still exists",
                s,
                EKI_OK,
            );

            // A full approval on the token destroys the key for every handle.
            let req = destroy_request(&dual, &key)?;
            approve(&dual, &req, &ap.keys[1], &ap.sign(1, &req, &key)?)?;
            let rem = approve(&dual, &req, &ap.keys[0], &ap.sign(0, &req, &key)?)?;
            r.check(rem == 0, || {
                format!("{}: second approval: remaining {rem}", x.name())
            });
            let s = plain.get_info(Some(&key), Some(&mut prefill_key_info()));
            r.status(
                x,
                "key destroyed by approvals, seen by another handle",
                s,
                EKI_ERR_KEY_NOT_FOUND,
            );

            // States set on the dual handle are the token's: a retired key on it is RETIRED for
            // the plain handle.
            let key = ks::generate(&dual, AES, &unique_label("dual-state"))?;
            made.push(key);
            set_state(&dual, &key, RETIRED, made)?;
            let i = info_v2(&plain, &key)?;
            r.check(i.state == RETIRED, || {
                format!("{}: key retired on another handle is {i:?}", x.name())
            });
            drop(dual);
            drop(plain);
            Ok(())
        });
    }
}
