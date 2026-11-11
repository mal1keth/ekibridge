//! PKCS#11 key store (`EKI_KS_PKCS11`) against a SoftHSM2 token shared by both libraries.
//!
//! Needs `EKI_PKCS11_MODULE`, `EKI_PKCS11_TOKEN_LABEL` and `EKI_PKCS11_PIN`
//! (`source scripts/softhsm-init.sh`); every test skips with a message otherwise. The two
//! libraries never hold a PKCS#11 store open at the same time (docs/ffi-contract.md, "Thread
//! safety": the second `C_Finalize` owner problem): a static mutex serialises the tests, the
//! runner also passes `--test-threads=1`, and every scenario closes one library's store before
//! opening the other's. Every store is closed before the test returns.

mod common;

use std::sync::{Mutex, MutexGuard};

use common::ks::{self, run};
use common::{cstr, unique_label};
use ekicore_conformance::sel::{KEY_AES_256, KEY_ECDSA_P256, KEY_HMAC_SHA256};
use ekicore_conformance::status::*;
use ekicore_conformance::{In, KsConfig, Lib, prefill_array, prefill_key_info};

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

#[test]
fn store_error_matrix() {
    let Some((a, b, cfg, _guard)) = setup("ks_pkcs11::store_error_matrix") else {
        return;
    };
    run("ks_pkcs11::store_error_matrix", |r| {
        for lib in [a, b] {
            let st = ks::open(lib, &cfg)?;
            ks::last_error_rows(r, &st);
            ks::store_error_rows(r, &st)?;
            drop(st);
        }
        Ok(())
    });
}

/// Wrong PIN and unknown token label → `EKI_ERR_BACKEND`; afterwards a correct open still works
/// (the failed opens must have released the module).
#[test]
fn open_backend_failures() {
    let Some((a, b, cfg, _guard)) = setup("ks_pkcs11::open_backend_failures") else {
        return;
    };
    run("ks_pkcs11::open_backend_failures", |r| {
        let module = cfg.module_path.clone().unwrap_or_default();
        let module = module.to_str().unwrap_or_default();
        let label = cfg.token_label.clone().unwrap_or_default();
        let label = label.to_str().unwrap_or_default();
        let pin = cfg.user_pin.clone().unwrap_or_default();
        let pin = pin.to_str().unwrap_or_default();
        let wrong_pin = if pin == "9999" { "8888" } else { "9999" };
        for lib in [a, b] {
            for (row, c) in [
                ("wrong PIN", KsConfig::pkcs11(module, label, wrong_pin)),
                (
                    "unknown token label",
                    KsConfig::pkcs11(module, "no-such-token-xyz", pin),
                ),
            ] {
                let (s, st) = lib.ks_open(&c);
                r.status(lib, row, s, EKI_ERR_BACKEND);
                r.check(st.is_none(), || {
                    format!("{}: {row}: a handle was returned", lib.name())
                });
            }
            drop(ks::open(lib, &cfg)?); // a correct open still succeeds
        }
        Ok(())
    });
}

/// `ks_hmac` and `ks_sign` accept an empty message (SoftHSM2 needs a non-NULL data pointer even
/// for length 0; the library must supply one).
#[test]
fn empty_message_rows() {
    let Some((a, b, cfg, _guard)) = setup("ks_pkcs11::empty_message_rows") else {
        return;
    };
    run("ks_pkcs11::empty_message_rows", |r| {
        for lib in [a, b] {
            let st = ks::open(lib, &cfg)?;
            let hk = ks::generate(&st, KEY_HMAC_SHA256, &unique_label("empty-hmac"))?;
            let ec = ks::generate(&st, KEY_ECDSA_P256, &unique_label("empty-ec"))?;
            for msg in [In::NULL, In::Bytes(&[])] {
                let mut out = prefill_array::<32>();
                r.status(
                    lib,
                    "ks_hmac msg_len 0",
                    st.hmac_sha256(Some(&hk), msg, Some(&mut out)),
                    EKI_OK,
                );
                let mut sig = prefill_array::<64>();
                if r.status(
                    lib,
                    "ks_sign msg_len 0",
                    st.sign(Some(&ec), msg, Some(&mut sig)),
                    EKI_OK,
                ) {
                    let pk = ks::public_key(&st, &ec)?;
                    let s = lib.ecdsa_p256_verify(Some(&pk), In::NULL, Some(&sig));
                    r.status(lib, "verify of the empty-message signature", s, EKI_OK);
                }
            }
            ks::destroy(&st, &hk)?;
            ks::destroy(&st, &ec)?;
        }
        Ok(())
    });
}

/// (e) Keys created by one library are used by the other through the shared token:
/// get_info and get_public_key agree, `ks_hmac` agrees, the other library signs with the key and
/// the first verifies, a blob wrapped by one is unwrapped by the other, and a key destroyed by
/// the other is gone for the first. Runs in both directions.
#[test]
fn cross_library_token() {
    let Some((a, b, cfg, _guard)) = setup("ks_pkcs11::cross_library_token") else {
        return;
    };
    run("ks_pkcs11::cross_library_token", |r| {
        let msg = b"cross-library message".to_vec();
        for (x, y) in [(a, b), (b, a)] {
            let dir = format!("{} -> {}", x.name(), y.name());
            let (kek_l, hk_l, ec_l) = (
                unique_label("x-kek"),
                unique_label("x-hmac"),
                unique_label("x-ec"),
            );

            // Phase 1: x creates keys and computes reference values.
            let st = ks::open(x, &cfg)?;
            let kek = ks::generate(&st, KEY_AES_256, &kek_l)?;
            let hk = ks::generate(&st, KEY_HMAC_SHA256, &hk_l)?;
            let ec = ks::generate(&st, KEY_ECDSA_P256, &ec_l)?;
            let infos_x = [
                ks::info(&st, &kek)?,
                ks::info(&st, &hk)?,
                ks::info(&st, &ec)?,
            ];
            let h_x = ks::hmac(&st, &hk, &msg)?;
            let pk_x = ks::public_key(&st, &ec)?;
            let sig_x = ks::sign(&st, &ec, &msg)?;
            let blob = ks::wrap(&st, &kek, &hk)?;
            drop(st);

            // Phase 2: y uses x's keys.
            let st = ks::open(y, &cfg)?;
            let infos_y = [
                ks::info(&st, &kek)?,
                ks::info(&st, &hk)?,
                ks::info(&st, &ec)?,
            ];
            for (ix, iy) in infos_x.iter().zip(&infos_y) {
                r.check(ix == iy, || {
                    format!("{dir}: get_info differs: {ix:?} vs {iy:?}")
                });
            }
            let pk_y = ks::public_key(&st, &ec)?;
            r.check(pk_x == pk_y, || format!("{dir}: get_public_key differs"));
            let h_y = ks::hmac(&st, &hk, &msg)?;
            r.check(h_x == h_y, || format!("{dir}: ks_hmac differs"));
            let s = y.ecdsa_p256_verify(Some(&pk_x), In::from(&msg), Some(&sig_x));
            r.status(y, &format!("{dir}: verify x's signature"), s, EKI_OK);
            let sig_y = ks::sign(&st, &ec, &msg)?;
            let new_id = ks::fresh_id();
            let new_l = unique_label("x-unwrapped");
            ks::unwrap(&st, &kek, &blob, KEY_HMAC_SHA256, &new_l, &new_id)?;
            let h_unwrapped = ks::hmac(&st, &new_id, &msg)?;
            r.check(h_unwrapped == h_x, || {
                format!("{dir}: key unwrapped in y computes a different HMAC")
            });
            ks::destroy(&st, &ec)?;
            drop(st);

            // Phase 3: x sees y's changes.
            let st = ks::open(x, &cfg)?;
            let s = x.ecdsa_p256_verify(Some(&pk_x), In::from(&msg), Some(&sig_y));
            r.status(
                x,
                &format!("{dir}: verify y's signature with x's key"),
                s,
                EKI_OK,
            );
            let s = st.get_info(Some(&ec), Some(&mut prefill_key_info()));
            r.status(
                x,
                &format!("{dir}: get_info of the key y destroyed"),
                s,
                EKI_ERR_KEY_NOT_FOUND,
            );
            let s = st.sign(Some(&ec), In::from(&msg), Some(&mut prefill_array()));
            r.status(
                x,
                &format!("{dir}: sign with the key y destroyed"),
                s,
                EKI_ERR_KEY_NOT_FOUND,
            );
            let i = ks::info(&st, &new_id)?;
            r.check(
                i.alg == KEY_HMAC_SHA256 && Some(i.label_str().as_str()) == new_l.to_str().ok(),
                || format!("{dir}: get_info of the key y unwrapped: {i:?}"),
            );
            r.check(ks::hmac(&st, &new_id, &msg)? == h_x, || {
                format!("{dir}: x computes a different HMAC with the key y unwrapped")
            });
            for id in [&new_id, &hk, &kek] {
                ks::destroy(&st, id)?;
            }
            drop(st);
        }
        Ok(())
    });
}

/// ECDSA cross-verification inside the token, both directions.
#[test]
fn ecdsa_cross_language() {
    let Some((a, b, cfg, _guard)) = setup("ks_pkcs11::ecdsa_cross_language") else {
        return;
    };
    run("ks_pkcs11::ecdsa_cross_language", |r| {
        for (x, y) in [(a, b), (b, a)] {
            let st = ks::open(x, &cfg)?;
            ks::ecdsa_cross(r, &st, y)?;
            drop(st);
        }
        Ok(())
    });
}

/// Labels need not be unique (docs/ffi-contract.md, "Labels"): two keys with one label are
/// separate objects.
#[test]
fn duplicate_labels_are_allowed() {
    let Some((a, b, cfg, _guard)) = setup("ks_pkcs11::duplicate_labels_are_allowed") else {
        return;
    };
    run("ks_pkcs11::duplicate_labels_are_allowed", |r| {
        for lib in [a, b] {
            let st = ks::open(lib, &cfg)?;
            let label = cstr(&format!("dup-{}", std::process::id()));
            let k1 = ks::generate(&st, KEY_AES_256, &label)?;
            let k2 = ks::generate(&st, KEY_AES_256, &label)?;
            r.check(k1 != k2, || {
                format!("{}: two generates returned the same id", lib.name())
            });
            ks::destroy(&st, &k1)?;
            ks::info(&st, &k2)?;
            ks::destroy(&st, &k2)?;
        }
        Ok(())
    });
}
