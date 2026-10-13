//! Software key store (`EKI_KS_SOFTWARE`) in both libraries: `eki_ks_open` rows, the store rows
//! of the §4.4 matrix, `get_info` parity, ECDSA cross-verification and handle independence.
//!
//! Two software stores never share key material and the ABI has no import of a raw key, so a
//! key cannot be unwrapped in the other library's software store: the wrap → unwrap → `ks_hmac`
//! round trip runs inside each library's store here (in `store_error_matrix`) and across
//! libraries only in `ks_pkcs11`, where both libraries see the same token.

mod common;

use std::ptr::NonNull;

use common::ks::{self, run};
use common::{Report, cstr, unique_label};
use ekicore_conformance::sel::{
    KEY_AES_256, KEY_ECDSA_P256, KEY_HMAC_SHA256, KS_PKCS11, KS_SOFTWARE,
};
use ekicore_conformance::status::*;
use ekicore_conformance::{KsConfig, Lib, eki_ks, prefill_key_info};

#[test]
fn store_error_matrix() {
    let Some((a, b)) = common::setup("ks_software::store_error_matrix") else {
        return;
    };
    run("ks_software::store_error_matrix", |r| {
        for lib in [a, b] {
            let st = ks::open(lib, &KsConfig::software())?;
            ks::last_error_rows(r, &st);
            ks::store_error_rows(r, &st)?;
        }
        Ok(())
    });
}

/// Calls `eki_ks_open` with `*out` pre-set to a non-NULL sentinel; checks the status and that a
/// failure leaves `*out == NULL`. A handle returned on success is closed.
fn open_row(
    r: &mut Report,
    lib: &Lib,
    row: &str,
    cfg: Option<&KsConfig>,
    with_out: bool,
    want: i32,
) {
    let raw_cfg = cfg.map(KsConfig::as_raw);
    let sentinel = NonNull::<eki_ks>::dangling().as_ptr();
    let mut out = sentinel;
    let s = lib.ks_open_raw(raw_cfg.as_ref(), with_out.then_some(&mut out));
    if r.status(lib, row, s, want) && with_out && want != EKI_OK {
        r.check(out.is_null(), || {
            format!("{}: {row}: *out is {out:?}, want NULL", lib.name())
        });
    }
    if s == EKI_OK && with_out && !out.is_null() && out != sentinel {
        // SAFETY: the library just returned this handle from eki_ks_open and nothing else owns it.
        drop(unsafe { lib.adopt(out) });
    }
}

#[test]
fn ks_open_error_matrix() {
    let Some((a, b)) = common::setup("ks_software::ks_open_error_matrix") else {
        return;
    };
    let mut r = Report::new("ks_software::ks_open_error_matrix");
    let sw = KsConfig::software();
    let backend = |b: i32| KsConfig {
        backend: b,
        ..KsConfig::default()
    };
    // Software ignores the PKCS#11 fields, even malformed ones.
    let sw_garbage = KsConfig {
        backend: KS_SOFTWARE,
        module_path: Some(cstr("/nonexistent/module.so")),
        token_label: Some(cstr("")),
        user_pin: Some(cstr("")),
    };
    // PKCS#11 configs: the field checks (steps 1 and 3) come before the module is loaded, so a
    // module path that does not exist is fine for them.
    let nomod = "/nonexistent/ekibridge-test-module.so";
    let p11 = |m: Option<&str>, l: Option<&str>, p: Option<&str>| KsConfig {
        backend: KS_PKCS11,
        module_path: m.map(cstr),
        token_label: l.map(cstr),
        user_pin: p.map(cstr),
    };
    let label33 = "a".repeat(33);
    let label32 = "a".repeat(32);
    let pin256 = "1".repeat(256);
    let pin255 = "1".repeat(255);
    let rows: Vec<(&str, Option<KsConfig>, bool, i32)> = vec![
        ("config NULL", None, true, EKI_ERR_NULL_POINTER),
        ("out NULL", Some(sw.clone()), false, EKI_ERR_NULL_POINTER),
        (
            "config NULL and out NULL",
            None,
            false,
            EKI_ERR_NULL_POINTER,
        ),
        (
            "backend 0",
            Some(backend(0)),
            true,
            EKI_ERR_INVALID_ARGUMENT,
        ),
        (
            "backend 99",
            Some(backend(99)),
            true,
            EKI_ERR_INVALID_ARGUMENT,
        ),
        (
            "backend -1",
            Some(backend(-1)),
            true,
            EKI_ERR_INVALID_ARGUMENT,
        ),
        (
            "backend 99 and out NULL (NULL first)",
            Some(backend(99)),
            false,
            EKI_ERR_NULL_POINTER,
        ),
        ("software", Some(sw.clone()), true, EKI_OK),
        (
            "software with malformed PKCS#11 fields",
            Some(sw_garbage),
            true,
            EKI_OK,
        ),
        (
            "PKCS#11 module_path NULL",
            Some(p11(None, Some("ekibridge"), Some("1234"))),
            true,
            EKI_ERR_NULL_POINTER,
        ),
        (
            "PKCS#11 token_label NULL",
            Some(p11(Some(nomod), None, Some("1234"))),
            true,
            EKI_ERR_NULL_POINTER,
        ),
        (
            "PKCS#11 user_pin NULL",
            Some(p11(Some(nomod), Some("ekibridge"), None)),
            true,
            EKI_ERR_NULL_POINTER,
        ),
        (
            "PKCS#11 all fields NULL",
            Some(p11(None, None, None)),
            true,
            EKI_ERR_NULL_POINTER,
        ),
        (
            "PKCS#11 token_label \"\"",
            Some(p11(Some(nomod), Some(""), Some("1234"))),
            true,
            EKI_ERR_INVALID_ARGUMENT,
        ),
        (
            "PKCS#11 33-byte token_label",
            Some(p11(Some(nomod), Some(&label33), Some("1234"))),
            true,
            EKI_ERR_INVALID_ARGUMENT,
        ),
        (
            "PKCS#11 token_label with 0x01",
            Some(p11(Some(nomod), Some("ekib\u{1}ridge"), Some("1234"))),
            true,
            EKI_ERR_INVALID_ARGUMENT,
        ),
        (
            "PKCS#11 user_pin \"\"",
            Some(p11(Some(nomod), Some("ekibridge"), Some(""))),
            true,
            EKI_ERR_INVALID_ARGUMENT,
        ),
        (
            "PKCS#11 256-byte user_pin",
            Some(p11(Some(nomod), Some("ekibridge"), Some(&pin256))),
            true,
            EKI_ERR_INVALID_ARGUMENT,
        ),
        (
            "PKCS#11 module that does not exist",
            Some(p11(Some(nomod), Some(&label32), Some(&pin255))),
            true,
            EKI_ERR_BACKEND,
        ),
    ];
    for lib in [a, b] {
        for (row, cfg, with_out, want) in &rows {
            open_row(&mut r, lib, row, cfg.as_ref(), *with_out, *want);
        }
        // eki_ks_close(NULL) is a no-op.
        drop(lib.null_store());
    }
    r.finish();
}

/// (e) `get_info` parity: the same algorithm and label give identical `eki_key_info` fields
/// (alg, label text, NUL padding through byte 64) in both libraries.
#[test]
fn get_info_parity() {
    let Some((a, b)) = common::setup("ks_software::get_info_parity") else {
        return;
    };
    run("ks_software::get_info_parity", |r| {
        let sa = ks::open(a, &KsConfig::software())?;
        let sb = ks::open(b, &KsConfig::software())?;
        let labels = [
            cstr("k"),
            cstr(" ~"),
            cstr(&"L".repeat(64)),
            unique_label("parity"),
        ];
        for alg in [KEY_AES_256, KEY_HMAC_SHA256, KEY_ECDSA_P256] {
            for label in &labels {
                let ia = ks::info(&sa, &ks::generate(&sa, alg, label)?)?;
                let ib = ks::info(&sb, &ks::generate(&sb, alg, label)?)?;
                let ctx = format!("alg {alg}, label {label:?}");
                r.check(ia == ib, || {
                    format!("{ctx}: {} {ia:?} vs {} {ib:?}", a.name(), b.name())
                });
                for (lib, i) in [(a, &ia), (b, &ib)] {
                    r.check(i.alg == alg && i.label_nul_padded(), || {
                        format!("{}: {ctx}: {i:?}", lib.name())
                    });
                    r.check(Some(i.label_str().as_str()) == label.to_str().ok(), || {
                        format!("{}: {ctx}: label {:?}", lib.name(), i.label_str())
                    });
                }
            }
        }
        Ok(())
    });
}

/// (e) ECDSA generated and signed in one library verifies with the other's stateless verify.
#[test]
fn ecdsa_cross_language() {
    let Some((a, b)) = common::setup("ks_software::ecdsa_cross_language") else {
        return;
    };
    run("ks_software::ecdsa_cross_language", |r| {
        for (x, y) in [(a, b), (b, a)] {
            let st = ks::open(x, &KsConfig::software())?;
            ks::ecdsa_cross(r, &st, y)?;
        }
        Ok(())
    });
}

/// Two software handles of one library are separate stores; ids are 16 fresh bytes each time.
#[test]
fn handles_are_independent() {
    let Some((a, b)) = common::setup("ks_software::handles_are_independent") else {
        return;
    };
    run("ks_software::handles_are_independent", |r| {
        for lib in [a, b] {
            let s1 = ks::open(lib, &KsConfig::software())?;
            let s2 = ks::open(lib, &KsConfig::software())?;
            let label = cstr("same label");
            let id1 = ks::generate(&s1, KEY_HMAC_SHA256, &label)?;
            let id2 = ks::generate(&s1, KEY_HMAC_SHA256, &label)?;
            r.check(id1 != id2, || {
                format!("{}: two generates returned the same id", lib.name())
            });
            let s = s2.get_info(Some(&id1), Some(&mut prefill_key_info()));
            r.status(
                lib,
                "key of handle 1 looked up in handle 2",
                s,
                EKI_ERR_KEY_NOT_FOUND,
            );
            drop(s2);
            ks::info(&s1, &id1)?;
        }
        Ok(())
    });
}
