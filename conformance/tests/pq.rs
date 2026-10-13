//! Hybrid X25519 + ML-KEM-768 KEM (`eki_hybrid_kem_*`).
//!
//! With `EKI_PQ=1` (both libraries built with the feature: `EKI_PQ=1 scripts/run-conformance.sh
//! pq`) the round trips run across libraries. Without it the tests that need the feature print a
//! skip message, and the "feature off" rows check that both libraries answer
//! `EKI_ERR_UNSUPPORTED` after the NULL checks.

mod common;

use common::{Report, Rng};
use ekicore_conformance::status::*;
use ekicore_conformance::{
    EKI_HYBRID_CT_LEN, EKI_HYBRID_PK_LEN, EKI_HYBRID_SK_LEN, EKI_HYBRID_SS_LEN, Lib, prefill_array,
};

type Pk = [u8; EKI_HYBRID_PK_LEN];
type Sk = [u8; EKI_HYBRID_SK_LEN];
type Ct = [u8; EKI_HYBRID_CT_LEN];
type Ss = [u8; EKI_HYBRID_SS_LEN];

fn pq_enabled() -> bool {
    std::env::var("EKI_PQ").is_ok_and(|v| v == "1")
}

fn keygen(lib: &Lib) -> (i32, Box<Pk>, Box<Sk>) {
    let mut pk = Box::new(prefill_array::<EKI_HYBRID_PK_LEN>());
    let mut sk = Box::new(prefill_array::<EKI_HYBRID_SK_LEN>());
    let s = lib.hybrid_kem_keygen(Some(&mut pk), Some(&mut sk));
    (s, pk, sk)
}

fn encap(lib: &Lib, pk: &Pk) -> (i32, Box<Ct>, Ss) {
    let mut ct = Box::new(prefill_array::<EKI_HYBRID_CT_LEN>());
    let mut ss = prefill_array::<EKI_HYBRID_SS_LEN>();
    let s = lib.hybrid_kem_encap(Some(pk), Some(&mut ct), Some(&mut ss));
    (s, ct, ss)
}

fn decap(lib: &Lib, sk: &Sk, ct: &Ct) -> (i32, Ss) {
    let mut ss = prefill_array::<EKI_HYBRID_SS_LEN>();
    let s = lib.hybrid_kem_decap(Some(sk), Some(ct), Some(&mut ss));
    (s, ss)
}

/// NULL checks come first whether or not the feature is compiled in.
#[test]
fn null_pointer_rows() {
    let Some((a, b)) = common::setup("pq::null_pointer_rows") else {
        return;
    };
    let mut r = Report::new("pq::null_pointer_rows");
    let pk: Box<Pk> = Box::new([0x11; EKI_HYBRID_PK_LEN]);
    let sk: Box<Sk> = Box::new([0x22; EKI_HYBRID_SK_LEN]);
    let ct: Box<Ct> = Box::new([0x33; EKI_HYBRID_CT_LEN]);
    for lib in [a, b] {
        let mut pk_out = Box::new(prefill_array::<EKI_HYBRID_PK_LEN>());
        let mut sk_out = Box::new(prefill_array::<EKI_HYBRID_SK_LEN>());
        if r.status(
            lib,
            "keygen pk_out NULL",
            lib.hybrid_kem_keygen(None, Some(&mut sk_out)),
            EKI_ERR_NULL_POINTER,
        ) {
            r.zeroed(lib, "keygen pk_out NULL", "sk_out", &sk_out[..]);
        }
        if r.status(
            lib,
            "keygen sk_out NULL",
            lib.hybrid_kem_keygen(Some(&mut pk_out), None),
            EKI_ERR_NULL_POINTER,
        ) {
            r.zeroed(lib, "keygen sk_out NULL", "pk_out", &pk_out[..]);
        }
        let mut ct_out = Box::new(prefill_array::<EKI_HYBRID_CT_LEN>());
        let mut ss = prefill_array::<EKI_HYBRID_SS_LEN>();
        if r.status(
            lib,
            "encap pk NULL",
            lib.hybrid_kem_encap(None, Some(&mut ct_out), Some(&mut ss)),
            EKI_ERR_NULL_POINTER,
        ) {
            r.zeroed(lib, "encap pk NULL", "ct_out", &ct_out[..]);
            r.zeroed(lib, "encap pk NULL", "ss_out", &ss);
        }
        r.status(
            lib,
            "encap ct_out NULL",
            lib.hybrid_kem_encap(Some(&pk), None, Some(&mut ss)),
            EKI_ERR_NULL_POINTER,
        );
        r.status(
            lib,
            "encap ss_out NULL",
            lib.hybrid_kem_encap(Some(&pk), Some(&mut ct_out), None),
            EKI_ERR_NULL_POINTER,
        );
        let mut ss = prefill_array::<EKI_HYBRID_SS_LEN>();
        if r.status(
            lib,
            "decap sk NULL",
            lib.hybrid_kem_decap(None, Some(&ct), Some(&mut ss)),
            EKI_ERR_NULL_POINTER,
        ) {
            r.zeroed(lib, "decap sk NULL", "ss_out", &ss);
        }
        r.status(
            lib,
            "decap ct NULL",
            lib.hybrid_kem_decap(Some(&sk), None, Some(&mut ss)),
            EKI_ERR_NULL_POINTER,
        );
        r.status(
            lib,
            "decap ss_out NULL",
            lib.hybrid_kem_decap(Some(&sk), Some(&ct), None),
            EKI_ERR_NULL_POINTER,
        );
    }
    r.finish();
}

/// §4.4 "hybrid (feature off), valid pointers → UNSUPPORTED", outputs zero-filled.
#[test]
fn feature_off_is_unsupported() {
    if pq_enabled() {
        eprintln!(
            "skipping pq::feature_off_is_unsupported: EKI_PQ=1 (libraries built with the hybrid KEM)"
        );
        return;
    }
    let Some((a, b)) = common::setup("pq::feature_off_is_unsupported") else {
        return;
    };
    let mut r = Report::new("pq::feature_off_is_unsupported");
    let pk: Box<Pk> = Box::new([0x11; EKI_HYBRID_PK_LEN]);
    let sk: Box<Sk> = Box::new([0x22; EKI_HYBRID_SK_LEN]);
    let ct: Box<Ct> = Box::new([0x33; EKI_HYBRID_CT_LEN]);
    for lib in [a, b] {
        let (s, pk_out, sk_out) = keygen(lib);
        if r.status(lib, "keygen", s, EKI_ERR_UNSUPPORTED) {
            r.zeroed(lib, "keygen", "pk_out", &pk_out[..]);
            r.zeroed(lib, "keygen", "sk_out", &sk_out[..]);
        }
        let (s, ct_out, ss) = encap(lib, &pk);
        if r.status(lib, "encap", s, EKI_ERR_UNSUPPORTED) {
            r.zeroed(lib, "encap", "ct_out", &ct_out[..]);
            r.zeroed(lib, "encap", "ss_out", &ss);
        }
        let (s, ss) = decap(lib, &sk, &ct);
        if r.status(lib, "decap", s, EKI_ERR_UNSUPPORTED) {
            r.zeroed(lib, "decap", "ss_out", &ss);
        }
    }
    r.finish();
}

fn pq_setup(test: &str) -> Option<(&'static Lib, &'static Lib)> {
    if !pq_enabled() {
        eprintln!("skipping {test}: EKI_PQ is not 1 (run EKI_PQ=1 scripts/run-conformance.sh pq)");
        return None;
    }
    let (a, b) = common::setup(test)?;
    Some((a, b))
}

/// Keygen in one library, encap in the other, decap in the first: equal shared secrets. Decap
/// of the same `(sk, ct)` is deterministic, so both libraries must also agree on it. Tampering
/// with `ct` yields a different secret without an error (implicit rejection).
#[test]
fn cross_language_round_trips() {
    let Some((a, b)) = pq_setup("pq::cross_language_round_trips") else {
        return;
    };
    let mut r = Report::new("pq::cross_language_round_trips");
    let mut rng = Rng::new("hybrid_kem");
    for round in 0..8 {
        for (x, y) in [(a, b), (b, a)] {
            let ctx = format!(
                "round {round}: keygen/decap in {}, encap in {}",
                x.name(),
                y.name()
            );
            let (s, pk, sk) = keygen(x);
            if !r.status(x, &format!("{ctx}: keygen"), s, EKI_OK) {
                continue;
            }
            let (s, ct, ss_enc) = encap(y, &pk);
            if !r.status(y, &format!("{ctx}: encap"), s, EKI_OK) {
                continue;
            }
            let (s, ss_dec) = decap(x, &sk, &ct);
            if r.status(x, &format!("{ctx}: decap"), s, EKI_OK) {
                r.bytes(x, &ctx, "shared secret", &ss_dec, &ss_enc);
            }
            let (s, ss_other) = decap(y, &sk, &ct);
            if r.status(y, &format!("{ctx}: decap in the other library"), s, EKI_OK) {
                r.agree_bytes(&ctx, "decap shared secret", &ss_dec, &ss_other);
            }
            let mut bad = ct.clone();
            rng.flip_bit(&mut bad[..]);
            let (sa, ssa) = decap(x, &sk, &bad);
            let (sb, ssb) = decap(y, &sk, &bad);
            r.status(x, &format!("{ctx}: decap of tampered ct"), sa, EKI_OK);
            r.status(y, &format!("{ctx}: decap of tampered ct"), sb, EKI_OK);
            r.check(ssa != ss_enc, || {
                format!("{ctx}: tampered ct gave the same shared secret")
            });
            r.agree_bytes(&ctx, "tampered-ct shared secret", &ssa, &ssb);
        }
    }
    r.finish();
}

/// §4.4: an all-zero X25519 part of `pk` gives an all-zero X25519 secret → INVALID_ARGUMENT.
#[test]
fn encap_rejects_zero_x25519_key() {
    let Some((a, b)) = pq_setup("pq::encap_rejects_zero_x25519_key") else {
        return;
    };
    let mut r = Report::new("pq::encap_rejects_zero_x25519_key");
    for lib in [a, b] {
        let (s, mut pk, _) = keygen(lib);
        if !r.status(lib, "keygen", s, EKI_OK) {
            continue;
        }
        pk[..32].fill(0);
        let (s, ct, ss) = encap(lib, &pk);
        if r.status(
            lib,
            "encap with all-zero x25519 pk",
            s,
            EKI_ERR_INVALID_ARGUMENT,
        ) {
            r.zeroed(lib, "encap with all-zero x25519 pk", "ct_out", &ct[..]);
            r.zeroed(lib, "encap with all-zero x25519 pk", "ss_out", &ss);
        }
    }
    r.finish();
}
