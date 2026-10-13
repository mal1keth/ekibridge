//! `eki_hkdf_sha256`: RFC 5869 vectors, the §4.4 rows, and a seeded differential comparison.

mod common;

use common::{OkCount, Report, Rng, diff_n, iter_ctx};
use ekicore_conformance::status::*;
use ekicore_conformance::vectors::{self, File, HkdfCase};
use ekicore_conformance::{EKI_HKDF_MAX_INPUT_LEN, EKI_HKDF_MAX_OKM_LEN, In, Lib, Out, prefill};

/// Calls HKDF with a real `okm` buffer of `okm_len` bytes (or NULL when `okm_null`).
fn hkdf(lib: &Lib, ikm: In, salt: In, info: In, okm_len: usize, okm_null: bool) -> (i32, Vec<u8>) {
    let mut okm = prefill(okm_len);
    let out = if okm_null {
        Out::Null { len: okm_len }
    } else {
        Out::Buf(&mut okm)
    };
    let s = lib.hkdf_sha256(ikm, salt, info, out);
    (s, okm)
}

#[test]
fn rfc5869_vectors() {
    let Some((a, b)) = common::setup("hkdf::rfc5869_vectors") else {
        return;
    };
    let mut r = Report::new("hkdf::rfc5869_vectors");
    let file: File<HkdfCase> = vectors::load(vectors::HKDF_RFC5869);
    for c in &file.cases {
        // An empty salt or info goes in both as NULL and as a non-NULL empty slice.
        for null_when_empty in [true, false] {
            let ctx = format!("{} (empty inputs as NULL: {null_when_empty})", c.name);
            let mut outs = Vec::new();
            for lib in [a, b] {
                let (s, okm) = hkdf(
                    lib,
                    In::from(&c.ikm),
                    In::maybe_null(&c.salt, null_when_empty),
                    In::maybe_null(&c.info, null_when_empty),
                    c.length,
                    false,
                );
                if r.status(lib, &ctx, s, EKI_OK) {
                    r.bytes(lib, &ctx, "okm", &okm, &c.okm);
                }
                outs.push(okm);
            }
            r.agree_bytes(&ctx, "okm", &outs[0], &outs[1]);
        }
    }
    r.finish();
}

#[test]
fn error_matrix() {
    let Some((a, b)) = common::setup("hkdf::error_matrix") else {
        return;
    };
    let mut r = Report::new("hkdf::error_matrix");
    let ikm = [0x0bu8; 22];
    let salt = [0x01u8; 13];
    let info = [0xf0u8; 10];
    let big = vec![0x5au8; EKI_HKDF_MAX_INPUT_LEN + 1];
    let max = vec![0x5au8; EKI_HKDF_MAX_INPUT_LEN];
    let (i, s, n) = (In::from(&ikm), In::from(&salt), In::from(&info));
    for lib in [a, b] {
        // (row, ikm, salt, info, okm_len, okm NULL, expected)
        let rows: Vec<(&str, In, In, In, usize, bool, i32)> = vec![
            (
                "ikm NULL, ikm_len 22",
                In::Null { len: 22 },
                s,
                n,
                42,
                false,
                EKI_ERR_NULL_POINTER,
            ),
            (
                "salt NULL, salt_len 13",
                i,
                In::Null { len: 13 },
                n,
                42,
                false,
                EKI_ERR_NULL_POINTER,
            ),
            (
                "info NULL, info_len 10",
                i,
                s,
                In::Null { len: 10 },
                42,
                false,
                EKI_ERR_NULL_POINTER,
            ),
            (
                "okm NULL, okm_len 42",
                i,
                s,
                n,
                42,
                true,
                EKI_ERR_NULL_POINTER,
            ),
            (
                "ikm_len 0 and okm NULL, okm_len 42 (NULL first)",
                In::NULL,
                s,
                n,
                42,
                true,
                EKI_ERR_NULL_POINTER,
            ),
            (
                "ikm_len 0",
                In::NULL,
                s,
                n,
                42,
                false,
                EKI_ERR_INVALID_ARGUMENT,
            ),
            (
                "ikm_len 32769",
                In::from(&big),
                s,
                n,
                42,
                false,
                EKI_ERR_INVALID_ARGUMENT,
            ),
            (
                "salt_len 32769",
                i,
                In::from(&big),
                n,
                42,
                false,
                EKI_ERR_INVALID_ARGUMENT,
            ),
            (
                "info_len 32769",
                i,
                s,
                In::from(&big),
                42,
                false,
                EKI_ERR_INVALID_ARGUMENT,
            ),
            ("okm_len 0", i, s, n, 0, false, EKI_ERR_INVALID_ARGUMENT),
            (
                "okm NULL, okm_len 0",
                i,
                s,
                n,
                0,
                true,
                EKI_ERR_INVALID_ARGUMENT,
            ),
            (
                "okm_len 8161",
                i,
                s,
                n,
                EKI_HKDF_MAX_OKM_LEN + 1,
                false,
                EKI_ERR_INVALID_ARGUMENT,
            ),
            ("okm_len 8160", i, s, n, EKI_HKDF_MAX_OKM_LEN, false, EKI_OK),
            ("salt NULL, salt_len 0", i, In::NULL, n, 42, false, EKI_OK),
            ("info NULL, info_len 0", i, s, In::NULL, 42, false, EKI_OK),
            (
                "ikm, salt, info all 32768 bytes",
                In::from(&max),
                In::from(&max),
                In::from(&max),
                32,
                false,
                EKI_OK,
            ),
        ];
        for (row, ikm, salt, info, okm_len, okm_null, want) in rows {
            let (st, okm) = hkdf(lib, ikm, salt, info, okm_len, okm_null);
            if !r.status(lib, row, st, want) || want == EKI_OK || okm_null {
                continue;
            }
            if (1..=EKI_HKDF_MAX_OKM_LEN).contains(&okm_len) {
                r.zeroed(lib, row, "okm", &okm);
            } else {
                r.untouched(lib, row, "okm (okm_len out of range)", &okm);
            }
        }
    }
    r.finish();
}

/// (b) + (d): random lengths for every input and for `okm_len`, sometimes out of range.
#[test]
fn differential() {
    let Some((a, b)) = common::setup("hkdf::differential") else {
        return;
    };
    let mut r = Report::new("hkdf::differential");
    let mut rng = Rng::new("hkdf_sha256");
    let mut oks = OkCount::default();
    for it in 0..diff_n() {
        let ctx = iter_ctx("hkdf_sha256", it);
        let input_len = |rng: &mut Rng| {
            if rng.chance(1, 50) {
                EKI_HKDF_MAX_INPUT_LEN + rng.below(2)
            } else {
                rng.len(600)
            }
        };
        let n = input_len(&mut rng);
        let ikm = rng.bytes(n);
        let n = input_len(&mut rng);
        let salt = rng.bytes(n);
        let n = input_len(&mut rng);
        let info = rng.bytes(n);
        let okm_len = match rng.below(10) {
            0 => rng.pick(&[0, EKI_HKDF_MAX_OKM_LEN, EKI_HKDF_MAX_OKM_LEN + 1]),
            1 => 1 + rng.below(EKI_HKDF_MAX_OKM_LEN),
            _ => rng.pick(&[1, 16, 31, 32, 33, 42, 64, 82, 255, 256, 1000]),
        };
        let okm_null = okm_len == 0 && rng.chance(1, 2);
        let (i, s, n) = (
            In::maybe_null(&ikm, rng.chance(1, 2)),
            In::maybe_null(&salt, rng.chance(1, 2)),
            In::maybe_null(&info, rng.chance(1, 2)),
        );
        let (sa, oa) = hkdf(a, i, s, n, okm_len, okm_null);
        let (sb, ob) = hkdf(b, i, s, n, okm_len, okm_null);
        oks.add(sa, sb);
        if r.agree(&ctx, sa, sb) {
            r.agree_bytes(&ctx, "okm", &oa, &ob);
        }
        if (1..=EKI_HKDF_MAX_OKM_LEN).contains(&okm_len) {
            for (lib, st, o) in [(a, sa, &oa), (b, sb, &ob)] {
                if st != EKI_OK {
                    r.zeroed_after(lib, &ctx, st, "okm", o);
                }
            }
        }
    }
    oks.require_some(&mut r, "hkdf_sha256");
    r.finish();
}
