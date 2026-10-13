//! `eki_hmac_sha256` and `eki_hmac_sha256_verify`: RFC 4231 vectors, the §4.4 rows, and a
//! seeded differential comparison of the two libraries.

mod common;

use common::{OkCount, Report, Rng, diff_n, iter_ctx};
use ekicore_conformance::status::*;
use ekicore_conformance::vectors::{self, File, HmacCase};
use ekicore_conformance::{In, Lib, prefill_array};

fn hmac(lib: &Lib, key: In, msg: In) -> (i32, [u8; 32]) {
    let mut out = prefill_array::<32>();
    let s = lib.hmac_sha256(key, msg, Some(&mut out));
    (s, out)
}

#[test]
fn rfc4231_vectors() {
    let Some((a, b)) = common::setup("hmac::rfc4231_vectors") else {
        return;
    };
    let mut r = Report::new("hmac::rfc4231_vectors");
    let file: File<HmacCase> = vectors::load(vectors::HMAC_RFC4231);
    for c in &file.cases {
        let mut outs = Vec::new();
        for lib in [a, b] {
            let (s, out) = hmac(lib, In::from(&c.key), In::from(&c.data));
            if r.status(lib, &c.name, s, EKI_OK) {
                r.bytes(lib, &c.name, "mac", &out[..c.mac.len()], &c.mac);
            }
            outs.push(out);
            if c.truncated {
                continue; // only a prefix is published: no verify (plan §4.5)
            }
            let s = lib.hmac_sha256_verify(In::from(&c.key), In::from(&c.data), In::from(&c.mac));
            r.status(lib, &format!("{} verify", c.name), s, EKI_OK);
            let mut bad = c.mac.clone();
            bad[31] ^= 0x01;
            let s = lib.hmac_sha256_verify(In::from(&c.key), In::from(&c.data), In::from(&bad));
            r.status(
                lib,
                &format!("{} verify flipped tag", c.name),
                s,
                EKI_ERR_AUTH_FAILED,
            );
        }
        r.agree_bytes(&c.name, "mac", &outs[0], &outs[1]);
    }
    r.finish();
}

#[test]
fn error_matrix() {
    let Some((a, b)) = common::setup("hmac::error_matrix") else {
        return;
    };
    let mut r = Report::new("hmac::error_matrix");
    let key = [0x0bu8; 20];
    let msg = *b"Hi There";
    for lib in [a, b] {
        // (row, key, msg, expected): `out` is always a real buffer here.
        let rows: [(&str, In, In, i32); 6] = [
            (
                "key NULL, key_len 20",
                In::Null { len: 20 },
                In::from(&msg),
                EKI_ERR_NULL_POINTER,
            ),
            (
                "msg NULL, msg_len 8",
                In::from(&key),
                In::Null { len: 8 },
                EKI_ERR_NULL_POINTER,
            ),
            (
                "key NULL, key_len 0",
                In::NULL,
                In::from(&msg),
                EKI_ERR_INVALID_ARGUMENT,
            ),
            (
                "key non-NULL, key_len 0",
                In::Bytes(&[]),
                In::from(&msg),
                EKI_ERR_INVALID_ARGUMENT,
            ),
            ("msg NULL, msg_len 0", In::from(&key), In::NULL, EKI_OK),
            // Step 1 (NULL) comes before step 3 (lengths).
            (
                "key_len 0 and msg NULL, msg_len 1",
                In::NULL,
                In::Null { len: 1 },
                EKI_ERR_NULL_POINTER,
            ),
        ];
        for (row, k, m, want) in rows {
            let (s, out) = hmac(lib, k, m);
            if r.status(lib, row, s, want) && want != EKI_OK {
                r.zeroed(lib, row, "out", &out);
            }
        }
        let s = lib.hmac_sha256(In::from(&key), In::from(&msg), None);
        r.status(lib, "out NULL", s, EKI_ERR_NULL_POINTER);

        // Verify rows.
        let (_, tag) = hmac(lib, In::from(&key), In::from(&msg));
        let vrows: [(&str, In, In, In, i32); 8] = [
            (
                "verify key NULL, key_len 20",
                In::Null { len: 20 },
                In::from(&msg),
                In::from(&tag),
                EKI_ERR_NULL_POINTER,
            ),
            (
                "verify msg NULL, msg_len 8",
                In::from(&key),
                In::Null { len: 8 },
                In::from(&tag),
                EKI_ERR_NULL_POINTER,
            ),
            (
                "verify tag NULL, tag_len 32",
                In::from(&key),
                In::from(&msg),
                In::Null { len: 32 },
                EKI_ERR_NULL_POINTER,
            ),
            (
                "verify key_len 0",
                In::NULL,
                In::from(&msg),
                In::from(&tag),
                EKI_ERR_INVALID_ARGUMENT,
            ),
            (
                "verify tag_len 31",
                In::from(&key),
                In::from(&msg),
                In::Bytes(&tag[..31]),
                EKI_ERR_INVALID_ARGUMENT,
            ),
            (
                "verify tag NULL, tag_len 0",
                In::from(&key),
                In::from(&msg),
                In::NULL,
                EKI_ERR_INVALID_ARGUMENT,
            ),
            (
                "verify tag_len 33",
                In::from(&key),
                In::from(&msg),
                In::Bytes(&[0u8; 33]),
                EKI_ERR_INVALID_ARGUMENT,
            ),
            (
                "verify wrong tag",
                In::from(&key),
                In::from(&msg),
                In::Bytes(&[0u8; 32]),
                EKI_ERR_AUTH_FAILED,
            ),
        ];
        for (row, k, m, t, want) in vrows {
            let s = lib.hmac_sha256_verify(k, m, t);
            r.status(lib, row, s, want);
        }
    }
    r.finish();
}

/// (b) + (d): random keys and messages through both libraries; statuses and tags must match,
/// and verify must agree on correct, flipped and wrong-length tags.
#[test]
fn differential() {
    let Some((a, b)) = common::setup("hmac::differential") else {
        return;
    };
    let mut r = Report::new("hmac::differential");
    let mut rng = Rng::new("hmac_sha256");
    let mut oks = OkCount::default();
    let mut vrng = Rng::new("hmac_sha256_verify");
    let mut voks = OkCount::default();
    for i in 0..diff_n() {
        let ctx = iter_ctx("hmac_sha256", i);
        let key = rng.data(300);
        let msg = rng.data(5000);
        let (kn, mn) = (rng.chance(1, 2), rng.chance(1, 2));
        let k = In::maybe_null(&key, kn);
        let m = In::maybe_null(&msg, mn);
        let (sa, oa) = hmac(a, k, m);
        let (sb, ob) = hmac(b, k, m);
        oks.add(sa, sb);
        if r.agree(&ctx, sa, sb) {
            r.agree_bytes(&ctx, "out", &oa, &ob);
        }
        for (lib, s, o) in [(a, sa, &oa), (b, sb, &ob)] {
            if s != EKI_OK {
                r.zeroed_after(lib, &ctx, s, "out", o);
            }
        }

        // Verify: the tag A computed (or random bytes), possibly flipped or of the wrong length.
        let vctx = iter_ctx("hmac_sha256_verify", i);
        let mut tag = if sa == EKI_OK {
            oa.to_vec()
        } else {
            vrng.bytes(32)
        };
        match vrng.below(6) {
            0 => vrng.flip_bit(&mut tag),
            1 => tag.truncate(vrng.below(32)),
            2 => tag.push(vrng.array::<1>()[0]),
            _ => {}
        }
        let t = In::maybe_null(&tag, vrng.chance(1, 2));
        let va = a.hmac_sha256_verify(k, m, t);
        let vb = b.hmac_sha256_verify(k, m, t);
        voks.add(va, vb);
        r.agree(&vctx, va, vb);
    }
    oks.require_some(&mut r, "hmac_sha256");
    voks.require_some(&mut r, "hmac_sha256_verify");
    r.finish();
}
