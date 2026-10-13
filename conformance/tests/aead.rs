//! `eki_aead_seal` / `eki_aead_open` for AES-256-GCM and ChaCha20-Poly1305: RFC 8439, GCM spec
//! and Wycheproof vectors, the §4.4 rows, cross-language round trips and a seeded differential.

mod common;

use common::{OkCount, Report, Rng, diff_n, iter_ctx};
use ekicore_conformance::sel::{AEAD_AES_256_GCM as GCM, AEAD_CHACHA20_POLY1305 as CHACHA};
use ekicore_conformance::status::*;
use ekicore_conformance::vectors::{self, AeadCase, Expect, File};
use ekicore_conformance::{In, Lib, Out, prefill, prefill_array};

/// (row, alg, key, nonce, aad, pt, ct_out NULL, expected status)
type SealRow<'a> = (String, i32, In<'a>, In<'a>, In<'a>, In<'a>, bool, i32);
/// (row, alg, key, nonce, aad, ct, tag, pt_out NULL, expected status)
type OpenRow<'a> = (
    &'static str,
    i32,
    In<'a>,
    In<'a>,
    In<'a>,
    In<'a>,
    Option<&'a [u8; 16]>,
    bool,
    i32,
);

const ALGS: [(i32, &str); 2] = [(GCM, "AES-256-GCM"), (CHACHA, "ChaCha20-Poly1305")];

/// Seal with a prefilled `ct_out` of `pt.len()` bytes (NULL when `ct_null`) and `tag_out`.
fn seal(
    lib: &Lib,
    alg: i32,
    key: In,
    nonce: In,
    aad: In,
    pt: In,
    ct_null: bool,
) -> (i32, Vec<u8>, [u8; 16]) {
    let mut ct = prefill(pt.len());
    let mut tag = prefill_array::<16>();
    let out = if ct_null {
        Out::NULL
    } else {
        Out::Buf(&mut ct)
    };
    let s = lib.aead_seal(alg, key, nonce, aad, pt, out, Some(&mut tag));
    (s, ct, tag)
}

/// Open with a prefilled `pt_out` of `ct.len()` bytes (NULL when `pt_null`).
#[allow(clippy::too_many_arguments)]
fn open(
    lib: &Lib,
    alg: i32,
    key: In,
    nonce: In,
    aad: In,
    ct: In,
    tag: Option<&[u8; 16]>,
    pt_null: bool,
) -> (i32, Vec<u8>) {
    let mut pt = prefill(ct.len());
    let out = if pt_null {
        Out::NULL
    } else {
        Out::Buf(&mut pt)
    };
    let s = lib.aead_open(alg, key, nonce, aad, ct, tag, out);
    (s, pt)
}

fn tag16(v: &[u8]) -> [u8; 16] {
    v.try_into()
        .expect("vector tag is 16 bytes (checked by the vector-file test)")
}

fn run_vector_file(file_name: &str, alg: i32) {
    let Some((a, b)) = common::setup(&format!("aead::{file_name}")) else {
        return;
    };
    let mut r = Report::new(&format!("aead::{file_name}"));
    let file: File<AeadCase> = vectors::load(file_name);
    for c in &file.cases {
        let name = format!("{file_name} {}", c.label());
        let (k, n, aad) = (In::from(&c.key), In::from(&c.nonce), In::from(&c.aad));
        let tag = tag16(&c.tag);
        let mut opened = Vec::new();
        for lib in [a, b] {
            if c.result == Expect::Valid {
                let (s, ct, t) = seal(lib, alg, k, n, aad, In::from(&c.pt), false);
                if r.status(lib, &format!("{name} seal"), s, EKI_OK) {
                    r.bytes(lib, &name, "ct", &ct, &c.ct);
                    r.bytes(lib, &name, "tag", &t, &c.tag);
                }
                let (s, pt) = open(lib, alg, k, n, aad, In::from(&c.ct), Some(&tag), false);
                if r.status(lib, &format!("{name} open"), s, EKI_OK) {
                    r.bytes(lib, &name, "pt", &pt, &c.pt);
                }
                opened.push((s, pt));
            } else {
                let (s, pt) = open(lib, alg, k, n, aad, In::from(&c.ct), Some(&tag), false);
                if r.status(
                    lib,
                    &format!("{name} open (invalid)"),
                    s,
                    EKI_ERR_AUTH_FAILED,
                ) {
                    r.zeroed(lib, &name, "pt_out", &pt);
                }
                opened.push((s, pt));
            }
        }
        if r.agree(&name, opened[0].0, opened[1].0) {
            r.agree_bytes(&name, "pt_out", &opened[0].1, &opened[1].1);
        }
    }
    r.finish();
}

#[test]
fn chacha20poly1305_rfc8439_vectors() {
    run_vector_file(vectors::CHACHA_RFC8439, CHACHA);
}

#[test]
fn chacha20poly1305_wycheproof_vectors() {
    run_vector_file(vectors::CHACHA_WYCHEPROOF, CHACHA);
}

#[test]
fn aes256gcm_spec_vectors() {
    run_vector_file(vectors::GCM_SPEC, GCM);
}

#[test]
fn aes256gcm_wycheproof_vectors() {
    run_vector_file(vectors::GCM_WYCHEPROOF, GCM);
}

/// A known-good message per algorithm (with AAD) and an empty-plaintext one, from the vectors.
fn base_cases(alg: i32) -> (AeadCase, AeadCase) {
    let (file, with_aad) = if alg == GCM {
        (vectors::GCM_SPEC, "GCM spec Test Case 16")
    } else {
        (vectors::CHACHA_RFC8439, "RFC 8439 2.8.2")
    };
    let f: File<AeadCase> = vectors::load(file);
    let full = f
        .cases
        .iter()
        .find(|c| c.name.as_deref() == Some(with_aad))
        .expect("base vector present")
        .clone();
    let wf: File<AeadCase> = vectors::load(if alg == GCM {
        vectors::GCM_WYCHEPROOF
    } else {
        vectors::CHACHA_WYCHEPROOF
    });
    let empty = wf
        .cases
        .iter()
        .find(|c| c.result == Expect::Valid && c.pt.is_empty())
        .expect("an empty-plaintext valid vector")
        .clone();
    (full, empty)
}

#[test]
fn seal_error_matrix() {
    let Some((a, b)) = common::setup("aead::seal_error_matrix") else {
        return;
    };
    let mut r = Report::new("aead::seal_error_matrix");
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = [0xaau8; 5];
    let pt = [0x70u8; 5];
    let (k, n, d, p) = (
        In::from(&key),
        In::from(&nonce),
        In::from(&aad),
        In::from(&pt),
    );
    for lib in [a, b] {
        for (alg, an) in ALGS {
            // (row, alg, key, nonce, aad, pt, ct_out NULL, expected)
            let rows: Vec<SealRow> = vec![
                (
                    "key NULL, key_len 32".into(),
                    alg,
                    In::Null { len: 32 },
                    n,
                    d,
                    p,
                    false,
                    EKI_ERR_NULL_POINTER,
                ),
                (
                    "nonce NULL, nonce_len 12".into(),
                    alg,
                    k,
                    In::Null { len: 12 },
                    d,
                    p,
                    false,
                    EKI_ERR_NULL_POINTER,
                ),
                (
                    "aad NULL, aad_len 5".into(),
                    alg,
                    k,
                    n,
                    In::Null { len: 5 },
                    p,
                    false,
                    EKI_ERR_NULL_POINTER,
                ),
                (
                    "pt NULL, pt_len 5".into(),
                    alg,
                    k,
                    n,
                    d,
                    In::Null { len: 5 },
                    false,
                    EKI_ERR_NULL_POINTER,
                ),
                (
                    "ct_out NULL, pt_len 5".into(),
                    alg,
                    k,
                    n,
                    d,
                    p,
                    true,
                    EKI_ERR_NULL_POINTER,
                ),
                (
                    "key_len 16".into(),
                    alg,
                    In::Bytes(&key[..16]),
                    n,
                    d,
                    p,
                    false,
                    EKI_ERR_INVALID_ARGUMENT,
                ),
                (
                    "key_len 0".into(),
                    alg,
                    In::NULL,
                    n,
                    d,
                    p,
                    false,
                    EKI_ERR_INVALID_ARGUMENT,
                ),
                (
                    "nonce_len 11".into(),
                    alg,
                    k,
                    In::Bytes(&nonce[..11]),
                    d,
                    p,
                    false,
                    EKI_ERR_INVALID_ARGUMENT,
                ),
                (
                    "nonce_len 13".into(),
                    alg,
                    k,
                    In::Bytes(&[0x24; 13]),
                    d,
                    p,
                    false,
                    EKI_ERR_INVALID_ARGUMENT,
                ),
                (
                    "pt NULL, pt_len 0, ct_out NULL".into(),
                    alg,
                    k,
                    n,
                    d,
                    In::NULL,
                    true,
                    EKI_OK,
                ),
                (
                    "aad NULL, aad_len 0".into(),
                    alg,
                    k,
                    n,
                    In::NULL,
                    p,
                    false,
                    EKI_OK,
                ),
            ];
            for (row, alg, key, nonce, aad, pt, ct_null, want) in rows {
                let row = format!("seal {an} {row}");
                let (s, ct, tag) = seal(lib, alg, key, nonce, aad, pt, ct_null);
                if r.status(lib, &row, s, want) && want != EKI_OK {
                    r.zeroed(lib, &row, "tag_out", &tag);
                    if !ct_null {
                        r.zeroed(lib, &row, "ct_out", &ct);
                    }
                }
            }
            let s = lib.aead_seal(alg, k, n, d, p, Out::Buf(&mut prefill(5)), None);
            r.status(
                lib,
                &format!("seal {an} tag_out NULL"),
                s,
                EKI_ERR_NULL_POINTER,
            );
        }
        for bad in [0, 3, -1, 99, i32::MIN, i32::MAX] {
            let row = format!("seal alg {bad}");
            let (s, ct, tag) = seal(lib, bad, k, n, d, p, false);
            if r.status(lib, &row, s, EKI_ERR_INVALID_ARGUMENT) {
                r.zeroed(lib, &row, "tag_out", &tag);
                r.zeroed(lib, &row, "ct_out", &ct);
            }
        }
        // NULL beats an unknown selector (§4.4).
        let (s, _, tag) = seal(lib, 99, k, n, d, In::from(&pt[..1]), true);
        if r.status(
            lib,
            "seal ct_out NULL, pt_len 1, alg 99",
            s,
            EKI_ERR_NULL_POINTER,
        ) {
            r.zeroed(lib, "seal ct_out NULL, pt_len 1, alg 99", "tag_out", &tag);
        }
    }
    r.finish();
}

#[test]
fn open_error_matrix() {
    let Some((a, b)) = common::setup("aead::open_error_matrix") else {
        return;
    };
    let mut r = Report::new("aead::open_error_matrix");
    for lib in [a, b] {
        for (alg, an) in ALGS {
            let (c, e) = base_cases(alg);
            let (k, n, d, ct) = (
                In::from(&c.key),
                In::from(&c.nonce),
                In::from(&c.aad),
                In::from(&c.ct),
            );
            let tag = tag16(&c.tag);
            let mut flipped = tag;
            flipped[0] ^= 0x01;
            let mut aad2 = c.aad.clone();
            aad2[0] ^= 0x80;
            let short = &c.ct[..c.ct.len() - 1];
            let etag = tag16(&e.tag);
            let (ek, en, ed) = (In::from(&e.key), In::from(&e.nonce), In::from(&e.aad));
            // (row, alg, key, nonce, aad, ct, tag, pt_out NULL, expected)
            let rows: Vec<OpenRow> = vec![
                (
                    "key NULL, key_len 32",
                    alg,
                    In::Null { len: 32 },
                    n,
                    d,
                    ct,
                    Some(&tag),
                    false,
                    EKI_ERR_NULL_POINTER,
                ),
                (
                    "nonce NULL, nonce_len 12",
                    alg,
                    k,
                    In::Null { len: 12 },
                    d,
                    ct,
                    Some(&tag),
                    false,
                    EKI_ERR_NULL_POINTER,
                ),
                (
                    "aad NULL, aad_len > 0",
                    alg,
                    k,
                    n,
                    In::Null { len: c.aad.len() },
                    ct,
                    Some(&tag),
                    false,
                    EKI_ERR_NULL_POINTER,
                ),
                (
                    "ct NULL, ct_len > 0",
                    alg,
                    k,
                    n,
                    d,
                    In::Null { len: c.ct.len() },
                    Some(&tag),
                    false,
                    EKI_ERR_NULL_POINTER,
                ),
                (
                    "tag NULL",
                    alg,
                    k,
                    n,
                    d,
                    ct,
                    None,
                    false,
                    EKI_ERR_NULL_POINTER,
                ),
                (
                    "pt_out NULL, ct_len > 0",
                    alg,
                    k,
                    n,
                    d,
                    ct,
                    Some(&tag),
                    true,
                    EKI_ERR_NULL_POINTER,
                ),
                (
                    "pt_out NULL and alg 99 (NULL first)",
                    99,
                    k,
                    n,
                    d,
                    ct,
                    Some(&tag),
                    true,
                    EKI_ERR_NULL_POINTER,
                ),
                (
                    "alg 0",
                    0,
                    k,
                    n,
                    d,
                    ct,
                    Some(&tag),
                    false,
                    EKI_ERR_INVALID_ARGUMENT,
                ),
                (
                    "alg 3",
                    3,
                    k,
                    n,
                    d,
                    ct,
                    Some(&tag),
                    false,
                    EKI_ERR_INVALID_ARGUMENT,
                ),
                (
                    "key_len 16",
                    alg,
                    In::Bytes(&c.key[..16]),
                    n,
                    d,
                    ct,
                    Some(&tag),
                    false,
                    EKI_ERR_INVALID_ARGUMENT,
                ),
                (
                    "nonce_len 11",
                    alg,
                    k,
                    In::Bytes(&c.nonce[..11]),
                    d,
                    ct,
                    Some(&tag),
                    false,
                    EKI_ERR_INVALID_ARGUMENT,
                ),
                (
                    "nonce_len 13",
                    alg,
                    k,
                    In::Bytes(&[0u8; 13]),
                    d,
                    ct,
                    Some(&tag),
                    false,
                    EKI_ERR_INVALID_ARGUMENT,
                ),
                (
                    "tag bit flipped",
                    alg,
                    k,
                    n,
                    d,
                    ct,
                    Some(&flipped),
                    false,
                    EKI_ERR_AUTH_FAILED,
                ),
                (
                    "aad changed",
                    alg,
                    k,
                    n,
                    In::from(&aad2),
                    ct,
                    Some(&tag),
                    false,
                    EKI_ERR_AUTH_FAILED,
                ),
                (
                    "ct truncated by 1",
                    alg,
                    k,
                    n,
                    d,
                    In::Bytes(short),
                    Some(&tag),
                    false,
                    EKI_ERR_AUTH_FAILED,
                ),
                ("unmodified", alg, k, n, d, ct, Some(&tag), false, EKI_OK),
                (
                    "ct_len 0 with the right tag",
                    alg,
                    ek,
                    en,
                    ed,
                    In::Bytes(&[]),
                    Some(&etag),
                    false,
                    EKI_OK,
                ),
                (
                    "ct NULL, ct_len 0, pt_out NULL, right tag",
                    alg,
                    ek,
                    en,
                    ed,
                    In::NULL,
                    Some(&etag),
                    true,
                    EKI_OK,
                ),
            ];
            for (row, alg, key, nonce, aad, ct, tag, pt_null, want) in rows {
                let row = format!("open {an} {row}");
                let (s, pt) = open(lib, alg, key, nonce, aad, ct, tag, pt_null);
                if !r.status(lib, &row, s, want) {
                    continue;
                }
                if want == EKI_OK {
                    if !pt_null && ct.len() == c.ct.len() {
                        r.bytes(lib, &row, "pt", &pt, &c.pt);
                    }
                } else if !pt_null {
                    r.zeroed(lib, &row, "pt_out", &pt);
                }
            }
        }
    }
    r.finish();
}

/// (d): seal in one library, open in the other, both directions, several lengths; the two seals
/// must also be byte-identical (both algorithms are deterministic for a given nonce).
#[test]
fn cross_language_round_trips() {
    let Some((a, b)) = common::setup("aead::cross_language_round_trips") else {
        return;
    };
    let mut r = Report::new("aead::cross_language_round_trips");
    let mut rng = Rng::new("aead_round_trip");
    for (alg, an) in ALGS {
        for len in [0usize, 1, 15, 16, 17, 64, 255, 1000, 4096, 65536, 1 << 20] {
            let key = rng.bytes(32);
            let nonce = rng.bytes(12);
            let aad_len = rng.below(64);
            let aad = rng.bytes(aad_len);
            let pt = rng.bytes(len);
            let (k, n, d, p) = (
                In::from(&key),
                In::from(&nonce),
                In::from(&aad),
                In::from(&pt),
            );
            let mut sealed = Vec::new();
            for (x, y) in [(a, b), (b, a)] {
                let ctx = format!("{an} len {len}: seal in {}, open in {}", x.name(), y.name());
                let (s, ct, tag) = seal(x, alg, k, n, d, p, false);
                if !r.status(x, &ctx, s, EKI_OK) {
                    continue;
                }
                let (s, back) = open(y, alg, k, n, d, In::from(&ct), Some(&tag), false);
                if r.status(y, &ctx, s, EKI_OK) {
                    r.bytes(y, &ctx, "pt", &back, &pt);
                }
                sealed.push((ct, tag));
            }
            if sealed.len() == 2 {
                let ctx = format!("{an} len {len}");
                r.agree_bytes(&ctx, "ct", &sealed[0].0, &sealed[1].0);
                r.agree_bytes(&ctx, "tag", &sealed[0].1, &sealed[1].1);
            }
        }
    }
    r.finish();
}

fn random_alg(rng: &mut Rng) -> i32 {
    if rng.chance(1, 20) {
        rng.pick(&[0, 3, -1, 99, i32::MAX])
    } else {
        rng.pick(&[GCM, CHACHA])
    }
}

fn random_fixed(rng: &mut Rng, want: usize, odd: &[usize]) -> Vec<u8> {
    let n = if rng.chance(1, 20) {
        rng.pick(odd)
    } else {
        want
    };
    rng.bytes(n)
}

/// (b): random algorithms, keys, nonces, AAD and plaintexts, occasionally invalid.
#[test]
fn differential_seal() {
    let Some((a, b)) = common::setup("aead::differential_seal") else {
        return;
    };
    let mut r = Report::new("aead::differential_seal");
    let mut rng = Rng::new("aead_seal");
    let mut oks = OkCount::default();
    for i in 0..diff_n() {
        let ctx = iter_ctx("aead_seal", i);
        let alg = random_alg(&mut rng);
        let key = random_fixed(&mut rng, 32, &[0, 16, 31, 33, 64]);
        let nonce = random_fixed(&mut rng, 12, &[0, 8, 11, 13, 16]);
        let aad = rng.data(300);
        let pt = rng.data(5000);
        let (k, n) = (
            In::maybe_null(&key, rng.chance(1, 2)),
            In::maybe_null(&nonce, rng.chance(1, 2)),
        );
        let (d, p) = (
            In::maybe_null(&aad, rng.chance(1, 2)),
            In::maybe_null(&pt, rng.chance(1, 2)),
        );
        let ct_null = pt.is_empty() && rng.chance(1, 2);
        let (sa, ca, ta) = seal(a, alg, k, n, d, p, ct_null);
        let (sb, cb, tb) = seal(b, alg, k, n, d, p, ct_null);
        oks.add(sa, sb);
        if r.agree(&ctx, sa, sb) {
            r.agree_bytes(&ctx, "ct", &ca, &cb);
            r.agree_bytes(&ctx, "tag", &ta, &tb);
        }
        for (lib, s, c, t) in [(a, sa, &ca, &ta), (b, sb, &cb, &tb)] {
            if s != EKI_OK {
                r.zeroed_after(lib, &ctx, s, "ct_out", c);
                r.zeroed_after(lib, &ctx, s, "tag_out", t);
            }
        }
    }
    oks.require_some(&mut r, "aead_seal");
    r.finish();
}

/// (b): ciphertexts sealed by libekicore (random bytes if it cannot seal), opened by both after a
/// random tampering (none, bit flip in ct / tag / aad, truncation, extension).
#[test]
fn differential_open() {
    let Some((a, b)) = common::setup("aead::differential_open") else {
        return;
    };
    let mut r = Report::new("aead::differential_open");
    let mut rng = Rng::new("aead_open");
    let mut oks = OkCount::default();
    for i in 0..diff_n() {
        let ctx = iter_ctx("aead_open", i);
        let alg = random_alg(&mut rng);
        let key = random_fixed(&mut rng, 32, &[0, 16, 31, 33, 64]);
        let nonce = random_fixed(&mut rng, 12, &[0, 8, 11, 13, 16]);
        let mut aad = rng.data(300);
        let pt = rng.data(5000);
        let (s, mut ct, mut tag) = seal(
            a,
            alg,
            In::from(&key),
            In::from(&nonce),
            In::from(&aad),
            In::from(&pt),
            false,
        );
        if s != EKI_OK {
            ct = rng.bytes(pt.len());
            tag = rng.array();
        }
        match rng.below(8) {
            0 => rng.flip_bit(&mut ct),
            1 => rng.flip_bit(&mut tag),
            2 => rng.flip_bit(&mut aad),
            3 => {
                let n = rng.below(ct.len() + 1);
                ct.truncate(n);
            }
            4 => ct.push(0),
            _ => {}
        }
        let (k, n) = (
            In::maybe_null(&key, rng.chance(1, 2)),
            In::maybe_null(&nonce, rng.chance(1, 2)),
        );
        let (d, c) = (
            In::maybe_null(&aad, rng.chance(1, 2)),
            In::maybe_null(&ct, rng.chance(1, 2)),
        );
        let pt_null = ct.is_empty() && rng.chance(1, 2);
        let (sa, pa) = open(a, alg, k, n, d, c, Some(&tag), pt_null);
        let (sb, pb) = open(b, alg, k, n, d, c, Some(&tag), pt_null);
        oks.add(sa, sb);
        if r.agree(&ctx, sa, sb) {
            r.agree_bytes(&ctx, "pt_out", &pa, &pb);
        }
        for (lib, s, p) in [(a, sa, &pa), (b, sb, &pb)] {
            if s != EKI_OK {
                r.zeroed_after(lib, &ctx, s, "pt_out", p);
            }
        }
    }
    oks.require_some(&mut r, "aead_open");
    r.finish();
}
