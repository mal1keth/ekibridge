//! `eki_ecdsa_p256_verify`: RFC 6979 and Wycheproof vectors, the §4.4 rows, and a seeded
//! differential over mutated vectors. Signing is checked in the key-store modules, by
//! cross-verification only (signatures are not deterministic in every backend).

mod common;

use common::{OkCount, Report, Rng, diff_n, iter_ctx};
use ekicore_conformance::status::*;
use ekicore_conformance::vectors::{self, EcdsaCase, Expect, File};
use ekicore_conformance::{In, Lib};

/// P-256 group order n (RFC 6979 A.2.5 "q"; also `openssl ecparam -name prime256v1 -text`).
const N: [u8; 32] = hex32("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
/// P-256 field prime p (`openssl ecparam -name prime256v1 -param_enc explicit -text`).
const P: [u8; 32] = hex32("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");

const fn hex32(s: &str) -> [u8; 32] {
    const fn nib(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("bad hex"),
        }
    }
    let b = s.as_bytes();
    assert!(b.len() == 64);
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nib(b[2 * i]) << 4) | nib(b[2 * i + 1]);
        i += 1;
    }
    out
}

/// `n - x` for 32-byte big-endian integers with `x <= n` (to build the high-s twin of a
/// signature; plain byte arithmetic, not a cryptographic primitive).
fn n_minus(x: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut d = i16::from(N[i]) - i16::from(x[i]) - borrow;
        borrow = 0;
        if d < 0 {
            d += 256;
            borrow = 1;
        }
        out[i] = d as u8;
    }
    out
}

/// (row, public_key, msg, sig, expected status)
type Row<'a> = (
    &'static str,
    Option<&'a [u8; 65]>,
    In<'a>,
    Option<&'a [u8; 64]>,
    i32,
);

fn arr<const L: usize>(v: &[u8]) -> [u8; L] {
    v.try_into()
        .expect("vector field has the fixed length (checked by the vector-file test)")
}

fn verify(lib: &Lib, pk: &[u8; 65], msg: In, sig: &[u8; 64]) -> i32 {
    lib.ecdsa_p256_verify(Some(pk), msg, Some(sig))
}

fn run_vector_file(file_name: &str) {
    let Some((a, b)) = common::setup(&format!("ecdsa::{file_name}")) else {
        return;
    };
    let mut r = Report::new(&format!("ecdsa::{file_name}"));
    let file: File<EcdsaCase> = vectors::load(file_name);
    for c in &file.cases {
        let name = format!("{file_name} {}", c.label());
        let want = match c.result {
            Expect::Valid => EKI_OK,
            Expect::Invalid => EKI_ERR_AUTH_FAILED,
        };
        let (pk, sig) = (arr::<65>(&c.public_key), arr::<64>(&c.sig));
        let sa = verify(a, &pk, In::from(&c.msg), &sig);
        let sb = verify(b, &pk, In::from(&c.msg), &sig);
        r.status(a, &name, sa, want);
        r.status(b, &name, sb, want);
        r.agree(&name, sa, sb);
    }
    r.finish();
}

#[test]
fn rfc6979_vectors() {
    run_vector_file(vectors::ECDSA_RFC6979);
}

#[test]
fn wycheproof_p1363_vectors() {
    run_vector_file(vectors::ECDSA_WYCHEPROOF);
}

#[test]
fn error_matrix() {
    let Some((a, b)) = common::setup("ecdsa::error_matrix") else {
        return;
    };
    let mut r = Report::new("ecdsa::error_matrix");
    let file: File<EcdsaCase> = vectors::load(vectors::ECDSA_RFC6979);
    let c = &file.cases[0]; // "sample"
    let pk = arr::<65>(&c.public_key);
    let sig = arr::<64>(&c.sig);
    let msg = c.msg.clone();

    let mut prefix02 = pk;
    prefix02[0] = 0x02;
    let mut prefix00 = pk;
    prefix00[0] = 0x00;
    let mut off_curve = pk;
    off_curve[64] ^= 0x01;
    let mut x_is_p = pk;
    x_is_p[1..33].copy_from_slice(&P);
    let mut r_zero = sig;
    r_zero[..32].fill(0);
    let mut s_zero = sig;
    s_zero[32..].fill(0);
    let mut s_is_n = sig;
    s_is_n[32..].copy_from_slice(&N);
    let mut r_is_n = sig;
    r_is_n[..32].copy_from_slice(&N);
    let mut high_s = sig;
    high_s[32..].copy_from_slice(&n_minus(&sig[32..]));
    let other_msg = b"other message".to_vec();

    for lib in [a, b] {
        let rows: Vec<Row> = vec![
            (
                "public_key NULL",
                None,
                In::from(&msg),
                Some(&sig),
                EKI_ERR_NULL_POINTER,
            ),
            (
                "msg NULL, msg_len 6",
                Some(&pk),
                In::Null { len: 6 },
                Some(&sig),
                EKI_ERR_NULL_POINTER,
            ),
            (
                "sig NULL",
                Some(&pk),
                In::from(&msg),
                None,
                EKI_ERR_NULL_POINTER,
            ),
            (
                "sig NULL and public_key[0] = 0x02 (NULL first)",
                Some(&prefix02),
                In::from(&msg),
                None,
                EKI_ERR_NULL_POINTER,
            ),
            (
                "public_key[0] = 0x02",
                Some(&prefix02),
                In::from(&msg),
                Some(&sig),
                EKI_ERR_INVALID_ARGUMENT,
            ),
            (
                "public_key[0] = 0x00",
                Some(&prefix00),
                In::from(&msg),
                Some(&sig),
                EKI_ERR_INVALID_ARGUMENT,
            ),
            (
                "off-curve point",
                Some(&off_curve),
                In::from(&msg),
                Some(&sig),
                EKI_ERR_INVALID_ARGUMENT,
            ),
            (
                "x coordinate = p",
                Some(&x_is_p),
                In::from(&msg),
                Some(&sig),
                EKI_ERR_INVALID_ARGUMENT,
            ),
            (
                "r = 0",
                Some(&pk),
                In::from(&msg),
                Some(&r_zero),
                EKI_ERR_AUTH_FAILED,
            ),
            (
                "s = 0",
                Some(&pk),
                In::from(&msg),
                Some(&s_zero),
                EKI_ERR_AUTH_FAILED,
            ),
            (
                "s = n",
                Some(&pk),
                In::from(&msg),
                Some(&s_is_n),
                EKI_ERR_AUTH_FAILED,
            ),
            (
                "r = n",
                Some(&pk),
                In::from(&msg),
                Some(&r_is_n),
                EKI_ERR_AUTH_FAILED,
            ),
            (
                "sig over other msg",
                Some(&pk),
                In::from(&other_msg),
                Some(&sig),
                EKI_ERR_AUTH_FAILED,
            ),
            (
                "msg NULL, msg_len 0 (signature is over \"sample\")",
                Some(&pk),
                In::NULL,
                Some(&sig),
                EKI_ERR_AUTH_FAILED,
            ),
            (
                "high-s twin is accepted",
                Some(&pk),
                In::from(&msg),
                Some(&high_s),
                EKI_OK,
            ),
            ("unmodified", Some(&pk), In::from(&msg), Some(&sig), EKI_OK),
        ];
        for (row, pk, m, sg, want) in rows {
            let s = lib.ecdsa_p256_verify(pk, m, sg);
            r.status(lib, row, s, want);
        }
    }
    r.finish();
}

/// (b): random Wycheproof cases, randomly mutated (bit flips in key, message or signature,
/// prefix changes, r or s forced to 0 or n, random signatures), through both libraries.
#[test]
fn differential() {
    let Some((a, b)) = common::setup("ecdsa::differential") else {
        return;
    };
    let mut r = Report::new("ecdsa::differential");
    let file: File<EcdsaCase> = vectors::load(vectors::ECDSA_WYCHEPROOF);
    let mut rng = Rng::new("ecdsa_p256_verify");
    let mut oks = OkCount::default();
    for i in 0..diff_n() {
        let ctx = iter_ctx("ecdsa_p256_verify", i);
        let c = &file.cases[rng.below(file.cases.len())];
        let mut pk = arr::<65>(&c.public_key);
        let mut sig = arr::<64>(&c.sig);
        let mut msg = c.msg.clone();
        match rng.below(12) {
            0 => rng.flip_bit(&mut sig),
            1 => rng.flip_bit(&mut msg),
            2 => rng.flip_bit(&mut pk[1..]),
            3 => pk[0] = rng.pick(&[0x00, 0x02, 0x03, 0x05, 0xff]),
            4 => sig[..32].fill(0),
            5 => sig[32..].copy_from_slice(&N),
            6 => sig = rng.array(),
            7 => msg = rng.data(300),
            _ => {}
        }
        let m = In::maybe_null(&msg, rng.chance(1, 2));
        let sa = verify(a, &pk, m, &sig);
        let sb = verify(b, &pk, m, &sig);
        oks.add(sa, sb);
        r.agree(&ctx, sa, sb);
    }
    oks.require_some(&mut r, "ecdsa_p256_verify");
    r.finish();
}

#[test]
fn n_minus_is_correct() {
    // n - 1 = ...632550; n - (n - 1) = 1.
    let one = {
        let mut x = [0u8; 32];
        x[31] = 1;
        x
    };
    let n1 = n_minus(&one);
    assert_eq!(n1[31], 0x50);
    assert_eq!(n_minus(&n1), one);
}
