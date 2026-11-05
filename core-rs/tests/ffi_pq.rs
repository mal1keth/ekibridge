//! Hybrid X25519 + ML-KEM-768 KEM through the C ABI (lesson L9).
//!
//! Rows: plan §4.4 `hybrid` rows and the KEM sequence of §4.2 (NULL checks, then UNSUPPORTED
//! when not compiled in, then the all-zero X25519 and ML-KEM key checks; decapsulation never
//! fails). The round-trip tests need `--features pq`; without it the functions must answer
//! `EKI_ERR_UNSUPPORTED`, which the stubs already do.

mod common;

use ekicore_abi::{
    EKI_HYBRID_CT_LEN, EKI_HYBRID_PK_LEN, EKI_HYBRID_SK_LEN, EKI_HYBRID_SS_LEN, eki_status,
};
use ekicore_rs::ffi::{eki_hybrid_kem_decap, eki_hybrid_kem_encap, eki_hybrid_kem_keygen};

type Pk = [u8; EKI_HYBRID_PK_LEN];
type Sk = [u8; EKI_HYBRID_SK_LEN];
type Ct = [u8; EKI_HYBRID_CT_LEN];
type Ss = [u8; EKI_HYBRID_SS_LEN];

const FILL: u8 = common::FILL;

fn keygen(pk: Option<&mut Pk>, sk: Option<&mut Sk>) -> eki_status {
    let pk = pk.map_or(core::ptr::null_mut(), |p| p.as_mut_ptr());
    let sk = sk.map_or(core::ptr::null_mut(), |s| s.as_mut_ptr());
    // SAFETY: each pointer is NULL or a live array of the fixed size the ABI requires.
    unsafe { eki_hybrid_kem_keygen(pk, sk) }
}

fn encap(pk: Option<&Pk>, ct: Option<&mut Ct>, ss: Option<&mut Ss>) -> eki_status {
    let pk = pk.map_or(core::ptr::null(), |p| p.as_ptr());
    let ct = ct.map_or(core::ptr::null_mut(), |c| c.as_mut_ptr());
    let ss = ss.map_or(core::ptr::null_mut(), |s| s.as_mut_ptr());
    // SAFETY: each pointer is NULL or a live array of the fixed size the ABI requires.
    unsafe { eki_hybrid_kem_encap(pk, ct, ss) }
}

fn decap(sk: Option<&Sk>, ct: Option<&Ct>, ss: Option<&mut Ss>) -> eki_status {
    let sk = sk.map_or(core::ptr::null(), |s| s.as_ptr());
    let ct = ct.map_or(core::ptr::null(), |c| c.as_ptr());
    let ss = ss.map_or(core::ptr::null_mut(), |s| s.as_mut_ptr());
    // SAFETY: each pointer is NULL or a live array of the fixed size the ABI requires.
    unsafe { eki_hybrid_kem_decap(sk, ct, ss) }
}

/// NULL pointers are reported before anything else, with or without the feature.
#[test]
fn null_pointers() {
    use eki_status::EKI_ERR_NULL_POINTER;
    let pk: Pk = [FILL; EKI_HYBRID_PK_LEN];
    let sk: Sk = [FILL; EKI_HYBRID_SK_LEN];
    let ct: Ct = [FILL; EKI_HYBRID_CT_LEN];

    let mut sk_out = sk;
    assert_eq!(
        keygen(None, Some(&mut sk_out)),
        EKI_ERR_NULL_POINTER,
        "keygen pk_out"
    );
    common::assert_zero(&sk_out);
    let mut pk_out = pk;
    assert_eq!(
        keygen(Some(&mut pk_out), None),
        EKI_ERR_NULL_POINTER,
        "keygen sk_out"
    );
    common::assert_zero(&pk_out);

    let (mut ct_out, mut ss) = (ct, [FILL; 32]);
    assert_eq!(
        encap(None, Some(&mut ct_out), Some(&mut ss)),
        EKI_ERR_NULL_POINTER,
        "encap pk"
    );
    common::assert_zero(&ct_out);
    common::assert_zero(&ss);
    assert_eq!(
        encap(Some(&pk), None, Some(&mut [FILL; 32])),
        EKI_ERR_NULL_POINTER,
        "encap ct_out"
    );
    assert_eq!(
        encap(Some(&pk), Some(&mut ct_out), None),
        EKI_ERR_NULL_POINTER,
        "encap ss_out"
    );

    let mut ss = [FILL; 32];
    assert_eq!(
        decap(None, Some(&ct), Some(&mut ss)),
        EKI_ERR_NULL_POINTER,
        "decap sk"
    );
    common::assert_zero(&ss);
    assert_eq!(
        decap(Some(&sk), None, Some(&mut [FILL; 32])),
        EKI_ERR_NULL_POINTER,
        "decap ct"
    );
    assert_eq!(
        decap(Some(&sk), Some(&ct), None),
        EKI_ERR_NULL_POINTER,
        "decap ss_out"
    );
}

#[cfg(not(feature = "pq"))]
mod without_pq {
    use super::*;
    use eki_status::EKI_ERR_UNSUPPORTED;

    /// The stubs and the finished library agree on this one: not compiled in → UNSUPPORTED.
    #[test]
    fn unsupported_with_valid_pointers() {
        let mut pk: Pk = [FILL; EKI_HYBRID_PK_LEN];
        let mut sk: Sk = [FILL; EKI_HYBRID_SK_LEN];
        let mut ct: Ct = [FILL; EKI_HYBRID_CT_LEN];
        let mut ss: Ss = [FILL; EKI_HYBRID_SS_LEN];
        assert_eq!(keygen(Some(&mut pk), Some(&mut sk)), EKI_ERR_UNSUPPORTED);
        assert_eq!(
            encap(Some(&pk), Some(&mut ct), Some(&mut ss)),
            EKI_ERR_UNSUPPORTED
        );
        assert_eq!(
            decap(Some(&sk), Some(&ct), Some(&mut ss)),
            EKI_ERR_UNSUPPORTED
        );
    }

    /// UNSUPPORTED is an error status, so every output is zero-filled (§4.2).
    #[test]
    fn unsupported_zeroes_outputs() {
        let mut pk: Pk = [FILL; EKI_HYBRID_PK_LEN];
        let mut sk: Sk = [FILL; EKI_HYBRID_SK_LEN];
        assert_eq!(keygen(Some(&mut pk), Some(&mut sk)), EKI_ERR_UNSUPPORTED);
        common::assert_zero(&pk);
        common::assert_zero(&sk);

        let pk_in: Pk = [FILL; EKI_HYBRID_PK_LEN];
        let mut ct: Ct = [FILL; EKI_HYBRID_CT_LEN];
        let mut ss: Ss = [FILL; EKI_HYBRID_SS_LEN];
        assert_eq!(
            encap(Some(&pk_in), Some(&mut ct), Some(&mut ss)),
            EKI_ERR_UNSUPPORTED
        );
        common::assert_zero(&ct);
        common::assert_zero(&ss);

        let sk_in: Sk = [FILL; EKI_HYBRID_SK_LEN];
        let ct_in: Ct = [FILL; EKI_HYBRID_CT_LEN];
        let mut ss: Ss = [FILL; EKI_HYBRID_SS_LEN];
        assert_eq!(
            decap(Some(&sk_in), Some(&ct_in), Some(&mut ss)),
            EKI_ERR_UNSUPPORTED
        );
        common::assert_zero(&ss);
    }
}

#[cfg(feature = "pq")]
mod with_pq {
    use super::*;
    use eki_status::{EKI_ERR_INVALID_ARGUMENT, EKI_OK};

    /// Length of the X25519 part, which is also the offset of the ML-KEM part, of `pk`, `sk` and `ct`.
    const X25519_LEN: usize = 32;

    fn new_keypair() -> (Pk, Sk) {
        let mut pk: Pk = [FILL; EKI_HYBRID_PK_LEN];
        let mut sk: Sk = [FILL; EKI_HYBRID_SK_LEN];
        assert_eq!(keygen(Some(&mut pk), Some(&mut sk)), EKI_OK, "keygen");
        (pk, sk)
    }

    fn encapsulate(pk: &Pk) -> (Ct, Ss) {
        let mut ct: Ct = [FILL; EKI_HYBRID_CT_LEN];
        let mut ss: Ss = [FILL; EKI_HYBRID_SS_LEN];
        assert_eq!(
            encap(Some(pk), Some(&mut ct), Some(&mut ss)),
            EKI_OK,
            "encap"
        );
        (ct, ss)
    }

    fn decapsulate(sk: &Sk, ct: &Ct) -> (eki_status, Ss) {
        let mut ss: Ss = [FILL; EKI_HYBRID_SS_LEN];
        let status = decap(Some(sk), Some(ct), Some(&mut ss));
        (status, ss)
    }

    #[test]
    fn round_trip() {
        let (pk, sk) = new_keypair();
        let (ct, ss) = encapsulate(&pk);
        let (status, ss2) = decapsulate(&sk, &ct);
        assert_eq!(status, EKI_OK);
        assert_eq!(ss, ss2, "both sides derive the same secret");
        assert_ne!(ss, [FILL; 32]);

        // Fresh randomness everywhere.
        let (pk2, sk2) = new_keypair();
        assert_ne!(pk, pk2);
        assert_ne!(sk, sk2);
        let (ct2, ss3) = encapsulate(&pk);
        assert_ne!(ct, ct2);
        assert_ne!(ss, ss3);

        // Decapsulation is deterministic.
        assert_eq!(decapsulate(&sk, &ct), (EKI_OK, ss));
    }

    #[test]
    fn tampered_mlkem_ciphertext_gives_a_different_secret() {
        // Implicit rejection: decapsulation succeeds with an unrelated secret.
        let (pk, sk) = new_keypair();
        let (ct, ss) = encapsulate(&pk);
        for index in [X25519_LEN, X25519_LEN + 500, EKI_HYBRID_CT_LEN - 1] {
            let mut bad = ct;
            bad[index] ^= 0x01;
            let (status, other) = decapsulate(&sk, &bad);
            assert_eq!(status, EKI_OK, "byte {index}");
            assert_ne!(other, ss, "byte {index}");
        }
    }

    #[test]
    fn tampered_x25519_ciphertext_gives_a_different_secret() {
        let (pk, sk) = new_keypair();
        let (ct, ss) = encapsulate(&pk);
        let mut bad = ct;
        bad[0] ^= 0x02;
        let (status, other) = decapsulate(&sk, &bad);
        assert_eq!(status, EKI_OK);
        assert_ne!(other, ss);
    }

    #[test]
    fn wrong_secret_key_gives_a_different_secret() {
        let (pk, _) = new_keypair();
        let (_, other_sk) = new_keypair();
        let (ct, ss) = encapsulate(&pk);
        let (status, other) = decapsulate(&other_sk, &ct);
        assert_eq!(status, EKI_OK);
        assert_ne!(other, ss);
    }

    #[test]
    fn encap_to_all_zero_x25519_part_is_invalid() {
        let (mut pk, _) = new_keypair();
        pk[..X25519_LEN].fill(0);
        let mut ct: Ct = [FILL; EKI_HYBRID_CT_LEN];
        let mut ss: Ss = [FILL; EKI_HYBRID_SS_LEN];
        assert_eq!(
            encap(Some(&pk), Some(&mut ct), Some(&mut ss)),
            EKI_ERR_INVALID_ARGUMENT
        );
        common::assert_zero(&ct);
        common::assert_zero(&ss);
    }

    #[test]
    fn decap_with_all_zero_x25519_part_is_invalid() {
        // The all-zero X25519 point gives an all-zero shared secret (§4.2).
        let (pk, sk) = new_keypair();
        let (mut ct, _) = encapsulate(&pk);
        ct[..X25519_LEN].fill(0);
        let (status, ss) = decapsulate(&sk, &ct);
        assert_eq!(status, EKI_ERR_INVALID_ARGUMENT);
        common::assert_zero(&ss);
    }

    #[test]
    fn encap_to_mlkem_key_failing_the_modulus_check_is_invalid() {
        // 0xff bytes encode 12-bit coefficients of 4095 ≥ q = 3329 (FIPS 203 §7.2 check).
        let (mut pk, _) = new_keypair();
        pk[X25519_LEN..X25519_LEN + 384].fill(0xff);
        let mut ct: Ct = [FILL; EKI_HYBRID_CT_LEN];
        let mut ss: Ss = [FILL; EKI_HYBRID_SS_LEN];
        assert_eq!(
            encap(Some(&pk), Some(&mut ct), Some(&mut ss)),
            EKI_ERR_INVALID_ARGUMENT
        );
        common::assert_zero(&ct);
        common::assert_zero(&ss);
    }

    #[test]
    fn key_pairs_share_no_half() {
        // Independent key pairs differ in both the X25519 and the ML-KEM part.
        let (pk1, sk1) = new_keypair();
        let (pk2, sk2) = new_keypair();
        assert_ne!(pk1[..X25519_LEN], pk2[..X25519_LEN]);
        assert_ne!(pk1[X25519_LEN..], pk2[X25519_LEN..]);
        assert_ne!(sk1[..X25519_LEN], sk2[..X25519_LEN]);
        assert_ne!(sk1[X25519_LEN..], sk2[X25519_LEN..]);
    }
}
