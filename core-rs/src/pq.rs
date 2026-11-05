//! Hybrid X25519 + ML-KEM-768 key encapsulation over `x25519-dalek` and `ml-kem`.
//!
//! The safe layer behind `eki_hybrid_kem_*`, compiled with the `pq` feature: fixed-size arrays in,
//! `Result<_, Error>` out. The shared secret is HKDF-SHA256 over both partial secrets, bound to
//! the whole ciphertext and the whole public key.

use ekicore_abi::{EKI_HYBRID_CT_LEN, EKI_HYBRID_PK_LEN, EKI_HYBRID_SK_LEN, EKI_HYBRID_SS_LEN};
use ml_kem::array::typenum::Unsigned;
use ml_kem::{
    Decapsulate, DecapsulationKey768, EncapsulationKey768, Kem, Key, KeyExport, KeyInit,
    KeySizeUser, MlKem768, Seed,
};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use subtle::ConstantTimeEq;
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::error::Error;
use crate::hkdf::hkdf_sha256;

/// Public key: the X25519 public key, then the ML-KEM-768 encapsulation key.
/// cbindgen:ignore
pub type PublicKey = [u8; EKI_HYBRID_PK_LEN];

/// Ciphertext: the X25519 ephemeral public key, then the ML-KEM-768 ciphertext.
/// cbindgen:ignore
pub type Ciphertext = [u8; EKI_HYBRID_CT_LEN];

/// Secret bytes on the heap, wiped when dropped.
///
/// A `SecretBox` and not a `Zeroizing` array: the bytes are allocated once, so returning the value
/// or passing it on moves a pointer and leaves no unwiped copy of the bytes on the stack behind.
/// cbindgen:ignore
pub type Secret<const N: usize> = SecretBox<[u8; N]>;

/// Secret key: the X25519 secret as drawn (not clamped), then the 64-byte ML-KEM-768 seed `d || z`.
/// cbindgen:ignore
pub type SecretKey = Secret<EKI_HYBRID_SK_LEN>;

/// Shared secret, the 32-byte output of the combiner.
/// cbindgen:ignore
pub type SharedSecret = Secret<EKI_HYBRID_SS_LEN>;

/// Length of an X25519 secret key, public key or shared secret, and so of the first part of `pk`,
/// `sk` and `ct`.
/// cbindgen:ignore
const X25519_LEN: usize = 32;

/// Length of the ML-KEM-768 seed `d || z`.
/// cbindgen:ignore
const SEED_LEN: usize = 64;

/// Length of the ML-KEM-768 encapsulation key.
/// cbindgen:ignore
const MLKEM_EK_LEN: usize = 1184;

/// Length of the ML-KEM-768 ciphertext.
/// cbindgen:ignore
const MLKEM_CT_LEN: usize = 1088;

/// Length of the ML-KEM-768 shared secret, which is also the X25519 one.
/// cbindgen:ignore
const PARTIAL_LEN: usize = 32;

/// Length of the message `m` that ML-KEM-768 encapsulation takes as its randomness.
/// cbindgen:ignore
const MLKEM_MESSAGE_LEN: usize = 32;

/// Randomness of one encapsulation: the X25519 ephemeral secret, then the ML-KEM-768 message.
/// cbindgen:ignore
const ENCAP_RANDOM_LEN: usize = X25519_LEN + MLKEM_MESSAGE_LEN;

/// Length of the combiner's input keying material: the two partial secrets.
/// cbindgen:ignore
const IKM_LEN: usize = 2 * PARTIAL_LEN;

/// Domain separation of the combiner, the start of its HKDF `info`.
/// cbindgen:ignore
const COMBINER_LABEL: &[u8] = b"ekibridge-hybrid-x25519-mlkem768-v1";

/// The layouts of the ABI constants are made of the sizes of the two halves, and the sizes used
/// here are those of the `ml-kem` types. A mismatch fails to compile instead of surfacing as an
/// error on a valid call.
/// cbindgen:ignore
const _: () = {
    assert!(EKI_HYBRID_PK_LEN == X25519_LEN + MLKEM_EK_LEN);
    assert!(EKI_HYBRID_SK_LEN == X25519_LEN + SEED_LEN);
    assert!(EKI_HYBRID_CT_LEN == X25519_LEN + MLKEM_CT_LEN);
    assert!(<<EncapsulationKey768 as KeySizeUser>::KeySize as Unsigned>::USIZE == MLKEM_EK_LEN);
    assert!(<<DecapsulationKey768 as KeySizeUser>::KeySize as Unsigned>::USIZE == SEED_LEN);
    assert!(<<MlKem768 as Kem>::CiphertextSize as Unsigned>::USIZE == MLKEM_CT_LEN);
    assert!(<<MlKem768 as Kem>::SharedKeySize as Unsigned>::USIZE == PARTIAL_LEN);
};

/// The expanded ML-KEM key and the secret key box wipe themselves when dropped; this assertion
/// makes that a compile-time fact rather than a reading of the crates' sources. The wipe of the
/// expanded key exists only with the `zeroize` feature of `ml-kem`.
/// cbindgen:ignore
const _: () = {
    const fn wipes_on_drop<T: ZeroizeOnDrop>() {}
    wipes_on_drop::<DecapsulationKey768>();
    wipes_on_drop::<SecretKey>();
};

/// Generates a key pair: 96 random bytes are the secret key, the public key is derived from them.
///
/// The X25519 secret is stored as drawn, and clamped by the X25519 function each time it is used.
/// Failure of the system random source is [`Error::Backend`].
pub fn keygen() -> Result<(PublicKey, SecretKey), Error> {
    let mut sk = secret::<EKI_HYBRID_SK_LEN>();
    random(sk.expose_secret_mut())?;
    // The same derivation `decap` uses to rebuild `pk`, so the two cannot disagree.
    let pk = public_key(sk.expose_secret())?;
    Ok((pk, sk))
}

/// Encapsulates a fresh shared secret to `pk` and returns the ciphertext and the secret.
///
/// An ML-KEM encapsulation key that fails the FIPS 203 modulus check, and an X25519 public key of
/// small order (the shared secret would be all zero), are [`Error::InvalidArgument`]. Failure of
/// the system random source is [`Error::Backend`]; it is reported before a small-order X25519 key
/// can be, since that check is made on the result of the key agreement.
pub fn encap(pk: &PublicKey) -> Result<(Ciphertext, SharedSecret), Error> {
    let (x25519_peer, ek) = parse_public_key(pk)?;
    let mut randomness = secret::<ENCAP_RANDOM_LEN>();
    random(randomness.expose_secret_mut())?;
    encapsulate(pk, x25519_peer, &ek, randomness.expose_secret())
}

/// Recovers the shared secret from `ct` with the secret key `sk`.
///
/// `pk` is rebuilt from `sk` for the combiner. An X25519 ephemeral key of small order is
/// [`Error::InvalidArgument`]. A malformed or foreign ML-KEM ciphertext is not an error: implicit
/// rejection makes the crate return an unrelated secret.
pub fn decap(sk: &[u8; EKI_HYBRID_SK_LEN], ct: &Ciphertext) -> Result<SharedSecret, Error> {
    let (x25519_secret, seed) = split::<EKI_HYBRID_SK_LEN, X25519_LEN, SEED_LEN>(sk)?;
    let dk = mlkem_key(seed);
    let pk = assemble_public_key(x25519_secret, &dk);

    let (x25519_ephemeral, mlkem_ct) = split::<EKI_HYBRID_CT_LEN, X25519_LEN, MLKEM_CT_LEN>(ct)?;
    let ss_x25519 = x25519_shared(x25519_secret, x25519_ephemeral)?;
    // The crate's `Decapsulate` is infallible: a ciphertext that does not re-encrypt to itself
    // yields the pseudorandom rejection secret `J(z || c)` in constant time.
    let ss_mlkem = Zeroizing::new(dk.decapsulate(<&_>::from(mlkem_ct)));
    combine(&ss_x25519, <&_>::from(&*ss_mlkem), ct, &pk)
}

/// An empty heap buffer of `N` bytes for secret material, wiped when dropped.
fn secret<const N: usize>() -> Secret<N> {
    SecretBox::new(Box::new([0u8; N]))
}

/// Fills `buf` from the operating system's random source.
fn random(buf: &mut [u8]) -> Result<(), Error> {
    getrandom::fill(buf).map_err(|_| Error::Backend)
}

/// Writes `a || b` to `out`. The lengths are tied to each other at compile time, so the copies
/// cannot fail at run time.
fn join_into<const A: usize, const B: usize, const N: usize>(
    out: &mut [u8; N],
    a: &[u8; A],
    b: &[u8; B],
) {
    const { assert!(A + B == N, "the two parts fill the output exactly") };
    out[..A].copy_from_slice(a);
    out[A..].copy_from_slice(b);
}

/// Splits `bytes` after its first `A` bytes into two arrays. The sizes are tied to each other at
/// compile time, so the conversions cannot fail; they are mapped instead of unwrapped so that this
/// path, which caller input reaches, contains no panic.
fn split<const N: usize, const A: usize, const B: usize>(
    bytes: &[u8; N],
) -> Result<(&[u8; A], &[u8; B]), Error> {
    const { assert!(A + B == N, "the two parts cover the input exactly") };
    let (a, b) = bytes.split_at(A);
    let a = a.try_into().map_err(|_| Error::Internal)?;
    let b = b.try_into().map_err(|_| Error::Internal)?;
    Ok((a, b))
}

/// The expanded ML-KEM-768 key of `seed`, which is `d` in its first 32 bytes and `z` in its last
/// 32 (the crate splits the array in that order). The key wipes itself when dropped.
fn mlkem_key(seed: &[u8; SEED_LEN]) -> DecapsulationKey768 {
    DecapsulationKey768::new(<&Seed>::from(seed))
}

/// The X25519 public key of `secret`: the function clamps the secret and multiplies the base point.
///
/// The crate takes the secret by value, so each call leaves a copy of it on the stack that the
/// crate does not wipe; the same holds for the typed API of `x25519-dalek`.
fn x25519_public(secret: &[u8; X25519_LEN]) -> [u8; X25519_LEN] {
    x25519(*secret, X25519_BASEPOINT_BYTES)
}

/// The public key that belongs to the secret key halves: X25519 public key, then ML-KEM key.
fn assemble_public_key(x25519_secret: &[u8; X25519_LEN], dk: &DecapsulationKey768) -> PublicKey {
    let ek = dk.encapsulation_key().to_bytes();
    let mut pk = [0u8; EKI_HYBRID_PK_LEN];
    join_into(
        &mut pk,
        &x25519_public(x25519_secret),
        <&[u8; MLKEM_EK_LEN]>::from(&ek),
    );
    pk
}

/// The public key of `sk`, derived from it alone.
fn public_key(sk: &[u8; EKI_HYBRID_SK_LEN]) -> Result<PublicKey, Error> {
    let (x25519_secret, seed) = split::<EKI_HYBRID_SK_LEN, X25519_LEN, SEED_LEN>(sk)?;
    Ok(assemble_public_key(x25519_secret, &mlkem_key(seed)))
}

/// Splits `pk` into the X25519 public key and the decoded ML-KEM encapsulation key.
///
/// The decoding is the FIPS 203 section 7.2 check: a coefficient that is not reduced modulo q
/// does not survive encoding and decoding unchanged, and is [`Error::InvalidArgument`].
fn parse_public_key(pk: &PublicKey) -> Result<(&[u8; X25519_LEN], EncapsulationKey768), Error> {
    let (x25519_public, ek) = split::<EKI_HYBRID_PK_LEN, X25519_LEN, MLKEM_EK_LEN>(pk)?;
    let ek = EncapsulationKey768::new(<&Key<EncapsulationKey768>>::from(ek))
        .map_err(|_| Error::InvalidArgument)?;
    Ok((x25519_public, ek))
}

/// The X25519 shared secret of `secret` and the peer's public key `peer`.
///
/// An all-zero result is [`Error::InvalidArgument`]. It arises exactly when `peer` has small
/// order, the case `SharedSecret::was_contributory` of `x25519-dalek` reports as `false`. That
/// type comes only from `EphemeralSecret`, which cannot be built from given bytes, and from
/// `StaticSecret` and `ReusableSecret`, which need cargo features that are off. So the
/// byte-oriented function is used and its result is compared with zero in constant time.
fn x25519_shared(
    secret: &[u8; X25519_LEN],
    peer: &[u8; X25519_LEN],
) -> Result<Zeroizing<[u8; PARTIAL_LEN]>, Error> {
    let shared = Zeroizing::new(x25519(*secret, *peer));
    if bool::from(shared.ct_eq(&[0u8; PARTIAL_LEN])) {
        return Err(Error::InvalidArgument);
    }
    Ok(shared)
}

/// The deterministic part of `encap`: all randomness is the argument `randomness`, the X25519
/// ephemeral secret followed by the ML-KEM-768 message `m`.
fn encapsulate(
    pk: &PublicKey,
    x25519_peer: &[u8; X25519_LEN],
    ek: &EncapsulationKey768,
    randomness: &[u8; ENCAP_RANDOM_LEN],
) -> Result<(Ciphertext, SharedSecret), Error> {
    let (x25519_ephemeral, message) =
        split::<ENCAP_RANDOM_LEN, X25519_LEN, MLKEM_MESSAGE_LEN>(randomness)?;
    let x25519_public = x25519_public(x25519_ephemeral);
    let ss_x25519 = x25519_shared(x25519_ephemeral, x25519_peer)?;

    // `encapsulate_deterministic` is the crate's entry point for a caller-supplied `m`. The crate
    // hides it from its documentation and warns that `m` must be uniformly random, which it is:
    // `encap` draws it from the system random source. The crate's own `Encapsulate::encapsulate`
    // would draw `m` itself, but it panics when the random source fails, and the ABI reports that
    // failure as `EKI_ERR_BACKEND`.
    let (mlkem_ct, ss_mlkem) = ek.encapsulate_deterministic(<&_>::from(message));
    let ss_mlkem = Zeroizing::new(ss_mlkem);

    let mut ct = [0u8; EKI_HYBRID_CT_LEN];
    join_into(
        &mut ct,
        &x25519_public,
        <&[u8; MLKEM_CT_LEN]>::from(&mlkem_ct),
    );
    let ss = combine(&ss_x25519, <&_>::from(&*ss_mlkem), &ct, pk)?;
    Ok((ct, ss))
}

/// The shared secret: HKDF-SHA256 of `ss_x25519 || ss_mlkem` with an empty salt and the `info`
/// `label || ct || pk`, 32 bytes.
fn combine(
    ss_x25519: &[u8; PARTIAL_LEN],
    ss_mlkem: &[u8; PARTIAL_LEN],
    ct: &Ciphertext,
    pk: &PublicKey,
) -> Result<SharedSecret, Error> {
    let mut ikm = secret::<IKM_LEN>();
    join_into(ikm.expose_secret_mut(), ss_x25519, ss_mlkem);
    // `ct` and `pk` are public, so `info` is an ordinary buffer.
    let info = [COMBINER_LABEL, ct, pk].concat();
    let mut ss = secret::<EKI_HYBRID_SS_LEN>();
    // The input lengths and the output length are fixed and within the HKDF limits, so no caller
    // input reaches the error: a failure here is a broken invariant, not a bad argument.
    hkdf_sha256(ikm.expose_secret(), &[], &info, ss.expose_secret_mut())
        .map_err(|_| Error::Internal)?;
    Ok(ss)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::{Digest, Sha256};

    /// RFC 7748 section 6.1: Alice's X25519 secret and public key, Bob's, and their shared secret.
    const ALICE_SECRET: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const ALICE_PUBLIC: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    const BOB_SECRET: &str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    const BOB_PUBLIC: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    const X25519_SHARED: &str = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

    fn unhex(text: &str) -> Vec<u8> {
        hex::decode(text).expect("test vector is valid hex")
    }

    fn array<const N: usize>(text: &str) -> [u8; N] {
        unhex(text)
            .try_into()
            .expect("test vector has the expected length")
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn new_pair() -> (PublicKey, SecretKey) {
        keygen().expect("the system random source works")
    }

    /// The same bit flipped in a copy of `ct`.
    fn flipped(ct: &Ciphertext, byte: usize, mask: u8) -> Ciphertext {
        let mut copy = *ct;
        copy[byte] ^= mask;
        copy
    }

    #[test]
    fn round_trip() {
        let (pk, sk) = new_pair();
        let (ct, ss) = encap(&pk).expect("encap");
        let again = decap(sk.expose_secret(), &ct).expect("decap");
        assert_eq!(ss.expose_secret(), again.expose_secret());
        assert_ne!(ss.expose_secret(), &[0u8; EKI_HYBRID_SS_LEN]);
    }

    #[test]
    fn two_encapsulations_to_one_key_differ() {
        let (pk, sk) = new_pair();
        let (ct1, ss1) = encap(&pk).expect("encap");
        let (ct2, ss2) = encap(&pk).expect("encap");
        assert_ne!(ct1, ct2);
        assert_ne!(ss1.expose_secret(), ss2.expose_secret());
        for (ct, ss) in [(ct1, ss1), (ct2, ss2)] {
            let opened = decap(sk.expose_secret(), &ct).expect("decap");
            assert_eq!(opened.expose_secret(), ss.expose_secret());
        }
    }

    #[test]
    fn flipped_bit_in_the_x25519_half_changes_the_secret() {
        let (pk, sk) = new_pair();
        let (ct, ss) = encap(&pk).expect("encap");
        // Bit 7 of byte 31 is ignored by X25519, so the key agreement result is the same and the
        // secret can differ only because the combiner covers the whole ciphertext.
        for (byte, mask) in [(0, 0x01), (X25519_LEN - 1, 0x80)] {
            match decap(sk.expose_secret(), &flipped(&ct, byte, mask)) {
                Ok(other) => assert_ne!(other.expose_secret(), ss.expose_secret(), "byte {byte}"),
                Err(error) => assert_eq!(error, Error::InvalidArgument, "byte {byte}"),
            }
        }
    }

    #[test]
    fn flipped_bit_in_the_mlkem_half_changes_the_secret() {
        // Implicit rejection: decapsulation succeeds with an unrelated secret.
        let (pk, sk) = new_pair();
        let (ct, ss) = encap(&pk).expect("encap");
        for byte in [X25519_LEN, X25519_LEN + 500, EKI_HYBRID_CT_LEN - 1] {
            let other = decap(sk.expose_secret(), &flipped(&ct, byte, 0x01)).expect("decap");
            assert_ne!(other.expose_secret(), ss.expose_secret(), "byte {byte}");
        }
    }

    #[test]
    fn small_order_ephemeral_key_is_rejected() {
        let (pk, sk) = new_pair();
        let (ct, _) = encap(&pk).expect("encap");
        // u = 0 and u = 1 are points of order 1 and 4: any clamped scalar maps them to zero.
        for point in [0u8, 1] {
            let mut bad = ct;
            bad[..X25519_LEN].fill(0);
            bad[0] = point;
            let result = decap(sk.expose_secret(), &bad);
            assert_eq!(result.err(), Some(Error::InvalidArgument), "u = {point}");
        }
    }

    #[test]
    fn public_key_with_all_zero_x25519_part_is_rejected() {
        let (mut pk, _) = new_pair();
        pk[..X25519_LEN].fill(0);
        assert_eq!(encap(&pk).err(), Some(Error::InvalidArgument));
    }

    #[test]
    fn public_key_with_unreduced_mlkem_coefficient_is_rejected() {
        // The first 12-bit coefficient is bytes 0 and the low nibble of byte 1 of the ML-KEM part;
        // 0xfff = 4095 is not below q = 3329.
        let (mut pk, _) = new_pair();
        pk[X25519_LEN] = 0xff;
        pk[X25519_LEN + 1] |= 0x0f;
        assert_eq!(encap(&pk).err(), Some(Error::InvalidArgument));
    }

    #[test]
    fn secret_key_of_another_pair_gives_a_different_secret() {
        let (pk, _) = new_pair();
        let (_, other_sk) = new_pair();
        let (ct, ss) = encap(&pk).expect("encap");
        let other = decap(other_sk.expose_secret(), &ct).expect("decap");
        assert_ne!(other.expose_secret(), ss.expose_secret());
    }

    #[test]
    fn public_key_is_a_function_of_the_secret_key() {
        let (pk, sk) = new_pair();
        assert_eq!(public_key(sk.expose_secret()), Ok(pk));
        assert_eq!(public_key(sk.expose_secret()), Ok(pk));
        // Both halves matter: changing a bit of the X25519 secret that is not clamped away, or of
        // `d`, the first half of the seed, changes the public key.
        for (byte, mask) in [(0, 0x08), (X25519_LEN - 1, 0x01), (X25519_LEN, 0x01)] {
            let mut other = *sk.expose_secret();
            other[byte] ^= mask;
            assert_ne!(public_key(&other), Ok(pk), "byte {byte}");
        }
    }

    #[test]
    fn second_half_of_the_seed_only_matters_for_rejection() {
        // `z`, the last 32 bytes of the seed, is the implicit rejection key: it is not part of the
        // encapsulation key, and it changes the result only for a ciphertext that fails the check.
        let (pk, sk) = new_pair();
        let mut other = *sk.expose_secret();
        other[EKI_HYBRID_SK_LEN - 1] ^= 0x01;
        assert_eq!(public_key(&other), Ok(pk));

        let (ct, ss) = encap(&pk).expect("encap");
        let opened = decap(&other, &ct).expect("decap");
        assert_eq!(opened.expose_secret(), ss.expose_secret());

        let bad = flipped(&ct, X25519_LEN + 7, 0x01);
        let rejected = decap(sk.expose_secret(), &bad).expect("decap");
        let rejected_other = decap(&other, &bad).expect("decap");
        assert_ne!(rejected.expose_secret(), rejected_other.expose_secret());
    }

    #[test]
    fn clamped_out_bits_of_the_x25519_secret_do_not_matter() {
        // The X25519 function clears bits 0 to 2 of byte 0 and bit 7 of byte 31 and sets bit 6 of
        // byte 31 each time it is used, so a secret stored clamped and one stored as drawn are the
        // same key.
        let (pk, sk) = new_pair();
        let mut clamped = *sk.expose_secret();
        clamped[0] &= 0b1111_1000;
        clamped[X25519_LEN - 1] &= 0b0111_1111;
        clamped[X25519_LEN - 1] |= 0b0100_0000;
        assert_eq!(public_key(&clamped), Ok(pk));
        let (ct, ss) = encap(&pk).expect("encap");
        let opened = decap(&clamped, &ct).expect("decap");
        assert_eq!(opened.expose_secret(), ss.expose_secret());
    }

    /// HKDF-SHA256 for one output block, from the definition in RFC 5869: with an empty salt the
    /// extract key is 32 zero bytes, and the 32-byte output is `HMAC(prk, info || 0x01)`.
    fn hkdf_one_block(ikm: &[u8], info: &[u8]) -> [u8; 32] {
        let mut extract = Hmac::<Sha256>::new_from_slice(&[0u8; 32]).expect("any key length");
        extract.update(ikm);
        let prk = extract.finalize().into_bytes();
        let mut expand = Hmac::<Sha256>::new_from_slice(&prk).expect("any key length");
        expand.update(info);
        expand.update(&[1]);
        expand.finalize().into_bytes().into()
    }

    #[test]
    fn combiner_matches_an_independent_computation() {
        let (pk, sk) = new_pair();
        let (ct, ss) = encap(&pk).expect("encap");
        let sk = sk.expose_secret();

        // The partial secrets and the public key, taken from the crates directly.
        let ss_x25519 = x25519_dalek::x25519(
            sk[..32].try_into().expect("32 bytes"),
            ct[..32].try_into().expect("32 bytes"),
        );
        let seed = Seed::try_from(&sk[32..]).expect("64 bytes");
        let dk = DecapsulationKey768::from_seed(seed);
        let mlkem_ct = ml_kem::ml_kem_768::Ciphertext::try_from(&ct[32..]).expect("1088 bytes");
        let ss_mlkem = dk.decapsulate(&mlkem_ct);
        let x25519_public = x25519_dalek::x25519(
            sk[..32].try_into().expect("32 bytes"),
            X25519_BASEPOINT_BYTES,
        );
        let expected_pk = [
            &x25519_public[..],
            dk.encapsulation_key().to_bytes().as_slice(),
        ]
        .concat();
        assert_eq!(pk.as_slice(), expected_pk.as_slice());

        let ikm = [&ss_x25519[..], ss_mlkem.as_slice()].concat();
        let info = [b"ekibridge-hybrid-x25519-mlkem768-v1".as_slice(), &ct, &pk].concat();
        assert_eq!(&ss.expose_secret()[..], &hkdf_one_block(&ikm, &info)[..]);
    }

    /// Fixed inputs for the known-answer test: Alice's X25519 secret and the seed `00 01 .. 3f`
    /// make the secret key, Bob's X25519 secret and `m = 80 81 .. 9f` are the encapsulation
    /// randomness.
    fn kat_secret_key() -> [u8; EKI_HYBRID_SK_LEN] {
        let mut sk = [0u8; EKI_HYBRID_SK_LEN];
        let seed: [u8; SEED_LEN] = core::array::from_fn(|i| i as u8);
        join_into(&mut sk, &array::<32>(ALICE_SECRET), &seed);
        sk
    }

    fn kat_randomness() -> [u8; ENCAP_RANDOM_LEN] {
        let mut randomness = [0u8; ENCAP_RANDOM_LEN];
        let message: [u8; MLKEM_MESSAGE_LEN] = core::array::from_fn(|i| 0x80 + i as u8);
        join_into(&mut randomness, &array::<32>(BOB_SECRET), &message);
        randomness
    }

    #[test]
    fn known_answer() {
        let sk = kat_secret_key();
        let pk = public_key(&sk).expect("public key");
        assert_eq!(hex::encode(&pk[..X25519_LEN]), ALICE_PUBLIC);
        assert_eq!(sha256_hex(&pk), KAT_PK_SHA256);

        let (x25519_peer, ek) = parse_public_key(&pk).expect("valid public key");
        let (ct, ss) = encapsulate(&pk, x25519_peer, &ek, &kat_randomness()).expect("encapsulate");
        assert_eq!(hex::encode(&ct[..X25519_LEN]), BOB_PUBLIC);
        assert_eq!(sha256_hex(&ct), KAT_CT_SHA256);
        assert_eq!(hex::encode(ss.expose_secret()), KAT_SS);

        let opened = decap(&sk, &ct).expect("decap");
        assert_eq!(hex::encode(opened.expose_secret()), KAT_SS);
    }

    #[test]
    fn known_answer_x25519_half_is_the_rfc_7748_shared_secret() {
        let shared = x25519_shared(&array::<32>(BOB_SECRET), &array::<32>(ALICE_PUBLIC));
        assert_eq!(
            hex::encode(shared.expect("contributory").as_slice()),
            X25519_SHARED
        );
        let shared = x25519_shared(&array::<32>(ALICE_SECRET), &array::<32>(BOB_PUBLIC));
        assert_eq!(
            hex::encode(shared.expect("contributory").as_slice()),
            X25519_SHARED
        );
    }

    /// Results of the known-answer test. The ML-KEM-768 encapsulation key of the seed `00 .. 3f`
    /// is the one in the example key of the IETF ML-KEM certificate draft, and OpenSSL 3.5
    /// decapsulates the ML-KEM part of the ciphertext to the same 32 bytes; the shared secret
    /// was recomputed from the two partial secrets with an HKDF-SHA256 written in Python.
    const KAT_PK_SHA256: &str = "a2859ad834a332dba265ef9abcdf619e4279fb887e0a22ad8a6aa9e74e825f31";
    const KAT_CT_SHA256: &str = "fec585cc05097978bb0a406f945eda8ae1b9f6c8d65c231fd3a18185de3fa513";
    const KAT_SS: &str = "a30f25540a394e757913e0f387d2463ac99d3906623d5bf020e23c9133b4d942";
}
