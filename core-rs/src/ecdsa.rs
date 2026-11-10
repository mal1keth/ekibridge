//! ECDSA P-256 signature verification over SHA-256, on the RustCrypto `p256` crate.
//!
//! The safe layer behind `eki_ecdsa_p256_verify`: it takes slices and returns
//! `Result<_, Error>`; `ffi.rs` converts the C pointers and maps the error to a status.

use ekicore_abi::{EKI_P256_PUBLIC_KEY_LEN, EKI_P256_SIGNATURE_LEN};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};

use crate::error::Error;

/// First byte of a SEC1 uncompressed point.
/// cbindgen:ignore
const UNCOMPRESSED_TAG: u8 = 0x04;

/// Verifies that `sig` is a signature by `public_key` over the SHA-256 digest of `msg`.
///
/// `public_key` is a SEC1 uncompressed point, `0x04 || X || Y`, and `sig` is `r || s`, each
/// 32 bytes big-endian. The checks run in this order and the first failure decides the error:
/// `public_key` is not 65 bytes or `sig` is not 64 bytes; `public_key` does not start with
/// `0x04`; `public_key` is not a point of the curve (a coordinate not below the field prime, or
/// a point off the curve), all [`Error::InvalidArgument`]; then `r` or `s` is zero or not below
/// the group order, or the signature does not verify, both [`Error::AuthFailed`]. A high `s` is
/// accepted: the crate does not normalise it for P-256 and does not reject the high member of
/// the malleable pair. `msg` may be empty.
pub fn p256_verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
    // The public key, the message and the signature are all public values, so nothing is wiped
    // and no step needs to run in constant time; the crate's verification is variable-time.
    check_sizes(public_key, sig)?;
    let key = parse_public_key(public_key)?;
    let signature = parse_signature(sig)?;
    // `Verifier::verify` hashes `msg` with the `Digest` type that `p256` assigns to the curve
    // (SHA-256) and then checks the signature against that digest, so no hashing happens here.
    key.verify(msg, &signature).map_err(|_| Error::AuthFailed)
}

/// Checks that `public_key` is a SEC1 uncompressed P-256 point: 65 bytes, the tag `0x04`, and
/// a point of the curve, else [`Error::InvalidArgument`]. These are the key checks of
/// [`p256_verify`], for a key that is accepted before any signature is checked (an approver key
/// of a key store).
pub fn p256_check_public_key(public_key: &[u8]) -> Result<(), Error> {
    if public_key.len() != EKI_P256_PUBLIC_KEY_LEN {
        return Err(Error::InvalidArgument);
    }
    parse_public_key(public_key).map(drop)
}

/// The size rules, which only a Rust caller can break: through the C ABI both buffers have a
/// fixed size by construction.
fn check_sizes(public_key: &[u8], sig: &[u8]) -> Result<(), Error> {
    if public_key.len() != EKI_P256_PUBLIC_KEY_LEN {
        return Err(Error::InvalidArgument);
    }
    if sig.len() != EKI_P256_SIGNATURE_LEN {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Decodes `public_key` into a point of the curve other than the identity.
///
/// The decoder of the crate also accepts compressed points. For a 65-byte input it rejects every
/// tag but `0x04` by itself, because only that tag has this length, but the ABI rule is stated
/// here so that it does not rest on the length table of the crate. The decoder then rejects a
/// coordinate not below the field prime and a point that does not satisfy the curve equation.
fn parse_public_key(public_key: &[u8]) -> Result<VerifyingKey, Error> {
    if public_key.first() != Some(&UNCOMPRESSED_TAG) {
        return Err(Error::InvalidArgument);
    }
    VerifyingKey::from_sec1_bytes(public_key).map_err(|_| Error::InvalidArgument)
}

/// Decodes `sig` into a signature whose `r` and `s` are both in `1..n`.
///
/// The range rule is the crate's: `Signature::from_slice` rejects a zero or a value not below
/// the group order, so there is no comparison here. The contract makes every defect of a
/// signature an authentication failure, so this error is `AuthFailed`, unlike the key's. The
/// other error `from_slice` can give, a length other than 64, cannot occur after `check_sizes`.
fn parse_signature(sig: &[u8]) -> Result<Signature, Error> {
    Signature::from_slice(sig).map_err(|_| Error::AuthFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6979 A.2.5 public key `U = xG`, SEC1 uncompressed.
    const PUBLIC_KEY: &str = "04\
        60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6\
        7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";

    /// RFC 6979 A.2.5, SHA-256, message "sample": `r || s`. Its `s` is above `n / 2`.
    const SIG_SAMPLE: &str = "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716\
        f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8";

    /// RFC 6979 A.2.5, SHA-256, message "test": `r || s`.
    const SIG_TEST: &str = "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367\
        019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083";

    /// `SIG_SAMPLE` with `s` replaced by `n - s`, the other member of the malleable pair.
    const SIG_SAMPLE_LOW_S: &str = "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716\
        0834e36ad29a83bf2bc9385e491d6099c8fdf9d1ed67aa7ea5f51f93782857a9";

    /// A signature over the empty message under the RFC 6979 key, made by an independent
    /// implementation with a random nonce.
    const SIG_EMPTY: &str = "9b764e1b7356ce0afc0ef77f30ea035b156ca8f8f70209f213db5a4752b7c5f1\
        d971d1b0f6cee519766877bc76afa8bc4c7b59a2781d1e5d8e6d37a4f9775dc0";

    /// The group order `n`.
    const N: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

    /// The field prime `p`.
    const P: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";

    /// A `y` with `y^2 = b`, where `b` is the curve constant: `(0, Y_AT_X_ZERO)` is a point of
    /// the curve, so `(p, Y_AT_X_ZERO)` is the same point with a coordinate that is not reduced.
    const Y_AT_X_ZERO: &str = "66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4";

    fn unhex(text: &str) -> Vec<u8> {
        hex::decode(text).expect("test vector is valid hex")
    }

    fn public_key() -> Vec<u8> {
        unhex(PUBLIC_KEY)
    }

    /// `r || s` from two hex scalars.
    fn signature(r: &str, s: &str) -> Vec<u8> {
        [unhex(r), unhex(s)].concat()
    }

    /// `0x04 || x || y`.
    fn point(x: &[u8], y: &[u8]) -> Vec<u8> {
        [&[UNCOMPRESSED_TAG][..], x, y].concat()
    }

    /// A copy of `bytes` with one bit inverted.
    fn flip(bytes: &[u8], index: usize, bit: u8) -> Vec<u8> {
        let mut copy = bytes.to_vec();
        copy[index] ^= 1 << bit;
        copy
    }

    #[test]
    fn rfc6979_vectors() {
        let key = public_key();
        for (msg, sig) in [(&b"sample"[..], SIG_SAMPLE), (&b"test"[..], SIG_TEST)] {
            assert_eq!(p256_verify(&key, msg, &unhex(sig)), Ok(()), "{msg:?}");
        }
    }

    #[test]
    fn high_and_low_s_both_verify() {
        let key = public_key();
        let high = unhex(SIG_SAMPLE);
        let low = unhex(SIG_SAMPLE_LOW_S);

        // The low vector is checked against the crate's own normalisation of the RFC signature,
        // which also shows that the RFC `s` is the high one.
        let normalized = Signature::from_slice(&high)
            .expect("valid signature")
            .normalize_s()
            .to_bytes();
        assert_eq!(normalized.as_slice(), low);
        assert_ne!(high, low);

        for sig in [high, low] {
            assert_eq!(p256_verify(&key, b"sample", &sig), Ok(()));
        }
    }

    #[test]
    fn empty_message_verifies_against_its_own_signature() {
        assert_eq!(p256_verify(&public_key(), b"", &unhex(SIG_EMPTY)), Ok(()));
    }

    #[test]
    fn empty_message_with_another_messages_signature_fails_cleanly() {
        assert_eq!(
            p256_verify(&public_key(), b"", &unhex(SIG_SAMPLE)),
            Err(Error::AuthFailed)
        );
    }

    #[test]
    fn wrong_sizes_are_invalid() {
        let key = public_key();
        let sig = unhex(SIG_SAMPLE);
        let filler = [UNCOMPRESSED_TAG; 130];
        for len in [0, 1, 33, 64, 66, 130] {
            assert_eq!(
                p256_verify(&filler[..len], b"sample", &sig),
                Err(Error::InvalidArgument),
                "public key of {len} bytes"
            );
        }
        // An over-long key that starts with the right bytes is not truncated or accepted.
        assert_eq!(
            p256_verify(&[key.as_slice(), &[0]].concat(), b"sample", &sig),
            Err(Error::InvalidArgument)
        );
        // A signature of the wrong size is a size error, not the authentication failure that a
        // malformed 64-byte signature is.
        let filler = [0x11; 128];
        for len in [0, 1, 32, 63, 65, 128] {
            assert_eq!(
                p256_verify(&key, b"sample", &filler[..len]),
                Err(Error::InvalidArgument),
                "signature of {len} bytes"
            );
        }
        assert_eq!(
            p256_verify(&key, b"sample", &sig[..63]),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn prefix_other_than_04_is_invalid() {
        let sig = unhex(SIG_SAMPLE);
        for prefix in [0x00, 0x02, 0x03, 0x05, 0x06, 0x07, 0xff] {
            let mut key = public_key();
            key[0] = prefix;
            assert_eq!(
                p256_verify(&key, b"sample", &sig),
                Err(Error::InvalidArgument),
                "prefix {prefix:#04x}"
            );
        }
    }

    #[test]
    fn point_off_the_curve_is_invalid() {
        let sig = unhex(SIG_SAMPLE);
        let mut key = public_key();
        key[64] ^= 0x01; // (x, y with its last bit flipped) does not satisfy the curve equation
        assert_eq!(
            p256_verify(&key, b"sample", &sig),
            Err(Error::InvalidArgument),
            "y changed"
        );
        assert_eq!(
            p256_verify(&point(&[0; 32], &[0; 32]), b"sample", &sig),
            Err(Error::InvalidArgument),
            "(0, 0)"
        );
    }

    #[test]
    fn coordinate_not_below_p_is_invalid() {
        let sig = unhex(SIG_SAMPLE);
        let (p, ones) = (unhex(P), [0xff; 32]);
        let key = public_key();
        let (x, y) = (&key[1..33], &key[33..]);

        // (0, y) satisfies the curve equation, so it is accepted as a key and the signature then
        // fails to verify. (p, y) is the same point with x written as p instead of 0: the only
        // thing wrong with it is that the coordinate is not below p.
        let y_at_zero = unhex(Y_AT_X_ZERO);
        assert_eq!(
            p256_verify(&point(&[0; 32], &y_at_zero), b"sample", &sig),
            Err(Error::AuthFailed),
            "(0, y) is a point of the curve"
        );
        assert_eq!(
            p256_verify(&point(&p, &y_at_zero), b"sample", &sig),
            Err(Error::InvalidArgument),
            "x = p"
        );

        for (name, key) in [
            ("y = p", point(x, &p)),
            ("x = 2^256 - 1", point(&ones, y)),
            ("y = 2^256 - 1", point(x, &ones)),
        ] {
            assert_eq!(
                p256_verify(&key, b"sample", &sig),
                Err(Error::InvalidArgument),
                "{name}"
            );
        }
    }

    #[test]
    fn r_or_s_out_of_range_is_auth_failed() {
        let key = public_key();
        let (r, s) = SIG_SAMPLE.split_at(64);
        let (zero, ones) = ("00".repeat(32), "ff".repeat(32));
        for (name, sig) in [
            ("r = 0", signature(&zero, s)),
            ("s = 0", signature(r, &zero)),
            ("r = n", signature(N, s)),
            ("s = n", signature(r, N)),
            ("r = 2^256 - 1", signature(&ones, s)),
            ("s = 2^256 - 1", signature(r, &ones)),
            ("r = 0, s = 0", signature(&zero, &zero)),
        ] {
            assert_eq!(
                p256_verify(&key, b"sample", &sig),
                Err(Error::AuthFailed),
                "{name}"
            );
        }
    }

    #[test]
    fn r_and_s_just_inside_the_range_reach_verification_and_fail_it() {
        // Values 1 and n - 1 are in range, so they pass the range rule; the signature is wrong
        // and the failure is the same status, without a panic on the boundary.
        let key = public_key();
        let (r, s) = SIG_SAMPLE.split_at(64);
        let one = format!("{}01", "00".repeat(31));
        let n_minus_one = format!("{}50", &N[..N.len() - 2]);
        for (name, sig) in [
            ("r = 1", signature(&one, s)),
            ("s = 1", signature(r, &one)),
            ("r = n - 1", signature(&n_minus_one, s)),
            ("s = n - 1", signature(r, &n_minus_one)),
        ] {
            assert_eq!(
                p256_verify(&key, b"sample", &sig),
                Err(Error::AuthFailed),
                "{name}"
            );
        }
    }

    #[test]
    fn public_key_is_checked_before_the_signature() {
        // A bad key with a bad signature reports the key.
        let mut key = public_key();
        key[0] = 0x02;
        let zero = "00".repeat(32);
        assert_eq!(
            p256_verify(&key, b"sample", &signature(&zero, &zero)),
            Err(Error::InvalidArgument),
            "prefix"
        );
        key[0] = UNCOMPRESSED_TAG;
        key[64] ^= 0x01;
        assert_eq!(
            p256_verify(&key, b"sample", &signature(&zero, &zero)),
            Err(Error::InvalidArgument),
            "off the curve"
        );
    }

    #[test]
    fn signature_over_another_message_is_auth_failed() {
        let key = public_key();
        assert_eq!(
            p256_verify(&key, b"test", &unhex(SIG_SAMPLE)),
            Err(Error::AuthFailed)
        );
        assert_eq!(
            p256_verify(&key, b"sample", &unhex(SIG_TEST)),
            Err(Error::AuthFailed)
        );
    }

    #[test]
    fn flipped_bit_in_the_signature_is_auth_failed() {
        let key = public_key();
        let sig = unhex(SIG_SAMPLE);
        for index in [0, 31, 32, 63] {
            for bit in [0, 7] {
                assert_eq!(
                    p256_verify(&key, b"sample", &flip(&sig, index, bit)),
                    Err(Error::AuthFailed),
                    "byte {index}, bit {bit}"
                );
            }
        }
    }

    #[test]
    fn flipped_bit_in_the_message_is_auth_failed() {
        let key = public_key();
        let sig = unhex(SIG_SAMPLE);
        for index in 0..b"sample".len() {
            assert_eq!(
                p256_verify(&key, &flip(b"sample", index, 0), &sig),
                Err(Error::AuthFailed),
                "byte {index}"
            );
        }
    }
}
