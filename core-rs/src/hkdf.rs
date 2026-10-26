//! HKDF-SHA256 over the RustCrypto `hkdf` and `sha2` crates.
//!
//! The safe layer behind `eki_hkdf_sha256`: it takes slices and returns `Result<_, Error>`;
//! `ffi.rs` converts the C pointers and maps the error to a status.

use ekicore_abi::{EKI_HKDF_MAX_INPUT_LEN, EKI_HKDF_MAX_OKM_LEN};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::Error;

/// Derives `okm.len()` bytes from `ikm`, `salt` and `info` with HKDF-SHA256 (RFC 5869).
///
/// The checks run in this order and the first failure decides the error, always
/// [`Error::InvalidArgument`]: `ikm` empty or longer than `EKI_HKDF_MAX_INPUT_LEN`, `salt` longer
/// than that, `info` longer than that, `okm` empty or longer than `EKI_HKDF_MAX_OKM_LEN`. An empty
/// `salt` selects the RFC default salt, HashLen zero bytes. On success every byte of `okm` is
/// written; on failure `okm` is left as it was.
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), Error> {
    // The crate limits only the output length. The caps on the three inputs are ABI rules (they
    // mirror OpenSSL's HKDF_MAXINFO, so both libraries answer alike), and the crate also accepts
    // an empty `ikm` and an empty `okm`, which the ABI rejects. All four checks run before any key
    // material is derived, so a rejected call has nothing to wipe.
    if ikm.is_empty() || ikm.len() > EKI_HKDF_MAX_INPUT_LEN {
        return Err(Error::InvalidArgument);
    }
    if salt.len() > EKI_HKDF_MAX_INPUT_LEN {
        return Err(Error::InvalidArgument);
    }
    if info.len() > EKI_HKDF_MAX_INPUT_LEN {
        return Err(Error::InvalidArgument);
    }
    if okm.is_empty() || okm.len() > EKI_HKDF_MAX_OKM_LEN {
        return Err(Error::InvalidArgument);
    }

    // `None` is the RFC 5869 default salt: the crate substitutes HashLen zero bytes. An empty
    // `Some` would give the same bytes (HMAC pads a short key with zeros), but `None` states the
    // rule instead of relying on that property.
    let salt = (!salt.is_empty()).then_some(salt);

    // Extract: the pseudorandom key (PRK) is not stored as bytes in the returned `Hkdf`; it is the
    // HMAC key state, two `Sha256VarCore` values and a block buffer, which wipe themselves on drop
    // because the `zeroize` feature of `sha2` is enabled. `Hkdf` has no zeroizing `Drop` of its
    // own, and `Hkdf::new` drops the PRK as a plain output array that the crate does not wipe.
    let hkdf = Hkdf::<Sha256>::new(salt, ikm);

    // Expand fails only when `okm` is longer than 255 blocks of 32 bytes, 8160 bytes, and that
    // is `EKI_HKDF_MAX_OKM_LEN`, rejected above, so no caller input reaches the error. It is mapped
    // instead of unwrapped so that this path contains no panic.
    hkdf.expand(info, okm).map_err(|_| Error::InvalidArgument)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5869 test cases A.1 to A.3 (the SHA-256 ones): IKM, salt, info, OKM. A.3 has an empty
    /// salt and empty info.
    const RFC5869: [(&str, &str, &str, &str); 3] = [
        (
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "000102030405060708090a0b0c",
            "f0f1f2f3f4f5f6f7f8f9",
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865",
        ),
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
             404142434445464748494a4b4c4d4e4f",
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
             808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
             a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
             d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f1d87",
        ),
        (
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "",
            "",
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8",
        ),
    ];

    /// Pre-fill of the output buffers, so that a write to one is visible.
    const FILL: u8 = 0xA5;

    fn unhex(text: &str) -> Vec<u8> {
        hex::decode(text).expect("test vector is valid hex")
    }

    /// Runs HKDF-SHA256 into a buffer of `len` bytes pre-filled with `fill`.
    fn derive_filled(
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        len: usize,
        fill: u8,
    ) -> Result<Vec<u8>, Error> {
        let mut okm = vec![fill; len];
        hkdf_sha256(ikm, salt, info, &mut okm)?;
        Ok(okm)
    }

    fn derive(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, Error> {
        derive_filled(ikm, salt, info, len, FILL)
    }

    #[test]
    fn rfc5869_vectors() {
        for (case, (ikm, salt, info, okm)) in RFC5869.iter().enumerate() {
            let expected = unhex(okm);
            let derived = derive(&unhex(ikm), &unhex(salt), &unhex(info), expected.len())
                .expect("valid arguments");
            assert_eq!(derived, expected, "case A.{}", case + 1);
        }
    }

    #[test]
    fn empty_ikm_is_rejected() {
        let mut okm = [FILL; 32];
        assert_eq!(
            hkdf_sha256(&[], b"salt", b"info", &mut okm),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn ikm_is_accepted_at_the_limit_and_rejected_above_it() {
        let ikm = vec![0x0b; EKI_HKDF_MAX_INPUT_LEN];
        assert!(derive(&ikm, b"salt", b"info", 32).is_ok());
        let ikm = vec![0x0b; EKI_HKDF_MAX_INPUT_LEN + 1];
        assert_eq!(
            derive(&ikm, b"salt", b"info", 32),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn salt_is_accepted_at_the_limit_and_rejected_above_it() {
        let salt = vec![0x0b; EKI_HKDF_MAX_INPUT_LEN];
        assert!(derive(b"ikm", &salt, b"info", 32).is_ok());
        let salt = vec![0x0b; EKI_HKDF_MAX_INPUT_LEN + 1];
        assert_eq!(
            derive(b"ikm", &salt, b"info", 32),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn info_is_accepted_at_the_limit_and_rejected_above_it() {
        let info = vec![0x0b; EKI_HKDF_MAX_INPUT_LEN];
        assert!(derive(b"ikm", b"salt", &info, 32).is_ok());
        let info = vec![0x0b; EKI_HKDF_MAX_INPUT_LEN + 1];
        assert_eq!(
            derive(b"ikm", b"salt", &info, 32),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn okm_is_accepted_at_the_limit_and_rejected_above_it() {
        assert!(derive(b"ikm", b"salt", b"info", 1).is_ok());
        assert!(derive(b"ikm", b"salt", b"info", EKI_HKDF_MAX_OKM_LEN).is_ok());
        assert_eq!(
            derive(b"ikm", b"salt", b"info", EKI_HKDF_MAX_OKM_LEN + 1),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            derive(b"ikm", b"salt", b"info", 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn empty_salt_and_empty_info_are_accepted() {
        // A.3 is exactly this case; the result is checked there.
        assert!(derive(b"ikm", &[], b"info", 32).is_ok());
        assert!(derive(b"ikm", b"salt", &[], 32).is_ok());
        assert!(derive(b"ikm", &[], &[], 32).is_ok());
    }

    #[test]
    fn success_writes_every_byte_of_okm() {
        // A byte left unwritten would keep its pre-fill, so two different pre-fills would give
        // two different buffers. The lengths cover a single byte, a block boundary on either side,
        // partial last blocks and the maximum.
        for len in [1, 31, 32, 33, EKI_HKDF_MAX_OKM_LEN] {
            let with_zeros = derive_filled(b"ikm", b"salt", b"info", len, 0x00);
            let with_ones = derive_filled(b"ikm", b"salt", b"info", len, 0xFF);
            assert_eq!(with_zeros, with_ones, "okm length {len}");
        }
    }

    #[test]
    fn bad_arguments_in_combination_are_rejected_before_okm_is_touched() {
        // Rules 1 to 4 share one error, so which of them fires first is not visible in the
        // result. What is visible: every combination of bad inputs is rejected, and none of them
        // writes `okm`, because all checks run before anything is derived.
        let too_long = vec![0u8; EKI_HKDF_MAX_INPUT_LEN + 1];
        for bad_ikm in [&[][..], &too_long[..]] {
            for mask in 1u8..16 {
                let ikm: &[u8] = if mask & 1 != 0 { bad_ikm } else { b"ikm" };
                let salt: &[u8] = if mask & 2 != 0 { &too_long } else { b"salt" };
                let info: &[u8] = if mask & 4 != 0 { &too_long } else { b"info" };
                let len = if mask & 8 != 0 {
                    EKI_HKDF_MAX_OKM_LEN + 1
                } else {
                    42
                };
                let mut okm = vec![FILL; len];
                assert_eq!(
                    hkdf_sha256(ikm, salt, info, &mut okm),
                    Err(Error::InvalidArgument),
                    "mask {mask:04b}, ikm length {}",
                    bad_ikm.len()
                );
                assert!(okm.iter().all(|&b| b == FILL), "mask {mask:04b}");
            }
        }
    }

    #[test]
    fn empty_salt_equals_a_salt_of_32_zero_bytes() {
        let (ikm, _, info, okm) = RFC5869[2];
        let ikm = unhex(ikm);
        let expected = unhex(okm);
        let with_empty = derive(&ikm, &[], &unhex(info), expected.len()).expect("valid arguments");
        assert_eq!(with_empty, expected);
        let with_zeros =
            derive(&ikm, &[0u8; 32], &unhex(info), expected.len()).expect("valid arguments");
        assert_eq!(with_empty, with_zeros);

        // The same holds with a non-empty `info`, where the A.3 value does not apply.
        let with_empty = derive(&ikm, &[], b"context", 100).expect("valid arguments");
        let with_zeros = derive(&ikm, &[0u8; 32], b"context", 100).expect("valid arguments");
        assert_eq!(with_empty, with_zeros);
    }

    #[test]
    fn shorter_output_is_a_prefix_of_a_longer_one() {
        let full = derive(b"ikm", b"salt", b"info", EKI_HKDF_MAX_OKM_LEN).expect("valid arguments");
        for len in [1, 31, 32, 33, 64, 255, EKI_HKDF_MAX_OKM_LEN - 1] {
            let shorter = derive(b"ikm", b"salt", b"info", len).expect("valid arguments");
            assert_eq!(shorter, full[..len], "okm length {len}");
        }
    }
}
