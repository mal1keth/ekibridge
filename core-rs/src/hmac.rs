//! HMAC-SHA256 over the RustCrypto `hmac` and `sha2` crates.
//!
//! The safe layer behind `eki_hmac_sha256` and `eki_hmac_sha256_verify`: it takes slices and
//! returns `Result<_, Error>`; `ffi.rs` converts the C pointers and maps the error to a status.

use ekicore_abi::EKI_HMAC_SHA256_LEN;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::error::Error;

type HmacSha256 = Hmac<Sha256>;

/// Starts an HMAC-SHA256 computation under `key`.
fn new_mac(key: &[u8]) -> Result<HmacSha256, Error> {
    // HMAC itself accepts an empty key. The ABI rejects it, because an empty key is almost always
    // a caller bug, and both libraries must answer alike.
    if key.is_empty() {
        return Err(Error::InvalidArgument);
    }
    // HMAC takes a key of any length (one longer than the block size is hashed first), so
    // `new_from_slice` has no failure to report here. The error is mapped instead of unwrapped so
    // that this path, which caller input reaches, contains no panic.
    HmacSha256::new_from_slice(key).map_err(|_| Error::InvalidArgument)
}

/// Computes HMAC-SHA256 of `msg` under `key`.
///
/// An empty `msg` is valid. An empty `key` is [`Error::InvalidArgument`].
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> Result<[u8; EKI_HMAC_SHA256_LEN], Error> {
    let mut mac = new_mac(key)?;
    mac.update(msg);
    // The conversion to `[u8; EKI_HMAC_SHA256_LEN]` compiles only while the SHA-256 output size
    // equals the ABI constant, so a mismatch cannot reach run time.
    Ok(mac.finalize().into_bytes().into())
}

/// Checks that `tag` is the HMAC-SHA256 of `msg` under `key`, comparing in constant time.
///
/// The checks run in this order and the first failure decides the error: an empty `key` and a
/// `tag` that is not 32 bytes long are [`Error::InvalidArgument`], a tag that does not match is
/// [`Error::AuthFailed`].
pub fn hmac_sha256_verify(key: &[u8], msg: &[u8], tag: &[u8]) -> Result<(), Error> {
    let mut mac = new_mac(key)?;
    if tag.len() != EKI_HMAC_SHA256_LEN {
        return Err(Error::InvalidArgument);
    }
    mac.update(msg);
    // `verify_slice` compares in constant time. A plain `==` on slices returns at the first
    // differing byte, so the response time would reveal how many leading bytes of a guessed tag
    // are right, and a tag could be forged one byte at a time. `verify_slice` also fails on a
    // length mismatch, but that case was handled above, so an error here is a tag mismatch.
    mac.verify_slice(tag).map_err(|_| Error::AuthFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4231 test cases 1 and 2: key, data, HMAC-SHA-256.
    const RFC4231: [(&str, &str, &str); 2] = [
        (
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "4869205468657265",
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        ),
        (
            "4a656665",
            "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        ),
    ];

    /// HMAC-SHA256 of the empty message under the key of RFC 4231 test case 1.
    const EMPTY_MSG_MAC: &str = "999a901219f032cd497cadb5e6051e97b6a29ab297bd6ae722bd6062a2f59542";

    fn unhex(text: &str) -> Vec<u8> {
        hex::decode(text).expect("test vector is valid hex")
    }

    #[test]
    fn rfc4231_tags() {
        for (case, (key, data, mac)) in RFC4231.iter().enumerate() {
            let tag = hmac_sha256(&unhex(key), &unhex(data)).expect("valid arguments");
            assert_eq!(tag.as_slice(), unhex(mac).as_slice(), "case {}", case + 1);
        }
    }

    #[test]
    fn rfc4231_tags_verify() {
        for (case, (key, data, mac)) in RFC4231.iter().enumerate() {
            let result = hmac_sha256_verify(&unhex(key), &unhex(data), &unhex(mac));
            assert_eq!(result, Ok(()), "case {}", case + 1);
        }
    }

    #[test]
    fn empty_message_is_accepted() {
        let key = unhex(RFC4231[0].0);
        let tag = hmac_sha256(&key, &[]).expect("an empty message is valid");
        assert_eq!(tag.as_slice(), unhex(EMPTY_MSG_MAC).as_slice());
        assert_eq!(hmac_sha256_verify(&key, &[], &tag), Ok(()));
    }

    #[test]
    fn empty_key_is_rejected() {
        let tag = [0u8; EKI_HMAC_SHA256_LEN];
        assert_eq!(hmac_sha256(&[], b"msg"), Err(Error::InvalidArgument));
        assert_eq!(hmac_sha256(&[], &[]), Err(Error::InvalidArgument));
        assert_eq!(
            hmac_sha256_verify(&[], b"msg", &tag),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn wrong_tag_length_is_invalid_argument() {
        let key = unhex(RFC4231[0].0);
        let tag = hmac_sha256(&key, b"msg").expect("valid arguments");
        let mut too_long = tag.to_vec();
        too_long.push(0);
        // The 31-byte prefix and the 33-byte extension of a correct tag are rejected by length,
        // not accepted as a truncated or padded form of it.
        for bad in [&tag[..31], &too_long[..], &tag[..0]] {
            assert_eq!(
                hmac_sha256_verify(&key, b"msg", bad),
                Err(Error::InvalidArgument),
                "tag length {}",
                bad.len()
            );
        }
    }

    #[test]
    fn empty_key_is_checked_before_tag_length() {
        for len in [0, 31, 33] {
            assert_eq!(
                hmac_sha256_verify(&[], b"msg", &vec![0u8; len]),
                Err(Error::InvalidArgument),
                "tag length {len}"
            );
        }
    }

    #[test]
    fn flipped_tag_bit_is_auth_failed() {
        let key = unhex(RFC4231[1].0);
        let msg = unhex(RFC4231[1].1);
        let tag = hmac_sha256(&key, &msg).expect("valid arguments");
        for bit in 0..EKI_HMAC_SHA256_LEN * 8 {
            let mut bad = tag;
            bad[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(
                hmac_sha256_verify(&key, &msg, &bad),
                Err(Error::AuthFailed),
                "bit {bit}"
            );
        }
    }

    #[test]
    fn correct_tag_is_accepted() {
        let key = unhex(RFC4231[1].0);
        let msg = unhex(RFC4231[1].1);
        let tag = hmac_sha256(&key, &msg).expect("valid arguments");
        assert_eq!(hmac_sha256_verify(&key, &msg, &tag), Ok(()));
    }
}
