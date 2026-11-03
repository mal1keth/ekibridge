//! RFC 3394 AES Key Wrap of a 32-byte key under a 256-bit key-encryption key (KEK), over the
//! RustCrypto `aes-kw` crate.
//!
//! The primitive behind `eki_ks_wrap` and `eki_ks_unwrap` of the software key store. The ABI
//! does not expose it directly: a key is wrapped and unwrapped only through stored keys. The
//! wrapped form is the 40-byte RFC 3394 output with the default initial value `A6A6A6A6A6A6A6A6`
//! and no header, which is what PKCS#11 `CKM_AES_KEY_WRAP` and OpenSSL `EVP_aes_256_wrap`
//! produce for the same key and KEK.

use aes_kw::cipher::consts::U32;
use aes_kw::{KeyInit, KwAes256};
use ekicore_abi::EKI_WRAPPED_KEY_LEN;
use secrecy::{ExposeSecretMut, SecretBox};

use crate::error::Error;

/// Length in bytes of a KEK and of a key that can be wrapped.
/// cbindgen:ignore
pub const KEY_LEN: usize = 32;

/// The cipher is dropped at the end of each call, and with it the expanded KEK schedule. These
/// assertions make "the schedule is wiped on drop" a compile-time fact: `KwAes256` implements
/// `ZeroizeOnDrop` only while the `zeroize` feature of `aes-kw` (and through it of `aes`) is on.
/// cbindgen:ignore
const _: () = {
    const fn wipes_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    wipes_on_drop::<KwAes256>();
    wipes_on_drop::<SecretBox<[u8; KEY_LEN]>>();
};

/// Wraps `key` under `kek`.
///
/// RFC 3394 is deterministic: the same key and KEK always give the same 40 bytes. Neither input
/// is copied: the crate reads both in place, and its copy of the expanded KEK is wiped when the
/// cipher is dropped at the end of the call.
pub fn wrap(kek: &[u8; KEY_LEN], key: &[u8; KEY_LEN]) -> [u8; EKI_WRAPPED_KEY_LEN] {
    let cipher = KwAes256::new(kek.into());
    // `wrap_fixed_key` takes the key size as a type (`U32`, 32 bytes, so the result is 40), so it
    // has no size error to report.
    cipher.wrap_fixed_key::<U32>(key.into()).into()
}

/// Unwraps `blob` under `kek` and returns the 32-byte key in zeroizing storage.
///
/// A blob that fails the RFC 3394 integrity check (the recovered initial value is not
/// `A6A6A6A6A6A6A6A6`), which includes a blob wrapped under another KEK, is
/// [`Error::AuthFailed`]; no key is returned and the crate zero-fills its output buffer.
///
/// The key is written straight into the heap buffer of the returned [`SecretBox`], so it is never
/// copied to a temporary first, and moving the result moves only the pointer.
pub fn unwrap(
    kek: &[u8; KEY_LEN],
    blob: &[u8; EKI_WRAPPED_KEY_LEN],
) -> Result<SecretBox<[u8; KEY_LEN]>, Error> {
    let cipher = KwAes256::new(kek.into());
    let mut key = SecretBox::<[u8; KEY_LEN]>::default();
    match cipher.unwrap_key(blob, key.expose_secret_mut()) {
        Ok(_) => Ok(key),
        Err(aes_kw::Error::IntegrityCheckFailed) => Err(Error::AuthFailed),
        // The other errors are size errors: a blob that is not a multiple of 8 bytes, or an
        // output shorter than the blob minus 8. The array types rule both out.
        Err(aes_kw::Error::InvalidDataSize | aes_kw::Error::InvalidOutputSize { .. }) => {
            Err(Error::Internal)
        }
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    /// RFC 3394 section 4.6: 256 bits of key data wrapped with a 256-bit KEK.
    const KEK: &str = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    const KEY: &str = "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F";
    const BLOB: &str =
        "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21";

    fn unhex<const N: usize>(text: &str) -> [u8; N] {
        hex::decode(text)
            .expect("test vector is valid hex")
            .try_into()
            .expect("test vector has the expected length")
    }

    #[test]
    fn rfc3394_section_4_6_wrap() {
        assert_eq!(wrap(&unhex(KEK), &unhex(KEY)), unhex::<40>(BLOB));
    }

    #[test]
    fn rfc3394_section_4_6_unwrap() {
        let key = unwrap(&unhex(KEK), &unhex(BLOB)).expect("the vector passes the check");
        assert_eq!(key.expose_secret(), &unhex::<32>(KEY));
    }

    #[test]
    fn every_flipped_bit_is_auth_failed() {
        let kek = unhex(KEK);
        let blob: [u8; 40] = unhex(BLOB);
        for bit in 0..EKI_WRAPPED_KEY_LEN * 8 {
            let mut bad = blob;
            bad[bit / 8] ^= 1 << (bit % 8);
            assert!(
                matches!(unwrap(&kek, &bad), Err(Error::AuthFailed)),
                "bit {bit}"
            );
        }
    }

    #[test]
    fn wrong_kek_is_auth_failed() {
        let mut other = unhex::<32>(KEK);
        other[31] ^= 0x01;
        assert!(matches!(
            unwrap(&other, &unhex(BLOB)),
            Err(Error::AuthFailed)
        ));
    }

    #[test]
    fn self_wrap_round_trips() {
        let kek = unhex(KEK);
        let blob = wrap(&kek, &kek);
        let key = unwrap(&kek, &blob).expect("a fresh blob passes the check");
        assert_eq!(key.expose_secret(), &kek);
    }
}
