//! AES-256-GCM and ChaCha20-Poly1305 with detached tags, over the RustCrypto `aes-gcm` and
//! `chacha20poly1305` crates.
//!
//! The safe layer behind `eki_aead_seal` and `eki_aead_open`: it takes slices and returns
//! `Result<_, Error>`; `ffi.rs` converts the C pointers and maps the error to a status.

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::array::typenum::Unsigned;
use aes_gcm::aead::consts::{U12, U16, U32};
use aes_gcm::aead::inout::InOutBuf;
use aes_gcm::aead::{AeadInOut, KeyInit, Nonce, Tag};
use chacha20poly1305::ChaCha20Poly1305;
use ekicore_abi::{
    EKI_AEAD_AES_256_GCM, EKI_AEAD_CHACHA20_POLY1305, EKI_AEAD_KEY_LEN, EKI_AEAD_MAX_LEN,
    EKI_AEAD_NONCE_LEN, EKI_AEAD_TAG_LEN, eki_aead_alg,
};

use crate::error::Error;

/// Both algorithms are used through the generic functions below, which fix the sizes in their
/// bounds. These assertions tie those sizes to the ABI constants, so a mismatch fails to compile
/// instead of surfacing as an error on a valid call.
/// cbindgen:ignore
const _: () = {
    assert!(U32::USIZE == EKI_AEAD_KEY_LEN);
    assert!(U12::USIZE == EKI_AEAD_NONCE_LEN);
    assert!(U16::USIZE == EKI_AEAD_TAG_LEN);
};

/// Largest plaintext or ciphertext length, the same for both algorithms.
///
/// This is `EKI_AEAD_MAX_LEN`, 2^36 - 32 bytes. It is the AES-GCM limit (`aes_gcm::P_MAX`, the
/// 32-bit block counter allows 2^32 - 2 blocks of 16 bytes). ChaCha20-Poly1305 would allow
/// 2^32 - 1 blocks of 64 bytes, about 2^38 bytes, but a single cap keeps the ABI independent of
/// the selector: a length that one algorithm accepts, the other accepts too. On a target whose
/// `usize` is narrower than the cap, every length a slice can have is within it, so the value
/// saturates at `usize::MAX`.
/// cbindgen:ignore
pub const MAX_LEN: usize = if EKI_AEAD_MAX_LEN > usize::MAX as u64 {
    usize::MAX
} else {
    EKI_AEAD_MAX_LEN as usize
};

/// Encrypts `pt` into `ct` with `alg` and writes the 16-byte authentication tag to `tag`.
///
/// The checks run in this order and the first failure decides the error, always
/// [`Error::InvalidArgument`]: `alg` is neither `EKI_AEAD_AES_256_GCM` nor
/// `EKI_AEAD_CHACHA20_POLY1305`; `key` is not 32 bytes; `nonce` is not 12 bytes; `pt` is longer
/// than [`MAX_LEN`]; `ct` is not as long as `pt`; `tag` is not 16 bytes. `aad` and `pt` may be
/// empty. `pt` and `ct` are separate buffers. On success every byte of `ct` and `tag` is
/// written; on failure both are left as they were.
pub fn seal(
    alg: eki_aead_alg,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    pt: &[u8],
    ct: &mut [u8],
    tag: &mut [u8],
) -> Result<(), Error> {
    // A `match` on the constants, not a conversion to an enum: `alg` is any `i32` a C caller
    // passes, and only the two known values may reach a cipher.
    match alg {
        EKI_AEAD_AES_256_GCM => seal_with::<Aes256Gcm>(key, nonce, aad, pt, ct, tag),
        EKI_AEAD_CHACHA20_POLY1305 => seal_with::<ChaCha20Poly1305>(key, nonce, aad, pt, ct, tag),
        _ => Err(Error::InvalidArgument),
    }
}

/// Verifies `tag` and decrypts `ct` into `pt` with `alg`.
///
/// The checks run in this order and the first failure decides the error: `alg` is neither
/// `EKI_AEAD_AES_256_GCM` nor `EKI_AEAD_CHACHA20_POLY1305`; `key` is not 32 bytes; `nonce` is not
/// 12 bytes; `ct` is longer than [`MAX_LEN`]; `pt` is not as long as `ct`; `tag` is not 16 bytes
/// (all [`Error::InvalidArgument`]); then a tag that does not verify, which is
/// [`Error::AuthFailed`]. `aad` and `ct` may be empty, and an empty `ct` with the right tag opens
/// successfully. `ct` and `pt` are separate buffers. On success every byte of `pt` is written. On
/// [`Error::InvalidArgument`] `pt` is left as it was; on [`Error::AuthFailed`] it is zero-filled.
pub fn open(
    alg: eki_aead_alg,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8],
    pt: &mut [u8],
) -> Result<(), Error> {
    match alg {
        EKI_AEAD_AES_256_GCM => open_with::<Aes256Gcm>(key, nonce, aad, ct, tag, pt),
        EKI_AEAD_CHACHA20_POLY1305 => open_with::<ChaCha20Poly1305>(key, nonce, aad, ct, tag, pt),
        _ => Err(Error::InvalidArgument),
    }
}

/// The text length rule: at most [`MAX_LEN`] bytes.
fn check_text_len(len: usize) -> Result<(), Error> {
    if len > MAX_LEN {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// The size rules of one call, in order: `key`, `nonce`, the length of the input text `text`,
/// then the sizes only a Rust caller can get wrong, `out` as long as `text` and a 16-byte `tag`.
/// Through the C ABI those two hold by construction: the output is sized by the input text and
/// the tag is a fixed-size buffer.
fn check_sizes(key: &[u8], nonce: &[u8], text: &[u8], out: &[u8], tag: &[u8]) -> Result<(), Error> {
    if key.len() != EKI_AEAD_KEY_LEN {
        return Err(Error::InvalidArgument);
    }
    if nonce.len() != EKI_AEAD_NONCE_LEN {
        return Err(Error::InvalidArgument);
    }
    check_text_len(text.len())?;
    if out.len() != text.len() {
        return Err(Error::InvalidArgument);
    }
    if tag.len() != EKI_AEAD_TAG_LEN {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Builds the cipher, which holds the expanded key and wipes it on drop, and the typed nonce.
///
/// The key is passed by reference all the way into the cipher, so no other copy of it is made
/// here. Both conversions fail only on a wrong length, and `check_sizes` has already rejected
/// those, so no caller input reaches the error. It is mapped instead of unwrapped so that this
/// path contains no panic.
fn init<'a, C>(key: &[u8], nonce: &'a [u8]) -> Result<(C, &'a Nonce<C>), Error>
where
    C: AeadInOut<NonceSize = U12, TagSize = U16> + KeyInit<KeySize = U32>,
{
    let cipher = C::new_from_slice(key).map_err(|_| Error::InvalidArgument)?;
    let nonce = <&Nonce<C>>::try_from(nonce).map_err(|_| Error::InvalidArgument)?;
    Ok((cipher, nonce))
}

/// `seal` for one algorithm, after the selector check.
fn seal_with<C>(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    pt: &[u8],
    ct: &mut [u8],
    tag: &mut [u8],
) -> Result<(), Error>
where
    C: AeadInOut<NonceSize = U12, TagSize = U16> + KeyInit<KeySize = U32>,
{
    check_sizes(key, nonce, pt, ct, tag)?;
    let (cipher, nonce) = init::<C>(key, nonce)?;
    // The lengths are equal (`check_sizes`), the only way `InOutBuf::new` fails.
    let buffer = InOutBuf::new(pt, ct).map_err(|_| Error::InvalidArgument)?;

    // Reads `pt`, writes `ct` and returns the tag. The crates fail only for a text longer than
    // their own limit (`aes_gcm::P_MAX`, which equals `MAX_LEN`, and about 2^38 bytes for
    // ChaCha20-Poly1305), both excluded by `check_sizes`, or for associated data longer than
    // 2^61 - 1 bytes, which no allocation reaches. Those limit checks run before the crates
    // write anything, so `ct` is left as it was.
    let computed = cipher
        .encrypt_inout_detached(nonce, aad, buffer)
        .map_err(|_| Error::InvalidArgument)?;
    tag.copy_from_slice(&computed);
    Ok(())
}

/// `open` for one algorithm, after the selector check.
fn open_with<C>(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8],
    pt: &mut [u8],
) -> Result<(), Error>
where
    C: AeadInOut<NonceSize = U12, TagSize = U16> + KeyInit<KeySize = U32>,
{
    check_sizes(key, nonce, ct, pt, tag)?;
    let (cipher, nonce) = init::<C>(key, nonce)?;
    // The tag is 16 bytes and the lengths are equal (`check_sizes`), the only ways these two
    // conversions fail.
    let tag = <&Tag<C>>::try_from(tag).map_err(|_| Error::InvalidArgument)?;
    let buffer = InOutBuf::new(ct, pt).map_err(|_| Error::InvalidArgument)?;

    // The crate recomputes the tag over `aad` and `ct`, compares it with `tag` in constant time
    // (`ctutils::CtEq`, which does not stop at the first differing byte) and only on a match
    // applies the keystream to `ct`, so `pt` is not written when the tag is wrong. That is a
    // property of the crates, not a promise of their interface, so the fill below does not rely
    // on it: after an authentication failure `pt` is all zero whatever the crate did with it.
    // The crate error carries no cause. After `check_sizes` the only one that can occur is the
    // tag mismatch: its other causes are a text above the crates' limits and associated data
    // longer than 2^61 - 1 bytes, which no allocation reaches.
    if cipher
        .decrypt_inout_detached(nonce, aad, buffer, tag)
        .is_err()
    {
        pt.fill(0);
        return Err(Error::AuthFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pre-fill of the output buffers, so that a write to one, and a zero-fill, are visible.
    const FILL: u8 = 0xA5;

    const ALGS: [eki_aead_alg; 2] = [EKI_AEAD_AES_256_GCM, EKI_AEAD_CHACHA20_POLY1305];

    /// RFC 8439 section 2.8.2: ChaCha20-Poly1305 with associated data.
    const RFC8439_KEY: &str = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    const RFC8439_NONCE: &str = "070000004041424344454647";
    const RFC8439_AAD: &str = "50515253c0c1c2c3c4c5c6c7";
    const RFC8439_PT: &str = "4c616469657320616e642047656e746c656d656e206f662074686520636c6173\
                              73206f66202739393a204966204920636f756c64206f6666657220796f75206f\
                              6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73\
                              637265656e20776f756c642062652069742e";
    const RFC8439_CT: &str = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
                              3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
                              92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
                              3ff4def08e4b7a9de576d26586cec64b6116";
    const RFC8439_TAG: &str = "1ae10b594f09e26a7e902ecbd0600691";

    /// Test case 16 of the GCM specification (McGrew and Viega): AES-256-GCM, 96-bit IV, 20 bytes
    /// of associated data and a 60-byte plaintext, so the last block is partial.
    const GCM16_KEY: &str = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
    const GCM16_NONCE: &str = "cafebabefacedbaddecaf888";
    const GCM16_AAD: &str = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
    const GCM16_PT: &str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                            1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
    const GCM16_CT: &str = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
                            8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662";
    const GCM16_TAG: &str = "76fc6ece0f4e1768cddf8853bb2d551b";

    /// Test case 13 of the GCM specification: all-zero key and IV, empty plaintext, no AAD.
    const GCM13_TAG: &str = "530f8afbc74536b9a963b4f1c4cb738b";

    fn unhex(text: &str) -> Vec<u8> {
        hex::decode(text).expect("test vector is valid hex")
    }

    /// The inputs of one call, with the expected ciphertext and tag where they are known.
    #[derive(Clone)]
    struct Case {
        alg: eki_aead_alg,
        key: Vec<u8>,
        nonce: Vec<u8>,
        aad: Vec<u8>,
        pt: Vec<u8>,
        ct: Vec<u8>,
        tag: Vec<u8>,
    }

    fn rfc8439() -> Case {
        Case {
            alg: EKI_AEAD_CHACHA20_POLY1305,
            key: unhex(RFC8439_KEY),
            nonce: unhex(RFC8439_NONCE),
            aad: unhex(RFC8439_AAD),
            pt: unhex(RFC8439_PT),
            ct: unhex(RFC8439_CT),
            tag: unhex(RFC8439_TAG),
        }
    }

    fn gcm16() -> Case {
        Case {
            alg: EKI_AEAD_AES_256_GCM,
            key: unhex(GCM16_KEY),
            nonce: unhex(GCM16_NONCE),
            aad: unhex(GCM16_AAD),
            pt: unhex(GCM16_PT),
            ct: unhex(GCM16_CT),
            tag: unhex(GCM16_TAG),
        }
    }

    /// The two known-answer cases, one per algorithm, both with associated data.
    fn known_cases() -> [Case; 2] {
        [rfc8439(), gcm16()]
    }

    /// Seals `c.pt` into a `ct_len`-byte and a `tag_len`-byte buffer pre-filled with `fill`.
    fn seal_into(
        c: &Case,
        ct_len: usize,
        tag_len: usize,
        fill: u8,
    ) -> (Result<(), Error>, Vec<u8>, Vec<u8>) {
        let mut ct = vec![fill; ct_len];
        let mut tag = vec![fill; tag_len];
        let result = seal(c.alg, &c.key, &c.nonce, &c.aad, &c.pt, &mut ct, &mut tag);
        (result, ct, tag)
    }

    /// Seals `c.pt` into correctly sized buffers.
    fn seal_case(c: &Case) -> (Result<(), Error>, Vec<u8>, Vec<u8>) {
        seal_into(c, c.pt.len(), EKI_AEAD_TAG_LEN, FILL)
    }

    /// Opens `c.ct` with `c.tag` into a `pt_len`-byte buffer pre-filled with `fill`.
    fn open_into(c: &Case, pt_len: usize, fill: u8) -> (Result<(), Error>, Vec<u8>) {
        let mut pt = vec![fill; pt_len];
        let result = open(c.alg, &c.key, &c.nonce, &c.aad, &c.ct, &c.tag, &mut pt);
        (result, pt)
    }

    /// Opens `c.ct` with `c.tag` into a correctly sized buffer.
    fn open_case(c: &Case) -> (Result<(), Error>, Vec<u8>) {
        open_into(c, c.ct.len(), FILL)
    }

    /// Asserts that opening `c` fails authentication and leaves `pt` all zero.
    #[track_caller]
    fn assert_auth_failed(c: &Case, what: &str) {
        let (result, pt) = open_case(c);
        assert_eq!(result, Err(Error::AuthFailed), "{what}");
        assert!(pt.iter().all(|&b| b == 0), "{what}: pt not zero-filled");
    }

    /// A case with a deterministic key, nonce and AAD and a plaintext of the given lengths.
    fn generated(alg: eki_aead_alg, aad_len: usize, pt_len: usize) -> Case {
        let bytes = |len: usize, seed: u8| -> Vec<u8> {
            (0..len).map(|i| (i as u8).wrapping_mul(7) ^ seed).collect()
        };
        Case {
            alg,
            key: bytes(EKI_AEAD_KEY_LEN, 0x11),
            nonce: bytes(EKI_AEAD_NONCE_LEN, 0x22),
            aad: bytes(aad_len, 0x33),
            pt: bytes(pt_len, 0x44),
            ct: Vec::new(),
            tag: Vec::new(),
        }
    }

    #[test]
    fn known_answer_seal() {
        for c in known_cases() {
            let (result, ct, tag) = seal_case(&c);
            assert_eq!(result, Ok(()), "alg {:?}", c.alg);
            assert_eq!(ct, c.ct, "alg {:?}: ciphertext", c.alg);
            assert_eq!(tag, c.tag, "alg {:?}: tag", c.alg);
        }
    }

    #[test]
    fn known_answer_open() {
        for c in known_cases() {
            let (result, pt) = open_case(&c);
            assert_eq!(result, Ok(()), "alg {:?}", c.alg);
            assert_eq!(pt, c.pt, "alg {:?}", c.alg);
        }
    }

    #[test]
    fn round_trip_over_text_and_aad_lengths() {
        // The text lengths cover empty, a single byte, either side of the 16-byte GCM block and
        // the 64-byte ChaCha block, and several blocks; the AAD lengths cover empty and partial
        // blocks.
        for alg in ALGS {
            for pt_len in [0, 1, 15, 16, 17, 63, 64, 65, 1000] {
                for aad_len in [0, 1, 20] {
                    let mut c = generated(alg, aad_len, pt_len);
                    let (result, ct, tag) = seal_case(&c);
                    assert_eq!(result, Ok(()), "alg {alg:?} pt {pt_len} aad {aad_len}");
                    assert_eq!(ct.len(), pt_len);
                    c.ct = ct;
                    c.tag = tag;
                    let (result, pt) = open_case(&c);
                    assert_eq!(result, Ok(()), "alg {alg:?} pt {pt_len} aad {aad_len}");
                    assert_eq!(pt, c.pt, "alg {alg:?} pt {pt_len} aad {aad_len}");
                }
            }
        }
    }

    #[test]
    fn empty_plaintext_and_empty_aad_have_the_specified_tag() {
        // GCM test case 13: the tag of an empty message under an all-zero key and IV.
        let mut c = Case {
            alg: EKI_AEAD_AES_256_GCM,
            key: vec![0; EKI_AEAD_KEY_LEN],
            nonce: vec![0; EKI_AEAD_NONCE_LEN],
            aad: Vec::new(),
            pt: Vec::new(),
            ct: Vec::new(),
            tag: unhex(GCM13_TAG),
        };
        let (result, ct, tag) = seal_case(&c);
        assert_eq!(result, Ok(()));
        assert!(ct.is_empty());
        assert_eq!(tag, c.tag);

        // An empty ciphertext with the right tag opens; with a wrong tag it does not.
        assert_eq!(open_case(&c), (Ok(()), Vec::new()));
        c.tag[15] ^= 1;
        assert_eq!(open_case(&c), (Err(Error::AuthFailed), Vec::new()));
    }

    #[test]
    fn success_writes_every_output_byte() {
        // A byte left unwritten would keep its pre-fill, so two different pre-fills would give
        // two different buffers.
        for alg in ALGS {
            for pt_len in [0, 1, 15, 16, 17, 63, 64, 65, 1000] {
                let mut c = generated(alg, 20, pt_len);
                let (result, ct, tag) = seal_into(&c, pt_len, EKI_AEAD_TAG_LEN, 0x00);
                assert_eq!(result, Ok(()));
                let (result, ct_ones, tag_ones) = seal_into(&c, pt_len, EKI_AEAD_TAG_LEN, 0xFF);
                assert_eq!(result, Ok(()));
                assert_eq!(
                    (&ct, &tag),
                    (&ct_ones, &tag_ones),
                    "alg {alg:?} seal {pt_len}"
                );

                c.ct = ct;
                c.tag = tag;
                let (result, pt) = open_into(&c, pt_len, 0x00);
                assert_eq!(result, Ok(()));
                let (result, pt_ones) = open_into(&c, pt_len, 0xFF);
                assert_eq!(result, Ok(()));
                assert_eq!(pt, pt_ones, "alg {alg:?} open {pt_len}");
            }
        }
    }

    #[test]
    fn unknown_alg_is_invalid_argument() {
        for alg in [0, 3, -1, 99, i32::MIN, i32::MAX] {
            let mut c = gcm16();
            c.alg = eki_aead_alg(alg);
            let (result, ct, tag) = seal_case(&c);
            assert_eq!(result, Err(Error::InvalidArgument), "seal alg {alg}");
            assert!(ct.iter().chain(&tag).all(|&b| b == FILL), "seal alg {alg}");
            let (result, pt) = open_case(&c);
            assert_eq!(result, Err(Error::InvalidArgument), "open alg {alg}");
            assert!(pt.iter().all(|&b| b == FILL), "open alg {alg}");
        }
    }

    #[test]
    fn key_length_must_be_32() {
        for alg in ALGS {
            for len in [0, 1, 16, 31, 33, 64] {
                let mut c = gcm16();
                c.alg = alg;
                c.key = vec![0x42; len];
                let (result, ct, tag) = seal_case(&c);
                assert_eq!(
                    result,
                    Err(Error::InvalidArgument),
                    "seal {alg:?} key {len}"
                );
                assert!(ct.iter().chain(&tag).all(|&b| b == FILL));
                let (result, pt) = open_case(&c);
                assert_eq!(
                    result,
                    Err(Error::InvalidArgument),
                    "open {alg:?} key {len}"
                );
                assert!(pt.iter().all(|&b| b == FILL));
            }
        }
    }

    #[test]
    fn nonce_length_must_be_12() {
        for alg in ALGS {
            for len in [0, 1, 11, 13, 16, 24] {
                let mut c = gcm16();
                c.alg = alg;
                c.nonce = vec![0x42; len];
                let (result, ct, tag) = seal_case(&c);
                assert_eq!(
                    result,
                    Err(Error::InvalidArgument),
                    "seal {alg:?} nonce {len}"
                );
                assert!(ct.iter().chain(&tag).all(|&b| b == FILL));
                let (result, pt) = open_case(&c);
                assert_eq!(
                    result,
                    Err(Error::InvalidArgument),
                    "open {alg:?} nonce {len}"
                );
                assert!(pt.iter().all(|&b| b == FILL));
            }
        }
    }

    #[test]
    fn text_length_is_capped_at_the_abi_maximum() {
        // A buffer of that size cannot be allocated in a test, so the rule is checked on the
        // length. `check_sizes` and both public functions go through it.
        assert_eq!(check_text_len(0), Ok(()));
        assert_eq!(check_text_len(MAX_LEN), Ok(()));
        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(MAX_LEN as u64, EKI_AEAD_MAX_LEN);
            assert_eq!(check_text_len(MAX_LEN + 1), Err(Error::InvalidArgument));
            assert_eq!(check_text_len(usize::MAX), Err(Error::InvalidArgument));
        }
        #[cfg(not(target_pointer_width = "64"))]
        assert_eq!(MAX_LEN, usize::MAX);
    }

    #[test]
    fn cap_is_the_gcm_limit_and_within_the_chacha_limit() {
        assert_eq!(aes_gcm::P_MAX, EKI_AEAD_MAX_LEN);
        assert_eq!(EKI_AEAD_MAX_LEN, (1 << 36) - 32);
        // `chacha20poly1305` rejects a text of 64 * (2^32 - 1) bytes or more.
        assert!(EKI_AEAD_MAX_LEN < 64 * (u64::from(u32::MAX) - 1));
    }

    #[test]
    fn output_text_length_must_equal_input_text_length() {
        for c in known_cases() {
            for ct_len in [0, c.pt.len() - 1, c.pt.len() + 1, 2 * c.pt.len()] {
                let (result, ct, tag) = seal_into(&c, ct_len, EKI_AEAD_TAG_LEN, FILL);
                assert_eq!(result, Err(Error::InvalidArgument), "seal ct {ct_len}");
                assert!(
                    ct.iter().chain(&tag).all(|&b| b == FILL),
                    "seal ct {ct_len}"
                );
            }
            for pt_len in [0, c.ct.len() - 1, c.ct.len() + 1, 2 * c.ct.len()] {
                let (result, pt) = open_into(&c, pt_len, FILL);
                assert_eq!(result, Err(Error::InvalidArgument), "open pt {pt_len}");
                assert!(pt.iter().all(|&b| b == FILL), "open pt {pt_len}");
            }
        }
    }

    #[test]
    fn tag_length_must_be_16() {
        for c in known_cases() {
            for tag_len in [0, 1, 15, 17, 32] {
                let (result, ct, tag) = seal_into(&c, c.pt.len(), tag_len, FILL);
                assert_eq!(result, Err(Error::InvalidArgument), "seal tag {tag_len}");
                assert!(
                    ct.iter().chain(&tag).all(|&b| b == FILL),
                    "seal tag {tag_len}"
                );

                // The right tag with bytes cut off or appended is a format error, not a mismatch.
                let mut bad = c.clone();
                bad.tag = if tag_len <= 16 {
                    c.tag[..tag_len].to_vec()
                } else {
                    [c.tag.clone(), vec![0; tag_len - 16]].concat()
                };
                let (result, pt) = open_case(&bad);
                assert_eq!(result, Err(Error::InvalidArgument), "open tag {tag_len}");
                assert!(pt.iter().all(|&b| b == FILL), "open tag {tag_len}");
            }
        }
    }

    #[test]
    fn invalid_arguments_are_reported_before_authentication() {
        // Each case also has a tag that would fail verification. The error stays
        // `InvalidArgument` and `pt` is not zero-filled, because the cipher is never run.
        for c in known_cases() {
            let mut bad_tag = c.clone();
            bad_tag.tag[0] ^= 1;

            let mut unknown_alg = bad_tag.clone();
            unknown_alg.alg = eki_aead_alg(0);
            let mut short_key = bad_tag.clone();
            short_key.key.pop();
            let mut short_nonce = bad_tag.clone();
            short_nonce.nonce.pop();
            for (what, case, pt_len) in [
                ("alg", &unknown_alg, c.ct.len()),
                ("key", &short_key, c.ct.len()),
                ("nonce", &short_nonce, c.ct.len()),
                ("pt length", &bad_tag, c.ct.len() + 1),
            ] {
                let (result, pt) = open_into(case, pt_len, FILL);
                assert_eq!(result, Err(Error::InvalidArgument), "{what}");
                assert!(pt.iter().all(|&b| b == FILL), "{what}");
            }
            let mut short_tag = bad_tag.clone();
            short_tag.tag.pop();
            let (result, pt) = open_case(&short_tag);
            assert_eq!(result, Err(Error::InvalidArgument), "tag length");
            assert!(pt.iter().all(|&b| b == FILL), "tag length");
        }
    }

    #[test]
    fn flipping_any_tag_bit_is_auth_failed() {
        for c in known_cases() {
            for bit in 0..EKI_AEAD_TAG_LEN * 8 {
                let mut bad = c.clone();
                bad.tag[bit / 8] ^= 1 << (bit % 8);
                assert_auth_failed(&bad, &format!("alg {:?} tag bit {bit}", c.alg));
            }
        }
    }

    #[test]
    fn changed_aad_is_auth_failed() {
        for c in known_cases() {
            let mut flipped = c.clone();
            flipped.aad[0] ^= 1;
            assert_auth_failed(&flipped, &format!("alg {:?}: AAD bit flipped", c.alg));

            let mut dropped = c.clone();
            dropped.aad.clear();
            assert_auth_failed(&dropped, &format!("alg {:?}: AAD dropped", c.alg));

            let mut extended = c.clone();
            extended.aad.push(0);
            assert_auth_failed(&extended, &format!("alg {:?}: AAD extended", c.alg));
        }
    }

    #[test]
    fn changed_ciphertext_is_auth_failed() {
        for c in known_cases() {
            for index in 0..c.ct.len() {
                let mut bad = c.clone();
                bad.ct[index] ^= 0x80;
                assert_auth_failed(&bad, &format!("alg {:?}: ct byte {index}", c.alg));
            }
            let mut truncated = c.clone();
            truncated.ct.pop();
            assert_auth_failed(&truncated, &format!("alg {:?}: ct truncated", c.alg));

            let mut extended = c.clone();
            extended.ct.push(0);
            assert_auth_failed(&extended, &format!("alg {:?}: ct extended", c.alg));
        }
    }

    #[test]
    fn wrong_key_or_nonce_is_auth_failed() {
        for c in known_cases() {
            let mut wrong_key = c.clone();
            wrong_key.key[31] ^= 1;
            assert_auth_failed(&wrong_key, &format!("alg {:?}: key", c.alg));

            let mut wrong_nonce = c.clone();
            wrong_nonce.nonce[0] ^= 1;
            assert_auth_failed(&wrong_nonce, &format!("alg {:?}: nonce", c.alg));
        }
    }

    #[test]
    fn ciphers_wipe_their_state_on_drop() {
        // The cipher objects hold the expanded key. These bounds are met only while the `zeroize`
        // features of `aes-gcm` and `chacha20poly1305` are enabled in `Cargo.toml`.
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<Aes256Gcm>();
        assert_zeroize_on_drop::<ChaCha20Poly1305>();
    }

    #[test]
    fn the_same_inputs_under_the_other_algorithm_are_auth_failed() {
        for c in known_cases() {
            let mut other = c.clone();
            other.alg = if c.alg == EKI_AEAD_AES_256_GCM {
                EKI_AEAD_CHACHA20_POLY1305
            } else {
                EKI_AEAD_AES_256_GCM
            };
            assert_auth_failed(
                &other,
                &format!("alg {:?} opened as {:?}", c.alg, other.alg),
            );
        }
    }
}
