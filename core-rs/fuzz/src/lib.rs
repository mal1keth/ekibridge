//! Inputs and shared checks for the cargo-fuzz targets of `ekicore-rs`.
//!
//! Every target calls the C ABI (`ekicore_rs::ffi::eki_*`) exactly as a C caller would: raw
//! pointers into live `Vec`s, lengths as `usize`, statuses read back as plain `i32`. The input
//! structs derive `Arbitrary`, so libFuzzer's byte strings become typed arguments. They live in
//! this library rather than in the targets so that `examples/seeds.rs` can build seed files for
//! them and check that each seed decodes back to the value it was built from.

use arbitrary::{Arbitrary, Result, Unstructured};

/// `EKI_OK`.
pub const EKI_OK: i32 = 0;
/// `EKI_ERR_NULL_POINTER`.
pub const EKI_ERR_NULL_POINTER: i32 = 1;
/// `EKI_ERR_UNSUPPORTED`. Today's stubs return it without looking at their arguments.
pub const EKI_ERR_UNSUPPORTED: i32 = 4;
/// `EKI_ERR_APPROVAL_REQUIRED`, the largest status value of ABI version 2.
pub const EKI_STATUS_MAX: i32 = 12;

/// Upper bound (inclusive) of the HKDF output length the targets ask for: a little past
/// `EKI_HKDF_MAX_OKM_LEN` (8160), so both sides of the limit get exercised.
pub const OKM_LEN_FUZZ_MAX: usize = 9000;

/// Longest label the unwrap targets pass, before the terminating NUL they append. Longer than
/// `EKI_LABEL_MAX_LEN` (64) so labels without a NUL in the first 65 bytes are covered.
pub const LABEL_FUZZ_MAX: usize = 80;

/// Panics unless `status` is one of the values ABI version 2 defines (0..=12).
pub fn assert_status_in_range(function: &str, status: i32) {
    assert!(
        (EKI_OK..=EKI_STATUS_MAX).contains(&status),
        "{function} returned {status}, outside 0..={EKI_STATUS_MAX}"
    );
}

/// True when `len` is a length the contract zero-fills on error for an output sized by the
/// caller (`okm_len` in 1..=8160). Lengths outside the range leave the output untouched.
pub fn okm_len_in_range(len: usize) -> bool {
    (1..=ekicore_abi::EKI_HKDF_MAX_OKM_LEN).contains(&len)
}

/// Reads the bounded `okm_len` used by [`HkdfInput`] and [`StatelessCall::Hkdf`].
pub fn arbitrary_okm_len(u: &mut Unstructured<'_>) -> Result<usize> {
    u.int_in_range(0..=OKM_LEN_FUZZ_MAX)
}

/// Input of the `aead_open` target.
#[derive(Arbitrary, Clone, Debug, PartialEq, Eq)]
pub struct AeadOpenInput {
    /// Algorithm selector, any `i32`.
    pub alg: i32,
    /// Key bytes, any length.
    pub key: Vec<u8>,
    /// Nonce bytes, any length.
    pub nonce: Vec<u8>,
    /// Associated data.
    pub aad: Vec<u8>,
    /// Ciphertext; the plaintext buffer gets the same length.
    pub ct: Vec<u8>,
    /// Detached tag.
    pub tag: [u8; 16],
}

/// Input of the `hkdf` target.
#[derive(Arbitrary, Clone, Debug, PartialEq, Eq)]
pub struct HkdfInput {
    /// Input keying material.
    pub ikm: Vec<u8>,
    /// Salt; empty means the RFC 5869 default salt.
    pub salt: Vec<u8>,
    /// Context string.
    pub info: Vec<u8>,
    /// Requested output length, 0..=[`OKM_LEN_FUZZ_MAX`].
    #[arbitrary(with = arbitrary_okm_len)]
    pub okm_len: usize,
}

/// A caller-supplied input buffer with a flag that replaces its pointer by NULL. The length is
/// passed unchanged either way: NULL with length 0 must succeed as if the buffer were empty,
/// NULL with a nonzero length must be `EKI_ERR_NULL_POINTER`, and the contract defines both.
#[derive(Arbitrary, Clone, Debug, PartialEq, Eq)]
pub struct InBuf {
    /// Pass NULL instead of the buffer's address.
    pub null: bool,
    /// The bytes; their count is the length argument.
    pub data: Vec<u8>,
}

impl InBuf {
    /// The pointer argument: NULL when [`InBuf::null`] is set, otherwise the buffer's address
    /// (a dangling but non-NULL address when the buffer is empty, which the contract allows).
    pub fn ptr(&self) -> *const u8 {
        if self.null {
            core::ptr::null()
        } else {
            self.data.as_ptr()
        }
    }

    /// The length argument.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// True when the length argument is 0.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// One call to a stateless function of the ABI, with a NULL flag for every pointer parameter.
#[derive(Arbitrary, Clone, Debug, PartialEq, Eq)]
pub enum StatelessCall {
    /// `eki_hmac_sha256`.
    Hmac {
        /// `key`, `key_len`.
        key: InBuf,
        /// `msg`, `msg_len`.
        msg: InBuf,
        /// Pass NULL as `out`.
        out_null: bool,
    },
    /// `eki_hmac_sha256_verify`.
    HmacVerify {
        /// `key`, `key_len`.
        key: InBuf,
        /// `msg`, `msg_len`.
        msg: InBuf,
        /// `tag`, `tag_len`.
        tag: InBuf,
    },
    /// `eki_hkdf_sha256`.
    Hkdf {
        /// `ikm`, `ikm_len`.
        ikm: InBuf,
        /// `salt`, `salt_len`.
        salt: InBuf,
        /// `info`, `info_len`.
        info: InBuf,
        /// Pass NULL as `okm`.
        okm_null: bool,
        /// `okm_len`, 0..=[`OKM_LEN_FUZZ_MAX`].
        #[arbitrary(with = arbitrary_okm_len)]
        okm_len: usize,
    },
    /// `eki_aead_seal`.
    AeadSeal {
        /// `alg`.
        alg: i32,
        /// `key`, `key_len`.
        key: InBuf,
        /// `nonce`, `nonce_len`.
        nonce: InBuf,
        /// `aad`, `aad_len`.
        aad: InBuf,
        /// `pt`, `pt_len`; `ct_out` gets the same length.
        pt: InBuf,
        /// Pass NULL as `ct_out`.
        ct_out_null: bool,
        /// Pass NULL as `tag_out`.
        tag_out_null: bool,
    },
    /// `eki_aead_open`.
    AeadOpen {
        /// `alg`.
        alg: i32,
        /// `key`, `key_len`.
        key: InBuf,
        /// `nonce`, `nonce_len`.
        nonce: InBuf,
        /// `aad`, `aad_len`.
        aad: InBuf,
        /// `ct`, `ct_len`; `pt_out` gets the same length.
        ct: InBuf,
        /// Pass NULL as `tag`.
        tag_null: bool,
        /// The 16 tag bytes.
        tag: [u8; 16],
        /// Pass NULL as `pt_out`.
        pt_out_null: bool,
    },
    /// `eki_ecdsa_p256_verify`.
    EcdsaVerify {
        /// Pass NULL as `public_key`.
        public_key_null: bool,
        /// The 65 public key bytes.
        public_key: [u8; 65],
        /// `msg`, `msg_len`.
        msg: InBuf,
        /// Pass NULL as `sig`.
        sig_null: bool,
        /// The 64 signature bytes.
        sig: [u8; 64],
    },
}

/// Input of the `unwrap_blob` target.
#[derive(Arbitrary, Clone, Debug, PartialEq, Eq)]
pub struct UnwrapInput {
    /// When set, the blob is a real wrap of a freshly generated HMAC key, XORed with
    /// [`UnwrapInput::blob`] (missing bytes count as 0), so a run can reach `EKI_OK`. When
    /// clear, [`UnwrapInput::blob`] is passed as it is.
    pub from_wrap: bool,
    /// Blob bytes (any length) or the XOR mask described above.
    pub blob: Vec<u8>,
    /// Key algorithm selector, any `i32`.
    pub alg: i32,
    /// Id to store the unwrapped key under.
    pub id: [u8; 16],
    /// Label bytes; the target keeps at most [`LABEL_FUZZ_MAX`] and appends a NUL.
    pub label: Vec<u8>,
}

/// Turns arbitrary label bytes into the NUL-terminated string the targets pass as `label`.
pub fn c_label(bytes: &[u8]) -> Vec<u8> {
    let mut label: Vec<u8> = bytes.iter().copied().take(LABEL_FUZZ_MAX).collect();
    label.push(0);
    label
}
