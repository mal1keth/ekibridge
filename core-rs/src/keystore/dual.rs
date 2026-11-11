//! Dual control of destroy (docs/ffi-contract.md, "Dual control"): the approver keys of a handle
//! and its pending destroy requests.
//!
//! The data lives in the handle, behind its lock, and vanishes when the handle closes. Approver
//! private keys never enter the library: an approval is an ECDSA P-256 signature made elsewhere
//! over [`approval_message`], checked here with [`crate::ecdsa`].

use std::collections::BTreeMap;

use ekicore_abi::{
    EKI_APPROVERS_MAX, EKI_DESTROY_REQUEST_LEN, EKI_KEY_ID_LEN, EKI_P256_PUBLIC_KEY_LEN,
};

use super::KeyId;
use crate::ecdsa;
use crate::error::Error;

/// The smallest number of approver keys a handle with dual control has.
/// cbindgen:ignore
pub const APPROVERS_MIN: usize = 2;

/// The number of distinct approvers whose approvals destroy a key.
/// cbindgen:ignore
pub const APPROVALS_NEEDED: u32 = 2;

/// The 20 ASCII bytes an approval message starts with.
/// cbindgen:ignore
pub const DOMAIN: &[u8; 20] = b"ekibridge-destroy-v1";

/// Length of an approval message: the domain, the request, the key id.
/// cbindgen:ignore
pub const MESSAGE_LEN: usize = DOMAIN.len() + EKI_DESTROY_REQUEST_LEN + EKI_KEY_ID_LEN;

/// A SEC1 uncompressed P-256 public key.
pub type PublicKey = [u8; EKI_P256_PUBLIC_KEY_LEN];

/// The value of a destroy request.
pub type Request = [u8; EKI_DESTROY_REQUEST_LEN];

/// The `approver_count` rule: 0 is single control (`None`), 2 to `EKI_APPROVERS_MAX` is dual
/// control with that many keys, anything else is `INVALID_ARGUMENT`.
pub fn approver_count(count: usize) -> Result<Option<usize>, Error> {
    match count {
        0 => Ok(None),
        APPROVERS_MIN..=EKI_APPROVERS_MAX => Ok(Some(count)),
        _ => Err(Error::InvalidArgument),
    }
}

/// The message an approver signs to approve `request` for the key `id`: the domain, the 32
/// request bytes, the 16 id bytes.
pub fn approval_message(request: &Request, id: &KeyId) -> [u8; MESSAGE_LEN] {
    let mut message = [0; MESSAGE_LEN];
    let parts: [&[u8]; 3] = [DOMAIN, request, &id.0];
    let mut rest = &mut message[..];
    for part in parts {
        let (head, tail) = rest.split_at_mut(part.len());
        head.copy_from_slice(part);
        rest = tail;
    }
    message
}

/// A destroy request that waits for approvals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pending {
    /// The key the request would destroy.
    pub key: KeyId,
    /// The approvers who approved it so far: bit `i` stands for approver `i`. There are at most
    /// 8 approvers, so a byte holds them all.
    approved: u8,
}

impl Pending {
    /// The approvals still needed.
    pub fn remaining(&self) -> u32 {
        APPROVALS_NEEDED.saturating_sub(self.approved.count_ones())
    }

    /// The request after an approval by approver `index`; the same request when that approver
    /// had approved already.
    pub fn approved_by(self, index: usize) -> Self {
        let bit = u32::try_from(index)
            .ok()
            .and_then(|index| 1_u8.checked_shl(index))
            .unwrap_or(0);
        Self {
            approved: self.approved | bit,
            ..self
        }
    }
}

/// The dual-control state of a handle: the approver keys and the pending requests, at most one
/// per key.
#[derive(Clone, Debug)]
pub struct DualControl {
    /// 2 to 8 distinct keys, each a valid point.
    approvers: Vec<PublicKey>,
    pending: BTreeMap<Request, Pending>,
}

impl DualControl {
    /// The approver keys of an `eki_ks_config_v2`, back to back, 65 bytes each: every key must
    /// be a valid SEC1 uncompressed P-256 point and no two may be equal, else
    /// `INVALID_ARGUMENT`. A point has one uncompressed encoding (its coordinates are below the
    /// field prime), so equal points are equal byte strings.
    pub fn parse(keys: &[u8]) -> Result<Self, Error> {
        let (chunks, remainder) = keys.as_chunks::<EKI_P256_PUBLIC_KEY_LEN>();
        if !remainder.is_empty() {
            return Err(Error::InvalidArgument);
        }
        // The count first, so that no more than `EKI_APPROVERS_MAX` keys are ever parsed.
        approver_count(chunks.len())?.ok_or(Error::InvalidArgument)?;
        let mut approvers: Vec<PublicKey> = Vec::with_capacity(EKI_APPROVERS_MAX);
        for key in chunks {
            ecdsa::p256_check_public_key(key)?;
            if approvers.contains(key) {
                return Err(Error::InvalidArgument);
            }
            approvers.push(*key);
        }
        Ok(Self {
            approvers,
            pending: BTreeMap::new(),
        })
    }

    /// The position of `key` among the approvers.
    pub fn approver_index(&self, key: &PublicKey) -> Option<usize> {
        self.approvers.iter().position(|approver| approver == key)
    }

    /// The pending request with this value.
    pub fn pending(&self, request: &Request) -> Option<Pending> {
        self.pending.get(request).copied()
    }

    /// Whether some pending request has this value.
    pub fn is_pending(&self, request: &Request) -> bool {
        self.pending.contains_key(request)
    }

    /// Records `request` for `key`, without approvals, replacing an earlier request for the
    /// same key and the approvals it had.
    pub fn replace(&mut self, key: KeyId, request: Request) {
        self.pending.retain(|_, pending| pending.key != key);
        self.pending.insert(request, Pending { key, approved: 0 });
    }

    /// Stores the new approvals of a pending request.
    pub fn update(&mut self, request: &Request, pending: Pending) {
        if let Some(slot) = self.pending.get_mut(request) {
            *slot = pending;
        }
    }

    /// Forgets a request.
    pub fn remove(&mut self, request: &Request) {
        self.pending.remove(request);
    }
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::SigningKey;

    use super::*;

    fn key(seed: u8) -> PublicKey {
        let secret = [seed; 32];
        let signing = SigningKey::from_slice(&secret).expect("valid scalar");
        signing
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .try_into()
            .expect("65 bytes")
    }

    #[test]
    fn approver_count_rule() {
        assert_eq!(approver_count(0), Ok(None));
        assert_eq!(approver_count(1), Err(Error::InvalidArgument));
        assert_eq!(approver_count(2), Ok(Some(2)));
        assert_eq!(approver_count(8), Ok(Some(8)));
        assert_eq!(approver_count(9), Err(Error::InvalidArgument));
        assert_eq!(approver_count(usize::MAX), Err(Error::InvalidArgument));
    }

    #[test]
    fn approvers_must_be_valid_and_distinct() {
        let (a, b) = (key(1), key(2));
        assert!(DualControl::parse(&[a, b].concat()).is_ok());
        let mut off_curve = b;
        off_curve[64] ^= 1;
        let mut compressed = b;
        compressed[0] = 0x02;
        for keys in [
            [a, a].concat(),
            [a, off_curve].concat(),
            [a, compressed].concat(),
            [a, [0; 65]].concat(),
            a.to_vec(),
            [a, b].concat()[..129].to_vec(),
        ] {
            assert_eq!(
                DualControl::parse(&keys).map(drop),
                Err(Error::InvalidArgument)
            );
        }
    }

    #[test]
    fn message_is_domain_request_id() {
        let message = approval_message(&[7; 32], &KeyId([9; 16]));
        assert_eq!(message.len(), 68);
        assert_eq!(&message[..20], b"ekibridge-destroy-v1");
        assert_eq!(&message[20..52], &[7; 32]);
        assert_eq!(&message[52..], &[9; 16]);
    }

    #[test]
    fn approvals_count_distinct_approvers() {
        let mut dual = DualControl::parse(&[key(1), key(2), key(3)].concat()).expect("valid");
        let id = KeyId([1; 16]);
        dual.replace(id, [1; 32]);
        let pending = dual.pending(&[1; 32]).expect("pending");
        assert_eq!(pending.remaining(), 2);
        let once = pending.approved_by(2);
        assert_eq!(once.remaining(), 1);
        assert_eq!(once.approved_by(2), once, "same approver twice");
        assert_eq!(once.approved_by(0).remaining(), 0);
        dual.update(&[1; 32], once);
        dual.replace(id, [2; 32]);
        assert_eq!(dual.pending(&[1; 32]), None, "replaced");
        assert_eq!(dual.pending(&[2; 32]).map(|p| p.remaining()), Some(2));
    }
}
