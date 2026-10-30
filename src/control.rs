//! Pause is easy, unpause is hard: any single trigger can pause, but resuming
//! needs M distinct approvers to sign a message bound to the current epoch.
//! The epoch advances on every unpause, so collected approvals cannot be replayed
//! after the next pause.

use crate::keccak::keccak256;

/// (approver id, signature)
pub type Approval = (Vec<u8>, Vec<u8>);

pub trait Verifier {
    fn verify(&self, approver: &[u8], msg: &[u8; 32], sig: &[u8]) -> bool;
}

pub struct Quorum<V: Verifier> {
    approvers: Vec<Vec<u8>>,
    threshold: usize,
    verifier: V,
    epoch: u64,
}

impl<V: Verifier> Quorum<V> {
    pub fn new(approvers: Vec<Vec<u8>>, threshold: usize, verifier: V) -> Self {
        Self { approvers, threshold, verifier, epoch: 0 }
    }

    /// The message approvers must sign to unpause right now.
    pub fn msg(&self) -> [u8; 32] {
        let mut b = b"COSIGN_UNPAUSE".to_vec();
        b.extend(self.epoch.to_be_bytes());
        keccak256(&b)
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    pub fn check(&self, sigs: &[Approval]) -> bool {
        self.check_msg(&self.msg(), sigs, self.threshold)
    }

    /// True if at least `threshold` distinct configured approvers signed `msg`.
    pub fn check_msg(&self, msg: &[u8; 32], sigs: &[Approval], threshold: usize) -> bool {
        let valid = self
            .approvers
            .iter()
            .filter(|a| sigs.iter().any(|(who, sig)| who == *a && self.verifier.verify(who, msg, sig)))
            .count();
        threshold > 0 && valid >= threshold
    }

    pub fn advance(&mut self) {
        self.epoch += 1;
    }
}

/// secp256k1 approver keys: `approver` = SEC1 public key, `sig` = 64-byte r||s over `msg`.
#[cfg(feature = "k256")]
pub struct Secp256k1Verifier;

#[cfg(feature = "k256")]
impl Verifier for Secp256k1Verifier {
    fn verify(&self, approver: &[u8], msg: &[u8; 32], sig: &[u8]) -> bool {
        use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
        let (Ok(vk), Ok(s)) = (VerifyingKey::from_sec1_bytes(approver), Signature::from_slice(sig)) else {
            return false;
        };
        vk.verify_prehash(msg, &s).is_ok()
    }
}

/// Test verifier: a signature is valid iff it equals approver || msg.
#[cfg(test)]
pub(crate) struct Tag;

#[cfg(test)]
impl Verifier for Tag {
    fn verify(&self, approver: &[u8], msg: &[u8; 32], sig: &[u8]) -> bool {
        sig == [approver, &msg[..]].concat()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(q: &Quorum<Tag>, who: u8) -> (Vec<u8>, Vec<u8>) {
        (vec![who], [&[who][..], &q.msg()[..]].concat())
    }

    #[test]
    fn needs_distinct_valid_approvers() {
        let q = Quorum::new(vec![vec![1], vec![2], vec![3]], 2, Tag);
        assert!(!q.check(&[sig(&q, 1), sig(&q, 1)])); // duplicates count once
        assert!(!q.check(&[sig(&q, 1), (vec![9], vec![9])])); // unknown approver / bad sig
        assert!(q.check(&[sig(&q, 1), sig(&q, 3)]));
    }

    #[test]
    fn zero_threshold_never_passes() {
        let q = Quorum::new(vec![vec![1]], 0, Tag);
        assert!(!q.check(&[]));
    }

    #[test]
    fn approvals_do_not_survive_the_epoch() {
        let mut q = Quorum::new(vec![vec![1], vec![2]], 2, Tag);
        let old = [sig(&q, 1), sig(&q, 2)];
        assert!(q.check(&old));
        q.advance();
        assert!(!q.check(&old));
    }
}
