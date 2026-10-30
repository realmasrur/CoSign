//! Policy changes: tighten instantly, loosen slowly.
//!
//! - Tightening: any single approver, takes effect immediately, and cancels any
//!   staged loosening (it must be re-approved against the new baseline).
//! - Loosening (any limit up, window or delay down, address added): full quorum
//!   stages it, a timelock must pass, and any single approver can veto meanwhile.
//! Every approval is bound to (kind, epoch, policy digest), so it cannot be replayed
//! or reused for a different change.

use crate::audit::{hex32, Sink};
use crate::control::{Approval, Verifier};
use crate::keccak::keccak256;
use crate::signer::{CoSigner, Key};
use crate::Policy;

#[derive(Debug, PartialEq, Eq)]
pub enum ChangeError {
    /// The new policy loosens something; use the staged path.
    NotTightening,
    Unauthorized,
    AuditFailure,
    NothingStaged,
    TooEarly,
}

struct Pending {
    policy: Policy,
    digest: [u8; 32],
    activate_at: u64,
}

pub struct Guard {
    epoch: u64,
    loosen_delay: u64,
    pending: Option<Pending>,
}

impl Guard {
    pub fn new(loosen_delay: u64) -> Self {
        Self { epoch: 0, loosen_delay, pending: None }
    }

    /// What approvers sign. `kind` is TIGHTEN, LOOSEN or CANCEL.
    pub(crate) fn msg(&self, kind: &str, digest: &[u8; 32]) -> [u8; 32] {
        let mut b = format!("COSIGN_POLICY_{kind}").into_bytes();
        b.extend(self.epoch.to_be_bytes());
        b.extend(digest);
        keccak256(&b)
    }
}

impl<K: Key, S: Sink, V: Verifier> CoSigner<K, S, V> {
    /// Instant, single approver. Logging is best-effort: tightening must never be blocked.
    pub fn tighten_policy(&mut self, now: u64, new: Policy, approval: &Approval) -> Result<(), ChangeError> {
        if self.engine.policy().loosens(&new) {
            return Err(ChangeError::NotTightening);
        }
        let d = new.digest();
        let msg = self.guard.msg("TIGHTEN", &d);
        if !self.quorum.check_msg(&msg, std::slice::from_ref(approval), 1) {
            return Err(ChangeError::Unauthorized);
        }
        let _ = self.log.append(now, format!("policy tighten {}", hex32(&d)));
        self.engine.set_policy(new);
        self.guard.pending = None;
        self.guard.epoch += 1;
        Ok(())
    }

    /// Full quorum stages a loosening. Returns when it can be activated.
    pub fn stage_loosening(&mut self, now: u64, new: Policy, approvals: &[Approval]) -> Result<u64, ChangeError> {
        let d = new.digest();
        let msg = self.guard.msg("LOOSEN", &d);
        if !self.quorum.check_msg(&msg, approvals, self.quorum.threshold()) {
            return Err(ChangeError::Unauthorized);
        }
        let activate_at = now.saturating_add(self.guard.loosen_delay);
        self.log
            .append(now, format!("policy stage {} activate_at {activate_at}", hex32(&d)))
            .map_err(|_| ChangeError::AuditFailure)?;
        self.guard.pending = Some(Pending { policy: new, digest: d, activate_at });
        self.guard.epoch += 1;
        Ok(activate_at)
    }

    /// Veto: any single approver cancels the staged loosening.
    pub fn cancel_staged(&mut self, now: u64, approval: &Approval) -> Result<(), ChangeError> {
        let d = self.guard.pending.as_ref().ok_or(ChangeError::NothingStaged)?.digest;
        let msg = self.guard.msg("CANCEL", &d);
        if !self.quorum.check_msg(&msg, std::slice::from_ref(approval), 1) {
            return Err(ChangeError::Unauthorized);
        }
        let _ = self.log.append(now, format!("policy cancel {}", hex32(&d)));
        self.guard.pending = None;
        self.guard.epoch += 1;
        Ok(())
    }

    /// Needs no approval: the quorum already approved it and the timelock has passed.
    pub fn activate_staged(&mut self, now: u64) -> Result<(), ChangeError> {
        let p = self.guard.pending.take().ok_or(ChangeError::NothingStaged)?;
        if now < p.activate_at {
            self.guard.pending = Some(p);
            return Err(ChangeError::TooEarly);
        }
        if self.log.append(now, format!("policy activate {}", hex32(&p.digest))).is_err() {
            self.guard.pending = Some(p);
            return Err(ChangeError::AuditFailure);
        }
        self.engine.set_policy(p.policy);
        Ok(())
    }
}
