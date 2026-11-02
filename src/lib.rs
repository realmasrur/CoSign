//! CoSign policy engine: pure, deterministic, fail-closed.
//!
//! Input is what the *simulator* found the transaction will do, never what the
//! exchange claims. Addresses must be canonicalised by the caller.
//! Output is Approve / Delay / Block. Any doubt means Block.

pub mod audit;
pub mod change;
pub mod control;
pub mod evm;
pub mod keccak;
pub mod license;
pub mod price;
pub mod signer;

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

pub type TxHash = [u8; 32];

#[derive(Debug, Clone)]
pub struct Outflow {
    pub to: String,
    pub usd_cents: u128, // priced by CoSign's own oracle, never by the caller
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Risk {
    DelegateCall,
    ProxyUpgrade,
    ApprovalChange,
    /// Any change to who or what controls a wallet or contract: owners, threshold,
    /// guard, modules, fallback handler, contract ownership or admin.
    OwnerChange,
    /// EIP-7702 delegation of an account to contract code that is not explicitly allowed.
    Delegation,
}

#[derive(Debug, Clone)]
pub struct Simulation {
    pub tx_hash: TxHash,
    pub outflows: Vec<Outflow>,
    pub risks: Vec<Risk>,
    /// Simulator could not fully explain the transaction.
    pub incomplete: bool,
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub max_tx_usd_cents: u128,
    pub window_secs: u64,
    pub max_window_usd_cents: u128,
    pub delay_above_usd_cents: u128,
    pub delay_secs: u64,
    pub allow_list: HashSet<String>,
    /// Per-outflow cap for destinations not on the allow-list (0 = strict allow-list).
    pub unlisted_max_usd_cents: u128,
}

impl Policy {
    /// True if `new` is less restrictive than `self` in ANY dimension.
    /// Mixed changes count as loosening, so they take the slow path.
    pub fn loosens(&self, new: &Policy) -> bool {
        new.max_tx_usd_cents > self.max_tx_usd_cents
            || new.max_window_usd_cents > self.max_window_usd_cents
            || new.delay_above_usd_cents > self.delay_above_usd_cents
            || new.unlisted_max_usd_cents > self.unlisted_max_usd_cents
            || new.window_secs < self.window_secs
            || new.delay_secs < self.delay_secs
            || !new.allow_list.is_subset(&self.allow_list)
    }

    /// Canonical hash of every field (allow-list sorted), used to bind approvals.
    pub fn digest(&self) -> [u8; 32] {
        let mut b = b"COSIGN_POLICY_V1".to_vec();
        for v in [
            self.max_tx_usd_cents,
            self.window_secs as u128,
            self.max_window_usd_cents,
            self.delay_above_usd_cents,
            self.delay_secs as u128,
            self.unlisted_max_usd_cents,
        ] {
            b.extend(v.to_be_bytes());
        }
        let mut list: Vec<&String> = self.allow_list.iter().collect();
        list.sort();
        b.extend((list.len() as u64).to_be_bytes());
        for a in list {
            b.extend((a.len() as u64).to_be_bytes());
            b.extend(a.as_bytes());
        }
        keccak::keccak256(&b)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    Paused,
    IncompleteSimulation,
    Risk(Risk),
    TxLimit,
    UnlistedDestination(String),
    WindowLimit,
    /// The cross-chain velocity limit shared by all engines would be exceeded.
    GlobalLimit,
    /// The license is past its 90-day transition: signing is stopped.
    LicenseExpired,
    SignerFailure,
    AuditFailure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The enclave may sign exactly this hash and nothing else.
    Approve(TxHash),
    /// Resubmit the same transaction at or after `until`.
    Delay { until: u64 },
    Block(Vec<Reason>),
}

/// Cross-chain velocity limit shared by every engine, so draining many wallets on
/// many chains still hits one ceiling. Immutable at runtime on purpose: changing it
/// means redeploying the attested enclave, so no remote change path exists.
pub struct GlobalLimit {
    window_secs: u64,
    max_usd_cents: u128,
    spent: VecDeque<(u64, u128)>,
}

pub type SharedLimit = Arc<Mutex<GlobalLimit>>;

impl GlobalLimit {
    pub fn shared(window_secs: u64, max_usd_cents: u128) -> SharedLimit {
        Arc::new(Mutex::new(Self { window_secs, max_usd_cents, spent: VecDeque::new() }))
    }

    fn used(&self, now: u64) -> u128 {
        self.spent
            .iter()
            .filter(|(t, _)| t.saturating_add(self.window_secs) > now)
            .fold(0u128, |a, &(_, v)| a.saturating_add(v))
    }

    fn fits(&self, now: u64, total: u128) -> bool {
        self.used(now).saturating_add(total) <= self.max_usd_cents
    }

    /// Atomic check-and-reserve, so concurrent engines cannot both slip under the cap.
    fn reserve(&mut self, now: u64, total: u128) -> bool {
        while let Some(&(t, _)) = self.spent.front() {
            if t.saturating_add(self.window_secs) <= now {
                self.spent.pop_front();
            } else {
                break;
            }
        }
        if !self.fits(now, total) {
            return false;
        }
        self.spent.push_back((now, total));
        true
    }
}

pub struct Engine {
    policy: Policy,
    global: Option<SharedLimit>,
    paused: bool,
    spent: VecDeque<(u64, u128)>,
    pending: HashMap<TxHash, u64>,
}

impl Engine {
    pub fn new(policy: Policy) -> Self {
        Self { policy, global: None, paused: false, spent: VecDeque::new(), pending: HashMap::new() }
    }

    /// Attach the shared cross-chain limit.
    pub fn with_global(mut self, g: SharedLimit) -> Self {
        self.global = Some(g);
        self
    }
    pub fn pause(&mut self) {
        self.paused = true;
    }

    pub(crate) fn policy(&self) -> &Policy {
        &self.policy
    }

    pub(crate) fn set_policy(&mut self, p: Policy) {
        self.policy = p;
    }

    /// Crate-private on purpose: the only way to resume is `CoSigner::unpause` (quorum).
    pub(crate) fn unpause(&mut self) {
        self.paused = false;
    }

    pub fn is_paused(&self) -> bool {
        self.paused
    }

    pub fn evaluate(&mut self, sim: &Simulation, now: u64) -> Decision {
        let p = &self.policy;
        let mut reasons = Vec::new();

        if self.paused {
            reasons.push(Reason::Paused);
        }
        if sim.incomplete {
            reasons.push(Reason::IncompleteSimulation);
        }
        reasons.extend(sim.risks.iter().map(|r| Reason::Risk(*r)));

        let total = sim.outflows.iter().fold(0u128, |a, o| a.saturating_add(o.usd_cents));
        if total > p.max_tx_usd_cents {
            reasons.push(Reason::TxLimit);
        }
        for o in &sim.outflows {
            if !p.allow_list.contains(&o.to) && o.usd_cents > p.unlisted_max_usd_cents {
                reasons.push(Reason::UnlistedDestination(o.to.clone()));
            }
        }

        while let Some(&(t, _)) = self.spent.front() {
            if t.saturating_add(p.window_secs) <= now {
                self.spent.pop_front();
            } else {
                break;
            }
        }
        let used = self.spent.iter().fold(0u128, |a, &(_, v)| a.saturating_add(v));
        if used.saturating_add(total) > p.max_window_usd_cents {
            reasons.push(Reason::WindowLimit);
        }
        let global_ok = match &self.global {
            None => true,
            Some(g) => g.lock().map(|g| g.fits(now, total)).unwrap_or(false), // poisoned lock blocks
        };
        if !global_ok {
            reasons.push(Reason::GlobalLimit);
        }

        if !reasons.is_empty() {
            self.pending.remove(&sim.tx_hash);
            return Decision::Block(reasons);
        }

        if total > p.delay_above_usd_cents {
            let release = *self.pending.entry(sim.tx_hash).or_insert(now.saturating_add(p.delay_secs));
            if now < release {
                return Decision::Delay { until: release };
            }
            self.pending.remove(&sim.tx_hash);
        }

        if let Some(g) = &self.global {
            let reserved = g.lock().map(|mut g| g.reserve(now, total)).unwrap_or(false);
            if !reserved {
                return Decision::Block(vec![Reason::GlobalLimit]);
            }
        }
        self.spent.push_back((now, total)); // reserve at approval, not at broadcast
        Decision::Approve(sim.tx_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> Engine {
        Engine::new(Policy {
            max_tx_usd_cents: 1_000,
            window_secs: 3_600,
            max_window_usd_cents: 1_500,
            delay_above_usd_cents: 500,
            delay_secs: 600,
            allow_list: ["0xA".to_string()].into_iter().collect(),
            unlisted_max_usd_cents: 100,
        })
    }

    fn sim(id: u8, to: &str, usd: u128) -> Simulation {
        Simulation {
            tx_hash: [id; 32],
            outflows: vec![Outflow { to: to.into(), usd_cents: usd }],
            risks: vec![],
            incomplete: false,
        }
    }

    #[test]
    fn approves_small_listed() {
        assert_eq!(engine().evaluate(&sim(1, "0xA", 100), 0), Decision::Approve([1; 32]));
    }

    #[test]
    fn blocks_over_tx_limit() {
        let d = engine().evaluate(&sim(1, "0xA", 1_001), 0);
        assert!(matches!(d, Decision::Block(ref r) if r.contains(&Reason::TxLimit)));
    }

    #[test]
    fn blocks_risky_and_incomplete() {
        let mut s = sim(1, "0xA", 1);
        s.risks.push(Risk::DelegateCall);
        s.incomplete = true;
        let d = engine().evaluate(&s, 0);
        assert!(matches!(d, Decision::Block(ref r)
            if r.contains(&Reason::Risk(Risk::DelegateCall)) && r.contains(&Reason::IncompleteSimulation)));
    }

    #[test]
    fn unlisted_destination_capped() {
        let mut e = engine();
        assert!(matches!(e.evaluate(&sim(1, "0xZ", 101), 0), Decision::Block(_)));
        assert_eq!(e.evaluate(&sim(2, "0xZ", 100), 0), Decision::Approve([2; 32]));
    }

    #[test]
    fn window_limit_then_recovers() {
        let mut e = engine();
        for i in 0..3 {
            assert_eq!(e.evaluate(&sim(i, "0xA", 500), 0), Decision::Approve([i; 32]));
        }
        let d = e.evaluate(&sim(9, "0xA", 1), 10);
        assert!(matches!(d, Decision::Block(ref r) if r.contains(&Reason::WindowLimit)));
        assert_eq!(e.evaluate(&sim(9, "0xA", 1), 3_600), Decision::Approve([9; 32]));
    }

    #[test]
    fn large_tx_is_delayed_then_approved() {
        let mut e = engine();
        assert_eq!(e.evaluate(&sim(1, "0xA", 600), 10), Decision::Delay { until: 610 });
        assert_eq!(e.evaluate(&sim(1, "0xA", 600), 100), Decision::Delay { until: 610 });
        assert_eq!(e.evaluate(&sim(1, "0xA", 600), 610), Decision::Approve([1; 32]));
    }

    #[test]
    fn pause_blocks_everything() {
        let mut e = engine();
        e.pause();
        let d = e.evaluate(&sim(1, "0xA", 1), 0);
        assert!(matches!(d, Decision::Block(ref r) if r.contains(&Reason::Paused)));
    }

    #[test]
    fn loosens_detects_every_dimension() {
        let base = engine().policy;
        let with = |f: fn(&mut Policy)| {
            let mut p = base.clone();
            f(&mut p);
            p
        };
        assert!(base.loosens(&with(|p| p.max_tx_usd_cents += 1)));
        assert!(base.loosens(&with(|p| p.max_window_usd_cents += 1)));
        assert!(base.loosens(&with(|p| p.delay_above_usd_cents += 1)));
        assert!(base.loosens(&with(|p| p.unlisted_max_usd_cents += 1)));
        assert!(base.loosens(&with(|p| p.window_secs -= 1)));
        assert!(base.loosens(&with(|p| p.delay_secs -= 1)));
        assert!(base.loosens(&with(|p| { p.allow_list.insert("0xB".into()); })));
        assert!(base.loosens(&with(|p| { p.max_tx_usd_cents -= 1; p.max_window_usd_cents += 1; })));

        assert!(!base.loosens(&base));
        assert!(!base.loosens(&with(|p| p.max_tx_usd_cents -= 1)));
        assert!(!base.loosens(&with(|p| p.window_secs += 1)));
        assert!(!base.loosens(&with(|p| p.allow_list.clear())));
    }

    #[test]
    fn digest_is_canonical_and_sensitive() {
        let base = engine().policy;
        let mut a = base.clone();
        a.allow_list = ["0x1".to_string(), "0x2".to_string()].into_iter().collect();
        let mut b = base.clone();
        b.allow_list = ["0x2".to_string(), "0x1".to_string()].into_iter().collect();
        assert_eq!(a.digest(), b.digest());
        b.delay_secs += 1;
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn global_limit_is_shared_across_engines_and_recovers() {
        let g = GlobalLimit::shared(3_600, 1_000);
        let mut a = engine().with_global(g.clone());
        let mut b = engine().with_global(g);
        assert_eq!(a.evaluate(&sim(1, "0xA", 400), 0), Decision::Approve([1; 32]));
        assert_eq!(b.evaluate(&sim(2, "0xA", 400), 0), Decision::Approve([2; 32]));
        let d = a.evaluate(&sim(3, "0xA", 400), 10);
        assert!(matches!(d, Decision::Block(ref r) if r == &vec![Reason::GlobalLimit]));
        assert_eq!(a.evaluate(&sim(3, "0xA", 400), 3_600), Decision::Approve([3; 32]));
    }
}
