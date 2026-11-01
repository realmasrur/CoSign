//! Co-signer: the only entry point that can produce a CoSign signature.
//!
//! Decode, policy and signing happen in one call from RAW transaction fields, so
//! a compromised host cannot feed in a doctored `Simulation`. The digest signed is
//! the one recomputed from those fields, never one supplied by the caller.
//! Run this whole struct inside the enclave; `Key` is the seam for KMS/HSM keys.

use crate::audit::{hex32, Log, Sink};
use crate::change::Guard;
use crate::control::{Approval, Quorum, Verifier};
use crate::evm::{analyze, analyze_authorization, analyze_raw, EvmConfig, Pricer, SafeTx, Word};
use crate::{Decision, Engine, Reason, Simulation, TxHash};
use std::collections::HashMap;

/// r(32) | s(32) | v(1), v = 27/28, as Safe expects for ECDSA owner signatures.
pub type Signature = [u8; 65];

#[derive(Debug)]
pub struct KeyError;

pub trait Key {
    fn sign(&self, digest: &Word) -> Result<Signature, KeyError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    Signed(Signature),
    /// Resubmit the same transaction at or after `until`.
    Delay { until: u64 },
    Blocked(Vec<Reason>),
}

pub struct CoSigner<K: Key, S: Sink, V: Verifier> {
    cfg: EvmConfig,
    pub(crate) engine: Engine,
    key: K,
    pub(crate) log: Log<S>,
    pub(crate) quorum: Quorum<V>,
    pub(crate) guard: Guard,
    /// Makes retries idempotent: same digest, same signature, no double-counted velocity.
    signed: HashMap<TxHash, Signature>,
}

impl<K: Key, S: Sink, V: Verifier> CoSigner<K, S, V> {
    /// `loosen_delay_secs`: timelock between a quorum approving a loosening and it taking effect.
    pub fn new(
        cfg: EvmConfig,
        engine: Engine,
        key: K,
        log: Log<S>,
        quorum: Quorum<V>,
        loosen_delay_secs: u64,
    ) -> Self {
        Self { cfg, engine, key, log, quorum, guard: Guard::new(loosen_delay_secs), signed: HashMap::new() }
    }

    /// Any single trigger may pause. Never depends on the log: pausing must always work.
    pub fn pause(&mut self, now: u64) {
        self.engine.pause();
        let _ = self.log.append(now, "pause".into());
    }

    /// Resume only with a quorum of approvals for the current epoch, and only
    /// if the unpause itself was durably logged.
    pub fn unpause(&mut self, now: u64, approvals: &[Approval]) -> bool {
        if !self.quorum.check(approvals) || self.log.append(now, "unpause".into()).is_err() {
            return false;
        }
        self.quorum.advance();
        self.engine.unpause();
        true
    }

    /// Safe multisig transaction.
    pub fn request(&mut self, pricer: &dyn Pricer, tx: &SafeTx, claimed: Word, now: u64) -> Response {
        let sim = analyze(&self.cfg, pricer, tx, claimed);
        self.decide(sim, now)
    }

    /// Raw hot-wallet transaction: the exact bytes that will be hashed and signed.
    pub fn request_raw(&mut self, pricer: &dyn Pricer, unsigned: &[u8], claimed: Word, now: u64) -> Response {
        let sim = analyze_raw(&self.cfg, pricer, unsigned, claimed);
        self.decide(sim, now)
    }

    /// EIP-7702 authorization preimage (`0x05 || rlp([chain_id, address, nonce])`).
    pub fn request_authorization(&mut self, preimage: &[u8], claimed: Word, now: u64) -> Response {
        let sim = analyze_authorization(&self.cfg, preimage, claimed);
        self.decide(sim, now)
    }

    fn decide(&mut self, sim: Simulation, now: u64) -> Response {

        let cached = if !sim.incomplete && !self.engine.is_paused() {
            self.signed.get(&sim.tx_hash).copied()
        } else {
            None
        };
        let decision = if cached.is_some() {
            Decision::Approve(sim.tx_hash)
        } else {
            self.engine.evaluate(&sim, now)
        };

        // Write-ahead: no signature is released unless the decision is durably logged.
        let id = hex32(&sim.tx_hash);
        let detail = match &decision {
            Decision::Approve(_) if cached.is_some() => format!("approve {id} (retry)"),
            Decision::Approve(_) => format!("approve {id}"),
            Decision::Delay { until } => format!("delay {id} until {until}"),
            Decision::Block(reasons) => format!("block {id} {reasons:?}"),
        };
        if self.log.append(now, detail).is_err() {
            return Response::Blocked(vec![Reason::AuditFailure]);
        }

        match decision {
            Decision::Approve(hash) => {
                if let Some(sig) = cached {
                    return Response::Signed(sig);
                }
                match self.key.sign(&hash) {
                    Ok(sig) => {
                        self.signed.insert(hash, sig);
                        Response::Signed(sig)
                    }
                    // Velocity stays reserved: over-counting is the safe direction.
                    Err(_) => Response::Blocked(vec![Reason::SignerFailure]),
                }
            }
            Decision::Delay { until } => Response::Delay { until },
            Decision::Block(reasons) => Response::Blocked(reasons),
        }
    }
}

/// In-memory secp256k1 key. For use INSIDE the enclave after KMS-attested unseal,
/// or in tests. Never on a normal host.
#[cfg(feature = "k256")]
pub struct LocalKey(k256::ecdsa::SigningKey);

#[cfg(feature = "k256")]
impl LocalKey {
    pub fn from_bytes(secret: &[u8; 32]) -> Result<Self, KeyError> {
        k256::ecdsa::SigningKey::from_bytes(k256::FieldBytes::from_slice(secret))
            .map(Self)
            .map_err(|_| KeyError)
    }
}

#[cfg(feature = "k256")]
impl Key for LocalKey {
    fn sign(&self, digest: &Word) -> Result<Signature, KeyError> {
        let (sig, rid) = self.0.sign_prehash_recoverable(digest).map_err(|_| KeyError)?;
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&sig.to_bytes());
        out[64] = 27 + rid.to_byte();
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{verify, Entry, SinkError};
    use crate::change::ChangeError;
    use crate::control::Tag;
    use crate::evm::{hex, safe_tx_hash, testenc, word, Addr, Asset};
    use crate::keccak::keccak256;
    use crate::price::{PriceBook, SignedPrice};
    use crate::{Policy, Risk};
    use std::cell::RefCell;

    struct Flat;
    impl Pricer for Flat {
        fn usd_cents(&self, _: &Asset, n: u128) -> Option<u128> {
            Some(n)
        }
    }

    struct MockKey {
        calls: RefCell<Vec<Word>>,
        fail: bool,
    }
    impl Key for MockKey {
        fn sign(&self, d: &Word) -> Result<Signature, KeyError> {
            if self.fail {
                return Err(KeyError);
            }
            self.calls.borrow_mut().push(*d);
            let mut s = [0u8; 65];
            s[..32].copy_from_slice(d);
            s[64] = 27;
            Ok(s)
        }
    }

    struct FailSink;
    impl Sink for FailSink {
        fn append(&mut self, _: &Entry) -> Result<(), SinkError> {
            Err(SinkError)
        }
    }

    const TOKEN: Addr = [0x11; 20];
    const GOOD: Addr = [0xaa; 20];
    const EVIL: Addr = [0x66; 20];

    type Test<S> = CoSigner<MockKey, S, Tag>;

    fn cfg() -> EvmConfig {
        EvmConfig { chain_id: 1, safe: [0x5a; 20], ..Default::default() }
    }

    fn signer_with<S: Sink>(max_window: u128, fail: bool, sink: S) -> Test<S> {
        let policy = Policy {
            max_tx_usd_cents: 10_000, window_secs: 3_600, max_window_usd_cents: max_window,
            delay_above_usd_cents: 5_000, delay_secs: 600,
            allow_list: [hex(&GOOD)].into_iter().collect(), unlisted_max_usd_cents: 0,
        };
        CoSigner::new(
            cfg(),
            Engine::new(policy),
            MockKey { calls: RefCell::new(vec![]), fail },
            Log::new(sink),
            Quorum::new(vec![vec![1], vec![2], vec![3]], 2, Tag),
            1_000,
        )
    }

    fn signer(max_window: u128, fail: bool) -> Test<Vec<Entry>> {
        signer_with(max_window, fail, Vec::new())
    }

    fn transfer_tx(op: u8, to: Addr, amount: u128) -> SafeTx {
        let mut data = vec![0xa9, 0x05, 0x9c, 0xbb];
        data.extend([0u8; 12]);
        data.extend(GOOD);
        data.extend(word(amount));
        SafeTx {
            to, value: word(0), data, operation: op, safe_tx_gas: word(0), base_gas: word(0),
            gas_price: word(0), gas_token: [0; 20], refund_receiver: [0; 20], nonce: word(1),
        }
    }

    fn ask<S: Sink>(s: &mut Test<S>, t: &SafeTx, now: u64) -> Response {
        s.request(&Flat, t, safe_tx_hash(&cfg(), t), now)
    }

    fn approvals<S: Sink>(s: &Test<S>, who: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        who.iter().map(|&w| (vec![w], [&[w][..], &s.quorum.msg()[..]].concat())).collect()
    }

    #[test]
    fn signs_exactly_the_recomputed_digest() {
        let mut s = signer(20_000, false);
        let t = transfer_tx(0, TOKEN, 600);
        let digest = safe_tx_hash(&cfg(), &t);
        assert!(matches!(ask(&mut s, &t, 0), Response::Signed(sig) if sig[..32] == digest));
        assert_eq!(*s.key.calls.borrow(), vec![digest]);
    }

    #[test]
    fn blocked_requests_never_reach_the_key() {
        let mut s = signer(20_000, false);
        let evil = transfer_tx(1, EVIL, 1); // delegatecall to attacker contract
        assert!(matches!(ask(&mut s, &evil, 0), Response::Blocked(_)));
        let t = transfer_tx(0, TOKEN, 600);
        assert!(matches!(s.request(&Flat, &t, [0u8; 32], 0), Response::Blocked(_)));
        assert!(s.key.calls.borrow().is_empty());
    }

    #[test]
    fn retry_is_idempotent_and_not_double_counted() {
        let mut s = signer(1_000, false); // a second distinct 600 would exceed the window
        let t = transfer_tx(0, TOKEN, 600);
        let first = ask(&mut s, &t, 0);
        assert!(matches!(first, Response::Signed(_)));
        assert_eq!(ask(&mut s, &t, 1), first);
        assert_eq!(s.key.calls.borrow().len(), 1);
    }

    #[test]
    fn key_failure_fails_closed() {
        let mut s = signer(20_000, true);
        let t = transfer_tx(0, TOKEN, 600);
        assert_eq!(ask(&mut s, &t, 0), Response::Blocked(vec![Reason::SignerFailure]));
    }

    #[test]
    fn large_transfer_is_delayed() {
        let mut s = signer(20_000, false);
        let t = transfer_tx(0, TOKEN, 6_000);
        assert_eq!(ask(&mut s, &t, 10), Response::Delay { until: 610 });
        assert!(matches!(ask(&mut s, &t, 610), Response::Signed(_)));
    }

    #[test]
    fn every_decision_is_logged_in_a_valid_chain() {
        let mut s = signer(20_000, false);
        let t = transfer_tx(0, TOKEN, 600);
        ask(&mut s, &t, 0);
        ask(&mut s, &t, 1); // retry
        ask(&mut s, &transfer_tx(1, EVIL, 1), 2); // blocked
        let log = s.log.sink();
        assert_eq!(log.len(), 3);
        assert!(verify(log));
        assert!(log[0].detail.starts_with("approve") && log[2].detail.starts_with("block"));
    }

    #[test]
    fn no_signature_without_a_durable_log_entry() {
        let mut s = signer_with(20_000, false, FailSink);
        let t = transfer_tx(0, TOKEN, 600);
        assert_eq!(ask(&mut s, &t, 0), Response::Blocked(vec![Reason::AuditFailure]));
        assert!(s.key.calls.borrow().is_empty());
    }

    #[test]
    fn pause_works_even_if_logging_fails() {
        let mut s = signer_with(20_000, false, FailSink);
        s.pause(0);
        assert!(s.engine.is_paused());
    }

    #[test]
    fn unpause_needs_quorum_and_old_approvals_are_dead() {
        let mut s = signer(20_000, false);
        let t = transfer_tx(0, TOKEN, 600);
        assert!(matches!(ask(&mut s, &t, 0), Response::Signed(_)));

        s.pause(1);
        // paused: even the previously signed request is refused
        assert!(matches!(ask(&mut s, &t, 2), Response::Blocked(ref r) if r.contains(&Reason::Paused)));

        assert!(!s.unpause(3, &approvals(&s, &[1]))); // below threshold
        let old = approvals(&s, &[1, 2]);
        assert!(s.unpause(4, &old));
        assert!(matches!(ask(&mut s, &t, 5), Response::Signed(_)));

        s.pause(6);
        assert!(!s.unpause(7, &old)); // replayed approvals from a previous epoch
        assert!(s.unpause(8, &approvals(&s, &[2, 3])));
        assert!(verify(s.log.sink()));
    }

    fn policy_of<S: Sink>(s: &Test<S>) -> Policy {
        s.engine.policy().clone()
    }

    fn vote(who: u8, msg: [u8; 32]) -> Approval {
        (vec![who], [&[who][..], &msg[..]].concat())
    }

    fn votes<S: Sink>(s: &Test<S>, p: &Policy, kind: &str, who: &[u8]) -> Vec<Approval> {
        let m = s.guard.msg(kind, &p.digest());
        who.iter().map(|&w| vote(w, m)).collect()
    }

    fn loosened<S: Sink>(s: &Test<S>) -> Policy {
        let mut p = policy_of(s);
        p.max_tx_usd_cents = 15_000;
        p
    }

    #[test]
    fn tightening_is_instant_single_approver_and_not_replayable() {
        let mut s = signer(20_000, false);
        let mut tight = policy_of(&s);
        tight.max_tx_usd_cents = 500;
        let a = votes(&s, &tight, "TIGHTEN", &[1]);

        let stranger = vote(9, s.guard.msg("TIGHTEN", &tight.digest()));
        assert_eq!(s.tighten_policy(0, tight.clone(), &stranger), Err(ChangeError::Unauthorized));

        assert_eq!(s.tighten_policy(0, tight.clone(), &a[0]), Ok(()));
        let t = transfer_tx(0, TOKEN, 600);
        assert!(matches!(ask(&mut s, &t, 1), Response::Blocked(ref r) if r.contains(&Reason::TxLimit)));
        assert_eq!(s.tighten_policy(2, tight, &a[0]), Err(ChangeError::Unauthorized)); // replay

        let l = loosened(&s);
        let la = votes(&s, &l, "TIGHTEN", &[1]);
        assert_eq!(s.tighten_policy(3, l, &la[0]), Err(ChangeError::NotTightening));
    }

    #[test]
    fn loosening_needs_quorum_then_timelock() {
        let mut s = signer(20_000, false);
        let big = transfer_tx(0, TOKEN, 12_000);
        assert!(matches!(ask(&mut s, &big, 0), Response::Blocked(_)));

        let l = loosened(&s);
        let one = votes(&s, &l, "LOOSEN", &[1]);
        assert_eq!(s.stage_loosening(0, l.clone(), &one), Err(ChangeError::Unauthorized));
        let two = votes(&s, &l, "LOOSEN", &[1, 2]);
        assert_eq!(s.stage_loosening(0, l, &two), Ok(1_000));

        assert_eq!(s.activate_staged(999), Err(ChangeError::TooEarly));
        assert!(matches!(ask(&mut s, &big, 999), Response::Blocked(_)));
        assert_eq!(s.activate_staged(1_000), Ok(()));
        assert!(matches!(ask(&mut s, &big, 1_000), Response::Delay { .. }));
        assert!(verify(s.log.sink()));
    }

    #[test]
    fn any_single_approver_can_veto_a_staged_loosening() {
        let mut s = signer(20_000, false);
        let l = loosened(&s);
        let two = votes(&s, &l, "LOOSEN", &[1, 2]);
        s.stage_loosening(0, l.clone(), &two).unwrap();

        let veto = vote(3, s.guard.msg("CANCEL", &l.digest()));
        assert_eq!(s.cancel_staged(1, &veto), Ok(()));
        assert_eq!(s.activate_staged(5_000), Err(ChangeError::NothingStaged));
    }

    #[test]
    fn tightening_cancels_a_staged_loosening() {
        let mut s = signer(20_000, false);
        let l = loosened(&s);
        let two = votes(&s, &l, "LOOSEN", &[1, 2]);
        s.stage_loosening(0, l, &two).unwrap();

        let mut tight = policy_of(&s);
        tight.max_tx_usd_cents = 500;
        let a = votes(&s, &tight, "TIGHTEN", &[2]);
        s.tighten_policy(1, tight, &a[0]).unwrap();
        assert_eq!(s.activate_staged(5_000), Err(ChangeError::NothingStaged));
    }

    #[test]
    fn staging_requires_a_durable_log_entry() {
        let mut s = signer_with(20_000, false, FailSink);
        let l = loosened(&s);
        let two = votes(&s, &l, "LOOSEN", &[1, 2]);
        assert_eq!(s.stage_loosening(0, l, &two), Err(ChangeError::AuditFailure));
        assert_eq!(s.activate_staged(u64::MAX), Err(ChangeError::NothingStaged));
    }

    #[test]
    fn no_signed_prices_no_signature() {
        let mut s = signer(20_000, false);
        let mut book = PriceBook::new(1, vec![vec![1], vec![2]], 2, 300, Tag);
        let t = transfer_tx(0, TOKEN, 600);
        let claimed = safe_tx_hash(&cfg(), &t);
        assert!(matches!(s.request(&book, &t, claimed, 10), Response::Blocked(_)));

        let mk = |feed: u8| {
            let mut m = SignedPrice {
                asset: Asset::Token(TOKEN), price_e8: 1_000_000, decimals: 0, issued_at: 0,
                expires_at: 100, feed: vec![feed], sig: vec![],
            };
            m.sig = [&[feed][..], &m.digest(1)[..]].concat();
            m
        };
        book.ingest(10, &[mk(1), mk(2)]); // $0.01 per unit, so 600 units = 600 cents
        assert!(matches!(s.request(&book, &t, claimed, 10), Response::Signed(_)));
    }

    #[test]
    fn hot_wallet_raw_tx_is_signed_but_7702_delegation_is_not() {
        let mut s = signer(20_000, false);
        let raw = testenc::type2(1, &TOKEN, 0, &transfer_tx(0, TOKEN, 600).data);
        assert!(matches!(s.request_raw(&Flat, &raw, keccak256(&raw), 0), Response::Signed(_)));

        let auth = testenc::authorization(1, &EVIL, 0);
        let r = s.request_authorization(&auth, keccak256(&auth), 1);
        assert!(matches!(r, Response::Blocked(ref x) if x.contains(&Reason::Risk(Risk::Delegation))));
        assert_eq!(s.key.calls.borrow().len(), 1); // only the legitimate transfer reached the key
    }
}
