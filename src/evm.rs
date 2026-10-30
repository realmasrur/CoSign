//! EVM decoder for Safe multisig transactions (the Bybit pattern).
//!
//! Rules: recompute the digest the signers will sign from the raw fields, never
//! trust a caller-supplied description, and fail closed on anything not explained.
//! This is static analysis. A state-based EVM simulator can later resolve the
//! `incomplete` cases; until then they simply block.
//! Supports Safe >= 1.3 (domain includes chainId).

use crate::keccak::keccak256;
use crate::{Outflow, Risk, Simulation};
use std::collections::HashSet;

pub type Addr = [u8; 20];
pub type Word = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Asset {
    Native,
    Token(Addr),
}

/// CoSign's own price source. `None` (unknown asset, stale price) blocks.
pub trait Pricer {
    fn usd_cents(&self, asset: &Asset, amount: u128) -> Option<u128>;
}

pub struct EvmConfig {
    pub chain_id: u64,
    /// The guarded Safe.
    pub safe: Addr,
    /// The only contracts a delegatecall may target (MultiSend variants).
    pub multisend: HashSet<Addr>,
}

pub struct SafeTx {
    pub to: Addr,
    pub value: Word,
    pub data: Vec<u8>,
    pub operation: u8, // 0 = call, 1 = delegatecall
    pub safe_tx_gas: Word,
    pub base_gas: Word,
    pub gas_price: Word,
    pub gas_token: Addr,
    pub refund_receiver: Addr,
    pub nonce: Word,
}

const SAFE_CONTROL: [&str; 8] = [
    "addOwnerWithThreshold(address,uint256)",
    "removeOwner(address,address,uint256)",
    "swapOwner(address,address,address)",
    "changeThreshold(uint256)",
    "setGuard(address)",
    "enableModule(address)",
    "disableModule(address,address)",
    "setFallbackHandler(address)",
];

pub fn word(n: u128) -> Word {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&n.to_be_bytes());
    w
}

fn addr_word(a: &Addr) -> Word {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

/// Saturates: an oversized amount becomes u128::MAX and trips every limit.
fn to_u128(w: &[u8]) -> u128 {
    if w[..16].iter().any(|&b| b != 0) {
        u128::MAX
    } else {
        u128::from_be_bytes(<[u8; 16]>::try_from(&w[16..32]).unwrap())
    }
}

fn to_addr(w: &[u8]) -> Option<Addr> {
    if w[..12].iter().any(|&b| b != 0) {
        None
    } else {
        Some(Addr::try_from(&w[12..32]).unwrap())
    }
}

pub fn hex(a: &Addr) -> String {
    let mut s = String::from("0x");
    for b in a {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn sel(sig: &str) -> [u8; 4] {
    let h = keccak256(sig.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

fn is(data: &[u8], sig: &str) -> bool {
    data.len() >= 4 && data[..4] == sel(sig)
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// The EIP-712 digest the Safe owners actually sign.
pub fn safe_tx_hash(cfg: &EvmConfig, tx: &SafeTx) -> Word {
    let domain = keccak256(&cat(&[
        &keccak256(b"EIP712Domain(uint256 chainId,address verifyingContract)"),
        &word(cfg.chain_id as u128),
        &addr_word(&cfg.safe),
    ]));
    let body = keccak256(&cat(&[
        &keccak256(b"SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"),
        &addr_word(&tx.to),
        &tx.value,
        &keccak256(&tx.data),
        &word(tx.operation as u128),
        &tx.safe_tx_gas,
        &tx.base_gas,
        &tx.gas_price,
        &addr_word(&tx.gas_token),
        &addr_word(&tx.refund_receiver),
        &tx.nonce,
    ]));
    keccak256(&cat(&[&[0x19, 0x01], &domain, &body]))
}

struct Ctx<'a> {
    cfg: &'a EvmConfig,
    pricer: &'a dyn Pricer,
    out: Vec<Outflow>,
    risks: Vec<Risk>,
    incomplete: bool,
}

impl Ctx<'_> {
    fn outflow(&mut self, asset: Asset, to: Addr, amount: u128) {
        if amount == 0 {
            return;
        }
        match self.pricer.usd_cents(&asset, amount) {
            Some(usd_cents) => self.out.push(Outflow { to: hex(&to), usd_cents }),
            None => self.incomplete = true,
        }
    }

    fn action(&mut self, delegate: bool, to: Addr, value: u128, data: &[u8], inner: bool) {
        if delegate {
            if inner || !self.cfg.multisend.contains(&to) {
                self.risks.push(Risk::DelegateCall);
            } else {
                self.multisend(data);
            }
            return;
        }
        self.outflow(Asset::Native, to, value);
        if data.is_empty() {
            return;
        }
        if to == self.cfg.safe {
            if SAFE_CONTROL.iter().any(|s| is(data, s)) {
                self.risks.push(Risk::OwnerChange);
            } else {
                self.incomplete = true;
            }
            return;
        }
        let a = |i: usize| data.get(4 + 32 * i..36 + 32 * i);
        if is(data, "transfer(address,uint256)") {
            match (a(0).and_then(to_addr), a(1)) {
                (Some(r), Some(n)) => self.outflow(Asset::Token(to), r, to_u128(n)),
                _ => self.incomplete = true,
            }
        } else if is(data, "transferFrom(address,address,uint256)") {
            match (a(0).and_then(to_addr), a(1).and_then(to_addr), a(2)) {
                (Some(f), Some(r), Some(n)) if f == self.cfg.safe => {
                    self.outflow(Asset::Token(to), r, to_u128(n))
                }
                _ => self.incomplete = true,
            }
        } else if ["approve(address,uint256)", "increaseAllowance(address,uint256)", "setApprovalForAll(address,bool)"]
            .iter()
            .any(|s| is(data, s))
        {
            self.risks.push(Risk::ApprovalChange);
        } else if ["upgradeTo(address)", "upgradeToAndCall(address,bytes)"].iter().any(|s| is(data, s)) {
            self.risks.push(Risk::ProxyUpgrade);
        } else if ["transferOwnership(address)", "renounceOwnership()", "changeAdmin(address)"]
            .iter()
            .any(|s| is(data, s))
        {
            self.risks.push(Risk::OwnerChange);
        } else {
            self.incomplete = true;
        }
    }

    /// multiSend(bytes): each entry is op(1) | to(20) | value(32) | len(32) | data.
    fn multisend(&mut self, data: &[u8]) {
        if !is(data, "multiSend(bytes)") || data.len() < 68 || to_u128(&data[4..36]) != 32 {
            self.incomplete = true;
            return;
        }
        let end = usize::try_from(to_u128(&data[36..68]))
            .ok()
            .and_then(|l| 68usize.checked_add(l))
            .filter(|&e| e <= data.len());
        let Some(end) = end else {
            self.incomplete = true;
            return;
        };
        let mut rest = &data[68..end];
        while !rest.is_empty() {
            let next = if rest.len() >= 85 {
                usize::try_from(to_u128(&rest[53..85]))
                    .ok()
                    .and_then(|d| 85usize.checked_add(d))
                    .filter(|&n| n <= rest.len())
            } else {
                None
            };
            let Some(next) = next else {
                self.incomplete = true;
                return;
            };
            let op = rest[0];
            if op > 1 {
                self.incomplete = true;
            } else {
                let to = Addr::try_from(&rest[1..21]).unwrap();
                self.action(op == 1, to, to_u128(&rest[21..53]), &rest[85..next], true);
            }
            rest = &rest[next..];
        }
    }
}

/// Turn a Safe transaction into a `Simulation` for the policy engine.
/// `claimed` is the digest the exchange says will be signed; a mismatch blocks.
pub fn analyze(cfg: &EvmConfig, pricer: &dyn Pricer, tx: &SafeTx, claimed: Word) -> Simulation {
    let digest = safe_tx_hash(cfg, tx);
    let mut c = Ctx {
        cfg,
        pricer,
        out: Vec::new(),
        risks: Vec::new(),
        // gasPrice > 0 would let the Safe pay a refund to an arbitrary receiver
        incomplete: digest != claimed || tx.operation > 1 || tx.gas_price != [0u8; 32],
    };
    c.action(tx.operation == 1, tx.to, to_u128(&tx.value), &tx.data, false);
    Simulation { tx_hash: digest, outflows: c.out, risks: c.risks, incomplete: c.incomplete }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Decision, Engine, Policy};

    struct Flat; // 1 unit = 1 cent
    impl Pricer for Flat {
        fn usd_cents(&self, _: &Asset, n: u128) -> Option<u128> {
            Some(n)
        }
    }
    struct NoPrice;
    impl Pricer for NoPrice {
        fn usd_cents(&self, _: &Asset, _: u128) -> Option<u128> {
            None
        }
    }

    const TOKEN: Addr = [0x11; 20];
    const GOOD: Addr = [0xaa; 20];
    const EVIL: Addr = [0x66; 20];
    const MULTISEND: Addr = [0x77; 20];

    fn cfg() -> EvmConfig {
        EvmConfig { chain_id: 1, safe: [0x5a; 20], multisend: [MULTISEND].into_iter().collect() }
    }

    fn tx(op: u8, to: Addr, data: Vec<u8>) -> SafeTx {
        SafeTx {
            to, value: word(0), data, operation: op, safe_tx_gas: word(0), base_gas: word(0),
            gas_price: word(0), gas_token: [0; 20], refund_receiver: [0; 20], nonce: word(1),
        }
    }

    fn run(t: &SafeTx) -> Simulation {
        analyze(&cfg(), &Flat, t, safe_tx_hash(&cfg(), t))
    }

    fn transfer(to: Addr, amt: u128) -> Vec<u8> {
        cat(&[&sel("transfer(address,uint256)"), &addr_word(&to), &word(amt)])
    }

    fn entry(op: u8, to: Addr, data: &[u8]) -> Vec<u8> {
        cat(&[&[op], &to, &word(0), &word(data.len() as u128), data])
    }

    fn multisend(entries: Vec<u8>) -> Vec<u8> {
        cat(&[&sel("multiSend(bytes)"), &word(32), &word(entries.len() as u128), &entries])
    }

    fn engine() -> Engine {
        Engine::new(Policy {
            max_tx_usd_cents: 10_000, window_secs: 3_600, max_window_usd_cents: 20_000,
            delay_above_usd_cents: 5_000, delay_secs: 600,
            allow_list: [hex(&GOOD)].into_iter().collect(), unlisted_max_usd_cents: 0,
        })
    }

    #[test]
    fn plain_token_transfer_is_explained_and_approved() {
        let t = tx(0, TOKEN, transfer(GOOD, 100));
        let s = run(&t);
        assert!(!s.incomplete && s.risks.is_empty());
        assert_eq!(s.outflows[0].to, hex(&GOOD));
        assert_eq!(engine().evaluate(&s, 0), Decision::Approve(s.tx_hash));
    }

    #[test]
    fn bybit_pattern_delegatecall_to_unknown_contract_is_blocked() {
        // transfer-looking calldata, but operation = delegatecall to an attacker contract
        let t = tx(1, EVIL, transfer(GOOD, 1));
        let s = run(&t);
        assert_eq!(s.risks, vec![Risk::DelegateCall]);
        assert!(matches!(engine().evaluate(&s, 0), Decision::Block(_)));
    }

    #[test]
    fn digest_mismatch_blocks() {
        let t = tx(0, TOKEN, transfer(GOOD, 100));
        assert!(analyze(&cfg(), &Flat, &t, [0u8; 32]).incomplete);
    }

    #[test]
    fn multisend_is_unpacked() {
        let inner = [entry(0, TOKEN, &transfer(GOOD, 100)), entry(0, TOKEN, &transfer(GOOD, 50))].concat();
        let s = run(&tx(1, MULTISEND, multisend(inner)));
        assert!(!s.incomplete && s.risks.is_empty());
        assert_eq!(s.outflows.iter().map(|o| o.usd_cents).sum::<u128>(), 150);
    }

    #[test]
    fn multisend_with_inner_delegatecall_is_risky() {
        let s = run(&tx(1, MULTISEND, multisend(entry(1, EVIL, &[]))));
        assert_eq!(s.risks, vec![Risk::DelegateCall]);
    }

    #[test]
    fn truncated_multisend_is_incomplete() {
        let mut d = multisend(entry(0, TOKEN, &transfer(GOOD, 1)));
        d.truncate(d.len() - 10);
        assert!(run(&tx(1, MULTISEND, d)).incomplete);
    }

    #[test]
    fn control_and_approval_calls_are_flagged() {
        let own = cat(&[&sel("changeThreshold(uint256)"), &word(1)]);
        assert_eq!(run(&tx(0, cfg().safe, own)).risks, vec![Risk::OwnerChange]);
        let app = cat(&[&sel("approve(address,uint256)"), &addr_word(&EVIL), &word(1)]);
        assert_eq!(run(&tx(0, TOKEN, app)).risks, vec![Risk::ApprovalChange]);
        let upg = cat(&[&sel("upgradeTo(address)"), &addr_word(&EVIL)]);
        assert_eq!(run(&tx(0, TOKEN, upg)).risks, vec![Risk::ProxyUpgrade]);
    }

    #[test]
    fn unknown_selector_unpriceable_asset_and_gas_refund_fail_closed() {
        assert!(run(&tx(0, TOKEN, vec![0xde, 0xad, 0xbe, 0xef])).incomplete);
        let t = tx(0, TOKEN, transfer(GOOD, 1));
        assert!(analyze(&cfg(), &NoPrice, &t, safe_tx_hash(&cfg(), &t)).incomplete);
        let mut g = tx(0, TOKEN, transfer(GOOD, 1));
        g.gas_price = word(1);
        assert!(run(&g).incomplete);
    }
}
