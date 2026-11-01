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

#[derive(Default)]
pub struct EvmConfig {
    pub chain_id: u64,
    /// The guarded account: the Safe, or the hot wallet for raw transactions.
    pub safe: Addr,
    /// The only contracts a delegatecall may target (MultiSend variants).
    pub multisend: HashSet<Addr>,
    /// Contracts an account may delegate to via EIP-7702. Empty by default:
    /// exchange hot wallets have no reason to delegate.
    pub allowed_delegates: HashSet<Addr>,
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


// ---------- raw EVM transactions and EIP-7702 authorizations ----------
//
// For hot wallets signed by MPC or a plain key. The caller supplies the exact
// bytes that will be hashed and signed (type byte || RLP for typed transactions,
// the EIP-155 payload for legacy, 0x05 || RLP for a 7702 authorization). CoSign
// parses and hashes those SAME bytes, so what it checks is what gets signed.

enum Item<'a> {
    Str(&'a [u8]),
    List(&'a [u8]),
}

/// Strict, canonical RLP: any non-canonical encoding is rejected.
fn next(b: &[u8]) -> Option<(Item<'_>, &[u8])> {
    let (&p, rest) = b.split_first()?;
    let (is_list, len, rest) = match p {
        0x00..=0x7f => return Some((Item::Str(&b[..1]), rest)),
        0x80..=0xb7 => (false, (p - 0x80) as usize, rest),
        0xc0..=0xf7 => (true, (p - 0xc0) as usize, rest),
        _ => {
            let is_list = p >= 0xf8;
            let n = (p - if is_list { 0xf7 } else { 0xb7 }) as usize;
            if rest.len() < n || rest[0] == 0 {
                return None;
            }
            let mut l = 0usize;
            for &x in &rest[..n] {
                l = l.checked_mul(256)?.checked_add(x as usize)?;
            }
            if l <= 55 {
                return None;
            }
            (is_list, l, &rest[n..])
        }
    };
    if rest.len() < len {
        return None;
    }
    let (body, tail) = rest.split_at(len);
    if !is_list && len == 1 && body[0] < 0x80 {
        return None;
    }
    Some((if is_list { Item::List(body) } else { Item::Str(body) }, tail))
}

fn items(mut b: &[u8]) -> Option<Vec<Item<'_>>> {
    let mut v = Vec::new();
    while !b.is_empty() {
        let (it, rest) = next(b)?;
        v.push(it);
        b = rest;
    }
    Some(v)
}

fn bytes<'a>(it: &Item<'a>) -> Option<&'a [u8]> {
    match it {
        Item::Str(x) => Some(*x),
        _ => None,
    }
}

fn list<'a>(it: &Item<'a>) -> Option<&'a [u8]> {
    match it {
        Item::List(x) => Some(*x),
        _ => None,
    }
}

/// Canonical big-endian integer; anything wider than 128 bits saturates and trips limits.
fn uint(s: &[u8]) -> Option<u128> {
    if s.first() == Some(&0) || s.len() > 32 {
        return None;
    }
    Some(if s.len() > 16 { u128::MAX } else { s.iter().fold(0u128, |a, &b| (a << 8) | b as u128) })
}

/// A delegation is acceptable only on this chain, to an allowed contract, or to the
/// zero address (which clears a delegation). Chain id 0 means "every chain": never.
fn delegation_ok(cfg: &EvmConfig, chain: u128, delegate: &Addr) -> bool {
    chain == cfg.chain_id as u128 && (*delegate == [0u8; 20] || cfg.allowed_delegates.contains(delegate))
}

impl Ctx<'_> {
    fn raw(&mut self, u: &[u8]) -> Option<()> {
        let first = *u.first()?;
        // (payload, chain, to, value, data, authorization_list, field count)
        let (payload, chain_i, to_i, value_i, data_i, auth_i, n) = match first {
            0x01 => (&u[1..], 0, 4, 5, 6, None, 8),
            0x02 => (&u[1..], 0, 5, 6, 7, None, 9),
            0x04 => (&u[1..], 0, 5, 6, 7, Some(9), 10),
            0xc0..=0xff => (u, 6, 3, 4, 5, None, 9),
            _ => return None,
        };
        let (outer, rest) = next(payload)?;
        if !rest.is_empty() {
            return None;
        }
        let f = items(list(&outer)?)?;
        if f.len() != n {
            return None;
        }
        if first >= 0xc0 && !(bytes(&f[7])?.is_empty() && bytes(&f[8])?.is_empty()) {
            return None; // EIP-155 payload ends with two empty fields
        }
        if uint(bytes(&f[chain_i])?)? != self.cfg.chain_id as u128 {
            return None; // wrong chain, or a pre-EIP-155 transaction
        }
        let to = Addr::try_from(bytes(&f[to_i])?).ok()?; // contract creation is rejected
        let value = uint(bytes(&f[value_i])?)?;
        let data = bytes(&f[data_i])?;
        if let Some(i) = auth_i {
            for entry in items(list(&f[i])?)? {
                let e = items(list(&entry)?)?;
                if e.len() != 6 {
                    return None;
                }
                let chain = uint(bytes(&e[0])?)?;
                let delegate = Addr::try_from(bytes(&e[1])?).ok()?;
                if !delegation_ok(self.cfg, chain, &delegate) {
                    self.risks.push(Risk::Delegation);
                }
            }
        }
        self.action(false, to, value, data, false);
        Some(())
    }
}

/// Raw transaction from a hot wallet (legacy EIP-155, 2930, 1559 or 7702 type).
pub fn analyze_raw(cfg: &EvmConfig, pricer: &dyn Pricer, unsigned: &[u8], claimed: Word) -> Simulation {
    let digest = keccak256(unsigned);
    let mut c = Ctx { cfg, pricer, out: Vec::new(), risks: Vec::new(), incomplete: digest != claimed };
    if c.raw(unsigned).is_none() {
        c.incomplete = true;
    }
    Simulation { tx_hash: digest, outflows: c.out, risks: c.risks, incomplete: c.incomplete }
}

/// A request to sign an EIP-7702 authorization (`0x05 || rlp([chain_id, address, nonce])`).
/// This is the move that turned Binance hot wallets into sweepers in October 2026.
pub fn analyze_authorization(cfg: &EvmConfig, preimage: &[u8], claimed: Word) -> Simulation {
    let digest = keccak256(preimage);
    let parsed = (|| -> Option<(u128, Addr)> {
        let (&magic, body) = preimage.split_first()?;
        if magic != 0x05 {
            return None;
        }
        let (outer, rest) = next(body)?;
        if !rest.is_empty() {
            return None;
        }
        let f = items(list(&outer)?)?;
        if f.len() != 3 {
            return None;
        }
        uint(bytes(&f[2])?)?;
        Some((uint(bytes(&f[0])?)?, Addr::try_from(bytes(&f[1])?).ok()?))
    })();
    let mut risks = Vec::new();
    let mut incomplete = digest != claimed;
    match parsed {
        Some((chain, delegate)) if !delegation_ok(cfg, chain, &delegate) => risks.push(Risk::Delegation),
        Some(_) => {}
        None => incomplete = true,
    }
    Simulation { tx_hash: digest, outflows: Vec::new(), risks, incomplete }
}

#[cfg(test)]
pub(crate) mod testenc {
    use super::Addr;

    fn hdr(base: u8, len: usize) -> Vec<u8> {
        if len <= 55 {
            vec![base + len as u8]
        } else {
            let l: Vec<u8> = len.to_be_bytes().into_iter().skip_while(|&x| x == 0).collect();
            [vec![base + 55 + l.len() as u8], l].concat()
        }
    }
    pub fn rlp_str(b: &[u8]) -> Vec<u8> {
        if b.len() == 1 && b[0] < 0x80 { b.to_vec() } else { [hdr(0x80, b.len()), b.to_vec()].concat() }
    }
    pub fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
        let p = items.concat();
        [hdr(0xc0, p.len()), p].concat()
    }
    pub fn u(n: u128) -> Vec<u8> {
        let b: Vec<u8> = n.to_be_bytes().into_iter().skip_while(|&x| x == 0).collect();
        rlp_str(&b)
    }
    pub fn type2(chain: u128, to: &[u8], value: u128, data: &[u8]) -> Vec<u8> {
        let f = [u(chain), u(7), u(1), u(2), u(21_000), rlp_str(to), u(value), rlp_str(data), rlp_list(&[])];
        [vec![2], rlp_list(&f)].concat()
    }
    pub fn type4(chain: u128, to: &[u8], value: u128, data: &[u8], auths: &[(u128, Addr)]) -> Vec<u8> {
        let a: Vec<Vec<u8>> =
            auths.iter().map(|(c, d)| rlp_list(&[u(*c), rlp_str(d), u(0), u(0), u(1), u(1)])).collect();
        let f = [u(chain), u(7), u(1), u(2), u(21_000), rlp_str(to), u(value), rlp_str(data), rlp_list(&[]), rlp_list(&a)];
        [vec![4], rlp_list(&f)].concat()
    }
    pub fn legacy(chain: u128, to: &[u8], value: u128, data: &[u8]) -> Vec<u8> {
        rlp_list(&[u(7), u(1), u(21_000), rlp_str(to), u(value), rlp_str(data), u(chain), rlp_str(&[]), rlp_str(&[])])
    }
    pub fn authorization(chain: u128, delegate: &Addr, nonce: u128) -> Vec<u8> {
        [vec![5], rlp_list(&[u(chain), rlp_str(delegate), u(nonce)])].concat()
    }
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
        EvmConfig { chain_id: 1, safe: [0x5a; 20], multisend: [MULTISEND].into_iter().collect(), ..Default::default() }
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

    fn raw(tx: &[u8]) -> Simulation {
        analyze_raw(&cfg(), &Flat, tx, keccak256(tx))
    }

    #[test]
    fn raw_transfers_are_decoded_and_the_signed_bytes_are_the_parsed_bytes() {
        let erc20 = testenc::type2(1, &TOKEN, 0, &transfer(GOOD, 100));
        let s = raw(&erc20);
        assert!(!s.incomplete && s.risks.is_empty());
        assert_eq!((s.outflows[0].to.clone(), s.outflows[0].usd_cents), (hex(&GOOD), 100));
        assert_eq!(s.tx_hash, keccak256(&erc20));
        assert_eq!(engine().evaluate(&s, 0), Decision::Approve(s.tx_hash));

        assert_eq!(raw(&testenc::type2(1, &GOOD, 500, &[])).outflows[0].usd_cents, 500);
        assert!(!raw(&testenc::legacy(1, &GOOD, 5, &[])).incomplete);
        assert!(!raw(&testenc::type4(1, &GOOD, 5, &[], &[])).incomplete);
    }

    #[test]
    fn malformed_or_foreign_raw_transactions_fail_closed() {
        let good = testenc::type2(1, &GOOD, 5, &[]);
        assert!(analyze_raw(&cfg(), &Flat, &good, [0u8; 32]).incomplete); // digest mismatch
        let mut trailing = good.clone();
        trailing.push(0);
        let non_canonical = [
            vec![2],
            testenc::rlp_list(&[
                testenc::u(1), vec![0x81, 0x07], testenc::u(1), testenc::u(2), testenc::u(21_000),
                testenc::rlp_str(&GOOD), testenc::u(5), testenc::rlp_str(&[]), testenc::rlp_list(&[]),
            ]),
        ]
        .concat();
        for tx in [
            testenc::type2(5, &GOOD, 5, &[]), // wrong chain
            testenc::type2(1, &[], 5, &[]),   // contract creation
            trailing,
            non_canonical,
            vec![3, 0xc0], // blob transaction type
            vec![],
        ] {
            assert!(raw(&tx).incomplete);
        }
    }

    #[test]
    fn eip7702_delegations_are_blocked_unless_allowed() {
        let evil = [(1u128, EVIL)];
        let t = testenc::type4(1, &GOOD, 0, &[], &evil);
        assert_eq!(raw(&t).risks, vec![Risk::Delegation]);

        let allowed = EvmConfig { allowed_delegates: [EVIL].into_iter().collect(), ..cfg() };
        assert!(analyze_raw(&allowed, &Flat, &t, keccak256(&t)).risks.is_empty());

        let all_chains = testenc::type4(1, &GOOD, 0, &[], &[(0, EVIL)]);
        assert_eq!(analyze_raw(&allowed, &Flat, &all_chains, keccak256(&all_chains)).risks, vec![Risk::Delegation]);
        assert!(raw(&testenc::type4(1, &GOOD, 0, &[], &[(1, [0u8; 20])])).risks.is_empty()); // clearing is fine
    }

    #[test]
    fn authorization_signing_requests_are_checked() {
        let check = |c: &EvmConfig, p: &[u8]| analyze_authorization(c, p, keccak256(p));
        let evil = testenc::authorization(1, &EVIL, 0);
        assert_eq!(check(&cfg(), &evil).risks, vec![Risk::Delegation]);

        let allowed = EvmConfig { allowed_delegates: [EVIL].into_iter().collect(), ..cfg() };
        let s = check(&allowed, &evil);
        assert!(s.risks.is_empty() && !s.incomplete);
        assert_eq!(check(&allowed, &testenc::authorization(0, &EVIL, 0)).risks, vec![Risk::Delegation]);

        let mut wrong_magic = evil.clone();
        wrong_magic[0] = 6;
        assert!(check(&cfg(), &wrong_magic).incomplete);
        assert!(analyze_authorization(&cfg(), &evil, [0u8; 32]).incomplete);
    }
}
