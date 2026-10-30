//! Signed price feed, verified inside the enclave. USD limits are only as
//! trustworthy as the prices behind them, so the host never supplies a bare number.
//!
//! - M distinct configured feeds must sign; the HIGHEST valid price wins
//!   (overstating value is the safe direction). Rounding is upward for the same reason.
//! - Messages bind the chain id, expire, and have a capped validity window.
//! - The clock never moves backwards, and an older quote never replaces a newer one.
//! - Anything missing, stale, unverifiable or overflowing returns `None`, which blocks.
//!
//! Call `ingest(now, ..)` (an empty slice is fine) with each request's time so the
//! clock advances before pricing.

use crate::control::Verifier;
use crate::evm::{Asset, Pricer};
use crate::keccak::keccak256;
use std::collections::{HashMap, HashSet};

const MAX_SKEW_SECS: u64 = 30;
const MAX_DECIMALS: u8 = 30;

#[derive(Debug, Clone)]
pub struct SignedPrice {
    pub asset: Asset,
    /// USD x 1e8 per whole unit (10^decimals base units).
    pub price_e8: u128,
    pub decimals: u8,
    pub issued_at: u64,
    pub expires_at: u64,
    /// Feed public key / id, and its signature over `digest(chain_id)`.
    pub feed: Vec<u8>,
    pub sig: Vec<u8>,
}

impl SignedPrice {
    pub fn digest(&self, chain_id: u64) -> [u8; 32] {
        let mut b = b"COSIGN_PRICE_V1".to_vec();
        b.extend(chain_id.to_be_bytes());
        match &self.asset {
            Asset::Native => {
                b.push(0);
                b.extend([0u8; 20]);
            }
            Asset::Token(a) => {
                b.push(1);
                b.extend(a);
            }
        }
        b.extend(self.price_e8.to_be_bytes());
        b.push(self.decimals);
        b.extend(self.issued_at.to_be_bytes());
        b.extend(self.expires_at.to_be_bytes());
        keccak256(&b)
    }
}

struct Quote {
    price_e8: u128,
    decimals: u8,
    issued_at: u64,
    expires_at: u64,
}

pub struct PriceBook<V: Verifier> {
    chain_id: u64,
    feeds: Vec<Vec<u8>>,
    threshold: usize,
    max_validity: u64,
    verifier: V,
    clock: u64,
    quotes: HashMap<Asset, Quote>,
}

impl<V: Verifier> PriceBook<V> {
    pub fn new(chain_id: u64, feeds: Vec<Vec<u8>>, threshold: usize, max_validity_secs: u64, verifier: V) -> Self {
        Self { chain_id, feeds, threshold, max_validity: max_validity_secs, verifier, clock: 0, quotes: HashMap::new() }
    }

    /// Advance the clock. Never goes backwards, so a lying host cannot rewind it.
    pub fn tick(&mut self, now: u64) {
        self.clock = self.clock.max(now);
    }

    pub fn ingest(&mut self, now: u64, msgs: &[SignedPrice]) {
        self.tick(now);

        let mut by_asset: HashMap<&Asset, Vec<&SignedPrice>> = HashMap::new();
        for m in msgs.iter().filter(|m| self.valid(m)) {
            by_asset.entry(&m.asset).or_default().push(m);
        }

        for (asset, group) in by_asset {
            let decimals = group[0].decimals;
            let distinct: HashSet<&Vec<u8>> = group.iter().map(|m| &m.feed).collect();
            if self.threshold == 0 || distinct.len() < self.threshold || group.iter().any(|m| m.decimals != decimals) {
                continue;
            }
            let q = Quote {
                price_e8: group.iter().map(|m| m.price_e8).max().unwrap(),
                decimals,
                issued_at: group.iter().map(|m| m.issued_at).min().unwrap(),
                expires_at: group.iter().map(|m| m.expires_at).min().unwrap(),
            };
            if self.quotes.get(asset).map_or(true, |old| q.issued_at >= old.issued_at) {
                self.quotes.insert(asset.clone(), q);
            }
        }
    }

    fn valid(&self, m: &SignedPrice) -> bool {
        m.price_e8 > 0
            && m.decimals <= MAX_DECIMALS
            && m.issued_at <= self.clock.saturating_add(MAX_SKEW_SECS)
            && m.expires_at >= self.clock
            && m.expires_at > m.issued_at
            && m.expires_at - m.issued_at <= self.max_validity
            && self.feeds.contains(&m.feed)
            && self.verifier.verify(&m.feed, &m.digest(self.chain_id), &m.sig)
    }
}

impl<V: Verifier> Pricer for PriceBook<V> {
    fn usd_cents(&self, asset: &Asset, amount: u128) -> Option<u128> {
        let q = self.quotes.get(asset)?;
        if self.clock > q.expires_at {
            return None;
        }
        let denom = 10u128.checked_pow(q.decimals as u32 + 6)?; // e8 -> cents is 1e6
        let num = amount.checked_mul(q.price_e8)?;
        Some(num.checked_add(denom - 1)? / denom) // round up
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::Tag;

    const ETH: Asset = Asset::Native;
    const E8: u128 = 100_000_000;

    fn book() -> PriceBook<Tag> {
        PriceBook::new(1, vec![vec![1], vec![2], vec![3]], 2, 300, Tag)
    }

    fn quote(b: &PriceBook<Tag>, feed: u8, price: u128, decimals: u8, issued: u64, expires: u64) -> SignedPrice {
        let mut m = SignedPrice {
            asset: ETH, price_e8: price, decimals, issued_at: issued, expires_at: expires,
            feed: vec![feed], sig: vec![],
        };
        m.sig = [&[feed][..], &m.digest(b.chain_id)[..]].concat();
        m
    }

    #[test]
    fn prices_correctly_and_rounds_up() {
        let mut b = book();
        let m = [quote(&b, 1, 3000 * E8, 18, 0, 100), quote(&b, 2, 3000 * E8, 18, 0, 100)];
        b.ingest(10, &m);
        assert_eq!(b.usd_cents(&ETH, 10u128.pow(18)), Some(300_000));
        assert_eq!(b.usd_cents(&ETH, 1), Some(1));
        assert_eq!(b.usd_cents(&ETH, u128::MAX), None); // overflow blocks
    }

    #[test]
    fn needs_threshold_of_distinct_feeds_and_uses_the_highest_price() {
        let mut b = book();
        b.ingest(10, &[quote(&b, 1, 3000 * E8, 18, 0, 100)]);
        assert_eq!(b.usd_cents(&ETH, 1), None);

        let dup = quote(&b, 1, 3000 * E8, 18, 0, 100);
        b.ingest(10, &[dup.clone(), dup]);
        assert_eq!(b.usd_cents(&ETH, 1), None);

        let m = [quote(&b, 1, 3000 * E8, 18, 0, 100), quote(&b, 2, 2000 * E8, 18, 0, 100)];
        b.ingest(10, &m);
        assert_eq!(b.usd_cents(&ETH, 10u128.pow(18)), Some(300_000));
    }

    #[test]
    fn expires_and_the_clock_never_rewinds() {
        let mut b = book();
        let m = [quote(&b, 1, 3000 * E8, 18, 0, 100), quote(&b, 2, 3000 * E8, 18, 0, 100)];
        b.ingest(10, &m);
        assert!(b.usd_cents(&ETH, 1).is_some());
        b.tick(101);
        assert_eq!(b.usd_cents(&ETH, 1), None);
        b.tick(5); // lying host tries to rewind
        assert_eq!(b.usd_cents(&ETH, 1), None);
    }

    #[test]
    fn older_quote_never_replaces_a_newer_one() {
        let mut b = book();
        let new = [quote(&b, 1, 3000 * E8, 18, 50, 150), quote(&b, 2, 3000 * E8, 18, 50, 150)];
        b.ingest(60, &new);
        let old = [quote(&b, 1, 1000 * E8, 18, 10, 100), quote(&b, 2, 1000 * E8, 18, 10, 100)];
        b.ingest(60, &old);
        assert_eq!(b.usd_cents(&ETH, 10u128.pow(18)), Some(300_000));
    }

    #[test]
    fn rejects_bad_messages() {
        let b0 = book();
        let good = quote(&b0, 1, 3000 * E8, 18, 0, 100);
        let mut tampered = quote(&b0, 2, 3000 * E8, 18, 0, 100);
        tampered.price_e8 -= 1;
        let mut wrong_chain = quote(&b0, 2, 3000 * E8, 18, 0, 100);
        wrong_chain.sig = [&[2u8][..], &wrong_chain.digest(2)[..]].concat();
        let bad = [
            tampered,
            wrong_chain,
            quote(&b0, 9, 3000 * E8, 18, 0, 100),   // unknown feed
            quote(&b0, 2, 3000 * E8, 18, 0, 301),   // validity window too long
            quote(&b0, 2, 3000 * E8, 18, 100, 200), // issued in the future
            quote(&b0, 2, 0, 18, 0, 100),           // zero price
            quote(&b0, 2, 3000 * E8, 31, 0, 100),   // absurd decimals
        ];
        for m in bad {
            let mut b = book();
            b.ingest(10, &[good.clone(), m]);
            assert_eq!(b.usd_cents(&ETH, 1), None);
        }
    }
}
