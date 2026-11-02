//! Request handling, independent of transport so it can be tested without TLS.
//! Caller identity (the mTLS client-certificate fingerprint) is checked per endpoint.
//! /unpause is authorized by approver signatures instead, never by caller identity.

use crate::config::Config;
use cosign_policy::audit::{Log, Sink};
use cosign_policy::control::{Approval, Quorum, Verifier};
use cosign_policy::evm::{Addr, Asset, EvmConfig, SafeTx, Word};
use cosign_policy::license::{hex, unhex, Entitlements};
use cosign_policy::price::{PriceBook, SignedPrice};
use cosign_policy::signer::{CoSigner, Key, Response};
use cosign_policy::{Engine, GlobalLimit, Policy};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

pub struct Reply {
    pub status: u16,
    pub body: String,
}

fn reply(status: u16, v: Value) -> Reply {
    Reply { status, body: v.to_string() }
}

pub fn err(status: u16, msg: &str) -> Reply {
    reply(status, json!({ "error": msg }))
}

fn bytes(s: &str) -> Option<Vec<u8>> {
    unhex(s.strip_prefix("0x").unwrap_or(s))
}

fn addr(s: &str) -> Option<Addr> {
    Addr::try_from(bytes(s)?.as_slice()).ok()
}

fn digest(s: &str) -> Option<Word> {
    Word::try_from(bytes(s)?.as_slice()).ok()
}

/// Numeric fields are hex of at most 32 bytes, left-padded.
fn word(s: &str) -> Option<Word> {
    let b = bytes(s)?;
    if b.len() > 32 {
        return None;
    }
    let mut w = [0u8; 32];
    w[32 - b.len()..].copy_from_slice(&b);
    Some(w)
}

pub fn h(b: &[u8]) -> String {
    format!("0x{}", hex(b))
}

fn addrs(v: &[String]) -> Result<Vec<Addr>, String> {
    v.iter().map(|a| addr(a).ok_or_else(|| format!("bad address: {a}"))).collect()
}

fn keys(v: &[String], what: &str) -> Result<Vec<Vec<u8>>, String> {
    v.iter().map(|a| bytes(a).filter(|b| !b.is_empty()).ok_or_else(|| format!("bad {what}: {a}"))).collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignReq {
    chain_id: u64,
    kind: String,
    claimed_digest: String,
    payload: Option<String>,
    safe: Option<SafeJson>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SafeJson {
    to: String,
    value: String,
    data: String,
    operation: u8,
    safe_tx_gas: String,
    base_gas: String,
    gas_price: String,
    gas_token: String,
    refund_receiver: String,
    nonce: String,
}

impl SafeJson {
    fn to_tx(&self) -> Option<SafeTx> {
        Some(SafeTx {
            to: addr(&self.to)?,
            value: word(&self.value)?,
            data: bytes(&self.data)?,
            operation: self.operation,
            safe_tx_gas: word(&self.safe_tx_gas)?,
            base_gas: word(&self.base_gas)?,
            gas_price: word(&self.gas_price)?,
            gas_token: addr(&self.gas_token)?,
            refund_receiver: addr(&self.refund_receiver)?,
            nonce: word(&self.nonce)?,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PricesReq {
    chain_id: u64,
    prices: Vec<PriceJson>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PriceJson {
    asset: String, // "native" or a token address
    price_e8: String,
    decimals: u8,
    issued_at: u64,
    expires_at: u64,
    feed: String,
    sig: String,
}

fn to_price(p: &PriceJson) -> Option<SignedPrice> {
    Some(SignedPrice {
        asset: if p.asset == "native" { Asset::Native } else { Asset::Token(addr(&p.asset)?) },
        price_e8: p.price_e8.parse().ok()?,
        decimals: p.decimals,
        issued_at: p.issued_at,
        expires_at: p.expires_at,
        feed: bytes(&p.feed)?,
        sig: bytes(&p.sig)?,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnpauseReq {
    approvals: Vec<ApprovalJson>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalJson {
    approver: String,
    sig: String,
}

fn out(r: Response) -> Reply {
    match r {
        Response::Signed(sig) => reply(200, json!({ "status": "signed", "signature": h(&sig) })),
        Response::Delay { until } => reply(202, json!({ "status": "delay", "until": until })),
        Response::Blocked(reasons) => reply(
            403,
            json!({ "status": "blocked", "reasons": reasons.iter().map(|r| format!("{r:?}")).collect::<Vec<_>>() }),
        ),
    }
}

struct ChainRt<K: Key, S: Sink, V: Verifier> {
    signer: CoSigner<K, S, V>,
    prices: PriceBook<V>,
}

pub struct Service<K: Key, S: Sink, V: Verifier> {
    chains: HashMap<u64, ChainRt<K, S, V>>,
    sign_callers: HashSet<String>,
    pause_callers: HashSet<String>,
}

impl<K: Key, S: Sink, V: Verifier + Clone> Service<K, S, V> {
    /// One signer per configured chain, all sharing one global limit. Each chain loads
    /// the license and is checked against its chain limit, so a plan's cap holds at startup.
    pub fn build(
        cfg: &Config,
        verifier: V,
        now: u64,
        mut key: impl FnMut(&crate::config::Chain) -> Result<K, String>,
        mut sink: impl FnMut(&crate::config::Chain) -> Result<S, String>,
    ) -> Result<Self, String> {
        let token = std::fs::read_to_string(&cfg.license_file).map_err(|e| format!("license: {e}"))?;
        let issuer = bytes(&cfg.issuer_pubkey).ok_or("bad issuer_pubkey")?;
        let approvers = keys(&cfg.approvers, "approver")?;
        let feeds = keys(&cfg.price_feeds, "price feed")?;
        if cfg.chains.is_empty() {
            return Err("no chains configured".into());
        }
        if cfg.quorum == 0 || cfg.quorum > approvers.len() {
            return Err("quorum must be between 1 and the number of approvers".into());
        }
        if cfg.price_threshold == 0 || cfg.price_threshold > feeds.len() {
            return Err("price_threshold must be between 1 and the number of feeds".into());
        }

        let global = GlobalLimit::shared(cfg.global.window_secs, cfg.global.max_usd_cents as u128);
        let mut chains = HashMap::new();
        for c in &cfg.chains {
            if chains.contains_key(&c.chain_id) {
                return Err(format!("duplicate chain {}", c.chain_id));
            }
            let ent = Entitlements::load(&token, now, &issuer, &verifier).map_err(|e| format!("license: {e:?}"))?;
            ent.check_new_chain(chains.len()).map_err(|e| format!("chain {}: {e:?}", c.chain_id))?;

            let evm = EvmConfig {
                chain_id: c.chain_id,
                safe: addr(&c.account).ok_or_else(|| format!("bad account: {}", c.account))?,
                multisend: addrs(&c.multisend)?.into_iter().collect(),
                allowed_delegates: addrs(&c.allowed_delegates)?.into_iter().collect(),
            };
            let p = &c.policy;
            let policy = Policy {
                max_tx_usd_cents: p.max_tx_usd_cents as u128,
                window_secs: p.window_secs,
                max_window_usd_cents: p.max_window_usd_cents as u128,
                delay_above_usd_cents: p.delay_above_usd_cents as u128,
                delay_secs: p.delay_secs,
                allow_list: addrs(&p.allow_list)?.iter().map(|a| hex_addr(a)).collect(),
                unlisted_max_usd_cents: p.unlisted_max_usd_cents as u128,
            };
            let signer = CoSigner::new(
                evm,
                Engine::new(policy).with_global(global.clone()),
                key(c)?,
                Log::new(sink(c)?),
                Quorum::new(approvers.clone(), cfg.quorum, verifier.clone()),
                cfg.loosen_delay_secs,
            )
            .with_license(ent);
            let prices = PriceBook::new(
                c.chain_id,
                feeds.clone(),
                cfg.price_threshold,
                cfg.price_max_validity_secs,
                verifier.clone(),
            );
            chains.insert(c.chain_id, ChainRt { signer, prices });
        }

        let fp = |v: &[String]| v.iter().map(|s| s.trim_start_matches("0x").to_ascii_lowercase()).collect();
        Ok(Self { chains, sign_callers: fp(&cfg.callers.sign), pause_callers: fp(&cfg.callers.pause) })
    }

    /// `peer` is the hex keccak256 fingerprint of the caller's client certificate.
    pub fn handle(&mut self, peer: &str, method: &str, path: &str, body: &[u8], now: u64) -> Reply {
        match (method, path) {
            ("GET", "/health") => self.health(),
            ("POST", "/sign") if self.sign_callers.contains(peer) => self.sign(body, now),
            ("POST", "/prices") if self.sign_callers.contains(peer) => self.prices(body, now),
            ("POST", "/pause") if self.pause_callers.contains(peer) => self.pause(now),
            ("POST", "/unpause") => self.unpause(body, now),
            ("POST", "/sign" | "/prices" | "/pause") => err(403, "caller not authorized"),
            _ => err(404, "not found"),
        }
    }

    fn health(&self) -> Reply {
        let mut ids: Vec<u64> = self.chains.keys().copied().collect();
        ids.sort();
        let chains: Vec<Value> = ids
            .iter()
            .map(|id| {
                let s = &self.chains[id].signer;
                json!({
                    "chain_id": id,
                    "paused": s.is_paused(),
                    "license": s.license_status().map(|l| format!("{l:?}")),
                    "unpause_message": h(&s.unpause_message()),
                })
            })
            .collect();
        reply(200, json!({ "chains": chains }))
    }

    fn sign(&mut self, body: &[u8], now: u64) -> Reply {
        let Ok(r) = serde_json::from_slice::<SignReq>(body) else { return err(400, "malformed request") };
        let Some(rt) = self.chains.get_mut(&r.chain_id) else { return err(404, "unknown chain") };
        let Some(claimed) = digest(&r.claimed_digest) else { return err(400, "claimed_digest must be 32 bytes") };
        rt.prices.tick(now);
        let payload = || r.payload.as_deref().and_then(bytes);
        let resp = match r.kind.as_str() {
            "safe" => {
                let Some(tx) = r.safe.as_ref().and_then(SafeJson::to_tx) else { return err(400, "bad safe fields") };
                rt.signer.request(&rt.prices, &tx, claimed, now)
            }
            "raw" => {
                let Some(p) = payload() else { return err(400, "bad payload") };
                rt.signer.request_raw(&rt.prices, &p, claimed, now)
            }
            "authorization" => {
                let Some(p) = payload() else { return err(400, "bad payload") };
                rt.signer.request_authorization(&p, claimed, now)
            }
            _ => return err(400, "kind must be safe, raw or authorization"),
        };
        out(resp)
    }

    fn prices(&mut self, body: &[u8], now: u64) -> Reply {
        let Ok(r) = serde_json::from_slice::<PricesReq>(body) else { return err(400, "malformed request") };
        let Some(rt) = self.chains.get_mut(&r.chain_id) else { return err(404, "unknown chain") };
        let Some(msgs) = r.prices.iter().map(to_price).collect::<Option<Vec<_>>>() else {
            return err(400, "bad price fields");
        };
        rt.prices.ingest(now, &msgs);
        reply(200, json!({ "received": msgs.len() }))
    }

    fn pause(&mut self, now: u64) -> Reply {
        for rt in self.chains.values_mut() {
            rt.signer.pause(now);
        }
        reply(200, json!({ "paused": true }))
    }

    fn unpause(&mut self, body: &[u8], now: u64) -> Reply {
        let Ok(r) = serde_json::from_slice::<UnpauseReq>(body) else { return err(400, "malformed request") };
        let Some(approvals) = r
            .approvals
            .iter()
            .map(|a| Some((bytes(&a.approver)?, bytes(&a.sig)?)))
            .collect::<Option<Vec<Approval>>>()
        else {
            return err(400, "bad approvals");
        };
        let (mut ok, mut failed) = (Vec::new(), Vec::new());
        for (id, rt) in self.chains.iter_mut() {
            if rt.signer.unpause(now, &approvals) { ok.push(*id) } else { failed.push(*id) }
        }
        reply(if failed.is_empty() { 200 } else { 403 }, json!({ "unpaused": ok, "failed": failed }))
    }
}

/// Canonical allow-list form used by the policy engine.
fn hex_addr(a: &Addr) -> String {
    h(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;
    use cosign_policy::audit::Entry;
    use cosign_policy::evm::{safe_tx_hash, word as w32};
    use cosign_policy::keccak::keccak256;
    use cosign_policy::license::License;
    use cosign_policy::signer::{KeyError, Signature};

    #[derive(Clone, Copy)]
    struct TestV; // a signature is valid iff it equals approver || message
    impl Verifier for TestV {
        fn verify(&self, a: &[u8], m: &[u8; 32], s: &[u8]) -> bool {
            s == [a, &m[..]].concat()
        }
    }

    struct MockKey;
    impl Key for MockKey {
        fn sign(&self, d: &Word) -> Result<Signature, KeyError> {
            let mut s = [0u8; 65];
            s[..32].copy_from_slice(d);
            Ok(s)
        }
    }

    const ACCOUNT: Addr = [0x5a; 20];
    const GOOD: Addr = [0xaa; 20];
    const EVIL: Addr = [0x66; 20];

    fn config(name: &str, max_chains: u32, chains: &[u64]) -> Config {
        let lic = License {
            licensee: "Test".into(), plan: "Exchange".into(), max_chains, features: vec![], platforms: vec![],
            issued_at: 1, expires_at: 10_000_000,
        };
        let p = lic.payload().unwrap();
        let sig = [&[9u8][..], &keccak256(p.as_bytes())[..]].concat();
        let path = std::env::temp_dir().join(format!("cosign-{}-{name}.lic", std::process::id()));
        std::fs::write(&path, format!("{p}sig={}\n", hex(&sig))).unwrap();
        Config {
            listen: "127.0.0.1:0".into(),
            tls: TlsCfg { cert: String::new(), key: String::new(), client_ca: String::new() },
            license_file: path.to_string_lossy().into_owned(),
            issuer_pubkey: "0x09".into(),
            global: GlobalCfg { window_secs: 3_600, max_usd_cents: 50_000 },
            approvers: vec!["0x01".into(), "0x02".into(), "0x03".into()],
            quorum: 2,
            loosen_delay_secs: 86_400,
            price_feeds: vec!["0x01".into()],
            price_threshold: 1,
            price_max_validity_secs: 300,
            callers: CallerCfg { sign: vec!["aa".into()], pause: vec!["bb".into()] },
            chains: chains
                .iter()
                .map(|&id| Chain {
                    chain_id: id,
                    account: h(&ACCOUNT),
                    multisend: vec![],
                    allowed_delegates: vec![],
                    key_file: String::new(),
                    audit_log: String::new(),
                    policy: PolicyCfg {
                        max_tx_usd_cents: 10_000, window_secs: 3_600, max_window_usd_cents: 20_000,
                        delay_above_usd_cents: 5_000, delay_secs: 600, allow_list: vec![h(&GOOD)],
                        unlisted_max_usd_cents: 0,
                    },
                })
                .collect(),
        }
    }

    fn svc(name: &str, max_chains: u32, chains: &[u64]) -> Result<Service<MockKey, Vec<Entry>, TestV>, String> {
        Service::build(&config(name, max_chains, chains), TestV, 10, |_| Ok(MockKey), |_| Ok(Vec::new()))
    }

    fn tx(op: u8, to: Addr, value: u128) -> SafeTx {
        SafeTx {
            to, value: w32(value), data: vec![], operation: op, safe_tx_gas: w32(0), base_gas: w32(0),
            gas_price: w32(0), gas_token: [0; 20], refund_receiver: [0; 20], nonce: w32(1),
        }
    }

    fn sign_body(t: &SafeTx) -> Vec<u8> {
        let evm = EvmConfig { chain_id: 1, safe: ACCOUNT, ..Default::default() };
        json!({
            "chain_id": 1, "kind": "safe", "claimed_digest": h(&safe_tx_hash(&evm, t)),
            "safe": {
                "to": h(&t.to), "value": h(&t.value), "data": h(&t.data), "operation": t.operation,
                "safe_tx_gas": h(&t.safe_tx_gas), "base_gas": h(&t.base_gas), "gas_price": h(&t.gas_price),
                "gas_token": h(&t.gas_token), "refund_receiver": h(&t.refund_receiver), "nonce": h(&t.nonce),
            }
        })
        .to_string()
        .into_bytes()
    }

    /// 1 unit of the native asset = 1 cent, signed by feed 0x01.
    fn prices_body() -> Vec<u8> {
        let m = SignedPrice {
            asset: Asset::Native, price_e8: 1_000_000, decimals: 0, issued_at: 0, expires_at: 100,
            feed: vec![1], sig: vec![],
        };
        let sig = [&[1u8][..], &m.digest(1)[..]].concat();
        json!({ "chain_id": 1, "prices": [{
            "asset": "native", "price_e8": "1000000", "decimals": 0, "issued_at": 0, "expires_at": 100,
            "feed": "0x01", "sig": h(&sig),
        }]})
        .to_string()
        .into_bytes()
    }

    fn call(s: &mut Service<MockKey, Vec<Entry>, TestV>, peer: &str, m: &str, p: &str, body: &[u8]) -> (u16, Value) {
        let r = s.handle(peer, m, p, body, 20);
        (r.status, serde_json::from_str(&r.body).unwrap())
    }

    #[test]
    fn signs_valid_requests_and_checks_caller_identity() {
        let mut s = svc("sign", 5, &[1]).ok().unwrap();
        assert_eq!(call(&mut s, "aa", "POST", "/prices", &prices_body()).0, 200);
        let (status, v) = call(&mut s, "aa", "POST", "/sign", &sign_body(&tx(0, GOOD, 500)));
        assert_eq!((status, v["status"].as_str()), (200, Some("signed")));

        assert_eq!(call(&mut s, "zz", "POST", "/sign", &sign_body(&tx(0, GOOD, 501))).0, 403);
        assert_eq!(call(&mut s, "aa", "POST", "/pause", b"{}").0, 403); // sign caller cannot pause
        assert_eq!(call(&mut s, "aa", "POST", "/nope", b"").0, 404);
        assert_eq!(call(&mut s, "aa", "POST", "/sign", b"{").0, 400);
        let mut unknown_chain = serde_json::from_slice::<Value>(&sign_body(&tx(0, GOOD, 1))).unwrap();
        unknown_chain["chain_id"] = json!(9);
        assert_eq!(call(&mut s, "aa", "POST", "/sign", unknown_chain.to_string().as_bytes()).0, 404);
    }

    #[test]
    fn blocks_delegatecall_and_rejects_bad_inputs() {
        let mut s = svc("block", 5, &[1]).ok().unwrap();
        call(&mut s, "aa", "POST", "/prices", &prices_body());
        let (status, v) = call(&mut s, "aa", "POST", "/sign", &sign_body(&tx(1, EVIL, 0)));
        assert_eq!(status, 403);
        assert!(v["reasons"].to_string().contains("DelegateCall"));

        let mut bad = serde_json::from_slice::<Value>(&sign_body(&tx(0, GOOD, 1))).unwrap();
        bad["kind"] = json!("weird");
        assert_eq!(call(&mut s, "aa", "POST", "/sign", bad.to_string().as_bytes()).0, 400);
        bad["kind"] = json!("raw");
        bad["payload"] = json!("0x00");
        assert_eq!(call(&mut s, "aa", "POST", "/sign", bad.to_string().as_bytes()).0, 403); // undecodable
    }

    #[test]
    fn pause_and_quorum_unpause_over_the_api() {
        let mut s = svc("pause", 5, &[1]).ok().unwrap();
        call(&mut s, "aa", "POST", "/prices", &prices_body());
        assert_eq!(call(&mut s, "bb", "POST", "/pause", b"{}").0, 200);
        let (status, v) = call(&mut s, "aa", "POST", "/sign", &sign_body(&tx(0, GOOD, 500)));
        assert_eq!(status, 403);
        assert!(v["reasons"].to_string().contains("Paused"));

        let (_, health) = call(&mut s, "any", "GET", "/health", b"");
        let msg = bytes(health["chains"][0]["unpause_message"].as_str().unwrap()).unwrap();
        let approval = |who: u8| json!({ "approver": h(&[who]), "sig": h(&[&[who][..], &msg[..]].concat()) });
        let one = json!({ "approvals": [approval(1)] }).to_string();
        let two = json!({ "approvals": [approval(1), approval(2)] }).to_string();
        assert_eq!(call(&mut s, "any", "POST", "/unpause", one.as_bytes()).0, 403);
        assert_eq!(call(&mut s, "any", "POST", "/unpause", two.as_bytes()).0, 200);
        assert_eq!(call(&mut s, "aa", "POST", "/sign", &sign_body(&tx(0, GOOD, 500))).0, 200);
        assert_eq!(call(&mut s, "any", "POST", "/unpause", two.as_bytes()).0, 403); // replayed approvals
    }

    #[test]
    fn plan_chain_limit_is_enforced_at_startup() {
        assert!(svc("limit_ok", 2, &[1, 56]).is_ok());
        let e = svc("limit_hit", 1, &[1, 56]).err().unwrap();
        assert!(e.contains("ChainLimit"), "{e}");
    }
}
