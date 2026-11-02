//! Signed license tokens: plan limits enforced offline, with no call-home and no
//! remote kill switch. The issuer signs the exact payload bytes; the enclave embeds
//! only the issuer's PUBLIC key and verifies them.
//!
//! After expiry there is a 90-day transition: existing protection keeps signing, but
//! no new chains load, so expiry never traps funds. After that, signing stops.
//! The clock only moves forward. Feed it a trusted time source in production.

use crate::control::Verifier;
use crate::keccak::keccak256;

const TRANSITION_SECS: u64 = 90 * 86_400;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct License {
    pub licensee: String,
    pub plan: String,
    /// `u32::MAX` means unlimited.
    pub max_chains: u32,
    pub features: Vec<String>,
    pub platforms: Vec<String>,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum LicenseError {
    Malformed,
    BadSignature,
    ChainLimit,
    /// Expired but in transition: no new chains.
    NoNewChains,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    Active { days_left: u64 },
    Transition { days_left: u64 },
    Expired,
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn field<'a>(it: &mut std::str::Lines<'a>, key: &str) -> Option<&'a str> {
    it.next()?.strip_prefix(key)?.strip_prefix('=')
}

fn list(s: &str) -> Vec<String> {
    if s.is_empty() { Vec::new() } else { s.split(',').map(String::from).collect() }
}

impl License {
    /// The exact bytes that get signed. `None` if any field could break the format.
    pub fn payload(&self) -> Option<String> {
        let bad = |s: &str| s.contains(['\n', '\r']);
        let names = |v: &[String]| v.iter().any(|s| s.is_empty() || bad(s) || s.contains(','));
        if self.licensee.is_empty() || bad(&self.licensee) || self.plan.is_empty() || bad(&self.plan)
            || names(&self.features) || names(&self.platforms)
            || self.max_chains == 0 || self.expires_at <= self.issued_at
        {
            return None;
        }
        let chains = if self.max_chains == u32::MAX { "unlimited".to_string() } else { self.max_chains.to_string() };
        Some(format!(
            "cosign-license-v1\nlicensee={}\nplan={}\nmax_chains={}\nfeatures={}\nplatforms={}\nissued_at={}\nexpires_at={}\n",
            self.licensee, self.plan, chains, self.features.join(","), self.platforms.join(","),
            self.issued_at, self.expires_at
        ))
    }

    /// Strict: exact field order, no extra or missing lines.
    fn parse(p: &str) -> Option<License> {
        if !p.ends_with('\n') || p.contains('\r') {
            return None;
        }
        let mut it = p.lines();
        if it.next()? != "cosign-license-v1" {
            return None;
        }
        let l = License {
            licensee: field(&mut it, "licensee")?.to_string(),
            plan: field(&mut it, "plan")?.to_string(),
            max_chains: match field(&mut it, "max_chains")? {
                "unlimited" => u32::MAX,
                n => n.parse().ok()?,
            },
            features: list(field(&mut it, "features")?),
            platforms: list(field(&mut it, "platforms")?),
            issued_at: field(&mut it, "issued_at")?.parse().ok()?,
            expires_at: field(&mut it, "expires_at")?.parse().ok()?,
        };
        // Re-serializing must reproduce the input exactly (rejects non-canonical numbers etc).
        if it.next().is_some() || l.payload()? != p {
            return None;
        }
        Some(l)
    }
}

pub struct Entitlements {
    license: License,
    clock: u64,
}

impl Entitlements {
    /// `token` = payload followed by a final `sig=<hex>` line. `issuer` is the issuer's public key.
    pub fn load<V: Verifier>(token: &str, now: u64, issuer: &[u8], v: &V) -> Result<Self, LicenseError> {
        let i = token.rfind("sig=").ok_or(LicenseError::Malformed)?;
        if i > 0 && token.as_bytes()[i - 1] != b'\n' {
            return Err(LicenseError::Malformed);
        }
        let (payload, sig) = token.split_at(i);
        let sig = unhex(sig[4..].trim()).ok_or(LicenseError::Malformed)?;
        if !v.verify(issuer, &keccak256(payload.as_bytes()), &sig) {
            return Err(LicenseError::BadSignature);
        }
        let license = License::parse(payload).ok_or(LicenseError::Malformed)?;
        Ok(Self { license, clock: now })
    }

    /// Advance the clock (never backwards) and return it.
    pub fn observe(&mut self, now: u64) -> u64 {
        self.clock = self.clock.max(now);
        self.clock
    }

    pub fn status(&self) -> Status {
        let (c, e) = (self.clock, self.license.expires_at);
        let end = e.saturating_add(TRANSITION_SECS);
        if c <= e {
            Status::Active { days_left: (e - c) / 86_400 }
        } else if c <= end {
            Status::Transition { days_left: (end - c) / 86_400 }
        } else {
            Status::Expired
        }
    }

    pub fn may_sign(&self) -> bool {
        self.status() != Status::Expired
    }

    /// Call before loading another chain; `loaded` is how many are already running.
    pub fn check_new_chain(&self, loaded: usize) -> Result<(), LicenseError> {
        match self.status() {
            Status::Active { .. } if (loaded as u64) < self.license.max_chains as u64 => Ok(()),
            Status::Active { .. } => Err(LicenseError::ChainLimit),
            _ => Err(LicenseError::NoNewChains),
        }
    }

    pub fn has_feature(&self, f: &str) -> bool {
        self.license.features.iter().any(|x| x == f)
    }

    pub fn covers(&self, platform: &str) -> bool {
        self.license.platforms.iter().any(|x| x == platform)
    }
}

#[cfg(test)]
pub(crate) mod testkit {
    use super::*;

    pub const ISSUER: [u8; 1] = [9];

    pub fn sample(max_chains: u32, expires_at: u64) -> License {
        License {
            licensee: "Acme Exchange".into(), plan: "Guard".into(), max_chains,
            features: vec!["mpc-adapters".into()], platforms: vec!["acme.example".into()],
            issued_at: 1_000, expires_at,
        }
    }

    /// Valid under the `Tag` test verifier: signature = issuer || digest.
    pub fn token(l: &License) -> String {
        let p = l.payload().unwrap();
        let sig = [&ISSUER[..], &keccak256(p.as_bytes())[..]].concat();
        format!("{p}sig={}\n", hex(&sig))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::Tag;
    use testkit::*;

    const YEAR: u64 = 365 * 86_400;

    fn load(l: &License, now: u64) -> Entitlements {
        Entitlements::load(&token(l), now, &ISSUER, &Tag).unwrap()
    }

    #[test]
    fn payload_round_trips_and_rejects_format_breaking_fields() {
        let l = sample(3, 1_000 + YEAR);
        assert_eq!(License::parse(&l.payload().unwrap()), Some(l.clone()));
        assert_eq!(License::parse(&sample(u32::MAX, 1_000 + YEAR).payload().unwrap()).unwrap().max_chains, u32::MAX);
        for bad in [
            License { licensee: "a\nplan=Exchange".into(), ..l.clone() },
            License { features: vec!["a,b".into()], ..l.clone() },
            License { max_chains: 0, ..l.clone() },
            License { expires_at: 1_000, ..l.clone() },
        ] {
            assert_eq!(bad.payload(), None);
        }
    }

    #[test]
    fn signature_and_format_are_enforced() {
        let l = sample(3, 1_000 + YEAR);
        let tok = token(&l);
        assert!(Entitlements::load(&tok, 2_000, &ISSUER, &Tag).is_ok());
        assert_eq!(Entitlements::load(&tok, 2_000, &[1], &Tag).err(), Some(LicenseError::BadSignature));
        let upgraded = tok.replace("max_chains=3", "max_chains=unlimited");
        assert_eq!(Entitlements::load(&upgraded, 2_000, &ISSUER, &Tag).err(), Some(LicenseError::BadSignature));
        assert_eq!(Entitlements::load("garbage", 2_000, &ISSUER, &Tag).err(), Some(LicenseError::Malformed));
    }

    #[test]
    fn expiry_has_a_ninety_day_transition_and_the_clock_never_rewinds() {
        let e = 1_000 + YEAR;
        let mut ent = load(&sample(3, e), 2_000);
        assert_eq!(ent.status(), Status::Active { days_left: 364 });
        ent.observe(e + 1);
        assert_eq!(ent.status(), Status::Transition { days_left: 89 });
        assert!(ent.may_sign());
        ent.observe(e + TRANSITION_SECS + 1);
        assert_eq!(ent.status(), Status::Expired);
        assert!(!ent.may_sign());
        ent.observe(0); // lying host tries to rewind
        assert!(!ent.may_sign());
    }

    #[test]
    fn plan_limits() {
        let e = 1_000 + YEAR;
        let ent = load(&sample(3, e), 2_000);
        assert_eq!(ent.check_new_chain(2), Ok(()));
        assert_eq!(ent.check_new_chain(3), Err(LicenseError::ChainLimit));
        assert_eq!(load(&sample(u32::MAX, e), 2_000).check_new_chain(500), Ok(()));
        assert!(ent.has_feature("mpc-adapters") && !ent.has_feature("non-evm"));
        assert!(ent.covers("acme.example") && !ent.covers("other.example"));

        let mut late = load(&sample(3, e), 2_000);
        late.observe(e + 1);
        assert_eq!(late.check_new_chain(0), Err(LicenseError::NoNewChains));
    }
}
