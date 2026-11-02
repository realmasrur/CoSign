//! Service configuration (JSON). All amounts are USD cents. Unknown fields are rejected.

use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address to listen on, e.g. "0.0.0.0:8443". In a Nitro enclave this is reached through a vsock proxy.
    pub listen: String,
    pub tls: TlsCfg,
    /// Signed license token file and the issuer's PUBLIC key (hex).
    pub license_file: String,
    pub issuer_pubkey: String,
    pub global: GlobalCfg,
    /// Approver public keys (hex) and how many must sign to unpause or loosen policy.
    pub approvers: Vec<String>,
    pub quorum: usize,
    pub loosen_delay_secs: u64,
    pub price_feeds: Vec<String>,
    pub price_threshold: usize,
    pub price_max_validity_secs: u64,
    pub callers: CallerCfg,
    pub chains: Vec<Chain>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsCfg {
    pub cert: String,
    pub key: String,
    /// CA that signs the client certificates allowed to connect.
    pub client_ca: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalCfg {
    pub window_secs: u64,
    pub max_usd_cents: u64,
}

/// Client certificates, identified by hex keccak256 of the DER certificate.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerCfg {
    /// May call /sign and /prices (the exchange's withdrawal system and price relay).
    pub sign: Vec<String>,
    /// May call /pause (any single trigger).
    pub pause: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Chain {
    pub chain_id: u64,
    /// The guarded Safe, or the hot wallet for raw transactions.
    pub account: String,
    pub multisend: Vec<String>,
    pub allowed_delegates: Vec<String>,
    /// File holding the 32-byte signing key as hex (mode 0600, provisioned inside the enclave).
    pub key_file: String,
    pub audit_log: String,
    pub policy: PolicyCfg,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyCfg {
    pub max_tx_usd_cents: u64,
    pub window_secs: u64,
    pub max_window_usd_cents: u64,
    pub delay_above_usd_cents: u64,
    pub delay_secs: u64,
    pub allow_list: Vec<String>,
    pub unlisted_max_usd_cents: u64,
}
