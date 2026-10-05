//! TOML configuration.
//!
//! The file holds bootstrap settings and policy defaults. Policy changed at
//! runtime through the TUI is stored in the database and takes precedence.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use apti_core::normalize::NormPolicy;
use apti_core::policy::Threshold;
use apti_core::{Behavior, Tlp};
use serde::Deserialize;
use url::Url;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub instance: Instance,
    pub storage: Storage,
    pub public: Public,
    pub api: Api,
    pub control: Control,
    #[serde(default)]
    pub federation: Federation,
    #[serde(default)]
    pub publish: Publish,
    #[serde(default)]
    pub policy: Policy,
    #[serde(default)]
    pub audit: AuditConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Instance {
    /// Public base URL under which the ActivityPub endpoints are reachable.
    pub base_url: Url,
    /// `preferredUsername` of the Service actor (WebFinger `acct:` user).
    #[serde(default = "default_username")]
    pub username: String,
    #[serde(default = "default_name")]
    pub name: String,
    /// Name of the operating organisation (Organization actor).
    pub organization: String,
    /// Contact for removal requests (Section 11), shown in the actor summary.
    #[serde(default)]
    pub contact: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Storage {
    pub database: PathBuf,
    /// PEM file with the actor's RSA key; generated on first start.
    pub key_file: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Public {
    pub bind: SocketAddr,
    #[serde(default = "default_max_body")]
    pub max_body_bytes: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Api {
    pub bind: SocketAddr,
    /// No longer supported: tokens are managed in apti-tui and stored hashed
    /// in the database. Parsed only to reject old configs with a hint.
    #[serde(default)]
    tokens: Option<toml::Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Control {
    pub socket: PathBuf,
    /// Octal file mode of the socket, e.g. "0600" or "0660".
    #[serde(default = "default_socket_mode")]
    pub mode: String,
    /// Peers allowed in addition to the daemon's own uid (SO_PEERCRED).
    #[serde(default)]
    pub allowed_uids: Vec<u32>,
    #[serde(default)]
    pub allowed_gids: Vec<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Federation {
    /// Permit plain-HTTP URLs for remote actors (development only).
    pub allow_http: bool,
    /// Permit outgoing requests to loopback, private and other
    /// special-purpose addresses (development only; SSRF protection).
    pub allow_private_addresses: bool,
    pub request_timeout_secs: u64,
    pub sync_interval_secs: u64,
    pub full_resync_interval_secs: u64,
    /// Wall-clock budget for synchronising one followed actor.
    pub sync_budget_secs: u64,
    pub delivery_max_attempts: u32,
    /// Inbox requests per actor per minute.
    pub inbox_rate_per_minute: u32,
    /// Remote key fetches per registrable domain per minute. Applies before
    /// signature verification, so it bounds unauthenticated fetches.
    pub key_fetch_rate_per_minute: u32,
    /// Max HTTP signature age.
    pub signature_max_age_secs: i64,
    /// Live evidence objects stored per remote publisher; further new
    /// objects are dropped.
    pub max_evidence_per_publisher: u64,
}

impl Default for Federation {
    fn default() -> Self {
        Self {
            allow_http: false,
            allow_private_addresses: false,
            request_timeout_secs: 20,
            sync_interval_secs: 900,
            full_resync_interval_secs: 7 * 86400,
            sync_budget_secs: 600,
            delivery_max_attempts: 12,
            inbox_rate_per_minute: 120,
            key_fetch_rate_per_minute: 30,
            signature_max_age_secs: 12 * 3600,
            max_evidence_per_publisher: 100_000,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Publish {
    /// How often local observations are batched into Sightings.
    pub batch_interval_secs: u64,
    /// Default TLP for published evidence (overridable in the TUI).
    pub default_tlp: Tlp,
    pub manually_approves_followers: bool,
    /// Keep Tombstones / revoked objects in activeObjects this long.
    pub tombstone_days: i64,
}

impl Default for Publish {
    fn default() -> Self {
        Self {
            batch_interval_secs: 300,
            default_tlp: Tlp::Green,
            manually_approves_followers: true,
            tombstone_days: 180,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AuditConfig {
    /// Log every change to an observable to stdout (target `audit`).
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(untagged)]
pub enum KValue {
    Number(f64),
    Word(OffWord),
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OffWord {
    Off,
}

impl KValue {
    pub fn threshold(self) -> anyhow::Result<Threshold> {
        match self {
            KValue::Word(OffWord::Off) => Ok(Threshold::Off),
            KValue::Number(k) if k > 0.0 && k.is_finite() => Ok(Threshold::Quorum(k)),
            KValue::Number(_) => bail!("k must be > 0 or \"off\""),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorConfig {
    pub k: Option<KValue>,
    pub ttl_secs: Option<i64>,
    pub max_age_secs: Option<i64>,
    pub tlp: Option<Tlp>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorConfig {
    /// Operator id: an Organization actor URL, or `domain:<registrable domain>`.
    pub id: String,
    pub behavior: Option<Behavior>,
    #[serde(default)]
    pub trusted: bool,
    #[serde(default = "one")]
    pub weight: f64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Policy {
    pub default_k: KValue,
    /// Weight of this organisation's own Sightings (always trusted).
    pub local_weight: f64,
    pub min_v4_prefix: u8,
    pub min_v6_prefix: u8,
    pub reject_special_purpose: bool,
    pub allow_documentation_ranges: bool,
    /// High-impact benign infrastructure that is never listed (Section 10).
    /// Domains also cover their subdomains.
    pub allowlist: Vec<String>,
    /// Delete records of inactive observables after this many days (Section 11).
    pub retention_days: i64,
    pub recompute_interval_secs: u64,
    pub behavior: BTreeMap<Behavior, BehaviorConfig>,
    pub operator: Vec<OperatorConfig>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            default_k: KValue::Number(2.0),
            local_weight: 2.0,
            min_v4_prefix: 24,
            min_v6_prefix: 48,
            reject_special_purpose: true,
            allow_documentation_ranges: false,
            allowlist: Vec::new(),
            retention_days: 30,
            recompute_interval_secs: 300,
            behavior: BTreeMap::new(),
            operator: Vec::new(),
        }
    }
}

fn default_username() -> String {
    "feed".into()
}
fn default_name() -> String {
    "AP-TI feed".into()
}
fn default_max_body() -> usize {
    4 * 1024 * 1024
}
fn default_socket_mode() -> String {
    "0600".into()
}
fn one() -> f64 {
    1.0
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let mut cfg: Config = toml::from_str(text).context("parsing config")?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&mut self) -> anyhow::Result<()> {
        let base = &mut self.instance.base_url;
        if !matches!(base.scheme(), "https" | "http") || base.host_str().is_none() {
            bail!("instance.base_url must be an http(s) URL");
        }
        if base.scheme() == "http" && !self.federation.allow_http {
            bail!("instance.base_url uses http; set federation.allow_http = true for development");
        }
        let trimmed = base.as_str().trim_end_matches('/').to_string();
        *base = Url::parse(&trimmed)?;
        if self.instance.username.is_empty()
            || !self
                .instance
                .username
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        {
            bail!("instance.username must be [A-Za-z0-9_-]+");
        }
        if self.publish.default_tlp == Tlp::Red {
            bail!("publish.default_tlp must not be red");
        }
        if self.publish.tombstone_days < 180 {
            bail!("publish.tombstone_days must be at least 180 (Section 5.3)");
        }
        if self.federation.full_resync_interval_secs > 7 * 86400 {
            bail!("federation.full_resync_interval_secs must be at most 604800 (Section 5.3)");
        }
        if self.policy.recompute_interval_secs > 3600 {
            bail!("policy.recompute_interval_secs must be at most 3600 (Section 9)");
        }
        if !self.policy.reject_special_purpose {
            bail!("policy.reject_special_purpose must be true (Section 10)");
        }
        self.policy.default_k.threshold()?;
        for (b, bc) in &self.policy.behavior {
            if let Some(k) = bc.k {
                k.threshold()
                    .with_context(|| format!("policy.behavior.{b}.k"))?;
            }
            if bc.tlp == Some(Tlp::Red) {
                bail!("policy.behavior.{b}.tlp must not be red");
            }
        }
        u32::from_str_radix(self.control.mode.trim_start_matches("0o"), 8)
            .context("control.mode must be octal, e.g. \"0660\"")?;
        if self.api.tokens.is_some() {
            bail!(
                "[[api.tokens]] is no longer supported: remove it and create the tokens \
                 in apti-tui (Tokens tab); they are stored hashed in the database"
            );
        }
        Ok(())
    }

    pub fn socket_mode(&self) -> u32 {
        u32::from_str_radix(self.control.mode.trim_start_matches("0o"), 8).unwrap_or(0o600)
    }

    pub fn norm_policy(&self) -> NormPolicy {
        NormPolicy {
            min_v4_prefix: self.policy.min_v4_prefix,
            min_v6_prefix: self.policy.min_v6_prefix,
            reject_special_purpose: self.policy.reject_special_purpose,
            allow_documentation: self.policy.allow_documentation_ranges,
        }
    }

    /// `host[:port]` of the public base URL, used for WebFinger `acct:`.
    pub fn authority(&self) -> String {
        let u = &self.instance.base_url;
        match u.port() {
            Some(p) => format!("{}:{}", u.host_str().unwrap_or_default(), p),
            None => u.host_str().unwrap_or_default().to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config_parses() {
        let text = include_str!("../../../config.example.toml");
        let cfg = Config::parse(text).unwrap();
        assert_eq!(cfg.instance.username, "feed");
    }

    #[test]
    fn config_tokens_rejected() {
        let text = format!(
            "{}\n[[api.tokens]]\nname = \"x\"\ntoken = \"0123456789abcdef\"\nscopes = [\"read\"]\n",
            include_str!("../../../config.example.toml")
        );
        let err = Config::parse(&text).unwrap_err();
        assert!(format!("{err:#}").contains("apti-tui"), "{err:#}");
    }

    #[test]
    fn k_off() {
        let text = r#"
[instance]
base_url = "https://ti.example.net/"
organization = "X"
[storage]
database = "/tmp/x.db"
key_file = "/tmp/x.pem"
[public]
bind = "127.0.0.1:1"
[api]
bind = "127.0.0.1:2"
[control]
socket = "/tmp/x.sock"
[policy]
default_k = "off"
[policy.behavior.scan]
k = 1
"#;
        let cfg = Config::parse(text).unwrap();
        assert_eq!(cfg.policy.default_k.threshold().unwrap(), Threshold::Off);
        assert_eq!(cfg.instance.base_url.as_str(), "https://ti.example.net/");
        assert_eq!(cfg.authority(), "ti.example.net");
    }

    #[test]
    fn spec_bounds_enforced() {
        let base = include_str!("../../../config.example.toml");
        for (from, to) in [
            ("tombstone_days = 180", "tombstone_days = 179"),
            (
                "recompute_interval_secs = 300",
                "recompute_interval_secs = 3601",
            ),
            (
                "reject_special_purpose = true",
                "reject_special_purpose = false",
            ),
            (
                "full_resync_interval_secs = 604800",
                "full_resync_interval_secs = 604801",
            ),
        ] {
            assert!(base.contains(from), "{from}");
            let err = Config::parse(&base.replace(from, to)).unwrap_err();
            assert!(format!("{err:#}").contains("must be"), "{err:#}");
        }
    }
}
