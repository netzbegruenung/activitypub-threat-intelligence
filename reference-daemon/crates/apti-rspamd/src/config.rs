//! TOML configuration of apti-rspamd.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use anyhow::{bail, Context};
use apti_core::normalize::{self, NormPolicy};
use apti_core::{Behavior, ObservableType, Tlp};
use ipnet::IpNet;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub aptid: Aptid,
    #[serde(default)]
    pub server: Server,
    pub ingest: Option<Ingest>,
    pub maps: Option<Maps>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Aptid {
    /// Base URL of the aptid internal REST API.
    pub url: String,
    /// Token with scope `push` (required for `[ingest]`).
    pub push_token: Option<String>,
    /// Token with scope `read` (required for `[maps]`).
    pub read_token: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    /// Address of the HTTP endpoint used by the Lua plugin and by multimap.
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            bind: default_bind(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ingest {
    /// Shared secret the Lua plugin sends as bearer token.
    pub report_secret: String,
    /// A message counts as bad if its score, minus the score of
    /// `ignore_symbols`, is at least this.
    #[serde(default = "default_min_score")]
    pub min_score: f64,
    /// Bad messages from one IP within `window_secs` before it is reported.
    #[serde(default = "default_min_messages")]
    pub min_messages: usize,
    #[serde(default = "default_window")]
    pub window_secs: u64,
    /// Minimum time between two reports of the same IP.
    #[serde(default = "default_report_interval")]
    pub report_interval_secs: u64,
    /// IPv6 senders are tracked and reported as this prefix (48..=128).
    #[serde(default = "default_ipv6_prefix")]
    pub ipv6_prefix: u8,
    #[serde(default = "default_behavior")]
    pub behavior: String,
    pub service: Option<String>,
    pub port: Option<u16>,
    /// TLP of the reported IPs; unset = the behaviour's publish TLP in aptid.
    pub tlp: Option<Tlp>,
    /// Symbols whose score is not counted, in particular the multimap
    /// symbols fed by `[maps]` (otherwise peer data would be re-published as
    /// own Sightings). A trailing `*` matches a prefix.
    #[serde(default = "default_ignore_symbols")]
    pub ignore_symbols: Vec<String>,
    /// Senders that are never reported, e.g. own relays and backup MX.
    #[serde(default, deserialize_with = "networks")]
    pub ignore_networks: Vec<IpNet>,
    /// Skip messages from authenticated users.
    #[serde(default = "default_true")]
    pub ignore_authenticated: bool,
    /// Upper bound of IPs and domains tracked at once.
    #[serde(default = "default_max_tracked")]
    pub max_tracked: usize,
    #[serde(default = "default_batch")]
    pub batch_interval_secs: u64,
    #[serde(default = "default_max_queue")]
    pub max_queue: usize,
    /// Also report the envelope-from domains of bad messages.
    pub envelope_from: Option<EnvelopeFrom>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeFrom {
    #[serde(default = "default_behavior")]
    pub behavior: String,
    /// TLP of the reported domains; unset = the behaviour's publish TLP.
    pub tlp: Option<Tlp>,
    /// Bad messages with this envelope-from domain within `window_secs`
    /// before it is reported ...
    #[serde(default = "default_min_messages")]
    pub min_messages: usize,
    /// ... sent by at least this many distinct senders (IP or IPv6 prefix).
    #[serde(default = "default_min_senders")]
    pub min_senders: usize,
    #[serde(default = "default_domain_window")]
    pub window_secs: u64,
    #[serde(default = "default_domain_window")]
    pub report_interval_secs: u64,
    /// All of these symbols must have fired, by default an SPF pass: the
    /// envelope-from domain is forged easily otherwise.
    #[serde(default = "default_require_symbols")]
    pub require_symbols: Vec<String>,
    /// Skip the message if any of these symbols fired.
    #[serde(default = "default_skip_symbols")]
    pub skip_symbols: Vec<String>,
    /// Domains (and their subdomains) that are never reported, e.g. own
    /// domains and the bounce domains of mail service providers.
    #[serde(default, deserialize_with = "domains")]
    pub ignore_domains: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MapKind {
    /// IP addresses and prefixes (Rspamd radix map).
    Ip,
    /// Domains as regular expressions that also match subdomains where the
    /// entry covers them.
    Domain,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MapDef {
    /// Served at `/maps/<name>`.
    pub name: String,
    pub kind: MapKind,
    /// Behaviours to include; empty = all.
    #[serde(default)]
    pub behaviors: Vec<String>,
    /// Include entries flagged for review (trusted disagreement).
    #[serde(default)]
    pub include_flagged: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Maps {
    #[serde(default = "default_maps_interval")]
    pub interval_secs: u64,
    #[serde(rename = "map")]
    pub maps: Vec<MapDef>,
}

/// Domains in normal form (lowercase A-labels).
fn domains<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    Vec::<String>::deserialize(d)?
        .iter()
        .map(|s| {
            normalize::normalise(s, Some(ObservableType::DomainName), &NormPolicy::lenient())
                .map(|(_, v)| v)
                .map_err(|e| serde::de::Error::custom(format!("invalid domain `{s}`: {e}")))
        })
        .collect()
}

/// IP addresses or prefixes.
fn networks<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<IpNet>, D::Error> {
    Vec::<String>::deserialize(d)?
        .iter()
        .map(|s| {
            s.parse::<IpNet>()
                .or_else(|_| s.parse::<IpAddr>().map(IpNet::from))
                .map_err(|_| serde::de::Error::custom(format!("invalid network `{s}`")))
        })
        .collect()
}

fn default_timeout() -> u64 {
    20
}
fn default_bind() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 11380))
}
fn default_min_score() -> f64 {
    10.0
}
fn default_min_messages() -> usize {
    3
}
fn default_window() -> u64 {
    3600
}
fn default_report_interval() -> u64 {
    3600
}
fn default_ipv6_prefix() -> u8 {
    64
}
fn default_behavior() -> String {
    "smtp-spam".into()
}
fn default_ignore_symbols() -> Vec<String> {
    vec!["APTI_*".into()]
}
fn default_min_senders() -> usize {
    1
}
fn default_domain_window() -> u64 {
    86400
}
fn default_require_symbols() -> Vec<String> {
    vec!["R_SPF_ALLOW".into()]
}
fn default_skip_symbols() -> Vec<String> {
    vec!["FREEMAIL_ENVFROM".into(), "DISPOSABLE_ENVFROM".into()]
}
fn default_true() -> bool {
    true
}
fn default_max_tracked() -> usize {
    100_000
}
fn default_batch() -> u64 {
    30
}
fn default_max_queue() -> usize {
    10_000
}
fn default_maps_interval() -> u64 {
    60
}

pub fn parse_behaviors(list: &[String]) -> anyhow::Result<Vec<Behavior>> {
    list.iter()
        .map(|b| b.parse::<Behavior>().map_err(anyhow::Error::msg))
        .collect()
}

/// Same rule as aptid applies to the `service` of an observation.
fn valid_service(s: &str) -> bool {
    !s.is_empty() && s.len() <= 63 && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let cfg: Config = toml::from_str(text).context("parsing config")?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if !self.aptid.url.starts_with("http://") && !self.aptid.url.starts_with("https://") {
            bail!("aptid.url must be an http(s) URL");
        }
        if let Some(i) = &self.ingest {
            if self.aptid.push_token.is_none() {
                bail!("[ingest] requires aptid.push_token");
            }
            if i.report_secret.len() < 16 {
                bail!("ingest.report_secret must be at least 16 characters");
            }
            i.behavior
                .parse::<Behavior>()
                .map_err(|e| anyhow::anyhow!("ingest.behavior: {e}"))?;
            if i.service.as_deref().is_some_and(|s| !valid_service(s)) {
                bail!("ingest.service must be 1-63 letters, digits or `-`");
            }
            if !i.min_score.is_finite() {
                bail!("ingest.min_score must be a number");
            }
            if !(48..=128).contains(&i.ipv6_prefix) {
                bail!("ingest.ipv6_prefix must be between 48 and 128");
            }
            if i.tlp == Some(Tlp::Red) {
                bail!("ingest.tlp must not be red");
            }
            if let Some(e) = &i.envelope_from {
                e.behavior
                    .parse::<Behavior>()
                    .map_err(|err| anyhow::anyhow!("ingest.envelope_from.behavior: {err}"))?;
                if e.tlp == Some(Tlp::Red) {
                    bail!("ingest.envelope_from.tlp must not be red");
                }
                if e.min_messages == 0
                    || e.min_senders == 0
                    || e.window_secs == 0
                    || e.min_senders > e.min_messages
                {
                    bail!("ingest.envelope_from: min_messages >= min_senders > 0 and window_secs > 0 required");
                }
            }
            if i.min_messages == 0
                || i.window_secs == 0
                || i.batch_interval_secs == 0
                || i.max_queue == 0
                || i.max_tracked == 0
            {
                bail!("ingest.min_messages, window_secs, batch_interval_secs, max_queue and max_tracked must be > 0");
            }
        }
        if let Some(m) = &self.maps {
            if self.aptid.read_token.is_none() {
                bail!("[maps] requires aptid.read_token");
            }
            if m.maps.is_empty() {
                bail!("[maps] needs at least one [[maps.map]]");
            }
            if m.interval_secs == 0 {
                bail!("maps.interval_secs must be > 0");
            }
            let mut names = BTreeSet::new();
            for d in &m.maps {
                if d.name.is_empty()
                    || !d
                        .name
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
                {
                    bail!(
                        "map name `{}` must consist of letters, digits, `-`, `_` or `.`",
                        d.name
                    );
                }
                if !names.insert(&d.name) {
                    bail!("duplicate map name `{}`", d.name);
                }
                parse_behaviors(&d.behaviors).with_context(|| format!("map {}", d.name))?;
            }
        }
        if self.ingest.is_none() && self.maps.is_none() {
            bail!("configure [ingest] and/or [maps]");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_parses() {
        let cfg = Config::parse(include_str!("../apti-rspamd.example.toml")).unwrap();
        let ingest = cfg.ingest.unwrap();
        assert_eq!(ingest.behavior, "smtp-spam");
        assert!(ingest.ignore_symbols.contains(&"APTI_*".to_string()));
        assert_eq!(ingest.tlp, Some(Tlp::Green));
        let ef = ingest.envelope_from.unwrap();
        assert_eq!(ef.tlp, Some(Tlp::Clear));
        assert_eq!(ef.require_symbols, ["R_SPF_ALLOW"]);
        let maps = cfg.maps.unwrap();
        assert_eq!(maps.maps.len(), 3);
        assert_eq!(maps.maps[0].kind, MapKind::Ip);
    }

    #[test]
    fn rejects_bad_config() {
        let base =
            "[aptid]\nurl = \"http://127.0.0.1:8081\"\npush_token = \"p\"\nread_token = \"r\"\n";
        assert!(Config::parse(base).is_err(), "neither ingest nor maps");
        let ingest = "[ingest]\nreport_secret = \"0123456789abcdef\"\n";
        assert!(Config::parse(&format!("{base}{ingest}")).is_ok());
        assert!(
            Config::parse(&format!("{base}[ingest]\nreport_secret = \"short\"\n")).is_err(),
            "short secret"
        );
        assert!(
            Config::parse(&format!("{base}{ingest}ipv6_prefix = 32\n")).is_err(),
            "ipv6 prefix below /48"
        );
        assert!(
            Config::parse(&format!("{base}{ingest}behavior = \"spam\"\n")).is_err(),
            "unknown behaviour"
        );
        assert!(
            Config::parse(&format!("{base}{ingest}service = \"smtp submission\"\n")).is_err(),
            "invalid service"
        );
        assert!(
            Config::parse(&format!("{base}{ingest}tlp = \"red\"\n")).is_err(),
            "red TLP"
        );
        let ef = "[ingest.envelope_from]\n";
        let cfg = Config::parse(&format!(
            "{base}{ingest}tlp = \"clear\"\n{ef}tlp = \"amber\"\nignore_domains = [\"Own.ORG.\"]\n"
        ))
        .unwrap();
        let i = cfg.ingest.unwrap();
        let e = i.envelope_from.unwrap();
        assert_eq!((i.tlp, e.tlp), (Some(Tlp::Clear), Some(Tlp::Amber)));
        assert_eq!(e.ignore_domains, ["own.org"]);
        assert_eq!(e.require_symbols, ["R_SPF_ALLOW"]);
        for bad in [
            "tlp = \"red\"\n",
            "min_messages = 1\nmin_senders = 2\n",
            "behavior = \"spam\"\n",
            "ignore_domains = [\"not a domain\"]\n",
        ] {
            assert!(
                Config::parse(&format!("{base}{ingest}{ef}{bad}")).is_err(),
                "{bad}"
            );
        }
        let map = "[[maps.map]]\nname = \"ip\"\nkind = \"ip\"\n";
        assert!(Config::parse(&format!("{base}[maps]\n{map}")).is_ok());
        assert!(
            Config::parse(&format!("{base}[maps]\n{map}{map}")).is_err(),
            "duplicate name"
        );
        assert!(
            Config::parse(&format!(
                "{base}[maps]\n[[maps.map]]\nname = \"../x\"\nkind = \"ip\"\n"
            ))
            .is_err(),
            "bad name"
        );
        let no_read = "[aptid]\nurl = \"http://127.0.0.1:8081\"\n";
        assert!(Config::parse(&format!("{no_read}[maps]\n{map}")).is_err());
        assert!(Config::parse(&format!("{no_read}{ingest}")).is_err());
    }
}
