//! TOML configuration of apti-fail2ban.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use apti_core::{Behavior, ObservableType};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub aptid: Aptid,
    pub push: Option<Push>,
    pub pull: Option<Pull>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Aptid {
    /// Base URL of the aptid internal REST API.
    pub url: String,
    /// Token with scope `push` (required for `push`).
    pub push_token: Option<String>,
    /// Token with scope `read` (required for `pull`).
    pub read_token: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JailMap {
    pub behavior: String,
    pub port: Option<u16>,
    pub service: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Push {
    /// fail2ban log file (`logtarget` in fail2ban.conf).
    pub log: PathBuf,
    /// Read position (inode + offset), saved after each accepted batch.
    pub state_file: PathBuf,
    #[serde(default = "default_batch")]
    pub batch_interval_secs: u64,
    #[serde(default = "default_poll_ms")]
    pub poll_interval_ms: u64,
    /// Jails that are never reported, in particular the jails fed by `pull`
    /// (otherwise imported bans would be re-published as own Sightings).
    #[serde(default)]
    pub ignore_jails: Vec<String>,
    /// Report "Restore Ban" lines written when fail2ban restarts.
    #[serde(default)]
    pub report_restored: bool,
    /// Behaviour for jails not listed in `jails`; unset = skip them.
    pub default_behavior: Option<String>,
    #[serde(default = "default_max_queue")]
    pub max_queue: usize,
    /// Jail name → behaviour, port, service.
    #[serde(default)]
    pub jails: BTreeMap<String, JailMap>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Output {
    /// File followed by a fail2ban jail using the `apti` filter.
    pub path: PathBuf,
    /// Behaviours to include; empty = all.
    #[serde(default)]
    pub behaviors: Vec<String>,
    /// Observable types to include (IP types only).
    #[serde(default = "default_types")]
    pub types: Vec<ObservableType>,
    /// Only entries whose supporting evidence reported this port.
    pub port: Option<u16>,
    #[serde(default = "default_max_size")]
    pub max_size_bytes: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pull {
    #[serde(default = "default_pull_interval")]
    pub interval_secs: u64,
    /// Re-write still-active IPs after this long. Must be shorter than the
    /// jail's `bantime` (minus `interval_secs`).
    #[serde(default = "default_refresh")]
    pub refresh_secs: u64,
    #[serde(rename = "output")]
    pub outputs: Vec<Output>,
}

fn default_timeout() -> u64 {
    20
}
fn default_batch() -> u64 {
    30
}
fn default_poll_ms() -> u64 {
    1000
}
fn default_max_queue() -> usize {
    10_000
}
fn default_types() -> Vec<ObservableType> {
    vec![ObservableType::Ipv4Addr, ObservableType::Ipv6Addr]
}
fn default_max_size() -> u64 {
    10 * 1024 * 1024
}
fn default_pull_interval() -> u64 {
    300
}
fn default_refresh() -> u64 {
    1800
}

pub fn parse_behaviors(list: &[String]) -> anyhow::Result<Vec<Behavior>> {
    list.iter()
        .map(|b| b.parse::<Behavior>().map_err(anyhow::Error::msg))
        .collect()
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
        if let Some(p) = &self.push {
            if self.aptid.push_token.is_none() {
                bail!("[push] requires aptid.push_token");
            }
            for (jail, m) in &p.jails {
                m.behavior
                    .parse::<Behavior>()
                    .map_err(|e| anyhow::anyhow!("push.jails.{jail}: {e}"))?;
                if p.ignore_jails.contains(jail) {
                    bail!("jail `{jail}` is both mapped and ignored");
                }
            }
            if let Some(b) = &p.default_behavior {
                b.parse::<Behavior>()
                    .map_err(|e| anyhow::anyhow!("push.default_behavior: {e}"))?;
            }
            if p.batch_interval_secs == 0 || p.max_queue == 0 {
                bail!("push.batch_interval_secs and push.max_queue must be > 0");
            }
        }
        if let Some(p) = &self.pull {
            if self.aptid.read_token.is_none() {
                bail!("[pull] requires aptid.read_token");
            }
            if p.outputs.is_empty() {
                bail!("[pull] needs at least one [[pull.output]]");
            }
            if p.interval_secs == 0 || p.refresh_secs < p.interval_secs {
                bail!("pull.refresh_secs must be >= pull.interval_secs > 0");
            }
            for o in &p.outputs {
                parse_behaviors(&o.behaviors)
                    .with_context(|| format!("output {}", o.path.display()))?;
                if o.types.is_empty() || o.types.iter().any(|t| !t.is_ip()) {
                    bail!(
                        "output {}: types must be ipv4-addr and/or ipv6-addr",
                        o.path.display()
                    );
                }
            }
        }
        if self.push.is_none() && self.pull.is_none() {
            bail!("configure [push] and/or [pull]");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_parses() {
        let cfg = Config::parse(include_str!("../apti-fail2ban.example.toml")).unwrap();
        let push = cfg.push.unwrap();
        assert_eq!(push.jails["sshd"].behavior, "ssh-bruteforce");
        assert!(push.ignore_jails.contains(&"aptid-ssh".to_string()));
        assert_eq!(cfg.pull.unwrap().outputs.len(), 1);
    }

    #[test]
    fn rejects_bad_config() {
        let base = "[aptid]\nurl = \"http://127.0.0.1:8081\"\nread_token = \"x\"\n";
        assert!(Config::parse(base).is_err(), "neither push nor pull");
        let bad = format!(
            "{base}[pull]\ninterval_secs = 600\nrefresh_secs = 60\n[[pull.output]]\npath = \"/tmp/x\"\n"
        );
        assert!(Config::parse(&bad).is_err(), "refresh < interval");
        let bad = format!("{base}[[pull.output]]\npath = \"/tmp/x\"\ntypes = [\"domain-name\"]\n");
        assert!(Config::parse(&bad).is_err());
        let bad = format!("{base}[push]\nlog = \"/x\"\nstate_file = \"/y\"\n");
        assert!(Config::parse(&bad).is_err(), "push without push_token");
    }
}
