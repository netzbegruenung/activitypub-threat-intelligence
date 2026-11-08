//! TOML configuration of pubsec-statsd.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use serde::Deserialize;

/// pubsec-statsd sits in front of a hub and republishes its TLP:CLEAR dataset
/// to the public: an aggregate statistics page and machine-readable data
/// endpoints. Only aggregate numbers are rendered into the page; the data
/// endpoints serve the same TLP:CLEAR entries the hub's active list and
/// timeline expose.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub pubsecd: Pubsecd,
    #[serde(default)]
    pub poll: Poll,
    #[serde(default)]
    pub server: Server,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pubsecd {
    /// Base URL of the hub's internal REST API.
    pub url: String,
    /// Token with scope `read` and `max_tlp = "clear"`, so only TLP:CLEAR
    /// entries are ever fetched.
    pub read_token: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Poll {
    /// How often the hub is polled.
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    /// Length of the findings window shown on the page.
    #[serde(default = "default_window_days")]
    pub window_days: u32,
}

impl Default for Poll {
    fn default() -> Self {
        Self {
            interval_secs: default_interval(),
            window_days: default_window_days(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    /// Public bind address. Unset by default: without it pubsec-statsd exposes
    /// no socket of its own and renders into `output_dir` instead. Set it
    /// only to serve directly, behind a TLS-terminating reverse proxy.
    #[serde(default)]
    pub bind: Option<String>,
    /// Directory the page and node directory are rendered into for a web
    /// server to serve. Used when `bind` is unset.
    #[serde(default = "default_output_dir")]
    pub output_dir: PathBuf,
    #[serde(default = "default_title")]
    pub title: String,
    /// Per-client request rate limit.
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_min: u32,
    /// Take the client address for rate limiting from the last
    /// `X-Forwarded-For` entry. Enable only when every request comes through
    /// a reverse proxy that sets or appends that header; otherwise clients
    /// can choose their own address.
    #[serde(default)]
    pub trust_forwarded_for: bool,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            bind: None,
            output_dir: default_output_dir(),
            title: default_title(),
            rate_limit_per_min: default_rate_limit(),
            trust_forwarded_for: false,
        }
    }
}

fn default_timeout() -> u64 {
    30
}
fn default_interval() -> u64 {
    60
}
fn default_window_days() -> u32 {
    30
}
fn default_title() -> String {
    "AP-TI public statistics".into()
}
fn default_rate_limit() -> u32 {
    120
}
fn default_output_dir() -> PathBuf {
    PathBuf::from("/var/lib/pubsec-statsd/public")
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
        if !self.pubsecd.url.starts_with("http://") && !self.pubsecd.url.starts_with("https://") {
            bail!("pubsecd.url must be an http(s) URL");
        }
        if self.pubsecd.read_token.trim().is_empty() {
            bail!("pubsecd.read_token must not be empty");
        }
        if self.poll.interval_secs < 5 {
            bail!("poll.interval_secs must be at least 5");
        }
        if self.poll.window_days == 0 {
            bail!("poll.window_days must be at least 1");
        }
        match &self.server.bind {
            Some(b) if b.is_empty() => bail!("server.bind must not be empty"),
            Some(_) => {}
            None if self.server.output_dir.as_os_str().is_empty() => {
                bail!("server.output_dir must not be empty")
            }
            None => {}
        }
        if self.server.rate_limit_per_min == 0 {
            bail!("server.rate_limit_per_min must be at least 1");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
[pubsecd]
url = "http://127.0.0.1:8081"
read_token = "pubsec_x"
[server]
bind = "0.0.0.0:8082"
"#;

    #[test]
    fn example_config_parses() {
        Config::parse(include_str!("../pubsec-statsd.example.toml")).unwrap();
    }

    #[test]
    fn defaults() {
        let c = Config::parse(MINIMAL).unwrap();
        assert_eq!(c.pubsecd.timeout_secs, 30);
        assert_eq!(c.poll.interval_secs, 60);
        assert_eq!(c.poll.window_days, 30);
        assert_eq!(c.server.rate_limit_per_min, 120);
        assert_eq!(c.server.title, "AP-TI public statistics");
        assert!(!c.server.trust_forwarded_for);
    }

    #[test]
    fn static_output_is_the_default() {
        let c = Config::parse(MINIMAL.split("[server]").next().unwrap()).unwrap();
        assert!(c.server.bind.is_none());
        assert_eq!(c.server.output_dir, default_output_dir());
    }

    #[test]
    fn invalid() {
        let with = |extra: &str| Config::parse(&format!("{MINIMAL}{extra}"));
        assert!(with("unknown = 1").is_err());
        assert!(with("[poll]\ninterval_secs = 1").is_err());
        assert!(with("[poll]\nwindow_days = 0").is_err());
        assert!(with("[server]\nrate_limit_per_min = 0").is_err());
        assert!(Config::parse(&MINIMAL.replace("http://", "ftp://")).is_err());
        assert!(Config::parse(&MINIMAL.replace("pubsec_x", "  ")).is_err());
    }
}
