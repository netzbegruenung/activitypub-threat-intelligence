//! TOML configuration of apti-dashboard.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use apti_core::Behavior;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub aptid: Aptid,
    pub geoip: GeoIp,
    #[serde(default)]
    pub dns: Dns,
    pub dashboard: Dashboard,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Aptid {
    /// Base URL of the aptid internal REST API.
    pub url: String,
    /// Token with scope `read`. Its `max_tlp` limits what the page shows.
    pub read_token: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoIp {
    /// MaxMind DB file with a `country` record, e.g. DB-IP Country Lite or
    /// GeoLite2-Country. Read anew on every run.
    pub country_db: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dns {
    /// Resolve domain findings to IP addresses to place them on the map.
    /// Sends DNS queries for potentially malicious domains.
    #[serde(default)]
    pub resolve_domains: bool,
    #[serde(default = "default_dns_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_dns_concurrency")]
    pub concurrency: usize,
}

impl Default for Dns {
    fn default() -> Self {
        Self {
            resolve_domains: false,
            timeout_secs: default_dns_timeout(),
            concurrency: default_dns_concurrency(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dashboard {
    /// HTML file to write; replaced atomically.
    pub output: PathBuf,
    #[serde(default = "default_title")]
    pub title: String,
    /// Time covered by the slider.
    #[serde(default = "default_range_days")]
    pub range_days: u32,
    /// A finding counts in a frame if it was seen within this window.
    #[serde(default = "default_window_days")]
    pub window_days: u32,
    /// Distance between two slider positions.
    #[serde(default = "default_step_hours")]
    pub step_hours: u32,
    /// Behaviours to include; empty = all.
    #[serde(default)]
    pub behaviors: Vec<String>,
    /// Embed the observables, behaviours and actors behind each country's
    /// count, shown in a table when a country is selected. Off = the page
    /// holds per-country counts only.
    #[serde(default = "default_true")]
    pub show_observables: bool,
}

fn default_true() -> bool {
    true
}
fn default_timeout() -> u64 {
    30
}
fn default_dns_timeout() -> u64 {
    5
}
fn default_dns_concurrency() -> usize {
    16
}
fn default_title() -> String {
    "AP-TI threat map".into()
}
fn default_range_days() -> u32 {
    30
}
fn default_window_days() -> u32 {
    7
}
fn default_step_hours() -> u32 {
    24
}

/// Upper bound on slider positions, to keep the page small.
pub const MAX_FRAMES: u32 = 2000;

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
        if self.aptid.read_token.trim().is_empty() {
            bail!("aptid.read_token must not be empty");
        }
        if self.dns.concurrency == 0 {
            bail!("dns.concurrency must be at least 1");
        }
        let d = &self.dashboard;
        if d.range_days == 0 || d.window_days == 0 || d.step_hours == 0 {
            bail!("dashboard.range_days, window_days and step_hours must be at least 1");
        }
        if d.range_days * 24 / d.step_hours > MAX_FRAMES {
            bail!("dashboard: range_days / step_hours gives more than {MAX_FRAMES} frames");
        }
        self.behaviors()?;
        Ok(())
    }

    pub fn behaviors(&self) -> anyhow::Result<Vec<Behavior>> {
        self.dashboard
            .behaviors
            .iter()
            .map(|b| {
                b.parse::<Behavior>()
                    .map_err(|e| anyhow::anyhow!("dashboard.behaviors: {e}"))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
[aptid]
url = "http://127.0.0.1:8081"
read_token = "apti_x"
[geoip]
country_db = "/tmp/country.mmdb"
[dashboard]
output = "/tmp/index.html"
"#;

    #[test]
    fn example_config_parses() {
        Config::parse(include_str!("../apti-dashboard.example.toml")).unwrap();
    }

    #[test]
    fn defaults() {
        let c = Config::parse(MINIMAL).unwrap();
        assert_eq!(c.dashboard.range_days, 30);
        assert_eq!(c.dashboard.window_days, 7);
        assert_eq!(c.dashboard.step_hours, 24);
        assert!(!c.dns.resolve_domains);
        assert!(c.dashboard.show_observables);
        assert!(c.behaviors().unwrap().is_empty());
    }

    #[test]
    fn invalid() {
        let with = |extra: &str| Config::parse(&format!("{MINIMAL}{extra}"));
        assert!(with("step_hours = 0").is_err());
        assert!(with("behaviors = [\"bogus\"]").is_err());
        assert!(with("range_days = 3650\nstep_hours = 1").is_err());
        assert!(with("unknown = 1").is_err());
        assert!(with("behaviors = [\"scan\"]").is_ok());
        assert!(Config::parse(&MINIMAL.replace("http://", "ftp://")).is_err());
    }
}
