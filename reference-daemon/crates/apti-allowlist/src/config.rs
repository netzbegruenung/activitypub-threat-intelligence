//! TOML configuration of apti-allowlist.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use apti_core::protocol::AllowlistScope;
use apti_core::Tlp;
use chrono::TimeDelta;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub aptid: Aptid,
    pub file: File,
    #[serde(default)]
    pub sync: Sync,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Aptid {
    /// Base URL of the aptid internal REST API.
    pub url: String,
    /// Token with scope `allowlist`. Set this or `token_file`.
    pub token: Option<String>,
    /// File containing the token (surrounding whitespace is ignored).
    pub token_file: Option<PathBuf>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct File {
    /// One IP address, prefix or domain per line.
    pub path: PathBuf,
    /// Internal `source` of the entries this tool creates (never
    /// published); only such entries are removed in source-of-truth mode.
    /// Defaults to `apti-allowlist:<path>`.
    pub source: Option<String>,
    /// Rationale stored with the entries; published entries carry it as
    /// the Opinion's `summary`.
    pub summary: Option<String>,
    /// Scope of the entries: `local` or `published` (federated as
    /// `strongly-disagree` Opinions; the token needs the `publish` scope).
    #[serde(default = "default_scope")]
    pub scope: AllowlistScope,
    /// TLP of published entries (required for `published`).
    pub tlp: Option<Tlp>,
    /// Validity of published entries.
    pub valid_for_days: Option<u32>,
    /// Published entries are renewed when they expire within this many days.
    /// Defaults to a tenth of `valid_for_days`.
    pub renew_before_days: Option<u32>,
}

impl File {
    pub fn published(&self) -> bool {
        self.scope == AllowlistScope::Published
    }

    /// Validity of published entries.
    pub fn valid_for(&self) -> TimeDelta {
        TimeDelta::days(self.valid_for_days.unwrap_or(90).into())
    }

    /// Renewal window of published entries.
    pub fn renew_before(&self) -> TimeDelta {
        match self.renew_before_days {
            Some(d) => TimeDelta::days(d.into()),
            None => self.valid_for() / 10,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sync {
    /// How often the file is read.
    #[serde(default = "default_poll")]
    pub poll_interval_secs: u64,
    /// Full reconcile even if the file did not change (restores entries
    /// removed elsewhere).
    #[serde(default = "default_resync")]
    pub resync_interval_secs: u64,
    /// Source of truth: also remove local entries not created by this tool.
    #[serde(default)]
    pub prune_all: bool,
    /// Source of truth: skip all removals of a reconcile that would remove
    /// more entries than this (0 = no limit).
    #[serde(default = "default_max_removals")]
    pub max_removals: usize,
    /// Source of truth: allow a file without any value to remove entries.
    #[serde(default)]
    pub allow_empty: bool,
}

impl Default for Sync {
    fn default() -> Self {
        Self {
            poll_interval_secs: default_poll(),
            resync_interval_secs: default_resync(),
            prune_all: false,
            max_removals: default_max_removals(),
            allow_empty: false,
        }
    }
}

fn default_scope() -> AllowlistScope {
    AllowlistScope::Local
}
fn default_timeout() -> u64 {
    20
}
fn default_poll() -> u64 {
    5
}
fn default_resync() -> u64 {
    300
}
fn default_max_removals() -> usize {
    100
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
        if self.aptid.token.is_some() == self.aptid.token_file.is_some() {
            bail!("set exactly one of aptid.token and aptid.token_file");
        }
        if self.file.path.as_os_str().is_empty() {
            bail!("file.path must not be empty");
        }
        for (key, v) in [
            ("source", &self.file.source),
            ("summary", &self.file.summary),
        ] {
            if v.as_deref().is_some_and(|s| s.trim().is_empty()) {
                bail!("file.{key} must not be empty");
            }
        }
        let f = &self.file;
        if f.published() {
            match f.tlp {
                None => bail!("file.tlp is required for published entries"),
                Some(Tlp::Red) => bail!("file.tlp: TLP:RED cannot be published"),
                Some(_) => {}
            }
            if f.valid_for_days == Some(0) {
                bail!("file.valid_for_days must be > 0");
            }
            if f.renew_before() >= f.valid_for() {
                bail!("file.renew_before_days must be smaller than file.valid_for_days");
            }
        } else if f.tlp.is_some() || f.valid_for_days.is_some() || f.renew_before_days.is_some() {
            bail!("file.tlp, valid_for_days and renew_before_days apply to published entries only");
        }
        if self.sync.poll_interval_secs == 0
            || self.sync.resync_interval_secs < self.sync.poll_interval_secs
        {
            bail!("sync.resync_interval_secs must be >= sync.poll_interval_secs > 0");
        }
        Ok(())
    }

    /// Source that marks entries managed by this tool.
    pub fn source(&self) -> String {
        self.file
            .source
            .clone()
            .unwrap_or_else(|| format!("apti-allowlist:{}", self.file.path.display()))
    }

    /// The API token, read from `token_file` if configured.
    pub fn token(&self) -> anyhow::Result<String> {
        if let Some(t) = &self.aptid.token {
            return Ok(t.clone());
        }
        let path = self.aptid.token_file.as_ref().expect("validated");
        let token = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?
            .trim()
            .to_string();
        if token.is_empty() {
            bail!("{} is empty", path.display());
        }
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_parses() {
        let cfg = Config::parse(include_str!("../apti-allowlist.example.toml")).unwrap();
        assert_eq!(cfg.source(), "apti-allowlist:/etc/aptid/allowlist.txt");
        assert_eq!(cfg.sync.poll_interval_secs, 5);
        assert!(!cfg.sync.prune_all);
    }

    #[test]
    fn defaults_and_source() {
        let cfg = Config::parse(
            "[aptid]\nurl = \"http://x\"\ntoken = \"t\"\n[file]\npath = \"/a\"\nsource = \"mine\"\nsummary = \"office\"\n",
        )
        .unwrap();
        assert_eq!(cfg.source(), "mine");
        assert_eq!(cfg.file.summary.as_deref(), Some("office"));
        assert_eq!(cfg.sync.resync_interval_secs, 300);
        assert_eq!(cfg.sync.max_removals, 100);
        assert_eq!(cfg.token().unwrap(), "t");
    }

    #[test]
    fn published() {
        let base = "[aptid]\nurl = \"http://x\"\ntoken = \"t\"\n[file]\npath = \"/a\"\n";
        let cfg = Config::parse(&format!(
            "{base}scope = \"published\"\ntlp = \"amber+strict\"\n"
        ))
        .unwrap();
        assert!(cfg.file.published());
        assert_eq!(cfg.file.tlp, Some(Tlp::AmberStrict));
        assert_eq!(cfg.file.valid_for(), TimeDelta::days(90));
        assert_eq!(cfg.file.renew_before(), TimeDelta::days(9));
        let cfg = Config::parse(&format!(
            "{base}scope = \"published\"\ntlp = \"green\"\nvalid_for_days = 30\nrenew_before_days = 5\n"
        ))
        .unwrap();
        assert_eq!(cfg.file.renew_before(), TimeDelta::days(5));

        for bad in [
            "scope = \"published\"\n",
            "scope = \"published\"\ntlp = \"red\"\n",
            "scope = \"published\"\ntlp = \"green\"\nvalid_for_days = 0\n",
            "scope = \"published\"\ntlp = \"green\"\nvalid_for_days = 5\nrenew_before_days = 5\n",
            "tlp = \"green\"\n",
            "valid_for_days = 30\n",
            "scope = \"global\"\n",
        ] {
            assert!(Config::parse(&format!("{base}{bad}")).is_err(), "{bad}");
        }
    }

    #[test]
    fn token_file() {
        let dir = tempfile::tempdir().unwrap();
        let tf = dir.path().join("token");
        std::fs::write(&tf, "secret\n").unwrap();
        let cfg = Config::parse(&format!(
            "[aptid]\nurl = \"http://x\"\ntoken_file = \"{}\"\n[file]\npath = \"/a\"\n",
            tf.display()
        ))
        .unwrap();
        assert_eq!(cfg.token().unwrap(), "secret");
    }

    #[test]
    fn rejects_bad_config() {
        let file = "[file]\npath = \"/a\"\n";
        let bad = format!("[aptid]\nurl = \"x\"\ntoken = \"t\"\n{file}");
        assert!(Config::parse(&bad).is_err(), "url scheme");
        let bad = format!("[aptid]\nurl = \"http://x\"\n{file}");
        assert!(Config::parse(&bad).is_err(), "no token");
        let bad =
            format!("[aptid]\nurl = \"http://x\"\ntoken = \"t\"\ntoken_file = \"/t\"\n{file}");
        assert!(Config::parse(&bad).is_err(), "two tokens");
        let base = format!("[aptid]\nurl = \"http://x\"\ntoken = \"t\"\n{file}");
        let bad = format!("{base}[sync]\npoll_interval_secs = 0\n");
        assert!(Config::parse(&bad).is_err());
        let bad = format!("{base}[sync]\npoll_interval_secs = 60\nresync_interval_secs = 10\n");
        assert!(Config::parse(&bad).is_err());
        let bad = format!("{base}[sync]\nunknown = 1\n");
        assert!(Config::parse(&bad).is_err());
    }
}
