//! TOML configuration of apti-allowlist.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
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
    /// `summary` of the entries this tool creates; only such entries are
    /// removed in source-of-truth mode. Defaults to `apti-allowlist:<path>`.
    pub summary: Option<String>,
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
        if self
            .file
            .summary
            .as_deref()
            .is_some_and(|s| s.trim().is_empty())
        {
            bail!("file.summary must not be empty");
        }
        if self.sync.poll_interval_secs == 0
            || self.sync.resync_interval_secs < self.sync.poll_interval_secs
        {
            bail!("sync.resync_interval_secs must be >= sync.poll_interval_secs > 0");
        }
        Ok(())
    }

    /// Summary that marks entries managed by this tool.
    pub fn marker(&self) -> String {
        self.file
            .summary
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
        assert_eq!(cfg.marker(), "apti-allowlist:/etc/aptid/allowlist.txt");
        assert_eq!(cfg.sync.poll_interval_secs, 5);
        assert!(!cfg.sync.prune_all);
    }

    #[test]
    fn defaults_and_marker() {
        let cfg = Config::parse(
            "[aptid]\nurl = \"http://x\"\ntoken = \"t\"\n[file]\npath = \"/a\"\nsummary = \"mine\"\n",
        )
        .unwrap();
        assert_eq!(cfg.marker(), "mine");
        assert_eq!(cfg.sync.resync_interval_secs, 300);
        assert_eq!(cfg.sync.max_removals, 100);
        assert_eq!(cfg.token().unwrap(), "t");
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
