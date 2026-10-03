//! aptid active list → ban files followed by fail2ban.
//!
//! fail2ban bans for a fixed per-jail `bantime`. To approximate each entry's
//! effective expiry, a line is written when an IP becomes active and again
//! every `refresh_secs` while it stays active. Once it expires or is
//! suspended no more lines are written and fail2ban unbans it after
//! `bantime`.

use std::collections::{BTreeSet, HashMap};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;

use apti_core::Behavior;
use chrono::{DateTime, Local, SecondsFormat, TimeDelta, Utc};

use crate::client::{ActiveEntry, AptidClient};
use crate::config::{parse_behaviors, Output, Pull};

/// Whether a line must be written for an IP last written at `last`.
pub fn should_emit(last: Option<DateTime<Utc>>, now: DateTime<Utc>, refresh: TimeDelta) -> bool {
    last.is_none_or(|t| now - t >= refresh)
}

/// One ban line. The leading timestamp is local time in fail2ban's default
/// format so that fail2ban needs no time zone configuration.
pub fn format_line(
    now: DateTime<Utc>,
    ip: &str,
    behaviors: &[Behavior],
    expires: DateTime<Utc>,
) -> String {
    let b: Vec<&str> = behaviors.iter().map(|b| b.as_str()).collect();
    format!(
        "{} apti-ban {ip} behavior={} expires={}\n",
        now.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S"),
        b.join(","),
        expires.to_rfc3339_opts(SecondsFormat::Secs, true)
    )
}

struct OutputState {
    cfg: Output,
    behaviors: Vec<Behavior>,
    last: HashMap<String, DateTime<Utc>>,
}

impl OutputState {
    fn matches(&self, e: &ActiveEntry) -> bool {
        self.cfg.types.contains(&e.observable_type)
            && (self.behaviors.is_empty() || self.behaviors.contains(&e.behavior))
            && self.cfg.port.is_none_or(|p| e.ports.contains(&p))
    }
}

pub struct Puller {
    cfg: Pull,
    client: AptidClient,
    outputs: Vec<OutputState>,
}

fn rotate_if_needed(path: &Path, max: u64) -> std::io::Result<()> {
    if std::fs::metadata(path).is_ok_and(|m| m.len() > max) {
        let mut rotated = path.as_os_str().to_owned();
        rotated.push(".1");
        std::fs::rename(path, rotated)?;
    }
    Ok(())
}

fn append(path: &Path, data: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)?;
        }
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o640)
        .open(path)?;
    f.write_all(data.as_bytes())
}

impl Puller {
    pub fn new(cfg: Pull, client: AptidClient) -> anyhow::Result<Self> {
        let outputs = cfg
            .outputs
            .iter()
            .map(|o| {
                Ok(OutputState {
                    behaviors: parse_behaviors(&o.behaviors)?,
                    cfg: o.clone(),
                    last: HashMap::new(),
                })
            })
            .collect::<anyhow::Result<_>>()?;
        Ok(Self {
            cfg,
            client,
            outputs,
        })
    }

    /// Fetch the active list once and update all outputs.
    /// Returns the number of lines written.
    pub async fn step(&mut self) -> anyhow::Result<usize> {
        let entries = self.client.active().await?;
        let now = Utc::now();
        let refresh = TimeDelta::seconds(self.cfg.refresh_secs as i64);
        let mut written = 0;
        for out in &mut self.outputs {
            // IP -> (behaviours, latest expiry)
            let mut current: HashMap<&str, (BTreeSet<Behavior>, DateTime<Utc>)> = HashMap::new();
            for e in entries
                .iter()
                .filter(|e| out.matches(e) && e.effective_expiry > now)
            {
                let slot = current
                    .entry(e.observable_value.as_str())
                    .or_insert_with(|| (BTreeSet::new(), e.effective_expiry));
                slot.0.insert(e.behavior);
                slot.1 = slot.1.max(e.effective_expiry);
            }
            // Forget IPs that are no longer active so a re-activation is
            // written immediately.
            out.last.retain(|ip, _| current.contains_key(ip.as_str()));
            let mut buf = String::new();
            let mut emitted = Vec::new();
            let mut ips: Vec<_> = current.into_iter().collect();
            ips.sort_by(|a, b| a.0.cmp(b.0));
            for (ip, (behaviors, expires)) in ips {
                if should_emit(out.last.get(ip).copied(), now, refresh) {
                    let b: Vec<Behavior> = behaviors.into_iter().collect();
                    buf.push_str(&format_line(now, ip, &b, expires));
                    emitted.push(ip.to_string());
                }
            }
            if buf.is_empty() {
                continue;
            }
            rotate_if_needed(&out.cfg.path, out.cfg.max_size_bytes)?;
            append(&out.cfg.path, &buf)?;
            written += emitted.len();
            tracing::info!(file = %out.cfg.path.display(), lines = emitted.len(), "wrote bans");
            for ip in emitted {
                out.last.insert(ip, now);
            }
        }
        Ok(written)
    }

    pub async fn run(mut self) -> anyhow::Result<()> {
        let every = Duration::from_secs(self.cfg.interval_secs);
        loop {
            // On failure nothing is written; existing fail2ban bans run out
            // after `bantime`, so an outage never causes permanent bans.
            if let Err(e) = self.step().await {
                tracing::warn!("pull failed: {e:#}");
            }
            tokio::time::sleep(every).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    #[test]
    fn emit_decision() {
        let now = Utc::now();
        let refresh = TimeDelta::minutes(30);
        assert!(should_emit(None, now, refresh));
        assert!(!should_emit(
            Some(now - TimeDelta::minutes(10)),
            now,
            refresh
        ));
        assert!(should_emit(
            Some(now - TimeDelta::minutes(30)),
            now,
            refresh
        ));
    }

    /// The line must match the shipped filter: `datepattern` at line start,
    /// then the failregex (with `<SUBNET>` approximated).
    #[test]
    fn line_matches_filter() {
        let now: DateTime<Utc> = "2026-10-03T12:00:00Z".parse().unwrap();
        let exp: DateTime<Utc> = "2026-10-04T12:00:00Z".parse().unwrap();
        let line = format_line(
            now,
            "2a01:4f8:1::/48",
            &[Behavior::Scan, Behavior::SshBruteforce],
            exp,
        );
        assert!(line.ends_with(
            " apti-ban 2a01:4f8:1::/48 behavior=scan,ssh-bruteforce expires=2026-10-04T12:00:00Z\n"
        ));
        let re = Regex::new(
            r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\s*apti-ban (?P<host>[0-9a-fA-F:.]+(?:/\d+)?) behavior=\S+ expires=\S+\s*$",
        )
        .unwrap();
        let c = re.captures(line.trim_end()).unwrap();
        assert_eq!(&c["host"], "2a01:4f8:1::/48");
    }
}
