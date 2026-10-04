//! Watch loop: read the file, reconcile it with aptid's allowlist.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context};
use chrono::Utc;

use crate::client::{ApiError, AptidClient};
use crate::config::{self, Config};
use crate::reconcile::{self, Mode};

/// Outcome of one reconcile.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    /// Entries created.
    pub added: usize,
    /// Adds answered with an existing entry.
    pub existing: usize,
    pub removed: usize,
    /// Removals withheld by `max_removals` / `allow_empty`.
    pub removals_skipped: usize,
    /// Lines that are not valid values.
    pub invalid: usize,
    /// Adds or removals aptid rejected.
    pub failed: usize,
}

impl Report {
    fn changed(&self) -> bool {
        self.added + self.removed > 0
    }
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} added, {} removed, {} invalid line(s), {} rejected, {} removal(s) skipped",
            self.added, self.removed, self.invalid, self.failed, self.removals_skipped
        )
    }
}

pub struct Syncer {
    cfg: config::Sync,
    path: PathBuf,
    marker: String,
    mode: Mode,
    client: AptidClient,
    /// File content of the last successful reconcile.
    applied: Option<Vec<u8>>,
    /// Changed content seen once; applied when it is still the same at the
    /// next poll, so that half-written files are not reconciled.
    pending: Option<Vec<u8>>,
    last_sync: Option<Instant>,
    failures: u32,
    retry_at: Option<Instant>,
}

impl Syncer {
    pub fn new(cfg: &Config, mode: Mode, client: AptidClient) -> Self {
        Self {
            cfg: cfg.sync.clone(),
            path: cfg.file.path.clone(),
            marker: cfg.marker(),
            mode,
            client,
            applied: None,
            pending: None,
            last_sync: None,
            failures: 0,
            retry_at: None,
        }
    }

    async fn read(&self) -> anyhow::Result<Vec<u8>> {
        tokio::fs::read(&self.path)
            .await
            .with_context(|| format!("reading {}", self.path.display()))
    }

    /// Reconcile once with the current file content.
    pub async fn sync_once(&mut self) -> anyhow::Result<Report> {
        let content = self.read().await?;
        self.apply(content).await
    }

    async fn apply(&mut self, content: Vec<u8>) -> anyhow::Result<Report> {
        let fresh = self.applied.as_ref() != Some(&content);
        let parsed = reconcile::parse(&String::from_utf8_lossy(&content));
        if fresh {
            for i in &parsed.invalid {
                tracing::warn!(file = %self.path.display(), line = i.line, value = %i.text, "ignoring line: {}", i.error);
            }
        }
        let current = self
            .client
            .list()
            .await
            .map_err(|e| anyhow!("listing allowlist: {e}"))?;
        let mut plan = reconcile::plan(
            &parsed.values,
            &current,
            self.mode,
            &self.marker,
            self.cfg.prune_all,
            Utc::now(),
        );
        let mut report = Report {
            invalid: parsed.invalid.len(),
            ..Default::default()
        };
        if !plan.remove.is_empty() {
            let n = plan.remove.len();
            if parsed.values.is_empty() && !self.cfg.allow_empty {
                tracing::error!(file = %self.path.display(), "file has no values; not removing {n} entries (set sync.allow_empty to allow this)");
                report.removals_skipped = n;
                plan.remove.clear();
            } else if self.cfg.max_removals > 0 && n > self.cfg.max_removals {
                tracing::error!(file = %self.path.display(), "not removing {n} entries: more than sync.max_removals = {}", self.cfg.max_removals);
                report.removals_skipped = n;
                plan.remove.clear();
            }
        }
        // Add before removing so that nothing is briefly un-allowlisted.
        for v in &plan.add {
            match self.client.add(v, &self.marker).await {
                Ok(true) => {
                    tracing::info!(value = %v, "allowlisted");
                    report.added += 1;
                }
                Ok(false) => report.existing += 1,
                Err(ApiError::Rejected(e)) => {
                    tracing::warn!(value = %v, "aptid rejected: {e:#}");
                    report.failed += 1;
                }
                Err(e @ ApiError::Transient(_)) => return Err(anyhow!("adding {v}: {e}")),
            }
        }
        for e in &plan.remove {
            match self.client.remove(e.id).await {
                Ok(()) => {
                    tracing::info!(value = %e.observable_value, id = e.id, "removed from allowlist");
                    report.removed += 1;
                }
                Err(ApiError::Rejected(err)) => {
                    tracing::warn!(value = %e.observable_value, id = e.id, "aptid rejected removal: {err:#}");
                    report.failed += 1;
                }
                Err(err @ ApiError::Transient(_)) => {
                    return Err(anyhow!("removing {}: {err}", e.observable_value))
                }
            }
        }
        self.applied = Some(content);
        self.pending = None;
        self.last_sync = Some(Instant::now());
        Ok(report)
    }

    /// One step of the watch loop. Reconciles when the file content changed
    /// (and was the same at the previous poll) or the resync interval
    /// elapsed. Returns the report if a reconcile ran successfully.
    pub async fn poll(&mut self) -> Option<Report> {
        if self.retry_at.is_some_and(|t| Instant::now() < t) {
            return None;
        }
        let content = match self.read().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("{e:#}");
                return None;
            }
        };
        let resync = Duration::from_secs(self.cfg.resync_interval_secs);
        match &self.applied {
            Some(a) if *a == content => {
                if self.last_sync.is_some_and(|t| t.elapsed() < resync) {
                    return None;
                }
            }
            Some(_) => {
                if self.pending.as_ref() != Some(&content) {
                    tracing::debug!(file = %self.path.display(), "file changed, waiting for it to settle");
                    self.pending = Some(content);
                    return None;
                }
            }
            None => {}
        }
        match self.apply(content).await {
            Ok(r) => {
                self.failures = 0;
                self.retry_at = None;
                if r.changed() {
                    tracing::info!("reconciled: {r}");
                } else {
                    tracing::debug!("reconciled: {r}");
                }
                Some(r)
            }
            Err(e) => {
                self.failures += 1;
                let backoff = Duration::from_secs((5u64 << self.failures.min(6)).min(300));
                tracing::warn!(retry_in = ?backoff, "reconcile failed: {e:#}");
                self.retry_at = Some(Instant::now() + backoff);
                None
            }
        }
    }

    pub async fn run(mut self) -> anyhow::Result<()> {
        let poll = Duration::from_secs(self.cfg.poll_interval_secs);
        loop {
            self.poll().await;
            tokio::time::sleep(poll).await;
        }
    }
}
