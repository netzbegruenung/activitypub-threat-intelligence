//! Polls the hub and keeps the latest snapshot for serving.
//!
//! The hub's active list, timeline and connected nodes are fetched together
//! every `interval_secs`. The active list and timeline are reduced to
//! aggregate figures and not kept: individual observables are never served.
//! The node directory is pre-serialised (with an ETag). If the hub cannot be
//! reached the last snapshot keeps being served, so a hub outage never turns
//! the public endpoints into a 500.

use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use chrono::{DateTime, TimeDelta, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::sync::Notify;

use crate::client::AptidClient;
use crate::stats::Stats;

/// A pre-serialised response body and the ETag of its content.
#[derive(Debug, Clone)]
pub struct Blob {
    pub body: Vec<u8>,
    pub etag: String,
}

/// One successful fetch of the hub, ready to serve.
#[derive(Debug)]
pub struct Snapshot {
    /// Wall-clock time of the fetch; used for `Last-Modified` and staleness.
    pub fetched: SystemTime,
    /// Aggregate figures rendered on the public page.
    pub stats: Stats,
    /// The hub's connected nodes.
    pub nodes: Blob,
}

impl Snapshot {
    /// Whether the fetch is old enough that the hub is presumed unreachable.
    pub fn is_stale(&self, interval: Duration) -> bool {
        SystemTime::now()
            .duration_since(self.fetched)
            .unwrap_or_default()
            > interval.saturating_mul(2)
    }

    /// Render the public statistics page for this snapshot.
    pub fn page(&self, title: &str, window_days: u32, interval: Duration) -> String {
        crate::page::page(&crate::page::Page {
            title,
            generated: DateTime::<Utc>::from(self.fetched),
            stale: self.is_stale(interval),
            stats: &self.stats,
            window_days,
            interval_secs: interval.as_secs(),
        })
    }
}

pub type SharedSnapshot = Arc<RwLock<Option<Arc<Snapshot>>>>;

pub fn etag(body: &[u8]) -> String {
    let h = Sha256::digest(body);
    let hex: String = h[..16].iter().map(|b| format!("{b:02x}")).collect();
    format!("\"{hex}\"")
}

fn blob<T: Serialize>(value: &T) -> Blob {
    let body = serde_json::to_vec(value).expect("serialisable");
    Blob {
        etag: etag(&body),
        body,
    }
}

pub struct Poller {
    client: AptidClient,
    interval: Duration,
    window_days: i64,
    snapshot: SharedSnapshot,
    updated: Arc<Notify>,
}

impl Poller {
    pub fn new(client: AptidClient, interval: Duration, window_days: i64) -> Self {
        Self {
            client,
            interval,
            window_days,
            snapshot: Arc::default(),
            updated: Arc::default(),
        }
    }

    pub fn snapshot(&self) -> SharedSnapshot {
        self.snapshot.clone()
    }

    /// Notified after every poll, successful or not, so a consumer can
    /// refresh its output and keep the staleness notice current.
    pub fn updated(&self) -> Arc<Notify> {
        self.updated.clone()
    }

    /// Fetch the hub once and publish a new snapshot.
    pub async fn step(&self) -> anyhow::Result<()> {
        let since = Utc::now() - TimeDelta::days(self.window_days);
        // All three share the read token; fail the whole fetch if any call
        // fails, so a partial snapshot is never published.
        let (active, timeline, nodes) = tokio::try_join!(
            self.client.active(),
            self.client.timeline(since),
            self.client.nodes(),
        )?;
        // The hub's follow list also holds follows that are still pending or
        // were rejected; those nodes are not exchanging evidence, so they are
        // neither counted nor published as connected.
        let nodes: Vec<_> = nodes
            .into_iter()
            .filter(|n| n.state == "accepted")
            .collect();
        let stats = Stats::compute(&active.entries, &timeline.entries, &nodes);
        let snap = Arc::new(Snapshot {
            fetched: SystemTime::now(),
            stats,
            nodes: blob(&nodes),
        });
        *self.snapshot.write().unwrap_or_else(|e| e.into_inner()) = Some(snap);
        Ok(())
    }

    /// Fetch once on start, then every `interval`. Failures keep the last
    /// snapshot and are logged.
    pub async fn run(self) -> anyhow::Result<()> {
        if let Err(e) = self.step().await {
            tracing::warn!("initial fetch of the hub failed: {e:#}");
        }
        self.updated.notify_one();
        loop {
            tokio::time::sleep(self.interval).await;
            if let Err(e) = self.step().await {
                tracing::warn!("fetch of the hub failed, serving the last snapshot: {e:#}");
            }
            self.updated.notify_one();
        }
    }
}
