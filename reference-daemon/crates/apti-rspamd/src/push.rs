//! Queued observations → aptid.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use apti_core::MAX_BATCH;
use chrono::Utc;

use crate::client::{ApiError, AptidClient};
use crate::reputation::Ingest;

pub type SharedIngest = Arc<Mutex<Ingest>>;

pub fn lock(i: &SharedIngest) -> std::sync::MutexGuard<'_, Ingest> {
    i.lock().unwrap_or_else(|e| e.into_inner())
}

pub struct Pusher {
    ingest: SharedIngest,
    client: AptidClient,
    batch_interval: Duration,
    failures: u32,
    retry_at: Option<Instant>,
}

impl Pusher {
    pub fn new(ingest: SharedIngest, client: AptidClient, batch_interval_secs: u64) -> Self {
        Self {
            ingest,
            client,
            batch_interval: Duration::from_secs(batch_interval_secs),
            failures: 0,
            retry_at: None,
        }
    }

    /// Send queued observations (up to 1000 per request). Returns the number
    /// accepted by aptid.
    pub async fn flush(&mut self) -> usize {
        if self.retry_at.is_some_and(|t| Instant::now() < t) {
            return 0;
        }
        let mut accepted = 0;
        loop {
            let items = lock(&self.ingest).take(MAX_BATCH);
            if items.is_empty() {
                break;
            }
            let n = items.len();
            match self.client.push(&items).await {
                Ok(r) => {
                    for rej in &r.rejected {
                        tracing::debug!("aptid rejected {}: {}", rej["value"], rej["error"]);
                    }
                    tracing::info!(sent = n, accepted = r.accepted, "pushed reports to aptid");
                    accepted += r.accepted;
                    self.failures = 0;
                    self.retry_at = None;
                }
                Err(ApiError::Rejected(e)) => {
                    tracing::error!("aptid rejected batch of {n}, dropping it: {e:#}");
                }
                Err(ApiError::Transient(e)) => {
                    self.failures += 1;
                    let backoff = Duration::from_secs((5u64 << self.failures.min(6)).min(300));
                    let mut ingest = lock(&self.ingest);
                    ingest.put_back(items);
                    tracing::warn!(queued = ingest.queued(), retry_in = ?backoff, "push failed: {e:#}");
                    self.retry_at = Some(Instant::now() + backoff);
                    break;
                }
            }
        }
        accepted
    }

    pub async fn run(mut self) -> anyhow::Result<()> {
        loop {
            tokio::time::sleep(self.batch_interval).await;
            lock(&self.ingest).prune(Utc::now());
            self.flush().await;
        }
    }
}
