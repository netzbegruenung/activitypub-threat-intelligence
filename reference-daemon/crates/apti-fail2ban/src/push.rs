//! fail2ban log → aptid observations.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use apti_core::MAX_BATCH;
use serde_json::Value;

use crate::client::{ApiError, AptidClient};
use crate::config::Push;
use crate::parse;
use crate::tail::{Position, Tailer};

pub struct Pusher {
    cfg: Push,
    client: AptidClient,
    tailer: Tailer,
    queue: VecDeque<(Value, Position)>,
    /// Position after the last line read.
    last_read: Option<Position>,
    /// Last position written to the state file.
    saved: Option<Position>,
    failures: u32,
    retry_at: Option<Instant>,
}

impl Pusher {
    pub fn new(cfg: Push, client: AptidClient) -> anyhow::Result<Self> {
        let saved = Position::load(&cfg.state_file);
        let tailer = Tailer::open(&cfg.log, saved)?;
        if saved.is_none() {
            tracing::info!(log = %cfg.log.display(), "no saved position, starting at end of log");
        }
        Ok(Self {
            cfg,
            client,
            tailer,
            queue: VecDeque::new(),
            last_read: None,
            saved,
            failures: 0,
            retry_at: None,
        })
    }

    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    /// Read new log lines and queue reportable bans. Returns the number queued.
    pub fn read(&mut self) -> anyhow::Result<usize> {
        let mut n = 0;
        for (line, pos) in self.tailer.poll()? {
            self.last_read = Some(pos);
            let Some(ev) = parse::parse_line(&line) else {
                continue;
            };
            let Some(obs) = parse::to_observation(&ev, &self.cfg) else {
                tracing::debug!(jail = %ev.jail, ip = %ev.ip, action = ?ev.action, "not reported");
                continue;
            };
            if self.queue.len() >= self.cfg.max_queue {
                if let Some((dropped, _)) = self.queue.pop_front() {
                    tracing::warn!(value = %dropped["value"], "queue full, dropping oldest ban");
                }
            }
            self.queue.push_back((obs, pos));
            n += 1;
        }
        Ok(n)
    }

    fn save(&mut self, pos: Position) {
        if self.saved == Some(pos) {
            return;
        }
        match pos.save(&self.cfg.state_file) {
            Ok(()) => self.saved = Some(pos),
            Err(e) => {
                tracing::warn!(file = %self.cfg.state_file.display(), "cannot save position: {e}")
            }
        }
    }

    /// Send queued bans (up to 1000 per request). Returns the number accepted.
    pub async fn flush(&mut self) -> anyhow::Result<usize> {
        if self.retry_at.is_some_and(|t| Instant::now() < t) {
            return Ok(0);
        }
        let mut accepted = 0;
        while !self.queue.is_empty() {
            let n = self.queue.len().min(MAX_BATCH);
            let items: Vec<Value> = self.queue.iter().take(n).map(|(v, _)| v.clone()).collect();
            let last_pos = self.queue[n - 1].1;
            match self.client.push(&items).await {
                Ok(r) => {
                    for rej in &r.rejected {
                        tracing::debug!("aptid rejected {}: {}", rej["value"], rej["error"]);
                    }
                    tracing::info!(sent = n, accepted = r.accepted, "pushed bans to aptid");
                    accepted += r.accepted;
                    self.queue.drain(..n);
                    self.failures = 0;
                    self.retry_at = None;
                    self.save(last_pos);
                }
                Err(ApiError::Rejected(e)) => {
                    tracing::error!("aptid rejected batch of {n}, dropping it: {e:#}");
                    self.queue.drain(..n);
                    self.save(last_pos);
                }
                Err(ApiError::Transient(e)) => {
                    self.failures += 1;
                    let backoff = Duration::from_secs((5u64 << self.failures.min(6)).min(300));
                    tracing::warn!(queued = self.queue.len(), retry_in = ?backoff, "push failed: {e:#}");
                    self.retry_at = Some(Instant::now() + backoff);
                    return Ok(accepted);
                }
            }
        }
        // Everything read has been handled: remember the read position.
        if let Some(pos) = self.last_read {
            self.save(pos);
        }
        Ok(accepted)
    }

    pub async fn run(mut self) -> anyhow::Result<()> {
        let poll = Duration::from_millis(self.cfg.poll_interval_ms.max(100));
        let batch = Duration::from_secs(self.cfg.batch_interval_secs);
        let mut last_flush = Instant::now();
        loop {
            if let Err(e) = self.read() {
                tracing::warn!(log = %self.cfg.log.display(), "reading log: {e}");
            }
            if last_flush.elapsed() >= batch || self.queue.len() >= MAX_BATCH {
                self.flush().await?;
                last_flush = Instant::now();
            }
            tokio::time::sleep(poll).await;
        }
    }
}
