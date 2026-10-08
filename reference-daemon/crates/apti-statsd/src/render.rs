//! Static output: render the statistics page and the node directory into a
//! directory that a web server (nginx, Apache) serves.
//!
//! This is the default mode. apti-statsd then exposes no socket of its own,
//! so the public attack surface is the web server's and the rate limiter,
//! conditional requests and compression are its job. Files are written to a
//! temporary name and renamed into place, so a request never reads a
//! half-written page. Output is refreshed after every poll, including a
//! failed one, so the staleness notice on the page stays current.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::sync::Notify;

use crate::config::Server;
use crate::poll::SharedSnapshot;

pub const PAGE_FILE: &str = "index.html";
pub const NODES_FILE: &str = "nodes.json";

pub struct Renderer {
    snapshot: SharedSnapshot,
    dir: PathBuf,
    title: String,
    window_days: u32,
    interval: Duration,
}

impl Renderer {
    pub fn new(
        cfg: &Server,
        snapshot: SharedSnapshot,
        window_days: u32,
        interval: Duration,
    ) -> Self {
        Self {
            snapshot,
            dir: cfg.output_dir.clone(),
            title: cfg.title.clone(),
            window_days,
            interval,
        }
    }

    /// Write the current snapshot. Does nothing before the first successful
    /// fetch, so a stale directory from an earlier run is left untouched
    /// rather than replaced by an empty page.
    pub fn step(&self) -> anyhow::Result<()> {
        let Some(snap) = self
            .snapshot
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .cloned()
        else {
            return Ok(());
        };
        let page = snap.page(&self.title, self.window_days, self.interval);
        write_atomic(&self.dir, PAGE_FILE, page.as_bytes())?;
        write_atomic(&self.dir, NODES_FILE, &snap.nodes.body)?;
        Ok(())
    }

    /// Render after every poll. Write failures are logged and retried on the
    /// next poll; they never take the process down.
    pub async fn run(self, updated: Arc<Notify>) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("creating {}", self.dir.display()))?;
        tracing::info!(dir = %self.dir.display(), "rendering to disk");
        loop {
            updated.notified().await;
            if let Err(e) = self.step() {
                tracing::warn!("rendering failed, keeping the previous output: {e:#}");
            }
        }
    }
}

/// Write `name` in `dir` by replacing it, so readers see either the previous
/// or the new file and never a partial one.
fn write_atomic(dir: &Path, name: &str, body: &[u8]) -> anyhow::Result<()> {
    let tmp = dir.join(format!(".{name}.tmp"));
    let path = dir.join(name);
    std::fs::write(&tmp, body).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poll::{Blob, Snapshot};
    use crate::stats::Stats;
    use std::time::SystemTime;

    fn renderer(dir: &Path) -> Renderer {
        Renderer {
            snapshot: SharedSnapshot::default(),
            dir: dir.to_path_buf(),
            title: "Hub".into(),
            window_days: 30,
            interval: Duration::from_secs(60),
        }
    }

    #[test]
    fn writes_page_and_nodes() {
        let dir = std::env::temp_dir().join(format!("apti-statsd-render-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let r = renderer(&dir);

        // Without a snapshot nothing is written.
        r.step().unwrap();
        assert!(!dir.join(PAGE_FILE).exists());

        *r.snapshot.write().unwrap() = Some(Arc::new(Snapshot {
            fetched: SystemTime::now(),
            stats: Stats::default(),
            nodes: Blob {
                body: b"[]".to_vec(),
                etag: "\"x\"".into(),
            },
        }));
        r.step().unwrap();
        let html = std::fs::read_to_string(dir.join(PAGE_FILE)).unwrap();
        assert!(html.contains("<title>Hub</title>"));
        assert_eq!(std::fs::read_to_string(dir.join(NODES_FILE)).unwrap(), "[]");
        // Rendering again leaves no temporary files behind.
        r.step().unwrap();
        let left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left.len(), 2, "unexpected files: {left:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
