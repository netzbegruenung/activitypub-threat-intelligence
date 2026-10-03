//! Blocking client for the aptid control socket.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context};
use apti_core::protocol::{Reply, Request};

pub struct Client {
    path: PathBuf,
    conn: Option<(BufReader<UnixStream>, UnixStream)>,
}

impl Client {
    pub fn new(path: PathBuf) -> Self {
        Self { path, conn: None }
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    fn connect(&mut self) -> anyhow::Result<&mut (BufReader<UnixStream>, UnixStream)> {
        if self.conn.is_none() {
            let s = UnixStream::connect(&self.path)
                .with_context(|| format!("connecting to {}", self.path.display()))?;
            // Follow requests involve remote HTTP; allow generous time.
            s.set_read_timeout(Some(Duration::from_secs(60)))?;
            let reader = BufReader::new(s.try_clone()?);
            self.conn = Some((reader, s));
        }
        Ok(self.conn.as_mut().expect("connected"))
    }

    fn send(&mut self, line: &[u8]) -> anyhow::Result<()> {
        let (_, writer) = self.connect()?;
        writer.write_all(line)?;
        writer.flush()?;
        Ok(())
    }

    /// Send a request. If writing fails (stale connection) it reconnects
    /// once; a request that was sent is never repeated.
    pub fn request(&mut self, req: Request) -> anyhow::Result<Reply> {
        let mut line = serde_json::to_vec(&req)?;
        line.push(b'\n');
        if self.send(&line).is_err() {
            self.conn = None;
            self.send(&line)?;
        }
        let (reader, _) = self.conn.as_mut().expect("connected");
        let mut buf = String::new();
        let n = reader.read_line(&mut buf);
        if !matches!(n, Ok(n) if n > 0) {
            self.conn = None;
            bail!("no reply from daemon");
        }
        Ok(serde_json::from_str(&buf)?)
    }
}
