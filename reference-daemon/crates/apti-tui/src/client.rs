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
        let mut reply: serde_json::Value = serde_json::from_str(&buf)?;
        strip_control(&mut reply);
        Ok(serde_json::from_value(reply)?)
    }
}

/// Replace control characters in all strings of a reply. Replies carry data
/// from remote peers (ids, operator claims, error messages); ratatui passes
/// control characters through to the terminal, which would allow escape
/// sequence injection.
pub fn strip_control(v: &mut serde_json::Value) {
    use serde_json::Value;
    match v {
        Value::String(s) if s.contains(char::is_control) => {
            *s = s
                .chars()
                .map(|c| match c {
                    '\n' | '\t' => ' ',
                    c if c.is_control() => char::REPLACEMENT_CHARACTER,
                    c => c,
                })
                .collect();
        }
        Value::Array(a) => a.iter_mut().for_each(strip_control),
        Value::Object(o) => o.values_mut().for_each(strip_control),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_nested_control_characters() {
        let mut v = serde_json::json!({"a": ["x\u{1b}[2Jy", {"b": "\u{9b}31m"}], "n": 1});
        strip_control(&mut v);
        assert_eq!(
            v,
            serde_json::json!({"a": ["x\u{fffd}[2Jy", {"b": "\u{fffd}31m"}], "n": 1})
        );
    }
}
