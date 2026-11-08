//! Polling log follower that survives rotation and truncation.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Position after a complete line: file identity and byte offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Position {
    pub inode: u64,
    pub offset: u64,
}

impl Position {
    pub fn load(path: &Path) -> Option<Self> {
        serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
    }

    /// Save atomically (write + rename).
    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec(self)?)?;
        std::fs::rename(tmp, path)
    }
}

pub struct Tailer {
    path: PathBuf,
    file: Option<File>,
    inode: u64,
    /// Bytes read from the current file.
    read: u64,
    /// Incomplete trailing line.
    partial: Vec<u8>,
}

impl Tailer {
    /// Open `path`. With a saved position for the same file, continue there;
    /// with a position for a different (rotated) file, start at the
    /// beginning; without a position, start at the end.
    pub fn open(path: &Path, start: Option<Position>) -> io::Result<Self> {
        let mut t = Self {
            path: path.to_path_buf(),
            file: None,
            inode: 0,
            read: 0,
            partial: Vec::new(),
        };
        if let Ok(mut f) = File::open(path) {
            let meta = f.metadata()?;
            let offset = match start {
                Some(p) if p.inode == meta.ino() && p.offset <= meta.len() => p.offset,
                Some(_) => 0,
                None => meta.len(),
            };
            f.seek(SeekFrom::Start(offset))?;
            t.inode = meta.ino();
            t.read = offset;
            t.file = Some(f);
        }
        Ok(t)
    }

    fn read_available(&mut self, out: &mut Vec<(String, Position)>) -> io::Result<()> {
        let Some(f) = self.file.as_mut() else {
            return Ok(());
        };
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        let base = self.read - self.partial.len() as u64;
        self.read += buf.len() as u64;
        self.partial.extend_from_slice(&buf);
        let mut consumed = 0usize;
        while let Some(nl) = self.partial[consumed..].iter().position(|&b| b == b'\n') {
            let end = consumed + nl;
            let line = String::from_utf8_lossy(&self.partial[consumed..end])
                .trim_end_matches('\r')
                .to_string();
            consumed = end + 1;
            out.push((
                line,
                Position {
                    inode: self.inode,
                    offset: base + consumed as u64,
                },
            ));
        }
        self.partial.drain(..consumed);
        Ok(())
    }

    fn reopen(&mut self) -> io::Result<bool> {
        match File::open(&self.path) {
            Ok(f) => {
                self.inode = f.metadata()?.ino();
                self.file = Some(f);
                self.read = 0;
                self.partial.clear();
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                self.file = None;
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// Return new complete lines with the position after each line.
    pub fn poll(&mut self) -> io::Result<Vec<(String, Position)>> {
        let mut out = Vec::new();
        if self.file.is_none() && !self.reopen()? {
            return Ok(out);
        }
        // Drain the current handle first (also after rotation).
        self.read_available(&mut out)?;
        match std::fs::metadata(&self.path) {
            Ok(meta) if meta.ino() != self.inode => {
                if self.reopen()? {
                    self.read_available(&mut out)?;
                }
            }
            Ok(meta) if meta.len() < self.read => {
                // Truncated in place.
                if let Some(f) = self.file.as_mut() {
                    f.seek(SeekFrom::Start(0))?;
                }
                self.read = 0;
                self.partial.clear();
                self.read_available(&mut out)?;
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn append(path: &Path, s: &str) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        f.write_all(s.as_bytes()).unwrap();
    }

    fn lines(t: &mut Tailer) -> Vec<String> {
        t.poll().unwrap().into_iter().map(|(l, _)| l).collect()
    }

    #[test]
    fn follows_rotation_and_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("f2b.log");
        append(&log, "old line\n");
        // No saved position: start at the end.
        let mut t = Tailer::open(&log, None).unwrap();
        assert!(lines(&mut t).is_empty());

        append(&log, "a\nb");
        assert_eq!(lines(&mut t), vec!["a"]);
        append(&log, "\n");
        assert_eq!(lines(&mut t), vec!["b"]);

        // Rotation: remaining lines of the old file, then the new file.
        append(&log, "c\n");
        std::fs::rename(&log, dir.path().join("f2b.log.1")).unwrap();
        append(&log, "d\n");
        assert_eq!(lines(&mut t), vec!["c", "d"]);

        // Truncation (copytruncate).
        std::fs::write(&log, "").unwrap();
        assert!(lines(&mut t).is_empty());
        append(&log, "e\n");
        assert_eq!(lines(&mut t), vec!["e"]);

        // Missing file is tolerated.
        std::fs::remove_file(&log).unwrap();
        assert!(lines(&mut t).is_empty());
        append(&log, "f\n");
        assert_eq!(lines(&mut t), vec!["f"]);
    }

    #[test]
    fn resumes_from_position() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("f2b.log");
        let state = dir.path().join("state.json");
        append(&log, "x\n");
        let mut t = Tailer::open(&log, None).unwrap();
        append(&log, "a\nb\n");
        let got = t.poll().unwrap();
        // Save the position after "a" only (as if "b" was not yet accepted).
        got[0].1.save(&state).unwrap();
        let pos = Position::load(&state).unwrap();
        let mut t = Tailer::open(&log, Some(pos)).unwrap();
        assert_eq!(lines(&mut t), vec!["b"]);

        // Position of another (rotated) file: start at the beginning.
        let mut t = Tailer::open(
            &log,
            Some(Position {
                inode: pos.inode + 1,
                offset: 2,
            }),
        )
        .unwrap();
        assert_eq!(lines(&mut t), vec!["x", "a", "b"]);
    }
}
