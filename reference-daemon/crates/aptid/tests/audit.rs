//! Audit log: every change to an observable is logged with its origin.
//! A separate test binary, because it installs a global subscriber.

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use apti_core::protocol::{AllowlistScope, ApiScope, NewAllowlistEntry, Reply, Request};
use apti_core::Tlp;
use aptid::config::Config;
use aptid::{api, db, engine, publish, Daemon};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixStream};

const PUSH: &str = "push-token-0123456789";
const ALLOW: &str = "allow-token-0123456789";

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Write for Buffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Buffer {
    fn lines(&self) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(String::from)
            .collect()
    }

    /// Wait until an audit line containing all of `parts` was logged.
    async fn expect(&self, parts: &[&str]) -> String {
        for _ in 0..200 {
            if let Some(l) = self
                .lines()
                .into_iter()
                .find(|l| l.contains(" audit: ") && parts.iter().all(|p| l.contains(p)))
            {
                return l;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("no audit line with {parts:?}:\n{}", self.lines().join("\n"));
    }
}

async fn spawn(dir: &std::path::Path, audit: bool) -> Daemon {
    let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = public.local_addr().unwrap().port();
    let cfg = format!(
        r#"
[instance]
base_url = "http://127.0.0.1:{port}"
organization = "Org"
[storage]
database = "{db}"
key_file = "{key}"
[public]
bind = "127.0.0.1:0"
[api]
bind = "127.0.0.1:0"
[control]
socket = "{sock}"
[federation]
allow_http = true
allow_private_addresses = true
sync_interval_secs = 3600
[publish]
batch_interval_secs = 3600
[policy]
recompute_interval_secs = 3600
[audit]
enabled = {audit}
"#,
        db = dir.join("db.sqlite").display(),
        key = dir.join("key.pem").display(),
        sock = dir.join("control.sock").display(),
    );
    let d = aptid::start_with_listeners(Config::parse(&cfg).unwrap(), public, api)
        .await
        .unwrap();
    for (name, secret, scope) in [
        ("sensor", PUSH, ApiScope::Push),
        ("sync-tool", ALLOW, ApiScope::Allowlist),
    ] {
        let hash = api::hash_token(secret);
        d.state
            .db
            .call(move |c| db::insert_api_token(c, name, &hash, &[scope], Tlp::Green))
            .await
            .unwrap();
    }
    d
}

async fn ctl(d: &Daemon, req: Request) -> Reply {
    let stream = UnixStream::connect(&d.state.cfg.control.socket)
        .await
        .unwrap();
    let (r, mut w) = stream.into_split();
    let mut line = serde_json::to_vec(&req).unwrap();
    line.push(b'\n');
    w.write_all(&line).await.unwrap();
    let reply = BufReader::new(r)
        .lines()
        .next_line()
        .await
        .unwrap()
        .unwrap();
    serde_json::from_str(&reply).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn audit_log() {
    let buf = Buffer::default();
    let writer = buf.clone();
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter("audit=info")
        .with_writer(move || writer.clone())
        .init();
    let dir = tempfile::tempdir().unwrap();
    let http = reqwest::Client::new();

    // Disabled: nothing is logged.
    let off = spawn(&dir.path().join("off"), false).await;
    let r = http
        .post(format!("http://{}/api/v1/observations", off.api_addr))
        .bearer_auth(PUSH)
        .json(&json!({"value": "45.13.7.1", "behavior": "scan"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    publish::run_batch(&off.state).await.unwrap();
    engine::recompute(&off.state).await.unwrap();
    assert!(buf.lines().is_empty(), "{:?}", buf.lines());
    off.shutdown();

    let d = spawn(&dir.path().join("on"), true).await;

    // A sensor pushes an observation.
    let r = http
        .post(format!("http://{}/api/v1/observations", d.api_addr))
        .bearer_auth(PUSH)
        .json(&json!({"value": "45.13.7.9", "behavior": "scan", "count": 3}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    buf.expect(&[
        "observation received",
        r#"by="api:sensor""#,
        r#"obs_type="ipv4-addr""#,
        r#"value="45.13.7.9""#,
        r#"behavior="scan""#,
        "count=3",
    ])
    .await;

    // The batch publishes it as a Sighting, which activates the entry.
    publish::run_batch(&d.state).await.unwrap();
    buf.expect(&[
        "evidence stored",
        r#"by="daemon""#,
        r#"evidence="Sighting""#,
        r#"value="45.13.7.9""#,
    ])
    .await;
    engine::recompute(&d.state).await.unwrap();
    buf.expect(&[
        "active changed",
        r#"value="45.13.7.9""#,
        r#"changes="added,activated""#,
        "active=true",
    ])
    .await;

    // An allowlist entry from the TUI suspends it. The summary cannot
    // break the line.
    let reply = ctl(
        &d,
        Request::AddAllowlist(NewAllowlistEntry {
            scope: AllowlistScope::Local,
            value: "45.13.7.9".into(),
            behaviors: vec![],
            tlp: None,
            valid_until: None,
            summary: Some("our scanner\nINFO audit: forged".into()),
            source: None,
        }),
    )
    .await;
    assert!(matches!(reply, Reply::Done), "{reply:?}");
    let uid = std::fs::metadata(dir.path())
        .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
        .unwrap();
    let line = buf
        .expect(&[
            "allowlist added",
            &format!(r#"by="control:uid={uid}""#),
            r#"scope="local""#,
            r#"behavior="all""#,
            r#"summary="our scanner\nINFO audit: forged""#,
        ])
        .await;
    assert!(!buf
        .lines()
        .iter()
        .any(|l| l.starts_with("INFO audit: forged")));
    engine::recompute(&d.state).await.unwrap();
    buf.expect(&[
        "active changed",
        r#"changes="deactivated,suspended""#,
        "allowlisted=true",
    ])
    .await;

    // Removing it over the REST API re-activates the entry.
    let id = line
        .split(" id=")
        .nth(1)
        .and_then(|s| s.split(' ').next())
        .unwrap();
    let r = http
        .delete(format!("http://{}/api/v1/allowlist/{id}", d.api_addr))
        .bearer_auth(ALLOW)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    buf.expect(&["allowlist removed", r#"by="api:sync-tool""#])
        .await;
    engine::recompute(&d.state).await.unwrap();
    buf.expect(&["active changed", r#"changes="activated,unsuspended""#])
        .await;

    // A recompute without changes logs nothing.
    let n = buf.lines().len();
    engine::recompute(&d.state).await.unwrap();
    assert_eq!(buf.lines().len(), n);
    d.shutdown();
}
