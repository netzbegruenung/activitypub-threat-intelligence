//! fail2ban log → aptid → ban file, against an in-process aptid.

use std::io::Write;
use std::path::Path;

use apti_fail2ban::client::AptidClient;
use apti_fail2ban::config::Config;
use apti_fail2ban::pull::Puller;
use apti_fail2ban::push::Pusher;
use apti_fail2ban::tail::Position;
use aptid::{engine, publish, Daemon};
use serde_json::{json, Value};
use tokio::net::TcpListener;

const PUSH: &str = "push-token-0123456789";
const READ: &str = "read-token-0123456789";
const ALLOW: &str = "allow-token-0123456789";

async fn spawn_aptid(dir: &Path) -> Daemon {
    let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = public.local_addr().unwrap().port();
    let cfg = format!(
        r#"
[instance]
base_url = "http://127.0.0.1:{port}"
organization = "Test"
[storage]
database = "{d}/db.sqlite"
key_file = "{d}/key.pem"
[public]
bind = "127.0.0.1:0"
[api]
bind = "127.0.0.1:0"
[[api.tokens]]
name = "push"
token = "{PUSH}"
scopes = ["push"]
[[api.tokens]]
name = "read"
token = "{READ}"
scopes = ["read"]
[[api.tokens]]
name = "allow"
token = "{ALLOW}"
scopes = ["allowlist"]
[control]
socket = "{d}/control.sock"
[federation]
allow_http = true
[publish]
batch_interval_secs = 3600
[policy]
recompute_interval_secs = 3600
"#,
        d = dir.display()
    );
    aptid::start_with_listeners(aptid::config::Config::parse(&cfg).unwrap(), public, api)
        .await
        .unwrap()
}

fn client_config(api: &str, dir: &Path) -> Config {
    Config::parse(&format!(
        r#"
[aptid]
url = "{api}"
push_token = "{PUSH}"
read_token = "{READ}"
[push]
log = "{d}/fail2ban.log"
state_file = "{d}/push.state"
ignore_jails = ["aptid-ssh"]
[push.jails.sshd]
behavior = "ssh-bruteforce"
port = 22
service = "ssh"
[pull]
interval_secs = 60
refresh_secs = 1800
[[pull.output]]
path = "{d}/out/ssh.log"
behaviors = ["ssh-bruteforce"]
"#,
        d = dir.display()
    ))
    .unwrap()
}

fn append(path: &Path, s: &str) {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    f.write_all(s.as_bytes()).unwrap();
}

fn f2b(ts: &str, jail: &str, action: &str, ip: &str) -> String {
    format!("{ts},123 fail2ban.actions        [4711]: NOTICE  [{jail}] {action} {ip}\n")
}

async fn api(d: &Daemon, method: reqwest::Method, path: &str, body: Option<Value>) -> Value {
    let mut r = reqwest::Client::new()
        .request(method, format!("http://{}{path}", d.api_addr))
        .bearer_auth(ALLOW);
    if let Some(b) = body {
        r = r.json(&b);
    }
    r.send().await.unwrap().json().await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fail2ban_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let d = spawn_aptid(&dir.path().join("aptid")).await;
    let cfg = client_config(&format!("http://{}", d.api_addr), dir.path());
    let log = dir.path().join("fail2ban.log");
    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    // Existing content is skipped on first start.
    append(&log, &f2b(&ts, "sshd", "Ban", "45.13.7.1"));
    let mut pusher = Pusher::new(
        cfg.push.clone().unwrap(),
        AptidClient::new(&cfg.aptid).unwrap(),
    )
    .unwrap();
    assert_eq!(pusher.read().unwrap(), 0);

    append(&log, &f2b(&ts, "sshd", "Ban", "45.13.7.9"));
    append(&log, &f2b(&ts, "aptid-ssh", "Ban", "45.13.7.50")); // own import jail
    append(&log, &f2b(&ts, "sshd", "Restore Ban", "45.13.7.51"));
    append(&log, &f2b(&ts, "sshd", "Unban", "45.13.7.52"));
    append(&log, &f2b(&ts, "nginx-http-auth", "Ban", "45.13.7.53")); // unmapped
    append(&log, &f2b(&ts, "sshd", "Ban", "10.0.0.1")); // rejected by aptid
    assert_eq!(pusher.read().unwrap(), 2);
    assert_eq!(pusher.flush().await.unwrap(), 1);
    assert_eq!(pusher.queued(), 0);
    let saved = Position::load(&cfg.push.as_ref().unwrap().state_file).unwrap();
    assert_eq!(saved.offset, std::fs::metadata(&log).unwrap().len());

    publish::run_batch(&d.state).await.unwrap();
    engine::recompute(&d.state).await.unwrap();

    // Pull writes the active IP once; a second step within refresh_secs is a no-op.
    let out = dir.path().join("out/ssh.log");
    let mut puller = Puller::new(
        cfg.pull.clone().unwrap(),
        AptidClient::new(&cfg.aptid).unwrap(),
    )
    .unwrap();
    assert_eq!(puller.step().await.unwrap(), 1);
    let content = std::fs::read_to_string(&out).unwrap();
    assert!(
        content.contains(" apti-ban 45.13.7.9 behavior=ssh-bruteforce expires="),
        "{content}"
    );
    assert_eq!(puller.step().await.unwrap(), 0);

    // Dynamic allowlist via REST: the IP is no longer written.
    let e = api(
        &d,
        reqwest::Method::POST,
        "/api/v1/allowlist",
        Some(json!({"value": "45.13.7.9"})),
    )
    .await;
    engine::recompute(&d.state).await.unwrap();
    assert_eq!(puller.step().await.unwrap(), 0);
    // Removing it re-activates; the IP is written again immediately.
    api(
        &d,
        reqwest::Method::DELETE,
        &format!("/api/v1/allowlist/{}", e["id"]),
        None,
    )
    .await;
    engine::recompute(&d.state).await.unwrap();
    assert_eq!(puller.step().await.unwrap(), 1);
    assert_eq!(std::fs::read_to_string(&out).unwrap().lines().count(), 2);

    // aptid unreachable: bans stay queued and the position is not advanced.
    let mut down = cfg.clone();
    down.aptid.url = "http://127.0.0.1:1".into();
    let mut pusher = Pusher::new(
        down.push.clone().unwrap(),
        AptidClient::new(&down.aptid).unwrap(),
    )
    .unwrap();
    append(&log, &f2b(&ts, "sshd", "Ban", "45.13.7.10"));
    assert_eq!(pusher.read().unwrap(), 1);
    assert_eq!(pusher.flush().await.unwrap(), 0);
    assert_eq!(pusher.queued(), 1);
    assert_eq!(
        Position::load(&cfg.push.as_ref().unwrap().state_file).unwrap(),
        saved
    );
    // A restarted pusher resumes from the saved position and delivers it.
    let mut pusher = Pusher::new(
        cfg.push.clone().unwrap(),
        AptidClient::new(&cfg.aptid).unwrap(),
    )
    .unwrap();
    assert_eq!(pusher.read().unwrap(), 1);
    assert_eq!(pusher.flush().await.unwrap(), 1);

    d.shutdown();
}
