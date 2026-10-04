//! Rspamd reports → aptid → multimap files, against an in-process aptid.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use apti_core::protocol::ApiScope;
use apti_core::Tlp;
use apti_rspamd::client::AptidClient;
use apti_rspamd::config::Config;
use apti_rspamd::maps::Puller;
use apti_rspamd::push::{lock, Pusher};
use apti_rspamd::reputation::Ingest;
use apti_rspamd::server::{self, AppState};
use aptid::{api, db, engine, publish, Daemon};
use reqwest::StatusCode;
use serde_json::{json, Value};
use tokio::net::TcpListener;

const PUSH: &str = "push-token-0123456789";
const READ: &str = "read-token-0123456789";
const ALLOW: &str = "allow-token-0123456789";
const SECRET: &str = "report-secret-0123456789";

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
    let d = aptid::start_with_listeners(aptid::config::Config::parse(&cfg).unwrap(), public, api)
        .await
        .unwrap();
    d.state
        .db
        .call(|c| {
            let add = |name, secret, scope| {
                db::insert_api_token(c, name, &api::hash_token(secret), &[scope], Tlp::Green)
            };
            add("push", PUSH, ApiScope::Push)?;
            add("read", READ, ApiScope::Read)?;
            add("allow", ALLOW, ApiScope::Allowlist)?;
            Ok(())
        })
        .await
        .unwrap();
    d
}

fn client_config(api: &str) -> Config {
    Config::parse(&format!(
        r#"
[aptid]
url = "{api}"
push_token = "{PUSH}"
read_token = "{READ}"
[ingest]
report_secret = "{SECRET}"
min_score = 10
min_messages = 2
service = "smtp"
port = 25
tlp = "green"
[ingest.envelope_from]
tlp = "clear"
min_messages = 2
[maps]
[[maps.map]]
name = "ip"
kind = "ip"
[[maps.map]]
name = "sender-domains"
kind = "domain"
behaviors = ["smtp-spam"]
"#
    ))
    .unwrap()
}

struct Connector {
    addr: SocketAddr,
    ingest: Arc<Mutex<Ingest>>,
    pusher: Pusher,
    puller: Puller,
}

async fn spawn_connector(cfg: &Config) -> Connector {
    let ingest = Arc::new(Mutex::new(
        Ingest::new(cfg.ingest.clone().unwrap()).unwrap(),
    ));
    let pusher = Pusher::new(ingest.clone(), AptidClient::new(&cfg.aptid).unwrap(), 30);
    let puller = Puller::new(
        cfg.maps.clone().unwrap(),
        AptidClient::new(&cfg.aptid).unwrap(),
    )
    .unwrap();
    let state = AppState {
        ingest: Some((ingest.clone(), SECRET.into())),
        maps: Some((puller.maps(), Duration::from_secs(60))),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, server::router(state)).await });
    Connector {
        addr,
        ingest,
        pusher,
        puller,
    }
}

async fn report(addr: SocketAddr, secret: &str, body: Value) -> (StatusCode, Value) {
    let r = reqwest::Client::new()
        .post(format!("http://{addr}/v1/report"))
        .bearer_auth(secret)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = r.status();
    (status, r.json().await.unwrap_or(Value::Null))
}

async fn get_map(addr: SocketAddr, name: &str, etag: Option<&str>) -> (StatusCode, String, String) {
    let mut r = reqwest::Client::new().get(format!("http://{addr}/maps/{name}"));
    if let Some(e) = etag {
        r = r.header("If-None-Match", e);
    }
    let r = r.send().await.unwrap();
    let status = r.status();
    let etag = r.headers()["etag"].to_str().unwrap().to_string();
    (status, etag, r.text().await.unwrap())
}

async fn aptid_api(d: &Daemon, method: reqwest::Method, path: &str, body: Option<Value>) -> Value {
    let mut r = reqwest::Client::new()
        .request(method, format!("http://{}{path}", d.api_addr))
        .bearer_auth(ALLOW);
    if let Some(b) = body {
        r = r.json(&b);
    }
    r.send().await.unwrap().json().await.unwrap()
}

fn spam(ip: &str, score: f64, symbols: Value) -> Value {
    json!({"ip": ip, "score": score, "action": "reject", "symbols": symbols, "authenticated": false})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rspamd_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let d = spawn_aptid(&dir.path().join("aptid")).await;
    let cfg = client_config(&format!("http://{}", d.api_addr));
    let mut c = spawn_connector(&cfg).await;

    // The plugin must present the shared secret.
    let (status, _) = report(c.addr, "wrong", spam("45.13.7.9", 20.0, json!([]))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Messages that are bad only because of APTI_* symbols do not count.
    let looped = spam(
        "45.13.7.8",
        14.0,
        json!([{"name": "APTI_BAD_IP", "score": 6.0}, {"name": "BAYES_SPAM", "score": 8.0}]),
    );
    let (status, r) = report(c.addr, SECRET, json!([looped.clone(), looped])).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        (r["received"].as_u64(), r["counted"].as_u64()),
        (Some(2), Some(0))
    );

    // A forged envelope sender (no SPF pass) does not count.
    let mut forged = spam("45.13.7.8", 12.0, json!([]));
    forged["from_domain"] = json!("bulk-mailer.net");
    let (_, r) = report(c.addr, SECRET, forged).await;
    assert_eq!(r["countedDomains"], 0);

    // Two bad messages report the sender and its SPF-authenticated
    // envelope-from domain once.
    let mut authed = spam(
        "45.13.7.9",
        12.0,
        json!([{"name": "R_SPF_ALLOW", "score": -0.2}]),
    );
    authed["from_domain"] = json!("bulk-mailer.net");
    let (_, r) = report(c.addr, SECRET, authed.clone()).await;
    assert_eq!(
        (r["reported"].as_u64(), r["countedDomains"].as_u64()),
        (Some(0), Some(1))
    );
    let (_, r) = report(c.addr, SECRET, authed).await;
    assert_eq!(
        (r["reported"].as_u64(), r["reportedDomains"].as_u64()),
        (Some(1), Some(1))
    );
    // Private and allowlisted senders: aptid rejects the latter.
    let (_, r) = report(
        c.addr,
        SECRET,
        json!([
            spam("10.0.0.1", 50.0, json!([])),
            spam("10.0.0.1", 50.0, json!([]))
        ]),
    )
    .await;
    assert_eq!(r["counted"], 0);
    aptid_api(
        &d,
        reqwest::Method::POST,
        "/api/v1/allowlist",
        Some(json!({"value": "45.13.7.77"})),
    )
    .await;
    for _ in 0..2 {
        report(c.addr, SECRET, spam("45.13.7.77", 12.0, json!([]))).await;
    }
    assert_eq!(lock(&c.ingest).queued(), 3);
    assert_eq!(c.pusher.flush().await, 2, "allowlisted IP is rejected");
    assert_eq!(lock(&c.ingest).queued(), 0);

    publish::run_batch(&d.state).await.unwrap();
    engine::recompute(&d.state).await.unwrap();

    // The active list is served as multimap file with ETag revalidation.
    let (status, etag, body) = get_map(c.addr, "ip", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "# apti-rspamd map ip\n", "nothing fetched yet");
    c.puller.step().await.unwrap();
    let (status, etag2, body) = get_map(c.addr, "ip", Some(&etag)).await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(etag, etag2);
    assert_eq!(body, "# apti-rspamd map ip\n# smtp-spam\n45.13.7.9\n");
    let (status, _, body) = get_map(c.addr, "ip", Some(&etag2)).await;
    assert_eq!((status, body.as_str()), (StatusCode::NOT_MODIFIED, ""));
    let (_, _, body) = get_map(c.addr, "sender-domains", None).await;
    assert_eq!(
        body,
        "# apti-rspamd map sender-domains\n# smtp-spam\n/^bulk-mailer\\.net$/i\n"
    );
    // IPs and domains carry the TLP configured for each.
    let active: Value = reqwest::Client::new()
        .get(format!("http://{}/api/v1/active", d.api_addr))
        .bearer_auth(READ)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let tlp_of = |v: &str| {
        active["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["observableValue"] == v)
            .map(|e| e["tlp"].clone())
    };
    assert_eq!(tlp_of("45.13.7.9"), Some(json!("green")));
    assert_eq!(tlp_of("bulk-mailer.net"), Some(json!("clear")));
    let r = reqwest::get(format!("http://{}/maps/nope", c.addr))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);

    // Allowlisting the IP removes it from the map.
    aptid_api(
        &d,
        reqwest::Method::POST,
        "/api/v1/allowlist",
        Some(json!({"value": "45.13.7.9"})),
    )
    .await;
    engine::recompute(&d.state).await.unwrap();
    c.puller.step().await.unwrap();
    let (status, _, body) = get_map(c.addr, "ip", Some(&etag2)).await;
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::OK, "# apti-rspamd map ip\n")
    );

    // aptid unreachable: reports stay queued; maps keep the cached list.
    let mut down = cfg.clone();
    down.aptid.url = "http://127.0.0.1:1".into();
    let mut c = spawn_connector(&down).await;
    for _ in 0..2 {
        report(c.addr, SECRET, spam("45.13.7.10", 12.0, json!([]))).await;
    }
    assert_eq!(c.pusher.flush().await, 0);
    assert_eq!(lock(&c.ingest).queued(), 1);
    assert!(c.puller.step().await.is_err());
    let (status, _, _) = get_map(c.addr, "ip", None).await;
    assert_eq!(status, StatusCode::OK);

    d.shutdown();
}
