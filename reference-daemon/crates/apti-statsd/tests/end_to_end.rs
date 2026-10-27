//! apti-statsd against an in-process aptid: TLP:CLEAR aggregates with no
//! observable served, ETag/304, per-client rate limiting, stale-serve on hub
//! outage, and 503 before the first fetch.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use apti_core::protocol::ApiScope;
use apti_core::Tlp;
use apti_statsd::client::AptidClient;
use apti_statsd::config::{Aptid, Server};
use apti_statsd::poll::{Poller, SharedSnapshot};
use apti_statsd::server::{self, AppState, RateLimiter};
use aptid::config::Config as AptidConfig;
use aptid::{api, db, engine, publish, start_with_listeners, Daemon};
use axum::http::StatusCode;
use serde_json::{json, Value};
use tokio::net::TcpListener;

const PUSH: &str = "push-token-0123456789";
const READ: &str = "read-token-0123456789";

/// A hub that activates its own (TLP:CLEAR and TLP:GREEN) Sightings.
async fn spawn_aptid(dir: &Path) -> Daemon {
    let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = public.local_addr().unwrap().port();
    let cfg = format!(
        r#"
[instance]
base_url = "http://127.0.0.1:{port}"
organization = "Hub"
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
    let d = start_with_listeners(AptidConfig::parse(&cfg).unwrap(), public, api)
        .await
        .unwrap();
    d.state
        .db
        .call(|c| {
            let add = |name, secret, scope, tlp| {
                db::insert_api_token(c, name, &api::hash_token(secret), &[scope], tlp)
            };
            add("push", PUSH, ApiScope::Push, Tlp::Amber)?;
            add("read", READ, ApiScope::Read, Tlp::Clear)?;
            Ok(())
        })
        .await
        .unwrap();
    d
}

fn make_state(snapshot: SharedSnapshot, limit: u32) -> AppState {
    AppState {
        snapshot,
        window_days: 30,
        interval: Duration::from_secs(60),
        limiter: Arc::new(RateLimiter::new(limit as usize, Duration::from_secs(60))),
        cfg: Server {
            bind: Some("127.0.0.1:0".into()),
            title: "Test stats".into(),
            rate_limit_per_min: limit,
            ..Server::default()
        },
    }
}

/// Serve a state on an ephemeral port; returns its base URL.
async fn start_server(state: AppState) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = server::router(state);
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    format!("http://{}", addr)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let d = spawn_aptid(dir.path()).await;
    let api = format!("http://{}", d.api_addr);

    // Push a CLEAR and a GREEN Sighting; both activate (local weight meets k).
    let r = reqwest::Client::new()
        .post(format!("{api}/api/v1/observations"))
        .bearer_auth(PUSH)
        .json(&json!([
            {"value": "45.13.7.9", "behavior": "scan", "tlp": "clear"},
            {"value": "45.13.7.11", "behavior": "scan", "tlp": "green"}
        ]))
        .send()
        .await
        .unwrap();
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["accepted"], 2, "{body}");
    publish::run_batch(&d.state).await.unwrap();
    engine::recompute(&d.state).await.unwrap();

    // Poll the hub once (with the CLEAR-capped token) and serve it.
    let client = AptidClient::new(&Aptid {
        url: api.clone(),
        read_token: READ.into(),
        timeout_secs: 10,
    })
    .unwrap();
    let poller = Poller::new(client, Duration::from_secs(60), 30);
    poller.step().await.unwrap();
    let base = start_server(make_state(poller.snapshot(), 1000)).await;
    let c = reqwest::Client::new();

    // Individual observables are never served: the hub's active list and
    // timeline are not republished.
    for path in ["/api/v1/active", "/api/v1/timeline"] {
        let s = c
            .get(format!("{base}{path}"))
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(s, StatusCode::NOT_FOUND, "{path}");
    }

    // The node directory is a valid JSON array (the hub has no followers here).
    let n: Value = c
        .get(format!("{base}/api/v1/nodes"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(n.is_array(), "{n}");

    // The page shows aggregates and leaks no raw observable.
    let html = c
        .get(format!("{base}/"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("TLP:CLEAR only"), "{html}");
    assert!(
        !html.contains("45.13.7"),
        "raw observable leaked onto the page"
    );
    assert!(html.contains("<div class=\"n\">1</div>"), "{html}");

    // ETag / 304.
    let etag = c
        .get(format!("{base}/api/v1/nodes"))
        .send()
        .await
        .unwrap()
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let s = c
        .get(format!("{base}/api/v1/nodes"))
        .header("if-none-match", &etag)
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(s, StatusCode::NOT_MODIFIED);

    // Stale-serve: the hub is gone, but the last snapshot is still served.
    d.shutdown();
    let html = c
        .get(format!("{base}/"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("<div class=\"n\">1</div>"), "{html}");
}

#[tokio::test]
async fn rate_limited() {
    let state = make_state(SharedSnapshot::default(), 2);
    let base = start_server(state).await;
    let c = reqwest::Client::new();
    let mut limited = false;
    for _ in 0..6 {
        let s = c
            .get(format!("{base}/api/v1/nodes"))
            .send()
            .await
            .unwrap()
            .status();
        if s == StatusCode::TOO_MANY_REQUESTS {
            limited = true;
        }
    }
    assert!(limited, "expected a 429 under the rate limit");
}

#[tokio::test]
async fn no_snapshot_is_503() {
    let base = start_server(make_state(SharedSnapshot::default(), 1000)).await;
    let s = reqwest::Client::new()
        .get(format!("{base}/api/v1/nodes"))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
}
