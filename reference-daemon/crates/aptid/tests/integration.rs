//! End-to-end tests: REST API, control socket and federation between two
//! daemons on localhost.

use std::path::Path;
use std::time::Duration;

use apti_core::policy::OperatorPolicy;
use apti_core::protocol::{
    AllowlistScope, ApiScope, NewAllowlistEntry, NewApiToken, Reply, Request,
};
use apti_core::{Behavior, Tlp};
use aptid::config::Config;
use aptid::{api, db, engine, inbox, publish, Daemon};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixStream};

const PUSH: &str = "push-token-0123456789";
const READ: &str = "read-token-0123456789";
const READ_CLEAR: &str = "read-clear-0123456789";
const ALLOW: &str = "allow-token-0123456789";
const ADMIN: &str = "admin-token-0123456789";

async fn spawn(dir: &Path, name: &str) -> Daemon {
    spawn_with(dir, name, "").await
}

/// Spawn a daemon; `federation` is appended to the `[federation]` table.
async fn spawn_with(dir: &Path, name: &str, federation: &str) -> Daemon {
    let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = public.local_addr().unwrap().port();
    let d = dir.join(name);
    let cfg = format!(
        r#"
[instance]
base_url = "http://127.0.0.1:{port}"
organization = "Org {name}"
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
{federation}
[publish]
batch_interval_secs = 3600
[policy]
recompute_interval_secs = 3600
allowlist = ["8.8.8.8"]
"#,
        db = d.join("db.sqlite").display(),
        key = d.join("key.pem").display(),
        sock = d.join("control.sock").display(),
    );
    let cfg = Config::parse(&cfg).unwrap();
    let d = aptid::start_with_listeners(cfg, public, api).await.unwrap();
    add_token(&d, "push", PUSH, &[ApiScope::Push], Tlp::Green).await;
    add_token(&d, "read", READ, &[ApiScope::Read], Tlp::Amber).await;
    add_token(&d, "read-clear", READ_CLEAR, &[ApiScope::Read], Tlp::Clear).await;
    add_token(&d, "allow", ALLOW, &[ApiScope::Allowlist], Tlp::Green).await;
    add_token(
        &d,
        "admin",
        ADMIN,
        &[ApiScope::Allowlist, ApiScope::Publish],
        Tlp::Green,
    )
    .await;
    d
}

/// Store a token with a known secret (the control socket only hands out
/// generated ones).
async fn add_token(d: &Daemon, name: &str, secret: &str, scopes: &[ApiScope], max_tlp: Tlp) {
    let (name, hash, scopes) = (name.to_string(), api::hash_token(secret), scopes.to_vec());
    d.state
        .db
        .call(move |c| db::insert_api_token(c, &name, &hash, &scopes, max_tlp))
        .await
        .unwrap();
}

async fn ctl(d: &Daemon, req: Request) -> Reply {
    let stream = UnixStream::connect(&d.state.cfg.control.socket)
        .await
        .unwrap();
    let (r, mut w) = stream.into_split();
    let mut line = serde_json::to_vec(&req).unwrap();
    line.push(b'\n');
    w.write_all(&line).await.unwrap();
    let mut lines = BufReader::new(r).lines();
    let reply = lines.next_line().await.unwrap().unwrap();
    serde_json::from_str(&reply).unwrap()
}

async fn ctl_ok(d: &Daemon, req: Request) {
    match ctl(d, req).await {
        Reply::Done => {}
        other => panic!("unexpected reply {other:?}"),
    }
}

async fn push(d: &Daemon, token: &str, body: Value) -> (u16, Value) {
    let r = reqwest::Client::new()
        .post(format!("http://{}/api/v1/observations", d.api_addr))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    (status, r.json().await.unwrap_or(Value::Null))
}

async fn active(d: &Daemon, token: &str) -> Vec<Value> {
    let r: Value = reqwest::Client::new()
        .get(format!("http://{}/api/v1/active", d.api_addr))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    r["entries"].as_array().cloned().unwrap_or_default()
}

/// Poll `f` until it returns `Some`, or panic after 20 s.
async fn wait_for<T, F, Fut>(what: &str, mut f: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    for _ in 0..200 {
        if let Some(v) = f().await {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_pipeline() {
    let dir = tempfile::tempdir().unwrap();
    let d = spawn(dir.path(), "a").await;

    // Authentication and scopes.
    let (s, _) = push(
        &d,
        "wrong-token-0000000000",
        json!({"value": "45.13.7.9", "behavior": "scan"}),
    )
    .await;
    assert_eq!(s, 401);
    let (s, _) = push(&d, READ, json!({"value": "45.13.7.9", "behavior": "scan"})).await;
    assert_eq!(s, 403);

    let (s, r) = push(
        &d,
        PUSH,
        json!([
            {"value": "45.13.7.9", "behavior": "ssh-bruteforce", "port": 22, "service": "ssh", "count": 12},
            {"value": "10.0.0.1", "behavior": "scan"},
            {"value": "8.8.8.8", "behavior": "scan"},
            {"value": "45.13.7.9", "behavior": "bogus"},
            {"value": "Evil-Domain.COM.", "behavior": "phishing"}
        ]),
    )
    .await;
    assert_eq!(s, 200, "{r}");
    assert_eq!(r["accepted"], 2, "{r}");
    let errors: Vec<&str> = r["rejected"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["error"].as_str().unwrap())
        .collect();
    assert_eq!(errors.len(), 3);
    assert!(errors.iter().any(|e| e.contains("special-purpose")));
    assert!(errors.iter().any(|e| e.contains("allowlisted")));

    assert_eq!(publish::run_batch(&d.state).await.unwrap(), 2);
    engine::recompute(&d.state).await.unwrap();

    // Local weight (2) meets k (2): our own Sightings activate.
    let list = active(&d, READ).await;
    assert_eq!(list.len(), 2, "{list:?}");
    let ssh = list
        .iter()
        .find(|e| e["observableValue"] == "45.13.7.9")
        .unwrap();
    assert_eq!(ssh["behavior"], "ssh-bruteforce");
    assert_eq!(ssh["tlp"], "green");
    assert_eq!(ssh["ports"], json!([22]));
    assert!(ssh["ttl"].as_i64().unwrap() > 23 * 3600);
    assert!(list
        .iter()
        .any(|e| e["observableValue"] == "evil-domain.com"));
    // TLP is preserved: a CLEAR-only client gets nothing.
    assert!(active(&d, READ_CLEAR).await.is_empty());

    // activeObjects requires signed fetch.
    let r = reqwest::get(format!("{}/actor/active?page=true", d.state.urls.base))
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);
    // Actor and WebFinger are public.
    let wf: Value = reqwest::get(format!(
        "{}/.well-known/webfinger?resource=acct:feed@127.0.0.1:{}",
        d.state.urls.base,
        d.public_addr.port()
    ))
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(wf["links"][0]["href"], d.state.urls.actor);
    let org: Value = reqwest::get(&d.state.urls.org)
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(org["operatedActors"], json!([d.state.urls.actor]));

    // Control socket.
    let Reply::Status(st) = ctl(&d, Request::Status).await else {
        panic!()
    };
    assert_eq!(st.active, 2);
    let Reply::Lookup(l) = ctl(
        &d,
        Request::Lookup {
            value: "45.13.7.9".into(),
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(l.evidence.len(), 1);
    assert_eq!(l.assessments.len(), 1);
    assert!(l.assessments[0].active);

    // Behaviour policy: k = off disables Sighting activation.
    ctl_ok(
        &d,
        Request::SetBehaviorPolicy {
            behavior: Behavior::Phishing,
            overrides: apti_core::policy::BehaviorOverride {
                k: Some(apti_core::policy::Threshold::Off),
                ..Default::default()
            },
            default_tlp: Some(Tlp::Amber),
        },
    )
    .await;
    ctl_ok(&d, Request::Recompute).await;
    assert_eq!(active(&d, READ).await.len(), 1);

    // Local allowlist suspends.
    ctl_ok(
        &d,
        Request::AddAllowlist(NewAllowlistEntry {
            scope: AllowlistScope::Local,
            value: "45.13.7.0/24".into(),
            behaviors: vec![],
            tlp: None,
            valid_until: None,
            summary: Some("test".into()),
            source: None,
        }),
    )
    .await;
    ctl_ok(&d, Request::Recompute).await;
    assert!(active(&d, READ).await.is_empty());

    // Invalid input is reported, not fatal.
    assert!(matches!(
        ctl(
            &d,
            Request::Lookup {
                value: "not a value".into()
            }
        )
        .await,
        Reply::Error(_)
    ));
    d.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn federation_between_two_daemons() {
    let dir = tempfile::tempdir().unwrap();
    let a = spawn(dir.path(), "a").await;
    let b = spawn(dir.path(), "b").await;
    let a_actor = a.state.urls.actor.clone();
    let b_actor = b.state.urls.actor.clone();
    let a_org = a.state.urls.org.clone();

    // A publishes a GREEN Sighting before B follows.
    push(
        &a,
        PUSH,
        json!({"value": "45.13.7.9", "behavior": "ssh-bruteforce", "port": 22}),
    )
    .await;
    publish::run_batch(&a.state).await.unwrap();

    // B follows A via WebFinger; A requires approval.
    ctl_ok(
        &b,
        Request::Follow {
            handle: format!("feed@127.0.0.1:{}", a.public_addr.port()),
        },
    )
    .await;
    wait_for("follow request at A", || async {
        match ctl(&a, Request::ListFollowers).await {
            Reply::Followers(f) => f
                .iter()
                .any(|f| f.actor == b_actor && f.state == "pending")
                .then_some(()),
            _ => None,
        }
    })
    .await;
    ctl_ok(
        &a,
        Request::ApproveFollower {
            actor: b_actor.clone(),
        },
    )
    .await;
    wait_for("accepted follow at B", || async {
        match ctl(&b, Request::ListFollowing).await {
            Reply::Following(f) => f
                .iter()
                .any(|f| f.actor == a_actor && f.state == "accepted")
                .then_some(()),
            _ => None,
        }
    })
    .await;

    // After Accept, B re-reads activeObjects and now sees the GREEN Sighting.
    wait_for("synced sighting at B", || async {
        match ctl(
            &b,
            Request::Lookup {
                value: "45.13.7.9".into(),
            },
        )
        .await
        {
            Reply::Lookup(l) => (!l.evidence.is_empty()).then_some(()),
            _ => None,
        }
    })
    .await;

    // A's operator link is verified at B.
    let Reply::Operators(ops) = ctl(&b, Request::ListOperators).await else {
        panic!()
    };
    let op = ops
        .iter()
        .find(|o| o.id == a_org)
        .expect("A's operator known at B");
    assert_eq!(op.source, "verified");
    assert!(op.actors.contains(&a_actor));

    // Untrusted by default: nothing is active, item queued for review.
    ctl_ok(&b, Request::Recompute).await;
    assert!(active(&b, READ).await.is_empty());
    let Reply::Review(items) = ctl(
        &b,
        Request::ListReview {
            include_resolved: false,
        },
    )
    .await
    else {
        panic!()
    };
    assert!(items
        .iter()
        .any(|i| i.kind == "untrusted" && i.observable_value == "45.13.7.9"));

    // Trust A with weight 2 (= k): A alone activates.
    ctl_ok(
        &b,
        Request::SetOperatorPolicy {
            operator: a_org.clone(),
            behavior: None,
            policy: OperatorPolicy {
                trusted: true,
                weight: 2.0,
            },
        },
    )
    .await;
    ctl_ok(&b, Request::Recompute).await;
    let list = active(&b, READ).await;
    assert_eq!(list.len(), 1, "{list:?}");
    assert_eq!(list[0]["observableValue"], "45.13.7.9");

    // New observations are pushed to B's inbox (Create, then Update).
    push(
        &a,
        PUSH,
        json!({"value": "2a01:4f8:1::/48", "behavior": "scan"}),
    )
    .await;
    publish::run_batch(&a.state).await.unwrap();
    wait_for("delivered sighting at B", || async {
        match ctl(
            &b,
            Request::Lookup {
                value: "2a01:4f8:1::/48".into(),
            },
        )
        .await
        {
            Reply::Lookup(l) => (!l.evidence.is_empty()).then_some(()),
            _ => None,
        }
    })
    .await;
    push(
        &a,
        PUSH,
        json!({"value": "2a01:4f8:1::/48", "behavior": "scan", "count": 5}),
    )
    .await;
    publish::run_batch(&a.state).await.unwrap();
    wait_for("updated sighting at B", || async {
        match ctl(
            &b,
            Request::Lookup {
                value: "2a01:4f8:1::/48".into(),
            },
        )
        .await
        {
            Reply::Lookup(l) => l
                .evidence
                .iter()
                .any(|e| e.detail.contains("count 6"))
                .then_some(()),
            _ => None,
        }
    })
    .await;

    // A publishes an allowlist entry; B (trusting A) suspends.
    ctl_ok(
        &a,
        Request::AddAllowlist(NewAllowlistEntry {
            scope: AllowlistScope::Published,
            value: "45.13.7.9".into(),
            behaviors: vec![],
            tlp: Some(Tlp::Green),
            valid_until: None,
            summary: Some("false positive".into()),
            source: None,
        }),
    )
    .await;
    wait_for("allowlist suspension at B", || async {
        publish::run_batch(&a.state).await.unwrap();
        ctl_ok(&b, Request::Recompute).await;
        active(&b, READ)
            .await
            .iter()
            .all(|e| e["observableValue"] != "45.13.7.9")
            .then_some(())
    })
    .await;

    // Withdrawing the entry (Delete) re-activates.
    let Reply::Allowlist(entries) = ctl(&a, Request::ListAllowlist).await else {
        panic!()
    };
    ctl_ok(&a, Request::RemoveAllowlist { id: entries[0].id }).await;
    wait_for("re-activation at B", || async {
        publish::run_batch(&a.state).await.unwrap();
        ctl_ok(&b, Request::Recompute).await;
        active(&b, READ)
            .await
            .iter()
            .any(|e| e["observableValue"] == "45.13.7.9")
            .then_some(())
    })
    .await;

    // Unfollow is delivered as Undo.
    ctl_ok(
        &b,
        Request::Unfollow {
            actor: a_actor.clone(),
        },
    )
    .await;
    wait_for("follower removed at A", || async {
        match ctl(&a, Request::ListFollowers).await {
            Reply::Followers(f) => f.iter().all(|f| f.actor != b_actor).then_some(()),
            _ => None,
        }
    })
    .await;

    a.shutdown();
    b.shutdown();
}

async fn api(
    d: &Daemon,
    method: reqwest::Method,
    path: &str,
    token: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let mut req = reqwest::Client::new()
        .request(method, format!("http://{}{path}", d.api_addr))
        .bearer_auth(token);
    if let Some(b) = body {
        req = req.json(&b);
    }
    let r = req.send().await.unwrap();
    let status = r.status().as_u16();
    (status, r.json().await.unwrap_or(Value::Null))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rest_allowlist() {
    use reqwest::Method;
    let dir = tempfile::tempdir().unwrap();
    let d = spawn(dir.path(), "a").await;

    push(&d, PUSH, json!({"value": "45.13.7.9", "behavior": "scan"})).await;
    publish::run_batch(&d.state).await.unwrap();
    engine::recompute(&d.state).await.unwrap();
    assert_eq!(active(&d, READ).await.len(), 1);

    // Scope checks.
    let body = json!({"value": "45.13.7.0/24", "summary": "our scanner"});
    let (s, _) = api(
        &d,
        Method::POST,
        "/api/v1/allowlist",
        READ,
        Some(body.clone()),
    )
    .await;
    assert_eq!(s, 403);
    let (s, _) = api(
        &d,
        Method::POST,
        "/api/v1/allowlist",
        ALLOW,
        Some(json!({"value": "45.13.7.9", "scope": "published"})),
    )
    .await;
    assert_eq!(s, 403, "published requires publish scope");
    let (s, _) = api(
        &d,
        Method::POST,
        "/api/v1/allowlist",
        ALLOW,
        Some(json!({"value": "nonsense value"})),
    )
    .await;
    assert_eq!(s, 400);
    let (s, _) = api(
        &d,
        Method::POST,
        "/api/v1/allowlist",
        ALLOW,
        Some(json!({"value": "1.2.3.4", "behaviors": ["bogus"]})),
    )
    .await;
    assert_eq!(s, 400);

    // Create, idempotent repeat, list, get.
    let (s, e) = api(
        &d,
        Method::POST,
        "/api/v1/allowlist",
        ALLOW,
        Some(body.clone()),
    )
    .await;
    assert_eq!(s, 201, "{e}");
    assert_eq!(e["observableValue"], "45.13.7.0/24");
    assert_eq!(e["scope"], "local");
    let id = e["id"].as_i64().unwrap();
    let (s, e2) = api(&d, Method::POST, "/api/v1/allowlist", ALLOW, Some(body)).await;
    assert_eq!(s, 200);
    assert_eq!(e2["id"].as_i64(), Some(id));
    let (s, list) = api(&d, Method::GET, "/api/v1/allowlist?scope=local", READ, None).await;
    assert_eq!(s, 200);
    assert_eq!(list.as_array().unwrap().len(), 1);
    let (s, _) = api(
        &d,
        Method::GET,
        &format!("/api/v1/allowlist/{id}"),
        ALLOW,
        None,
    )
    .await;
    assert_eq!(s, 200);

    // Allowlisted: suspended, and further pushes are rejected.
    engine::recompute(&d.state).await.unwrap();
    assert!(active(&d, READ).await.is_empty());
    let (_, r) = push(&d, PUSH, json!({"value": "45.13.7.10", "behavior": "scan"})).await;
    assert_eq!(r["accepted"], 0);

    // Published entry creates a local Opinion; deleting it withdraws it.
    let (s, p) = api(
        &d,
        Method::POST,
        "/api/v1/allowlist",
        ADMIN,
        Some(json!({"value": "45.13.8.1", "scope": "published", "tlp": "green", "behaviors": ["scan"],
                    "summary": "our scanner", "source": "sync-tool:/etc/x"})),
    )
    .await;
    assert_eq!(s, 201, "{p}");
    let object_id = p["objectId"].as_str().unwrap().to_string();
    assert!(p["validUntil"].is_string());
    assert_eq!(p["source"], "sync-tool:/etc/x");
    let pid = p["id"].as_i64().unwrap();
    let last_activity = || async {
        d.state
            .db
            .call(|c| aptid::db::recent_activities(c, 1))
            .await
            .unwrap()
            .pop()
            .map(|a| a.json)
            .unwrap_or_default()
    };
    // The Create is sent with the next batch; the source is not published.
    assert_ne!(
        last_activity().await["object"]["id"].as_str(),
        Some(object_id.as_str())
    );
    assert_eq!(publish::run_batch(&d.state).await.unwrap(), 1);
    let act = last_activity().await;
    assert_eq!(act["type"], "Create");
    assert_eq!(act["object"]["id"].as_str(), Some(object_id.as_str()));
    assert_eq!(act["object"]["summary"], "our scanner");
    assert!(!act.to_string().contains("sync-tool"), "{act}");

    // A later validUntil extends the entry and sends an Update of the Opinion.
    let later = "2099-01-01T00:00:00Z";
    let (s, x) = api(
        &d,
        Method::POST,
        "/api/v1/allowlist",
        ADMIN,
        Some(
            json!({"value": "45.13.8.1", "scope": "published", "tlp": "green",
                    "behaviors": ["scan"], "validUntil": later}),
        ),
    )
    .await;
    assert_eq!(s, 200, "{x}");
    assert_eq!(x["id"].as_i64(), Some(pid));
    assert_eq!(x["objectId"].as_str(), Some(object_id.as_str()));
    assert_eq!(x["validUntil"], "2099-01-01T00:00:00Z");
    let oid = object_id.clone();
    let ev = d
        .state
        .db
        .call(move |c| aptid::db::get_evidence(c, &oid))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        ev.object.valid_until.map(|t| t.to_rfc3339()),
        Some("2099-01-01T00:00:00+00:00".into())
    );
    assert!(ev.object.updated.is_some());
    assert_eq!(publish::run_batch(&d.state).await.unwrap(), 1);
    let act = last_activity().await;
    assert_eq!(act["type"], "Update");
    assert_eq!(act["object"]["id"].as_str(), Some(object_id.as_str()));
    assert_eq!(act["object"]["validUntil"], later);
    // An earlier validUntil changes nothing.
    let (s, x) = api(
        &d,
        Method::POST,
        "/api/v1/allowlist",
        ADMIN,
        Some(
            json!({"value": "45.13.8.1", "scope": "published", "tlp": "green",
                    "behaviors": ["scan"], "validUntil": "2098-01-01T00:00:00Z"}),
        ),
    )
    .await;
    assert_eq!((s, x["validUntil"].as_str()), (200, Some(later)));

    // Another TLP is another entry.
    let (s, c) = api(
        &d,
        Method::POST,
        "/api/v1/allowlist",
        ADMIN,
        Some(json!({"value": "45.13.8.1", "scope": "published", "tlp": "clear", "behaviors": ["scan"]})),
    )
    .await;
    assert_eq!(s, 201, "{c}");
    assert_ne!(c["id"].as_i64(), Some(pid));
    let (s, _) = api(
        &d,
        Method::DELETE,
        &format!("/api/v1/allowlist/{}", c["id"]),
        ADMIN,
        None,
    )
    .await;
    assert_eq!(s, 200);
    // Created and withdrawn within one interval: only the Delete is sent.
    assert_eq!(publish::run_batch(&d.state).await.unwrap(), 1);
    let act = last_activity().await;
    assert_eq!(act["type"], "Delete");
    assert_eq!(act["object"], c["objectId"]);

    // Several entries in one interval share one activity.
    let mut ids = vec![];
    for v in ["45.13.9.1", "45.13.9.2", "45.13.9.3"] {
        let (s, e) = api(
            &d,
            Method::POST,
            "/api/v1/allowlist",
            ADMIN,
            Some(json!({"value": v, "scope": "published", "tlp": "green"})),
        )
        .await;
        assert_eq!(s, 201, "{e}");
        ids.push(e["id"].as_i64().unwrap());
    }
    assert_eq!(publish::run_batch(&d.state).await.unwrap(), 3);
    let act = last_activity().await;
    assert_eq!(act["type"], "Create");
    assert_eq!(act["object"].as_array().map(Vec::len), Some(3), "{act}");
    for id in ids {
        let (s, _) = api(
            &d,
            Method::DELETE,
            &format!("/api/v1/allowlist/{id}"),
            ADMIN,
            None,
        )
        .await;
        assert_eq!(s, 200);
    }
    assert_eq!(publish::run_batch(&d.state).await.unwrap(), 3);
    let act = last_activity().await;
    assert_eq!(act["type"], "Delete");
    assert_eq!(act["object"].as_array().map(Vec::len), Some(3), "{act}");
    assert_eq!(publish::run_batch(&d.state).await.unwrap(), 0);
    let (s, _) = api(
        &d,
        Method::DELETE,
        &format!("/api/v1/allowlist/{pid}"),
        ALLOW,
        None,
    )
    .await;
    assert_eq!(s, 403, "removing a published entry requires publish scope");
    let (s, _) = api(
        &d,
        Method::DELETE,
        &format!("/api/v1/allowlist/{pid}"),
        ADMIN,
        None,
    )
    .await;
    assert_eq!(s, 200);
    let ev = d
        .state
        .db
        .call(move |c| aptid::db::get_evidence(c, &object_id))
        .await
        .unwrap()
        .unwrap();
    assert!(ev.deleted.is_some());

    // Delete the local entry: active again.
    let (s, _) = api(
        &d,
        Method::DELETE,
        &format!("/api/v1/allowlist/{id}"),
        ALLOW,
        None,
    )
    .await;
    assert_eq!(s, 200);
    let (s, _) = api(
        &d,
        Method::DELETE,
        &format!("/api/v1/allowlist/{id}"),
        ALLOW,
        None,
    )
    .await;
    assert_eq!(s, 404);
    engine::recompute(&d.state).await.unwrap();
    assert_eq!(active(&d, READ).await.len(), 1);
    d.shutdown();
}

/// Remote input that used to crash the engine or exhaust resources.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hostile_remote_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let d = spawn_with(dir.path(), "a", "max_evidence_per_publisher = 2").await;
    let peer = "https://peer.example.org/actor";
    let now = chrono::Utc::now();
    let earlier = db::ts(now - chrono::TimeDelta::minutes(1));
    let sighting = |i: u8| {
        json!({
            "type": "Sighting", "id": format!("https://peer.example.org/s/{i}"),
            "attributedTo": peer, "published": earlier,
            "observableType": "ipv4-addr", "observableValue": format!("45.13.7.{i}"),
            "observedBehavior": "scan", "firstSeen": earlier, "lastSeen": earlier,
            "count": 1, "tlp": "clear"
        })
    };

    // Per-publisher quota: new objects beyond it are dropped, updates of
    // known objects are still accepted.
    let r = inbox::ingest_objects(&d.state, peer, (1..=3).map(sighting).collect(), false)
        .await
        .unwrap();
    assert_eq!((r.stored, r.ignored), (2, 1), "{r:?}");
    let mut update = sighting(1);
    update["updated"] = json!(db::ts(now));
    let r = inbox::ingest_objects(&d.state, peer, vec![update], true)
        .await
        .unwrap();
    assert_eq!(r.stored, 1, "{r:?}");

    // Extended-year timestamps are rejected on ingest ...
    let extreme = json!({
        "type": "ThreatIndicator", "id": "https://peer.example.org/i/1",
        "attributedTo": peer, "published": "+262142-12-31T00:00:00Z",
        "observableType": "ipv4-addr", "observableValue": "45.13.7.1",
        "observedBehavior": "scan", "validFrom": "2026-01-01T00:00:00Z",
        "validUntil": "+262142-12-31T23:00:00Z", "tlp": "clear"
    });
    let r = inbox::ingest_objects(&d.state, peer, vec![extreme.clone()], false)
        .await
        .unwrap();
    assert_eq!(r.invalid, 1, "{r:?}");
    // ... and objects stored before that check do not crash the engine.
    let o: apti_core::EvidenceObject = serde_json::from_value(extreme).unwrap();
    d.state
        .db
        .call(move |c| db::upsert_evidence(c, &o, false, &[], None))
        .await
        .unwrap();
    engine::recompute(&d.state).await.unwrap();

    // Control characters in remote strings are rejected.
    let mut evil = sighting(2);
    evil["summary"] = json!("\u{1b}]52;c;cm0gLXJmIH4=\u{7}");
    evil["updated"] = json!(db::ts(now));
    let r = inbox::ingest_objects(&d.state, peer, vec![evil], true)
        .await
        .unwrap();
    assert_eq!(r.invalid, 1, "{r:?}");
    d.shutdown();
}

/// A Sighting must not be less restrictive than the indicators it
/// references (Section 4.4).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn indicator_refs_tlp() {
    let dir = tempfile::tempdir().unwrap();
    let d = spawn(dir.path(), "a").await;
    let peer = "https://peer.example.org/actor";
    let now = chrono::Utc::now();
    let earlier = db::ts(now - chrono::TimeDelta::minutes(1));
    let later = db::ts(now + chrono::TimeDelta::days(1));
    let indicator = json!({
        "type": "ThreatIndicator", "id": "https://peer.example.org/i/1",
        "attributedTo": peer, "published": earlier,
        "observableType": "ipv4-addr", "observableValue": "45.13.7.1",
        "observedBehavior": "scan", "validFrom": earlier, "validUntil": later,
        "tlp": "amber"
    });
    let sighting = |id: &str, tlp: &str| {
        json!({
            "type": "Sighting", "id": format!("https://peer.example.org/s/{id}"),
            "attributedTo": peer, "published": earlier,
            "observableType": "ipv4-addr", "observableValue": "45.13.7.1",
            "observedBehavior": "scan", "firstSeen": earlier, "lastSeen": earlier,
            "count": 1, "tlp": tlp, "indicatorRefs": ["https://peer.example.org/i/1"]
        })
    };
    let r = inbox::ingest_objects(
        &d.state,
        peer,
        vec![
            indicator,
            sighting("1", "green"),
            sighting("2", "amber"),
            sighting("3", "amber+strict"),
        ],
        false,
    )
    .await
    .unwrap();
    assert_eq!((r.stored, r.invalid), (3, 1), "{r:?}");
    d.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn token_management() {
    let dir = tempfile::tempdir().unwrap();
    let d = spawn(dir.path(), "a").await;
    let obs = json!({"value": "45.13.7.9", "behavior": "scan"});

    let Reply::TokenCreated { token, secret } = ctl(
        &d,
        Request::CreateToken(NewApiToken {
            name: "sensor".into(),
            scopes: vec![ApiScope::Push, ApiScope::Push],
            max_tlp: Tlp::Green,
        }),
    )
    .await
    else {
        panic!("expected TokenCreated")
    };
    assert_eq!(token.scopes, vec![ApiScope::Push]);
    assert_eq!(push(&d, &secret, obs.clone()).await.0, 200);

    // Only the SHA-512 hash is stored.
    let (stored, last_used) = d
        .state
        .db
        .call(|c| {
            Ok(c.query_row(
                "SELECT hash, last_used FROM api_tokens WHERE name = 'sensor'",
                [],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(stored, api::hash_token(&secret));
    assert_ne!(stored, secret);
    assert!(last_used.is_some());

    // Invalid input is rejected.
    for (name, scopes) in [
        ("sensor", vec![ApiScope::Read]),
        ("bad name", vec![ApiScope::Read]),
        ("x", vec![]),
    ] {
        let r = ctl(
            &d,
            Request::CreateToken(NewApiToken {
                name: name.into(),
                scopes,
                max_tlp: Tlp::Green,
            }),
        )
        .await;
        assert!(matches!(r, Reply::Error(_)), "{name}: {r:?}");
    }

    // Scope changes apply immediately.
    ctl_ok(
        &d,
        Request::UpdateToken {
            id: token.id,
            scopes: vec![ApiScope::Read],
            max_tlp: Tlp::Clear,
        },
    )
    .await;
    assert_eq!(push(&d, &secret, obs.clone()).await.0, 403);

    // Rotation invalidates the old secret.
    ctl_ok(
        &d,
        Request::UpdateToken {
            id: token.id,
            scopes: vec![ApiScope::Push],
            max_tlp: Tlp::Clear,
        },
    )
    .await;
    let Reply::TokenCreated { secret: new, .. } =
        ctl(&d, Request::RotateToken { id: token.id }).await
    else {
        panic!("expected TokenCreated")
    };
    assert_ne!(new, secret);
    assert_eq!(push(&d, &secret, obs.clone()).await.0, 401);
    assert_eq!(push(&d, &new, obs.clone()).await.0, 200);

    let Reply::Tokens(list) = ctl(&d, Request::ListTokens).await else {
        panic!("expected Tokens")
    };
    assert!(list.iter().any(|t| t.name == "sensor"));
    assert_eq!(list.len(), 6);

    ctl_ok(&d, Request::DeleteToken { id: token.id }).await;
    assert_eq!(push(&d, &new, obs).await.0, 401);
    d.shutdown();
}
