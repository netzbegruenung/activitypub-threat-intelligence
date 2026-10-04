//! Allowlist file → aptid, against an in-process aptid.

use std::path::Path;

use apti_allowlist::client::AptidClient;
use apti_allowlist::config::Config;
use apti_allowlist::reconcile::Mode;
use apti_allowlist::sync::{Report, Syncer};
use apti_core::protocol::ApiScope;
use apti_core::Tlp;
use aptid::{api, db, Daemon};
use tokio::net::TcpListener;

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
            db::insert_api_token(
                c,
                "allow",
                &api::hash_token(ALLOW),
                &[ApiScope::Allowlist],
                Tlp::Green,
            )?;
            Ok(())
        })
        .await
        .unwrap();
    d
}

fn config(d: &Daemon, file: &Path, extra: &str) -> Config {
    Config::parse(&format!(
        r#"
[aptid]
url = "http://{api}"
token = "{ALLOW}"
[file]
path = "{f}"
[sync]
poll_interval_secs = 1
resync_interval_secs = 3600
{extra}
"#,
        api = d.api_addr,
        f = file.display()
    ))
    .unwrap()
}

fn syncer(cfg: &Config, mode: Mode) -> Syncer {
    Syncer::new(cfg, mode, AptidClient::new(cfg).unwrap())
}

/// Sorted values of all local entries.
async fn values(cfg: &Config) -> Vec<String> {
    let mut v: Vec<String> = AptidClient::new(cfg)
        .unwrap()
        .list()
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.observable_value)
        .collect();
    v.sort();
    v
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn source_of_truth() {
    let dir = tempfile::tempdir().unwrap();
    let d = spawn_aptid(&dir.path().join("aptid")).await;
    let file = dir.path().join("allowlist.txt");
    let cfg = config(&d, &file, "max_removals = 2");
    let client = AptidClient::new(&cfg).unwrap();

    // An entry created elsewhere (TUI, curl) is never removed by default.
    client.add("192.0.2.1", "added by hand").await.unwrap();

    std::fs::write(
        &file,
        "# office\n45.13.7.9\n45.13.7.0/24 # lab\nexample.org\nnope nope\n",
    )
    .unwrap();
    let mut s = syncer(&cfg, Mode::SourceOfTruth);
    let r = s.sync_once().await.unwrap();
    assert_eq!((r.added, r.invalid, r.removed), (3, 1, 0), "{r}");
    assert_eq!(
        values(&cfg).await,
        vec!["192.0.2.1", "45.13.7.0/24", "45.13.7.9", "example.org"]
    );
    let entries = client.list().await.unwrap();
    let marked = entries
        .iter()
        .filter(|e| e.summary.as_deref() == Some(cfg.marker().as_str()))
        .count();
    assert_eq!(marked, 3);

    // Unchanged file: nothing to do.
    assert_eq!(
        s.sync_once().await.unwrap(),
        Report {
            invalid: 1,
            ..Default::default()
        }
    );

    // A value inserted in the middle and one removed.
    std::fs::write(&file, "45.13.7.9\n198.51.100.7\n45.13.7.0/24\n").unwrap();
    let r = s.sync_once().await.unwrap();
    assert_eq!((r.added, r.removed), (1, 1), "{r}");
    assert_eq!(
        values(&cfg).await,
        vec!["192.0.2.1", "198.51.100.7", "45.13.7.0/24", "45.13.7.9"]
    );

    // An entry deleted elsewhere is restored.
    let id = client
        .list()
        .await
        .unwrap()
        .into_iter()
        .find(|e| e.observable_value == "198.51.100.7")
        .unwrap()
        .id;
    client.remove(id).await.unwrap();
    assert_eq!(s.sync_once().await.unwrap().added, 1);

    // Guards: an empty file and too many removals remove nothing.
    std::fs::write(&file, "# all gone\n").unwrap();
    let r = s.sync_once().await.unwrap();
    assert_eq!((r.removed, r.removals_skipped), (0, 3), "{r}");
    std::fs::write(&file, "203.0.113.5\n").unwrap();
    let r = s.sync_once().await.unwrap();
    assert_eq!((r.added, r.removed, r.removals_skipped), (1, 0, 3), "{r}");
    std::fs::write(&file, "203.0.113.5\n45.13.7.9\n").unwrap();
    let r = s.sync_once().await.unwrap();
    assert_eq!((r.removed, r.removals_skipped), (2, 0), "{r}");
    assert_eq!(
        values(&cfg).await,
        vec!["192.0.2.1", "203.0.113.5", "45.13.7.9"]
    );

    // A missing file is an error, not an empty allowlist.
    std::fs::remove_file(&file).unwrap();
    assert!(s.sync_once().await.is_err());
    assert_eq!(values(&cfg).await.len(), 3);

    // prune_all also removes entries this tool did not create.
    std::fs::write(&file, "45.13.7.9\n").unwrap();
    let cfg = config(&d, &file, "prune_all = true");
    let r = syncer(&cfg, Mode::SourceOfTruth).sync_once().await.unwrap();
    assert_eq!(r.removed, 2, "{r}");
    assert_eq!(values(&cfg).await, vec!["45.13.7.9"]);

    d.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn append_and_watch() {
    let dir = tempfile::tempdir().unwrap();
    let d = spawn_aptid(&dir.path().join("aptid")).await;
    let file = dir.path().join("allowlist.txt");
    let cfg = config(&d, &file, "");

    std::fs::write(&file, "45.13.7.9\n45.13.7.10\n").unwrap();
    let mut s = syncer(&cfg, Mode::Append);
    // The first poll reconciles immediately.
    assert_eq!(s.poll().await.unwrap().added, 2);
    // Unchanged before the resync interval: no reconcile.
    assert!(s.poll().await.is_none());

    // A change is applied once it has been stable for two polls.
    std::fs::write(&file, "45.13.7.9\n").unwrap();
    assert!(s.poll().await.is_none());
    std::fs::write(&file, "45.13.7.9\n45.13.7.11\n").unwrap();
    assert!(s.poll().await.is_none(), "content changed again");
    let r = s.poll().await.unwrap();
    // Append mode never removes: 45.13.7.10 stays.
    assert_eq!((r.added, r.removed), (1, 0), "{r}");
    assert_eq!(
        values(&cfg).await,
        vec!["45.13.7.10", "45.13.7.11", "45.13.7.9"]
    );

    // aptid unreachable: the poll fails and is retried after a backoff.
    let mut down = cfg.clone();
    down.aptid.url = "http://127.0.0.1:1".into();
    let mut s = syncer(&down, Mode::Append);
    assert!(s.poll().await.is_none());
    assert!(s.sync_once().await.is_err());

    d.shutdown();
}
