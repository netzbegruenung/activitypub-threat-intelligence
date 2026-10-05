//! aptid timeline → GeoIP → HTML page, against an in-process aptid and a
//! generated MaxMind DB.

use std::path::Path;

use apti_core::protocol::ApiScope;
use apti_core::Tlp;
use apti_dashboard::config::Config;
use aptid::{api, db, inbox, publish, Daemon};
use serde_json::{json, Value};
use tokio::net::TcpListener;

const PUSH: &str = "push-token-0123456789";
const READ: &str = "read-token-0123456789";

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
            Ok(())
        })
        .await
        .unwrap();
    d
}

/// Minimal MaxMind DB writer: IPv6 tree, 24-bit records, GeoIP2 country
/// records. IPv4 networks live in `::/96`.
mod mmdb {
    use std::net::IpAddr;

    use ipnet::IpNet;

    #[derive(Clone, Copy)]
    enum Rec {
        Empty,
        Node(u32),
        Data(u32),
    }

    fn ctrl(out: &mut Vec<u8>, ty: u8, size: usize) {
        assert!(size < 29);
        if ty <= 7 {
            out.push((ty << 5) | size as u8);
        } else {
            out.extend([size as u8, ty - 7]);
        }
    }

    fn string(out: &mut Vec<u8>, s: &str) {
        ctrl(out, 2, s.len());
        out.extend(s.as_bytes());
    }

    fn uint(out: &mut Vec<u8>, ty: u8, v: u64) {
        let bytes: Vec<u8> = v
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        ctrl(out, ty, bytes.len());
        out.extend(bytes);
    }

    fn country(code: &str, name: &str) -> Vec<u8> {
        let mut d = Vec::new();
        ctrl(&mut d, 7, 1);
        string(&mut d, "country");
        ctrl(&mut d, 7, 2);
        string(&mut d, "iso_code");
        string(&mut d, code);
        string(&mut d, "names");
        ctrl(&mut d, 7, 1);
        string(&mut d, "en");
        string(&mut d, name);
        d
    }

    fn bits(net: IpNet) -> Vec<bool> {
        let (addr, len) = match net {
            IpNet::V4(n) => (n.network().to_ipv6_compatible(), 96 + n.prefix_len()),
            IpNet::V6(n) => (n.network(), n.prefix_len()),
        };
        let v = u128::from(addr);
        (0..len).map(|i| v >> (127 - i) & 1 == 1).collect()
    }

    pub fn build(networks: &[(&str, &str, &str)]) -> Vec<u8> {
        let mut nodes: Vec<[Rec; 2]> = vec![[Rec::Empty; 2]];
        let mut data = Vec::new();
        for (net, code, name) in networks {
            let off = data.len() as u32;
            data.extend(country(code, name));
            let path = bits(net.parse().unwrap());
            let mut node = 0usize;
            for (i, &bit) in path.iter().enumerate() {
                let b = bit as usize;
                if i == path.len() - 1 {
                    nodes[node][b] = Rec::Data(off);
                } else {
                    node = match nodes[node][b] {
                        Rec::Node(n) => n as usize,
                        _ => {
                            nodes.push([Rec::Empty; 2]);
                            let n = nodes.len() - 1;
                            nodes[node][b] = Rec::Node(n as u32);
                            n
                        }
                    };
                }
            }
        }
        let count = nodes.len() as u32;
        let mut out = Vec::new();
        for n in &nodes {
            for r in n {
                let v = match *r {
                    Rec::Empty => count,
                    Rec::Node(i) => i,
                    Rec::Data(off) => count + 16 + off,
                };
                out.extend(&v.to_be_bytes()[1..]);
            }
        }
        out.extend([0u8; 16]);
        out.extend(data);
        out.extend(b"\xAB\xCD\xEFMaxMind.com");
        ctrl(&mut out, 7, 9);
        string(&mut out, "binary_format_major_version");
        uint(&mut out, 5, 2);
        string(&mut out, "binary_format_minor_version");
        uint(&mut out, 5, 0);
        string(&mut out, "build_epoch");
        uint(&mut out, 9, 1_760_000_000);
        string(&mut out, "database_type");
        string(&mut out, "Test-Country");
        string(&mut out, "description");
        ctrl(&mut out, 7, 1);
        string(&mut out, "en");
        string(&mut out, "test");
        string(&mut out, "ip_version");
        uint(&mut out, 5, 6);
        string(&mut out, "languages");
        ctrl(&mut out, 11, 1);
        string(&mut out, "en");
        string(&mut out, "node_count");
        uint(&mut out, 6, count.into());
        string(&mut out, "record_size");
        uint(&mut out, 5, 24);
        out
    }

    #[allow(dead_code)]
    pub fn sanity(db: &[u8], ip: &str) -> Option<String> {
        let r = maxminddb::Reader::from_source(db).unwrap();
        let ip: IpAddr = ip.parse().unwrap();
        r.lookup(ip)
            .unwrap()
            .decode_path::<String>(&maxminddb::path!["country", "iso_code"])
            .unwrap()
    }
}

fn dashboard_config(api: &str, dir: &Path, token: &str) -> Config {
    Config::parse(&format!(
        r#"
[aptid]
url = "{api}"
read_token = "{token}"
[geoip]
country_db = "{d}/country.mmdb"
[dashboard]
output = "{d}/index.html"
title = "Test map"
range_days = 3
window_days = 1
step_hours = 12
"#,
        d = dir.display()
    ))
    .unwrap()
}

fn page_data(html: &str) -> Value {
    let start = html.find(r#"id="apti-data">"#).unwrap() + 15;
    let end = start + html[start..].find("</script>").unwrap();
    serde_json::from_str(&html[start..end]).unwrap()
}

/// Country → count in the last frame of one behaviour/origin series.
fn last_counts(data: &Value, behavior: &str, origin: &str) -> Vec<(String, u64)> {
    let b = data["behaviors"]
        .as_array()
        .unwrap()
        .iter()
        .position(|v| v == behavior)
        .unwrap();
    let o = ["all", "local", "federated"]
        .iter()
        .position(|v| *v == origin)
        .unwrap();
    let s = &data["series"][b * 3 + o];
    let counts = s["counts"].as_array().unwrap().last().unwrap();
    counts
        .as_array()
        .unwrap()
        .chunks(2)
        .map(|p| {
            (
                data["countries"][p[0].as_u64().unwrap() as usize]
                    .as_str()
                    .unwrap()
                    .to_string(),
                p[1].as_u64().unwrap(),
            )
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn timeline_to_page() {
    let dir = tempfile::tempdir().unwrap();
    let d = spawn_aptid(dir.path()).await;
    let api = format!("http://{}", d.api_addr);

    let db = mmdb::build(&[
        ("45.0.0.0/8", "DE", "Germany"),
        ("46.0.0.0/8", "SG", "Singapore"),
        ("2a01::/16", "FR", "France"),
    ]);
    assert_eq!(mmdb::sanity(&db, "45.13.7.9").as_deref(), Some("DE"));
    assert_eq!(mmdb::sanity(&db, "2a01:4f8:1::").as_deref(), Some("FR"));
    assert_eq!(mmdb::sanity(&db, "47.1.1.1"), None);
    std::fs::write(dir.path().join("country.mmdb"), db).unwrap();

    let now = chrono::Utc::now();
    let ago = |h: i64| db::ts(now - chrono::TimeDelta::hours(h));
    let r = reqwest::Client::new()
        .post(format!("{api}/api/v1/observations"))
        .bearer_auth(PUSH)
        .json(&json!([
            {"value": "45.13.7.9", "behavior": "ssh-bruteforce", "seenAt": ago(1)},
            {"value": "45.13.7.9", "behavior": "scan", "seenAt": ago(1)},
            {"value": "45.13.7.10", "behavior": "scan", "seenAt": ago(30)},
            {"value": "46.1.1.1", "behavior": "scan", "seenAt": ago(2)},
            {"value": "46.2.2.2", "behavior": "scan", "tlp": "amber"},
            {"value": "47.1.1.1", "behavior": "scan"},
            {"value": "2a01:4f8:1::/48", "behavior": "scan"},
            {"value": "evil-domain.com", "behavior": "phishing"}
        ]))
        .send()
        .await
        .unwrap();
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["accepted"], 8, "{body}");
    publish::run_batch(&d.state).await.unwrap();

    let peer = "https://peer.example.org/actor";
    let sighting = json!({
        "type": "Sighting", "id": "https://peer.example.org/s/1",
        "attributedTo": peer, "published": ago(3),
        "observableType": "ipv4-addr", "observableValue": "45.20.0.1",
        "observedBehavior": "scan", "firstSeen": ago(5), "lastSeen": ago(3),
        "count": 1, "tlp": "clear"
    });
    let r = inbox::ingest_objects(&d.state, peer, vec![sighting], false)
        .await
        .unwrap();
    assert_eq!(r.stored, 1, "{r:?}");

    // A token without the read scope fails and leaves no file behind.
    let out = dir.path().join("index.html");
    let bad = dashboard_config(&api, dir.path(), PUSH);
    let err = apti_dashboard::run_once(&bad).await.unwrap_err();
    assert!(format!("{err:#}").contains("403"), "{err:#}");
    assert!(!out.exists());

    let cfg = dashboard_config(&api, dir.path(), READ);
    let report = apti_dashboard::run_once(&cfg).await.unwrap();
    // 8 entries within the read token's TLP (the AMBER one is not); the
    // domain is skipped and 47.1.1.1 is not in the database.
    assert_eq!(report.entries, 7, "{report:?}");
    assert_eq!(report.located, 6, "{report:?}");
    assert_eq!(report.skipped_domains, 1, "{report:?}");
    let html = std::fs::read_to_string(&out).unwrap();
    assert_eq!(html.len(), report.bytes);

    let data = page_data(&html);
    assert_eq!(data["frames"].as_array().unwrap().len(), 7);
    assert_eq!(data["windowHours"], 24);
    assert_eq!(
        last_counts(&data, "all", "all"),
        [
            ("DE".to_string(), 2),
            ("FR".to_string(), 1),
            ("SG".to_string(), 1),
            ("ZZ".to_string(), 1)
        ]
    );
    assert_eq!(
        last_counts(&data, "all", "local"),
        [
            ("DE".to_string(), 1),
            ("FR".to_string(), 1),
            ("SG".to_string(), 1),
            ("ZZ".to_string(), 1)
        ]
    );
    assert_eq!(
        last_counts(&data, "scan", "federated"),
        [("DE".to_string(), 1)]
    );
    assert_eq!(
        last_counts(&data, "ssh-bruteforce", "all"),
        [("DE".to_string(), 1)]
    );
    // 45.13.7.10 (30 h ago) is only in earlier windows.
    let all = &data["series"][0];
    let totals: Vec<u64> = all["totals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap())
        .collect();
    assert_eq!(totals.last(), Some(&5));
    assert!(totals.contains(&1), "{totals:?}");
    assert_eq!(data["names"]["SG"], "Singapore");

    assert!(html.contains("TLP:GREEN"));
    assert!(html.contains("1 domain findings are not shown"));

    // Observables behind the counts, with their publishing actors.
    let det = &data["details"];
    let values: Vec<&str> = det["observables"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    for v in [
        "45.13.7.9",
        "45.13.7.10",
        "45.20.0.1",
        "46.1.1.1",
        "2a01:4f8:1::/48",
    ] {
        assert!(values.contains(&v), "{v} missing: {values:?}");
    }
    // Above the token's TLP, and domains while DNS is off.
    assert!(!values.contains(&"46.2.2.2"));
    assert!(!values.contains(&"evil-domain.com"));
    let actors = det["actors"].as_array().unwrap();
    assert!(
        actors.contains(&json!("Test (feed@127.0.0.1)")),
        "{actors:?}"
    );
    assert!(actors.contains(&json!("peer.example.org")), "{actors:?}");
    let de = data["countries"]
        .as_array()
        .unwrap()
        .iter()
        .position(|c| c == "DE")
        .unwrap();
    let in_de: Vec<&str> = det["observableCountries"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .filter(|(_, cs)| cs.as_array().unwrap().contains(&json!(de)))
        .map(|(i, _)| values[i])
        .collect();
    assert_eq!(in_de.len(), 3, "{in_de:?}");
    // 45.13.7.9 has two findings (scan, ssh-bruteforce) from our own actor.
    let key = values.iter().position(|v| *v == "45.13.7.9").unwrap();
    let rows: Vec<&Value> = det["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r[0] == json!(key))
        .collect();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r[2] == 1 && r[6] == 1));

    // Counts only: no IP or domain in the page.
    let mut cfg = cfg;
    cfg.dashboard.show_observables = false;
    apti_dashboard::run_once(&cfg).await.unwrap();
    let html = std::fs::read_to_string(&out).unwrap();
    assert!(page_data(&html).get("details").is_none());
    for v in [
        "45.13.7",
        "45.20.0",
        "46.1.1",
        "46.2.2",
        "47.1.1",
        "2a01:4f8",
        "evil-domain",
        "peer.example",
    ] {
        assert!(!html.contains(v), "{v} leaked into the page");
    }
    d.shutdown();
}
