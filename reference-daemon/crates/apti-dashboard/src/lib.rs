//! Static HTML threat map for aptid.
//!
//! Reads the timeline (`GET /api/v1/timeline`) with a `read` token, places
//! findings in countries with a MaxMind DB and writes one self-contained
//! HTML page with a world map, a time slider and behaviour/origin filters.
//! Selecting a country lists the observables behind its count, with
//! behaviours, publishing actors and counts, unless `show_observables` is
//! off; the page then holds per-country counts only.

pub mod client;
pub mod config;
pub mod details;
pub mod frames;
pub mod geo;
pub mod render;

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use apti_core::{ObservableType, Tlp};
use chrono::{DateTime, Utc};

use crate::client::{AptidClient, Timeline};
use crate::config::Config;
use crate::frames::{Finding, FrameSpec};
use crate::geo::{CountryLookup, MmdbLookup};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    /// Timeline entries used.
    pub entries: usize,
    /// Entries placed in at least one country.
    pub located: usize,
    /// Domain entries left out because DNS resolution is disabled.
    pub skipped_domains: usize,
    pub bytes: usize,
}

/// Fetch, locate, render and write the page once.
pub async fn run_once(cfg: &Config) -> anyhow::Result<Report> {
    let now = Utc::now();
    let spec = FrameSpec::new(&cfg.dashboard, now);
    let timeline = AptidClient::new(&cfg.aptid)?.timeline(spec.since()).await?;
    let resolved = if cfg.dns.resolve_domains {
        let domains: BTreeSet<String> = timeline
            .entries
            .iter()
            .filter(|e| e.observable_type == ObservableType::DomainName)
            .map(|e| e.observable_value.clone())
            .collect();
        geo::resolve(
            domains,
            Duration::from_secs(cfg.dns.timeout_secs),
            cfg.dns.concurrency,
        )
        .await
    } else {
        HashMap::new()
    };
    let geo = MmdbLookup::open(&cfg.geoip.country_db)?;
    let (html, report) = build_page(cfg, &geo, timeline, &resolved, now)?;
    write_atomic(&cfg.dashboard.output, html.as_bytes())?;
    Ok(report)
}

/// Turn the timeline into the page. `resolved` holds the addresses of
/// domains; it is only consulted if `[dns] resolve_domains` is set.
pub fn build_page(
    cfg: &Config,
    geo: &dyn CountryLookup,
    timeline: Timeline,
    resolved: &HashMap<String, Vec<IpAddr>>,
    now: DateTime<Utc>,
) -> anyhow::Result<(String, Report)> {
    let behaviors = cfg.behaviors()?;
    let resolve = cfg.dns.resolve_domains;
    let mut report = Report::default();
    let mut keys: HashMap<(ObservableType, String), usize> = HashMap::new();
    let mut names = HashMap::new();
    let mut tlp: Option<Tlp> = None;
    let mut findings = Vec::new();
    let mut extras = Vec::new();
    let mut observables = Vec::new();
    let mut actors: HashMap<String, usize> = HashMap::new();
    for e in timeline.entries {
        if e.observable_type == ObservableType::Unknown
            || !(behaviors.is_empty() || behaviors.contains(&e.behavior))
        {
            continue;
        }
        if e.observable_type == ObservableType::DomainName && !resolve {
            report.skipped_domains += 1;
            continue;
        }
        let countries = geo::countries_of(
            geo,
            e.observable_type,
            &e.observable_value,
            resolved,
            &mut names,
        );
        report.entries += 1;
        if !countries.is_empty() {
            report.located += 1;
        }
        tlp = tlp.max(Some(e.tlp));
        let n = keys.len();
        let key = *keys
            .entry((e.observable_type, e.observable_value.clone()))
            .or_insert(n);
        if key == observables.len() {
            observables.push(e.observable_value);
        }
        let n = actors.len();
        let actor = *actors.entry(e.actor).or_insert(n);
        extras.push(details::Extra {
            actor,
            count: e.count,
        });
        findings.push(Finding {
            key,
            behavior: e.behavior,
            origin: e.origin,
            start: e.start,
            end: e.end,
            countries: countries.into_iter().collect(),
        });
    }
    let spec = FrameSpec::new(&cfg.dashboard, now);
    let now = spec.end(spec.count - 1);
    let frames = frames::compute(&spec, &findings);
    let details = cfg.dashboard.show_observables.then(|| {
        let mut labels = vec![String::new(); actors.len()];
        for (id, i) in &actors {
            labels[*i] = details::actor_label(id, timeline.actors.get(id));
        }
        details::build(&frames, &findings, &extras, observables, labels)
    });
    let mut notes = Vec::new();
    if report.skipped_domains > 0 {
        notes.push(format!(
            "{} domain findings are not shown: DNS resolution is disabled.",
            report.skipped_domains
        ));
    } else if resolve {
        notes.push(
            "Domains are placed by the addresses they resolved to when this page was generated."
                .into(),
        );
    }
    let html = render::page(&render::Page {
        title: &cfg.dashboard.title,
        generated: now,
        frames: &frames,
        names: &names,
        tlp,
        notes,
        details: details.as_ref(),
    });
    report.bytes = html.len();
    Ok((html, report))
}

/// Replace `path` so that readers never see a partial file.
pub fn write_atomic(path: &Path, content: &[u8]) -> anyhow::Result<()> {
    let name = path
        .file_name()
        .with_context(|| format!("{} is not a file path", path.display()))?;
    let tmp = path.with_file_name(format!(".{}.tmp", name.to_string_lossy()));
    std::fs::write(&tmp, content).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("renaming to {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{Origin, TimelineEntry};
    use apti_core::Behavior;
    use chrono::TimeDelta;

    fn cfg(extra: &str) -> Config {
        Config::parse(&format!(
            r#"
[aptid]
url = "http://127.0.0.1:8081"
read_token = "t"
[geoip]
country_db = "/x"
[dashboard]
output = "/x"
range_days = 2
window_days = 1
{extra}
"#
        ))
        .unwrap()
    }

    const COUNTS_ONLY: &str = "show_observables = false";

    fn entry(ty: ObservableType, value: &str, b: Behavior, tlp: Tlp) -> TimelineEntry {
        let now = Utc::now();
        TimelineEntry {
            observable_type: ty,
            observable_value: value.into(),
            behavior: b,
            origin: Origin::Local,
            actor: "https://us.example/actor".into(),
            start: now - TimeDelta::hours(1),
            end: now,
            count: Some(3),
            tlp,
        }
    }

    fn timeline(entries: &[TimelineEntry]) -> Timeline {
        Timeline {
            entries: entries.to_vec(),
            actors: Default::default(),
        }
    }

    fn page_data(html: &str) -> serde_json::Value {
        let start = html.find(r#"id="apti-data">"#).unwrap() + 15;
        let end = start + html[start..].find("</script>").unwrap();
        serde_json::from_str(&html[start..end]).unwrap()
    }

    #[test]
    fn observables_by_country() {
        use ObservableType::*;
        let mut fed = entry(Ipv4Addr, "45.13.7.9", Behavior::SshBruteforce, Tlp::Green);
        fed.origin = Origin::Federated;
        fed.actor = "https://peer.example/actor".into();
        fed.count = None;
        let entries = [
            entry(Ipv4Addr, "45.13.7.9", Behavior::Scan, Tlp::Clear),
            fed,
            entry(Ipv4Addr, "198.51.100.7", Behavior::Scan, Tlp::Clear),
        ];
        let mut t = timeline(&entries);
        t.actors.insert(
            "https://us.example/actor".into(),
            client::TimelineActor {
                handle: Some("feed@us.example".into()),
                name: Some("Us </script>".into()),
            },
        );
        let (html, _) =
            build_page(&cfg(""), &geo::tests::Fake, t, &HashMap::new(), Utc::now()).unwrap();
        assert!(html.contains(r#"id="details""#));
        // Only inside the escaped JSON, never as markup.
        assert!(!html.contains("Us </script>"));
        let d = &page_data(&html)["details"];
        assert_eq!(
            d["observables"],
            serde_json::json!(["45.13.7.9", "198.51.100.7"])
        );
        // DE and the unknown bucket, as indices into `countries`.
        assert_eq!(
            page_data(&html)["countries"],
            serde_json::json!(["DE", "ZZ"])
        );
        assert_eq!(d["observableCountries"], serde_json::json!([[0], [1]]));
        assert_eq!(
            d["actors"],
            serde_json::json!(["Us </script> (feed@us.example)", "peer.example"])
        );
        let rows = d["findings"].as_array().unwrap();
        assert_eq!(rows.len(), 3);
        // observable, behaviour, origin, actor, ..., count
        assert_eq!(rows[1][0], 0);
        assert_eq!(rows[1][2], 2);
        assert_eq!(rows[1][3], 1);
        assert_eq!(rows[1][6], -1);
        assert_eq!(rows[0][6], 3);
    }

    #[test]
    fn counts_only_mode() {
        use ObservableType::*;
        let entries = vec![
            entry(Ipv4Addr, "45.13.7.9", Behavior::Scan, Tlp::Clear),
            entry(Ipv4Addr, "45.13.7.9", Behavior::SshBruteforce, Tlp::Green),
            entry(Ipv6Addr, "2a01:4f8:1::/48", Behavior::Scan, Tlp::Clear),
            entry(Ipv4Addr, "198.51.100.7", Behavior::Scan, Tlp::Clear),
            entry(
                DomainName,
                "evil-domain.com",
                Behavior::Phishing,
                Tlp::Amber,
            ),
        ];
        let resolved = HashMap::from([(
            "evil-domain.com".to_string(),
            vec!["46.1.2.3".parse().unwrap()],
        )]);

        let (html, r) = build_page(
            &cfg(COUNTS_ONLY),
            &geo::tests::Fake,
            timeline(&entries),
            &resolved,
            Utc::now(),
        )
        .unwrap();
        assert_eq!(
            r,
            Report {
                entries: 4,
                located: 3,
                skipped_domains: 1,
                bytes: html.len()
            }
        );
        assert!(html.contains("TLP:GREEN"));
        assert!(html.contains("1 domain findings are not shown"));
        // The same IP with two behaviours counts once.
        assert!(html.contains(r#"<strong id="total">3</strong>"#));

        let (html2, r) = build_page(
            &cfg(&format!("{COUNTS_ONLY}\n[dns]\nresolve_domains = true")),
            &geo::tests::Fake,
            timeline(&entries),
            &resolved,
            Utc::now(),
        )
        .unwrap();
        assert_eq!((r.entries, r.located, r.skipped_domains), (5, 4, 0));
        assert!(html2.contains("TLP:AMBER"));
        assert!(html2.contains("<title>United States: 1</title>"));

        for h in [&html, &html2] {
            assert!(page_data(h).get("details").is_none());
            assert!(!h.contains(r#"id="details""#));
            for e in &entries {
                assert!(!h.contains(&e.observable_value), "{}", e.observable_value);
            }
            assert!(!h.contains("45.13.7"));
            assert!(!h.contains("2a01:4f8"));
        }

        let (html, r) = build_page(
            &cfg("").clone_with_behaviors(&["ssh-bruteforce"]),
            &geo::tests::Fake,
            timeline(&entries),
            &resolved,
            Utc::now(),
        )
        .unwrap();
        assert_eq!(r.entries, 1);
        assert!(html.contains(r#"<strong id="total">1</strong>"#));
    }

    impl Config {
        fn clone_with_behaviors(&self, b: &[&str]) -> Config {
            let mut c = self.clone();
            c.dashboard.behaviors = b.iter().map(|s| s.to_string()).collect();
            c
        }
    }

    #[test]
    fn atomic_write() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("index.html");
        write_atomic(&p, b"one").unwrap();
        write_atomic(&p, b"two").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
