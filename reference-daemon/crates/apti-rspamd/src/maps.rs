//! aptid active list → Rspamd multimap files served over HTTP.
//!
//! The active list is fetched every `interval_secs` and rendered into one
//! body per configured map. If aptid cannot be reached, the maps are
//! rendered from the last fetched list, so entries still drop out at their
//! effective expiry and an outage never keeps an IP listed for good.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use apti_core::{Behavior, ObservableType};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use crate::client::{ActiveEntry, AptidClient};
use crate::config::{parse_behaviors, MapDef, MapKind, Maps};

/// A rendered map as served to Rspamd.
#[derive(Debug, Clone)]
pub struct Rendered {
    pub body: String,
    pub etag: String,
    /// Whole seconds, as sent in `Last-Modified`.
    pub modified: SystemTime,
    pub entries: usize,
}

pub type SharedMaps = Arc<RwLock<HashMap<String, Rendered>>>;

struct Def {
    cfg: MapDef,
    behaviors: Vec<Behavior>,
}

impl Def {
    fn matches(&self, e: &ActiveEntry, now: DateTime<Utc>) -> bool {
        let ty_ok = match self.cfg.kind {
            MapKind::Ip => e.observable_type.is_ip(),
            MapKind::Domain => e.observable_type == ObservableType::DomainName,
        };
        ty_ok
            && e.effective_expiry > now
            && (self.cfg.include_flagged || !e.flagged)
            && (self.behaviors.is_empty() || self.behaviors.contains(&e.behavior))
    }
}

/// Domain as a case-insensitive Rspamd regexp map line.
fn domain_regex(domain: &str, include_subdomains: bool) -> String {
    let mut escaped = String::with_capacity(domain.len() + 8);
    for c in domain.chars() {
        if !c.is_ascii_alphanumeric() && c != '-' {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    if include_subdomains {
        format!(r"/(^|\.){escaped}$/i")
    } else {
        format!("/^{escaped}$/i")
    }
}

/// Render the body of one map. Returns the body and the number of entries.
///
/// Entry lines carry no value: multimap reads a value as `symbol:score`.
/// The behaviours go into a comment line above each entry instead.
fn render(def: &Def, entries: &[ActiveEntry], now: DateTime<Utc>) -> (String, usize) {
    // value -> (behaviours, include_subdomains)
    let mut by_value: BTreeMap<&str, (BTreeSet<Behavior>, bool)> = BTreeMap::new();
    for e in entries.iter().filter(|e| def.matches(e, now)) {
        let slot = by_value.entry(e.observable_value.as_str()).or_default();
        slot.0.insert(e.behavior);
        slot.1 |= e.include_subdomains;
    }
    // A header line keeps the body non-empty, also when no entry is left.
    let mut body = format!("# apti-rspamd map {}\n", def.cfg.name);
    for (value, (behaviors, subdomains)) in &by_value {
        let b: Vec<&str> = behaviors.iter().map(|b| b.as_str()).collect();
        let key = match def.cfg.kind {
            MapKind::Ip => value.to_string(),
            MapKind::Domain => domain_regex(value, *subdomains),
        };
        body.push_str(&format!("# {}\n{key}\n", b.join(",")));
    }
    (body, by_value.len())
}

fn etag(body: &str) -> String {
    let h = Sha256::digest(body.as_bytes());
    let hex: String = h[..16].iter().map(|b| format!("{b:02x}")).collect();
    format!("\"{hex}\"")
}

fn whole_seconds(t: SystemTime) -> SystemTime {
    let secs = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    UNIX_EPOCH + Duration::from_secs(secs)
}

pub struct Puller {
    cfg: Maps,
    defs: Vec<Def>,
    client: AptidClient,
    maps: SharedMaps,
    cache: Vec<ActiveEntry>,
}

impl Puller {
    pub fn new(cfg: Maps, client: AptidClient) -> anyhow::Result<Self> {
        let defs = cfg
            .maps
            .iter()
            .map(|m| {
                Ok(Def {
                    behaviors: parse_behaviors(&m.behaviors)?,
                    cfg: m.clone(),
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let p = Self {
            cfg,
            defs,
            client,
            maps: Arc::default(),
            cache: Vec::new(),
        };
        p.update(Utc::now(), SystemTime::now());
        Ok(p)
    }

    pub fn maps(&self) -> SharedMaps {
        self.maps.clone()
    }

    /// Re-render all maps from the cached list; bodies that did not change
    /// keep their `Last-Modified` and `ETag`.
    fn update(&self, now: DateTime<Utc>, wall: SystemTime) {
        let wall = whole_seconds(wall);
        let mut maps = self.maps.write().unwrap_or_else(|e| e.into_inner());
        for def in &self.defs {
            let (body, entries) = render(def, &self.cache, now);
            let prev = maps.get(&def.cfg.name);
            if prev.is_some_and(|p| p.body == body) {
                continue;
            }
            // Last-Modified must increase with every change, also within
            // one second, or If-Modified-Since would hide the change.
            let modified = match prev {
                Some(p) if p.modified >= wall => p.modified + Duration::from_secs(1),
                _ => wall,
            };
            if prev.is_some() {
                tracing::info!(map = %def.cfg.name, entries, "map changed");
            }
            maps.insert(
                def.cfg.name.clone(),
                Rendered {
                    etag: etag(&body),
                    body,
                    modified,
                    entries,
                },
            );
        }
    }

    /// Fetch the active list once and re-render the maps. On failure the
    /// maps are re-rendered from the last list and the error is returned.
    pub async fn step(&mut self) -> anyhow::Result<()> {
        let fetched = self.client.active().await;
        let ok = fetched.as_ref().is_ok();
        if let Ok(entries) = fetched.as_ref() {
            self.cache = entries.clone();
        }
        let now = Utc::now();
        self.cache.retain(|e| e.effective_expiry > now);
        self.update(now, SystemTime::now());
        if ok {
            Ok(())
        } else {
            fetched.map(|_| ())
        }
    }

    pub async fn run(mut self) -> anyhow::Result<()> {
        let every = Duration::from_secs(self.cfg.interval_secs);
        loop {
            tokio::time::sleep(every).await;
            if let Err(e) = self.step().await {
                tracing::warn!("fetching active list failed, serving cached entries: {e:#}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;

    fn entry(ty: ObservableType, v: &str, b: Behavior, sub: bool) -> ActiveEntry {
        ActiveEntry {
            observable_type: ty,
            observable_value: v.into(),
            behavior: b,
            include_subdomains: sub,
            effective_expiry: Utc::now() + TimeDelta::hours(1),
            flagged: false,
        }
    }

    fn def(kind: MapKind, behaviors: &[Behavior], include_flagged: bool) -> Def {
        Def {
            cfg: MapDef {
                name: "m".into(),
                kind,
                behaviors: behaviors.iter().map(|b| b.as_str().to_string()).collect(),
                include_flagged,
            },
            behaviors: behaviors.to_vec(),
        }
    }

    #[test]
    fn renders_ip_map() {
        let now = Utc::now();
        let mut expired = entry(ObservableType::Ipv4Addr, "45.13.7.1", Behavior::Scan, false);
        expired.effective_expiry = now - TimeDelta::seconds(1);
        let mut flagged = entry(ObservableType::Ipv4Addr, "45.13.7.2", Behavior::Scan, false);
        flagged.flagged = true;
        let entries = vec![
            entry(
                ObservableType::Ipv4Addr,
                "45.13.7.9",
                Behavior::SshBruteforce,
                false,
            ),
            entry(ObservableType::Ipv4Addr, "45.13.7.9", Behavior::Scan, false),
            entry(
                ObservableType::Ipv6Addr,
                "2a01:4f8:1::/48",
                Behavior::SmtpSpam,
                false,
            ),
            entry(
                ObservableType::DomainName,
                "evil.example",
                Behavior::Scan,
                false,
            ),
            expired,
            flagged,
        ];
        let (body, n) = render(&def(MapKind::Ip, &[], false), &entries, now);
        assert_eq!(n, 2);
        assert_eq!(
            body,
            "# apti-rspamd map m\n# smtp-spam\n2a01:4f8:1::/48\n# scan,ssh-bruteforce\n45.13.7.9\n"
        );
        let (body, n) = render(&def(MapKind::Ip, &[], true), &entries, now);
        assert_eq!(n, 3, "{body}");
        let (_, n) = render(
            &def(MapKind::Ip, &[Behavior::SmtpSpam], false),
            &entries,
            now,
        );
        assert_eq!(n, 1);
        let (body, n) = render(&def(MapKind::Ip, &[], false), &[], now);
        assert_eq!((body.as_str(), n), ("# apti-rspamd map m\n", 0));
    }

    #[test]
    fn renders_domain_map() {
        let entries = vec![
            entry(
                ObservableType::DomainName,
                "phish.example",
                Behavior::Phishing,
                true,
            ),
            entry(
                ObservableType::DomainName,
                "phish.example",
                Behavior::MalwareHosting,
                false,
            ),
            entry(
                ObservableType::DomainName,
                "xn--bcher-kva.example",
                Behavior::Phishing,
                false,
            ),
            entry(
                ObservableType::Ipv4Addr,
                "45.13.7.9",
                Behavior::Phishing,
                false,
            ),
        ];
        let (body, n) = render(&def(MapKind::Domain, &[], false), &entries, Utc::now());
        assert_eq!(n, 2);
        assert_eq!(
            body,
            "# apti-rspamd map m\n# phishing,malware-hosting\n/(^|\\.)phish\\.example$/i\n# phishing\n/^xn--bcher-kva\\.example$/i\n"
        );
    }

    #[test]
    fn last_modified_increases() {
        let cfg = crate::config::Config::parse(
            "[aptid]\nurl = \"http://127.0.0.1:1\"\nread_token = \"r\"\n[maps]\n[[maps.map]]\nname = \"ip\"\nkind = \"ip\"\n",
        )
        .unwrap();
        let mut p = Puller::new(
            cfg.maps.clone().unwrap(),
            AptidClient::new(&cfg.aptid).unwrap(),
        )
        .unwrap();
        let get = |p: &Puller| p.maps.read().unwrap()["ip"].clone();
        let first = get(&p);
        assert_eq!(first.entries, 0);
        let (now, wall) = (Utc::now(), first.modified);
        p.update(now, wall);
        assert_eq!(get(&p).modified, first.modified, "unchanged body");
        p.cache = vec![entry(
            ObservableType::Ipv4Addr,
            "45.13.7.9",
            Behavior::Scan,
            false,
        )];
        p.update(now, wall);
        let second = get(&p);
        assert_eq!(second.modified, first.modified + Duration::from_secs(1));
        assert_ne!(second.etag, first.etag);
    }
}
