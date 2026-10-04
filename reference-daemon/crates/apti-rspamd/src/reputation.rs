//! Rspamd scan results → per-IP and per-domain reputation → aptid
//! observations.
//!
//! Each report from the Lua plugin describes one scanned message. A message
//! counts as bad if its score, minus the score of the ignored symbols, is at
//! least `min_score`. Two rules turn bad messages into observations:
//!
//! - **IP:** a sender (IP or IPv6 prefix) with `min_messages` bad messages
//!   within `window_secs`.
//! - **Envelope-from** (optional): a domain with `min_messages` bad
//!   messages from `min_senders` distinct senders within its window, counting
//!   only messages whose `require_symbols` (SPF pass) fired.
//!
//! Each value is reported at most once per `report_interval_secs`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;

use apti_core::normalize::{self, is_special_purpose_ip, NormPolicy};
use apti_core::{Behavior, ObservableType, Tlp};
use chrono::{DateTime, TimeDelta, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};

use crate::config::{EnvelopeFrom, Ingest as IngestCfg};

/// Hits kept per tracked value; bounds memory for very active senders.
const MAX_HITS: usize = 10_000;

/// A symbol that fired, with the score it added.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Symbol {
    pub name: String,
    #[serde(default)]
    pub score: f64,
}

/// One scanned message, as sent by the Lua plugin.
#[derive(Debug, Clone, Deserialize)]
pub struct Report {
    pub ip: String,
    pub score: f64,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default, deserialize_with = "symbols")]
    pub symbols: Vec<Symbol>,
    #[serde(default)]
    pub authenticated: bool,
    /// Domain of the envelope sender (SMTP `MAIL FROM`).
    #[serde(default)]
    pub from_domain: Option<String>,
}

/// UCL serialises an empty Lua table as `{}`; accept that and, for
/// convenience, a `{"NAME": score}` object besides the list form.
fn symbols<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Symbol>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Form {
        List(Vec<Symbol>),
        Map(HashMap<String, f64>),
    }
    Ok(match Form::deserialize(d)? {
        Form::List(v) => v,
        Form::Map(m) => m
            .into_iter()
            .map(|(name, score)| Symbol { name, score })
            .collect(),
    })
}

/// What happened to a report under one rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Not counted (see the reason).
    Skipped(&'static str),
    /// Below the score threshold.
    Good,
    /// Counted as bad, threshold not (yet) reached or in cooldown.
    Counted,
    /// Threshold reached; an observation was queued.
    Reported,
}

/// Outcomes of one report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handled {
    pub ip: Outcome,
    /// `None` if the envelope-from rule is not configured.
    pub domain: Option<Outcome>,
}

/// Whether `name` matches one of `patterns` (trailing `*` = prefix).
pub fn symbol_matches(name: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|p| match p.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => name == p,
    })
}

/// Message score without the contribution of ignored symbols.
pub fn effective_score(r: &Report, ignore: &[String]) -> f64 {
    r.score
        - r.symbols
            .iter()
            .filter(|s| symbol_matches(&s.name, ignore))
            .map(|s| s.score)
            .sum::<f64>()
}

/// The value an IP is tracked and reported as: the address itself, or its
/// IPv6 prefix.
pub fn tracking_key(ip: IpAddr, ipv6_prefix: u8) -> String {
    match ip {
        IpAddr::V6(v6) if ipv6_prefix < 128 => IpNet::new(IpAddr::V6(v6), ipv6_prefix)
            .map(|n| n.trunc().to_string())
            .unwrap_or_else(|_| v6.to_string()),
        _ => ip.to_string(),
    }
}

/// Whether `domain` equals or is a subdomain of one of `list`.
pub fn domain_listed(domain: &str, list: &[String]) -> bool {
    list.iter().any(|d| {
        domain == d
            || domain
                .strip_suffix(d.as_str())
                .is_some_and(|rest| rest.ends_with('.'))
    })
}

/// Thresholds and output of one rule.
struct Rule {
    observable_type: Option<ObservableType>,
    behavior: Behavior,
    tlp: Option<Tlp>,
    port: Option<u16>,
    service: Option<String>,
    min_messages: usize,
    min_senders: usize,
    window: TimeDelta,
    interval: TimeDelta,
}

#[derive(Debug, Default)]
struct Track {
    /// Time and sender of each bad message.
    hits: VecDeque<(DateTime<Utc>, String)>,
    last_report: Option<DateTime<Utc>>,
}

struct Tracker {
    rule: Rule,
    tracks: HashMap<String, Track>,
}

impl Tracker {
    fn new(rule: Rule) -> Self {
        Self {
            rule,
            tracks: HashMap::new(),
        }
    }

    /// Count a bad message for `key` from `sender`; returns the observation
    /// once the thresholds are reached.
    fn record(&mut self, key: &str, sender: &str, now: DateTime<Utc>) -> Option<Value> {
        let r = &self.rule;
        let t = self.tracks.entry(key.to_string()).or_default();
        t.hits.push_back((now, sender.to_string()));
        while t.hits.len() > MAX_HITS || t.hits.front().is_some_and(|(h, _)| now - *h > r.window) {
            t.hits.pop_front();
        }
        let due = t.last_report.is_none_or(|l| now - l >= r.interval);
        if !due || t.hits.len() < r.min_messages {
            return None;
        }
        if r.min_senders > 1 {
            let senders: HashSet<&str> = t.hits.iter().map(|(_, s)| s.as_str()).collect();
            if senders.len() < r.min_senders {
                return None;
            }
        }
        let count = t.hits.len();
        t.hits.clear();
        t.last_report = Some(now);
        let mut o = json!({
            "value": key,
            "behavior": r.behavior.as_str(),
            "seenAt": now,
            "count": count,
        });
        if let Some(ty) = r.observable_type {
            o["observableType"] = json!(ty.as_str());
        }
        if let Some(t) = r.tlp {
            o["tlp"] = json!(t.as_str());
        }
        if let Some(p) = r.port {
            o["port"] = json!(p);
        }
        if let Some(s) = &r.service {
            o["service"] = json!(s);
        }
        Some(o)
    }

    /// Forget values without recent bad messages or reports.
    fn prune(&mut self, now: DateTime<Utc>) {
        let (window, interval) = (self.rule.window, self.rule.interval);
        self.tracks.retain(|_, t| {
            while t.hits.front().is_some_and(|(h, _)| now - *h > window) {
                t.hits.pop_front();
            }
            !t.hits.is_empty() || t.last_report.is_some_and(|l| now - l < interval)
        });
    }
}

struct DomainRule {
    cfg: EnvelopeFrom,
    tracker: Tracker,
}

pub struct Ingest {
    cfg: IngestCfg,
    ips: Tracker,
    domains: Option<DomainRule>,
    queue: VecDeque<Value>,
}

impl Ingest {
    pub fn new(cfg: IngestCfg) -> anyhow::Result<Self> {
        let ips = Tracker::new(Rule {
            observable_type: None,
            behavior: cfg.behavior.parse().map_err(anyhow::Error::msg)?,
            tlp: cfg.tlp,
            port: cfg.port,
            service: cfg.service.clone(),
            min_messages: cfg.min_messages,
            min_senders: 1,
            window: TimeDelta::seconds(cfg.window_secs as i64),
            interval: TimeDelta::seconds(cfg.report_interval_secs as i64),
        });
        let domains = match &cfg.envelope_from {
            Some(e) => Some(DomainRule {
                tracker: Tracker::new(Rule {
                    observable_type: Some(ObservableType::DomainName),
                    behavior: e.behavior.parse().map_err(anyhow::Error::msg)?,
                    tlp: e.tlp,
                    port: None,
                    service: None,
                    min_messages: e.min_messages,
                    min_senders: e.min_senders,
                    window: TimeDelta::seconds(e.window_secs as i64),
                    interval: TimeDelta::seconds(e.report_interval_secs as i64),
                }),
                cfg: e.clone(),
            }),
            None => None,
        };
        Ok(Self {
            cfg,
            ips,
            domains,
            queue: VecDeque::new(),
        })
    }

    /// Number of tracked IPs and domains.
    pub fn tracked(&self) -> usize {
        self.ips.tracks.len() + self.domains.as_ref().map_or(0, |d| d.tracker.tracks.len())
    }

    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    /// Whether a new value may be tracked; prunes once if the limit is hit.
    fn room(&mut self, now: DateTime<Utc>) -> bool {
        if self.tracked() < self.cfg.max_tracked {
            return true;
        }
        self.prune(now);
        self.tracked() < self.cfg.max_tracked
    }

    /// Account one scanned message received at `now`.
    pub fn handle(&mut self, r: &Report, now: DateTime<Utc>) -> Handled {
        let both = |o: Outcome, domains: bool| Handled {
            ip: o,
            domain: domains.then_some(o),
        };
        let has_domains = self.domains.is_some();
        if self.cfg.ignore_authenticated && r.authenticated {
            return both(Outcome::Skipped("authenticated"), has_domains);
        }
        // Rspamd may print IPv4-mapped IPv6 addresses.
        let ip = match r.ip.parse::<IpAddr>() {
            Ok(IpAddr::V6(v6)) => v6
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(v6)),
            Ok(ip) => ip,
            Err(_) => return both(Outcome::Skipped("invalid ip"), has_domains),
        };
        if is_special_purpose_ip(ip) {
            return both(Outcome::Skipped("special-purpose ip"), has_domains);
        }
        if self.cfg.ignore_networks.iter().any(|n| n.contains(&ip)) {
            return both(Outcome::Skipped("ignored network"), has_domains);
        }
        if effective_score(r, &self.cfg.ignore_symbols) < self.cfg.min_score {
            return both(Outcome::Good, has_domains);
        }
        let sender = tracking_key(ip, self.cfg.ipv6_prefix);
        let ip_outcome = self.record_ip(&sender, now);
        let domain = has_domains.then(|| self.record_domain(r, &sender, now));
        Handled {
            ip: ip_outcome,
            domain,
        }
    }

    fn record_ip(&mut self, sender: &str, now: DateTime<Utc>) -> Outcome {
        if !self.ips.tracks.contains_key(sender) && !self.room(now) {
            tracing::warn!(ip = %sender, "too many tracked values, not counting");
            return Outcome::Skipped("tracker full");
        }
        match self.ips.record(sender, sender, now) {
            Some(o) => {
                tracing::info!(ip = %sender, count = %o["count"], "IP reputation threshold reached");
                self.enqueue(o);
                Outcome::Reported
            }
            None => Outcome::Counted,
        }
    }

    fn record_domain(&mut self, r: &Report, sender: &str, now: DateTime<Utc>) -> Outcome {
        let Some(d) = &self.domains else {
            return Outcome::Skipped("not configured");
        };
        let Some(raw) = r.from_domain.as_deref().filter(|s| !s.is_empty()) else {
            return Outcome::Skipped("no envelope-from");
        };
        let fired = |pattern: &String| {
            r.symbols
                .iter()
                .any(|s| symbol_matches(&s.name, std::slice::from_ref(pattern)))
        };
        if !d.cfg.require_symbols.iter().all(fired) {
            return Outcome::Skipped("not authenticated");
        }
        if d.cfg.skip_symbols.iter().any(fired) {
            return Outcome::Skipped("skip symbol");
        }
        let domain = match normalize::normalise(
            raw,
            Some(ObservableType::DomainName),
            &NormPolicy::default(),
        ) {
            Ok((_, v)) => v,
            Err(_) => return Outcome::Skipped("invalid domain"),
        };
        if domain_listed(&domain, &d.cfg.ignore_domains) {
            return Outcome::Skipped("ignored domain");
        }
        let known = d.tracker.tracks.contains_key(&domain);
        if !known && !self.room(now) {
            tracing::warn!(domain = %domain, "too many tracked values, not counting");
            return Outcome::Skipped("tracker full");
        }
        let Some(d) = &mut self.domains else {
            return Outcome::Skipped("not configured");
        };
        match d.tracker.record(&domain, sender, now) {
            Some(o) => {
                tracing::info!(domain = %domain, count = %o["count"], "envelope-from threshold reached");
                self.enqueue(o);
                Outcome::Reported
            }
            None => Outcome::Counted,
        }
    }

    fn enqueue(&mut self, o: Value) {
        if self.queue.len() >= self.cfg.max_queue {
            if let Some(dropped) = self.queue.pop_front() {
                tracing::warn!(value = %dropped["value"], "queue full, dropping oldest report");
            }
        }
        self.queue.push_back(o);
    }

    /// Forget values without recent bad messages or reports.
    pub fn prune(&mut self, now: DateTime<Utc>) {
        self.ips.prune(now);
        if let Some(d) = &mut self.domains {
            d.tracker.prune(now);
        }
    }

    /// Take up to `n` queued observations.
    pub fn take(&mut self, n: usize) -> Vec<Value> {
        let n = n.min(self.queue.len());
        self.queue.drain(..n).collect()
    }

    /// Put observations that could not be delivered back at the front,
    /// keeping at most `max_queue` (the oldest are dropped).
    pub fn put_back(&mut self, items: Vec<Value>) {
        for o in items.into_iter().rev() {
            self.queue.push_front(o);
        }
        while self.queue.len() > self.cfg.max_queue {
            if let Some(dropped) = self.queue.pop_front() {
                tracing::warn!(value = %dropped["value"], "queue full, dropping oldest report");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    const BASE: &str = r#"
[aptid]
url = "http://127.0.0.1:8081"
push_token = "p"
[ingest]
report_secret = "0123456789abcdef"
min_score = 10
min_messages = 2
window_secs = 600
report_interval_secs = 3600
service = "smtp"
port = 25
tlp = "clear"
ignore_networks = ["185.1.2.0/24", "185.9.9.9"]
max_tracked = 2
max_queue = 2
"#;

    fn cfg() -> IngestCfg {
        Config::parse(BASE).unwrap().ingest.unwrap()
    }

    fn cfg_domains() -> IngestCfg {
        Config::parse(&format!(
            r#"{BASE}
[ingest.envelope_from]
tlp = "amber"
min_messages = 2
min_senders = 2
window_secs = 3600
report_interval_secs = 3600
ignore_domains = ["Own-Domain.ORG", "sendgrid.net"]
"#
        ))
        .unwrap()
        .ingest
        .unwrap()
    }

    fn report(ip: &str, score: f64, symbols: &[(&str, f64)]) -> Report {
        Report {
            ip: ip.into(),
            score,
            action: None,
            symbols: symbols
                .iter()
                .map(|(n, s)| Symbol {
                    name: n.to_string(),
                    score: *s,
                })
                .collect(),
            authenticated: false,
            from_domain: None,
        }
    }

    fn from(ip: &str, domain: &str, symbols: &[(&str, f64)]) -> Report {
        Report {
            from_domain: Some(domain.into()),
            ..report(ip, 12.0, symbols)
        }
    }

    const SPF: (&str, f64) = ("R_SPF_ALLOW", -0.2);

    #[test]
    fn parses_plugin_json() {
        let r: Report = serde_json::from_str(
            r#"{"ip":"45.13.7.9","score":12.5,"action":"reject","symbols":[{"name":"APTI_BAD_IP","score":5.0},{"name":"BAYES_SPAM","score":7.5}],"authenticated":false,"from_domain":"bulk-mailer.net"}"#,
        )
        .unwrap();
        assert_eq!(r.symbols.len(), 2);
        assert_eq!(r.from_domain.as_deref(), Some("bulk-mailer.net"));
        let r: Report =
            serde_json::from_str(r#"{"ip":"45.13.7.9","score":1,"symbols":{}}"#).unwrap();
        assert!(r.symbols.is_empty() && !r.authenticated && r.from_domain.is_none());
        let r: Report =
            serde_json::from_str(r#"{"ip":"45.13.7.9","score":1,"symbols":{"X":1.5}}"#).unwrap();
        assert_eq!(r.symbols[0].score, 1.5);
    }

    #[test]
    fn ignored_symbols_do_not_count() {
        let ignore = vec!["APTI_*".to_string(), "EXACT".to_string()];
        assert!(symbol_matches("APTI_BAD_IP", &ignore));
        assert!(symbol_matches("EXACT", &ignore));
        assert!(!symbol_matches("EXACT_NOT", &ignore));
        let r = report(
            "45.13.7.9",
            15.0,
            &[("APTI_BAD_IP", 6.0), ("BAYES_SPAM", 9.0)],
        );
        assert_eq!(effective_score(&r, &ignore), 9.0);

        let mut ing = Ingest::new(cfg()).unwrap();
        let now = Utc::now();
        assert_eq!(ing.handle(&r, now).ip, Outcome::Good, "15 - 6 < 10");
        assert_eq!(ing.tracked(), 0);
    }

    #[test]
    fn keys() {
        let v6: IpAddr = "2a01:4f8:1:2:3::17".parse().unwrap();
        assert_eq!(tracking_key(v6, 64), "2a01:4f8:1:2::/64");
        assert_eq!(tracking_key(v6, 128), "2a01:4f8:1:2:3::17");
        let v4: IpAddr = "45.13.7.9".parse().unwrap();
        assert_eq!(tracking_key(v4, 64), "45.13.7.9");
        let list = vec!["sendgrid.net".to_string()];
        assert!(domain_listed("sendgrid.net", &list));
        assert!(domain_listed("bounces.sendgrid.net", &list));
        assert!(!domain_listed("notsendgrid.net", &list));
    }

    #[test]
    fn threshold_window_and_cooldown() {
        let mut ing = Ingest::new(cfg()).unwrap();
        let t0 = Utc::now();
        let bad = report("45.13.7.9", 12.0, &[]);
        assert_eq!(ing.handle(&bad, t0).ip, Outcome::Counted);
        // Outside the window: the first hit no longer counts.
        let t1 = t0 + TimeDelta::minutes(11);
        assert_eq!(ing.handle(&bad, t1).ip, Outcome::Counted);
        let t2 = t1 + TimeDelta::minutes(1);
        assert_eq!(
            ing.handle(&bad, t2),
            Handled {
                ip: Outcome::Reported,
                domain: None
            }
        );
        let q = ing.take(10);
        assert_eq!(q.len(), 1);
        assert_eq!(q[0]["value"], "45.13.7.9");
        assert_eq!(q[0]["behavior"], "smtp-spam");
        assert_eq!(q[0]["count"], 2);
        assert_eq!(q[0]["port"], 25);
        assert_eq!(q[0]["service"], "smtp");
        assert_eq!(q[0]["tlp"], "clear");
        assert!(q[0].get("observableType").is_none());
        // Cooldown: further bad messages are counted but not reported.
        for m in 1..=3 {
            assert_eq!(
                ing.handle(&bad, t2 + TimeDelta::minutes(m)).ip,
                Outcome::Counted
            );
        }
        // After the cooldown the next bad message reports the recent ones.
        let t3 = t2 + TimeDelta::minutes(61);
        assert_eq!(
            ing.handle(&bad, t3).ip,
            Outcome::Counted,
            "old hits expired"
        );
        assert_eq!(
            ing.handle(&bad, t3 + TimeDelta::minutes(1)).ip,
            Outcome::Reported
        );
        assert_eq!(ing.take(10)[0]["count"], 2);
    }

    #[test]
    fn skips() {
        let mut ing = Ingest::new(cfg_domains()).unwrap();
        let now = Utc::now();
        let mut r = from("45.13.7.9", "bulk-mailer.net", &[SPF]);
        r.authenticated = true;
        assert_eq!(
            ing.handle(&r, now),
            Handled {
                ip: Outcome::Skipped("authenticated"),
                domain: Some(Outcome::Skipped("authenticated"))
            }
        );
        for (ip, why) in [
            ("10.1.2.3", "special-purpose ip"),
            ("::1", "special-purpose ip"),
            ("::ffff:127.0.0.1", "special-purpose ip"),
            ("185.1.2.7", "ignored network"),
            ("185.9.9.9", "ignored network"),
            ("nope", "invalid ip"),
        ] {
            assert_eq!(
                ing.handle(&report(ip, 50.0, &[]), now).ip,
                Outcome::Skipped(why),
                "{ip}"
            );
        }
        // IPv4-mapped addresses are tracked as IPv4.
        ing.handle(&report("::ffff:45.13.7.9", 50.0, &[]), now);
        assert_eq!(
            ing.handle(&report("45.13.7.9", 50.0, &[]), now).ip,
            Outcome::Reported
        );
    }

    #[test]
    fn envelope_from_rule() {
        let mut ing = Ingest::new(cfg_domains()).unwrap();
        let now = Utc::now();
        let dom = |ing: &mut Ingest, r: &Report| ing.handle(r, now).domain.unwrap();
        // Forged senders are easy: without an SPF pass nothing counts.
        assert_eq!(
            dom(&mut ing, &from("45.13.7.1", "bulk-mailer.net", &[])),
            Outcome::Skipped("not authenticated")
        );
        // Zero-score skip symbols count as fired.
        assert_eq!(
            dom(
                &mut ing,
                &from("45.13.7.1", "gmail.com", &[SPF, ("FREEMAIL_ENVFROM", 0.0)])
            ),
            Outcome::Skipped("skip symbol")
        );
        for (d, why) in [
            ("bounces.sendgrid.net", "ignored domain"),
            ("own-domain.org", "ignored domain"),
            ("localhost", "invalid domain"),
            ("mail.example", "invalid domain"),
            ("", "no envelope-from"),
        ] {
            assert_eq!(
                dom(&mut ing, &from("45.13.7.1", d, &[SPF])),
                Outcome::Skipped(why),
                "{d}"
            );
        }
        // Good messages do not count either.
        let mut good = from("45.13.7.1", "bulk-mailer.net", &[SPF]);
        good.score = 1.0;
        assert_eq!(dom(&mut ing, &good), Outcome::Good);

        // min_messages = 2 from min_senders = 2.
        let spam = |ip: &str| from(ip, "Bulk-Mailer.NET.", &[SPF]);
        assert_eq!(dom(&mut ing, &spam("45.13.7.1")), Outcome::Counted);
        assert_eq!(
            dom(&mut ing, &spam("45.13.7.1")),
            Outcome::Counted,
            "one sender"
        );
        let h = ing.handle(&spam("45.13.7.2"), now);
        assert_eq!(h.domain, Some(Outcome::Reported));
        let q = ing.take(10);
        let d = q.iter().find(|o| o["value"] == "bulk-mailer.net").unwrap();
        assert_eq!(d["observableType"], "domain-name");
        assert_eq!(d["behavior"], "smtp-spam");
        assert_eq!(d["tlp"], "amber");
        assert_eq!(d["count"], 3);
        assert!(d.get("port").is_none() && d.get("service").is_none());
        // The IP from the same messages is reported with its own TLP.
        let ip = q.iter().find(|o| o["value"] == "45.13.7.1").unwrap();
        assert_eq!(ip["tlp"], "clear");
    }

    #[test]
    fn bounded_state() {
        let mut ing = Ingest::new(cfg()).unwrap();
        let now = Utc::now();
        ing.handle(&report("45.13.7.1", 50.0, &[]), now);
        ing.handle(&report("45.13.7.2", 50.0, &[]), now);
        assert_eq!(
            ing.handle(&report("45.13.7.3", 50.0, &[]), now).ip,
            Outcome::Skipped("tracker full")
        );
        // Once the old hits have left the window there is room again.
        let later = now + TimeDelta::minutes(11);
        assert_eq!(
            ing.handle(&report("45.13.7.3", 50.0, &[]), later).ip,
            Outcome::Counted
        );
        assert_eq!(ing.tracked(), 1);

        // IPs and domains share max_tracked.
        let mut ing = Ingest::new(cfg_domains()).unwrap();
        let h = ing.handle(&from("45.13.7.1", "bulk-mailer.net", &[SPF]), now);
        assert_eq!((h.ip, h.domain), (Outcome::Counted, Some(Outcome::Counted)));
        let h = ing.handle(&from("45.13.7.2", "other-mailer.net", &[SPF]), now);
        assert_eq!(h.ip, Outcome::Skipped("tracker full"));
        assert_eq!(h.domain, Some(Outcome::Skipped("tracker full")));

        // The queue keeps the newest max_queue observations.
        let mut ing = Ingest::new(cfg()).unwrap();
        for ip in ["45.13.7.1", "45.13.7.2"] {
            ing.handle(&report(ip, 50.0, &[]), now);
            ing.handle(&report(ip, 50.0, &[]), now);
            ing.prune(now + TimeDelta::hours(2));
        }
        ing.handle(&report("45.13.7.3", 50.0, &[]), now);
        ing.handle(&report("45.13.7.3", 50.0, &[]), now);
        assert_eq!(ing.queued(), 2);
        let items = ing.take(1);
        assert_eq!(items[0]["value"], "45.13.7.2");
        ing.put_back(items);
        assert_eq!(ing.take(5).len(), 2);
    }
}
