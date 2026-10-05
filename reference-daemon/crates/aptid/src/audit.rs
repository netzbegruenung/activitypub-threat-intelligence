//! Audit log of every change to an observable (`[audit] enabled = true`).
//!
//! Events are `tracing` events with target [`TARGET`] at level INFO, so they
//! go to stdout (and from there to the systemd journal) next to the other
//! log messages. Each event names what changed (`obs_type`, `value`,
//! `behavior`) and who caused it (`by`, see [`Origin`]):
//!
//! - `observation received`: a sensor pushed an observation;
//! - `evidence stored` / `updated` / `withdrawn` / `purged`: a Sighting,
//!   ThreatIndicator or Opinion was stored, replaced by a newer copy,
//!   withdrawn with `Delete`, or removed by retention;
//! - `allowlist added` / `extended` / `removed`;
//! - `review resolved`;
//! - `active changed`: the state of an entry of the active list changed
//!   after a recompute (`changes` lists what changed).
//!
//! String values are quoted and escaped, so a line cannot be forged by
//! remote input.

use std::collections::{HashMap, HashSet};
use std::fmt;

use apti_core::expiry::Assessment;
use apti_core::protocol::{AllowlistEntry, AllowlistScope, ReviewItem};
use apti_core::{Behavior, EvidenceObject, ObservableType};
use chrono::{DateTime, Utc};

use crate::db::{self, Observation, Upsert};

/// `tracing` target of audit events.
pub const TARGET: &str = "audit";

/// Who caused a change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// A REST API client, by token name.
    Api(String),
    /// A control socket client (apti-tui), by uid.
    Control(Option<u32>),
    /// A remote publisher, by actor id.
    Peer(String),
    /// The daemon itself: publish batches, recompute, retention.
    Daemon,
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Origin::Api(name) => write!(f, "api:{name}"),
            Origin::Control(Some(uid)) => write!(f, "control:uid={uid}"),
            Origin::Control(None) => write!(f, "control"),
            Origin::Peer(actor) => write!(f, "peer:{actor}"),
            Origin::Daemon => write!(f, "daemon"),
        }
    }
}

/// Audit switch; cheap to copy into database closures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Audit {
    pub enabled: bool,
}

/// Behaviours as a comma-separated list; empty means all.
fn behaviors(bs: &[Behavior]) -> String {
    if bs.is_empty() {
        return "all".into();
    }
    bs.iter().map(|b| b.as_str()).collect::<Vec<_>>().join(",")
}

fn obs_type(o: &EvidenceObject) -> &'static str {
    o.observable_type.map(ObservableType::as_str).unwrap_or("")
}

impl Audit {
    pub fn observation(self, by: &Origin, o: &Observation) {
        if !self.enabled {
            return;
        }
        tracing::info!(
            target: TARGET,
            by = by.to_string().as_str(),
            obs_type = o.observable_type.as_str(),
            value = o.observable_value.as_str(),
            behavior = o.behavior.as_str(),
            count = o.count,
            seen = db::ts(o.last_seen).as_str(),
            tlp = o.tlp.map(|t| t.as_str()),
            "observation received"
        );
    }

    /// An evidence object was written by [`db::upsert_evidence`].
    pub fn evidence(self, by: &Origin, o: &EvidenceObject, result: Upsert) {
        let msg = match result {
            Upsert::Inserted => "evidence stored",
            Upsert::Updated => "evidence updated",
            Upsert::Ignored => return,
        };
        if !self.enabled {
            return;
        }
        tracing::info!(
            target: TARGET,
            by = by.to_string().as_str(),
            obs_type = obs_type(o),
            value = o.observable_value.as_deref().unwrap_or(""),
            behavior = behaviors(&o.observed_behavior).as_str(),
            evidence = o.kind.as_str(),
            id = o.id.as_str(),
            tlp = o.tlp.as_str(),
            opinion = o.opinion.map(|v| v.as_str()),
            revoked = o.is_revoked().then_some(true),
            "{msg}"
        );
    }

    fn removed_evidence(self, by: &Origin, o: &EvidenceObject, msg: &str) {
        tracing::info!(
            target: TARGET,
            by = by.to_string().as_str(),
            obs_type = obs_type(o),
            value = o.observable_value.as_deref().unwrap_or(""),
            behavior = behaviors(&o.observed_behavior).as_str(),
            evidence = o.kind.as_str(),
            id = o.id.as_str(),
            "{msg}"
        );
    }

    /// Log an object that [`db::mark_deleted`] has just withdrawn. A failed
    /// lookup is logged as a warning and does not fail the caller.
    pub fn withdrawn(self, c: &rusqlite::Connection, by: &Origin, id: &str) {
        if !self.enabled {
            return;
        }
        match db::get_evidence(c, id) {
            Ok(Some(s)) => self.removed_evidence(by, &s.object, "evidence withdrawn"),
            Ok(None) => {}
            Err(e) => tracing::warn!(id, error = %e, "audit lookup failed"),
        }
    }

    /// Evidence deleted by retention (Section 11).
    pub fn purged(self, o: &EvidenceObject) {
        if self.enabled {
            self.removed_evidence(&Origin::Daemon, o, "evidence purged");
        }
    }

    /// `msg` is `allowlist added`, `allowlist extended` or `allowlist removed`.
    pub fn allowlist(self, by: &Origin, e: &AllowlistEntry, msg: &str) {
        if !self.enabled {
            return;
        }
        tracing::info!(
            target: TARGET,
            by = by.to_string().as_str(),
            obs_type = e.observable_type.as_str(),
            value = e.observable_value.as_str(),
            behavior = behaviors(&e.behaviors).as_str(),
            id = e.id,
            scope = match e.scope {
                AllowlistScope::Local => "local",
                AllowlistScope::Published => "published",
            },
            tlp = e.tlp.map(|t| t.as_str()),
            valid_until = e.valid_until.map(db::ts).as_deref(),
            object = e.object_id.as_deref(),
            source = e.source.as_deref(),
            summary = e.summary.as_deref(),
            "{msg}"
        );
    }

    pub fn review(self, by: &Origin, r: &ReviewItem) {
        if !self.enabled {
            return;
        }
        tracing::info!(
            target: TARGET,
            by = by.to_string().as_str(),
            obs_type = r.observable_type.as_str(),
            value = r.observable_value.as_str(),
            behavior = r.behavior.map_or("all", |b| b.as_str()),
            id = r.id,
            review = r.kind.as_str(),
            resolution = r.resolution.as_deref(),
            "review resolved"
        );
    }

    /// Log the differences between the active table before and after a
    /// recompute.
    pub fn active(self, old: &[Assessment], new: &[Assessment]) {
        if !self.enabled {
            return;
        }
        for (a, changes) in active_changes(old, new) {
            tracing::info!(
                target: TARGET,
                by = "daemon",
                obs_type = a.observable_type.as_str(),
                value = a.observable_value.as_str(),
                behavior = a.behavior.as_str(),
                changes = changes.join(",").as_str(),
                active = a.active,
                flagged = a.flagged,
                suspended = a.suspended,
                allowlisted = a.allowlisted,
                expiry = a.effective_expiry.map(db::ts).as_deref(),
                tlp = a.tlp.as_str(),
                // `+ 0.0` turns -0.0 into 0.0.
                support = a.support_weight + 0.0,
                dispute = a.dispute_weight + 0.0,
                "active changed"
            );
        }
    }
}

type Key<'a> = (ObservableType, &'a str, Behavior);

fn key(a: &Assessment) -> Key<'_> {
    (a.observable_type, a.observable_value.as_str(), a.behavior)
}

/// Entries whose state changed, with the names of the changes. Removed
/// entries that were listed, suspended or flagged are reported with their
/// last state and the change `removed`.
pub fn active_changes<'a>(
    old: &'a [Assessment],
    new: &'a [Assessment],
) -> Vec<(&'a Assessment, Vec<&'static str>)> {
    let before: HashMap<Key, &Assessment> = old.iter().map(|a| (key(a), a)).collect();
    let mut out = Vec::new();
    for a in new {
        let prev = before.get(&key(a)).copied();
        let mut changes = Vec::new();
        let flag = |changes: &mut Vec<_>, was: bool, is: bool, on, off| {
            if was != is {
                changes.push(if is { on } else { off });
            }
        };
        if prev.is_none() {
            changes.push("added");
        }
        flag(
            &mut changes,
            prev.is_some_and(|p| p.active),
            a.active,
            "activated",
            "deactivated",
        );
        flag(
            &mut changes,
            prev.is_some_and(|p| p.suspended),
            a.suspended,
            "suspended",
            "unsuspended",
        );
        flag(
            &mut changes,
            prev.is_some_and(|p| p.flagged),
            a.flagged,
            "flagged",
            "unflagged",
        );
        let prev_expiry: Option<DateTime<Utc>> = prev.and_then(|p| p.effective_expiry);
        if prev.is_some() && prev_expiry != a.effective_expiry {
            changes.push("expiry");
        }
        // The TLP of an entry matters only while it is listed.
        if prev.is_some_and(|p| p.active && a.active && p.tlp != a.tlp) {
            changes.push("tlp");
        }
        // A new entry that is neither listed, suspended nor flagged (e.g.
        // evidence only from untrusted operators) is not reported.
        if !changes.is_empty() && changes != ["added"] {
            out.push((a, changes));
        }
    }
    let after: HashSet<Key> = new.iter().map(key).collect();
    for a in old {
        // Like new entries above, an entry that was never reported is not
        // reported when it goes away.
        if !after.contains(&key(a)) && (a.active || a.suspended || a.flagged) {
            out.push((a, vec!["removed"]));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use apti_core::Tlp;
    use chrono::TimeDelta;

    fn entry(value: &str, active: bool) -> Assessment {
        Assessment {
            observable_type: ObservableType::Ipv4Addr,
            observable_value: value.into(),
            behavior: Behavior::Scan,
            e_ind: None,
            e_sig: None,
            effective_expiry: Some(DateTime::<Utc>::UNIX_EPOCH + TimeDelta::days(1)),
            active,
            flagged: false,
            suspended: false,
            allowlisted: false,
            support_weight: 2.0,
            dispute_weight: 0.0,
            supporting_operators: vec![],
            disputing_operators: vec![],
            untrusted_operators: vec![],
            tlp: Tlp::Green,
            include_subdomains: false,
            ports: vec![],
            services: vec![],
        }
    }

    fn names(changes: &[(&Assessment, Vec<&str>)]) -> Vec<String> {
        changes
            .iter()
            .map(|(a, c)| format!("{} {}", a.observable_value, c.join(",")))
            .collect()
    }

    #[test]
    fn unchanged_entries_are_not_reported() {
        let list = vec![entry("192.0.2.1", true), entry("192.0.2.2", false)];
        assert!(active_changes(&list, &list.clone()).is_empty());
    }

    #[test]
    fn transitions() {
        let old = vec![
            entry("192.0.2.1", true),
            entry("192.0.2.2", true),
            entry("192.0.2.3", true),
            entry("192.0.2.4", false),
            entry("192.0.2.5", true),
        ];
        let mut new = vec![
            entry("192.0.2.1", false),
            entry("192.0.2.2", false),
            entry("192.0.2.3", true),
            entry("192.0.2.4", true),
            entry("192.0.2.6", true),
            entry("192.0.2.7", false),
        ];
        new[1].suspended = true;
        new[1].allowlisted = true;
        new[2].flagged = true;
        new[2].tlp = Tlp::Amber;
        new[3].effective_expiry = new[3].effective_expiry.map(|e| e + TimeDelta::hours(1));
        assert_eq!(
            names(&active_changes(&old, &new)),
            [
                "192.0.2.1 deactivated",
                "192.0.2.2 deactivated,suspended",
                "192.0.2.3 flagged,tlp",
                "192.0.2.4 activated,expiry",
                "192.0.2.6 added,activated",
                "192.0.2.5 removed",
            ]
        );
    }

    #[test]
    fn unreported_entries_are_not_reported_as_removed() {
        let mut flagged = entry("192.0.2.3", false);
        flagged.flagged = true;
        let mut suspended = entry("192.0.2.4", false);
        suspended.suspended = true;
        let old = vec![
            entry("192.0.2.1", false),
            entry("192.0.2.2", true),
            flagged,
            suspended,
        ];
        assert_eq!(
            names(&active_changes(&old, &[])),
            [
                "192.0.2.2 removed",
                "192.0.2.3 removed",
                "192.0.2.4 removed",
            ]
        );
    }

    #[test]
    fn origin_display() {
        assert_eq!(Origin::Api("f2b".into()).to_string(), "api:f2b");
        assert_eq!(Origin::Control(Some(1000)).to_string(), "control:uid=1000");
        assert_eq!(
            Origin::Peer("https://a.example/actor".into()).to_string(),
            "peer:https://a.example/actor"
        );
        assert_eq!(Origin::Daemon.to_string(), "daemon");
    }
}
