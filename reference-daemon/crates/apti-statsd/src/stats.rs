//! Aggregate statistics over the hub's TLP:CLEAR dataset.
//!
//! These are the only numbers the public page shows. Individual IPs,
//! prefixes and domains are never aggregated here: they are personal data
//! even at TLP:CLEAR (Section 11), so the page renders counts and
//! distributions, not values.

use std::collections::BTreeMap;

use apti_core::{Behavior, ObservableType};

use crate::client::{ActiveEntry, NodeInfo, TimelineEntry, TimelineOrigin};

/// Per-behaviour counts, largest first.
pub type BehaviorCounts = Vec<(Behavior, usize)>;

#[derive(Debug, Clone, Default)]
pub struct Stats {
    /// Connected nodes (the hub's follow list).
    pub nodes: usize,
    /// Sum of evidence ingested from all connected nodes.
    pub evidence_ingested: u64,
    /// Current active (corroborated) observables.
    pub active_total: usize,
    pub active_ipv4: usize,
    pub active_ipv6: usize,
    pub active_domains: usize,
    /// Active entries marked for dispute.
    pub active_flagged: usize,
    pub active_by_behavior: BehaviorCounts,

    /// Findings in the window.
    pub findings_total: usize,
    pub findings_local: usize,
    pub findings_federated: usize,
    pub findings_ipv4: usize,
    pub findings_ipv6: usize,
    pub findings_domains: usize,
    pub findings_by_behavior: BehaviorCounts,
}

fn by_behavior<'a>(behaviors: impl Iterator<Item = &'a Behavior>) -> BehaviorCounts {
    let mut m: BTreeMap<Behavior, usize> = BTreeMap::new();
    for b in behaviors {
        *m.entry(*b).or_default() += 1;
    }
    let mut v: BehaviorCounts = m.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v
}

fn split_types<T: Copy>(
    values: impl Iterator<Item = T>,
    is_v4: fn(T) -> bool,
    is_v6: fn(T) -> bool,
    is_domain: fn(T) -> bool,
) -> (usize, usize, usize) {
    let (mut a, mut b, mut c) = (0usize, 0usize, 0usize);
    for v in values {
        if is_v4(v) {
            a += 1;
        } else if is_v6(v) {
            b += 1;
        } else if is_domain(v) {
            c += 1;
        }
    }
    (a, b, c)
}

impl Stats {
    pub fn compute(active: &[ActiveEntry], findings: &[TimelineEntry], nodes: &[NodeInfo]) -> Self {
        let (a4, a6, ad) = split_types(
            active.iter().map(|e| e.observable_type),
            |t| t == ObservableType::Ipv4Addr,
            |t| t == ObservableType::Ipv6Addr,
            |t| t == ObservableType::DomainName,
        );
        let (f4, f6, fd) = split_types(
            findings.iter().map(|e| e.observable_type),
            |t| t == ObservableType::Ipv4Addr,
            |t| t == ObservableType::Ipv6Addr,
            |t| t == ObservableType::DomainName,
        );
        let (mut local, mut federated) = (0usize, 0usize);
        for e in findings {
            match e.origin {
                TimelineOrigin::Local => local += 1,
                TimelineOrigin::Federated => federated += 1,
            }
        }
        Self {
            nodes: nodes.len(),
            evidence_ingested: nodes.iter().map(|n| n.evidence).sum(),
            active_total: active.len(),
            active_ipv4: a4,
            active_ipv6: a6,
            active_domains: ad,
            active_flagged: active.iter().filter(|e| e.flagged).count(),
            active_by_behavior: by_behavior(active.iter().map(|e| &e.behavior)),
            findings_total: findings.len(),
            findings_local: local,
            findings_federated: federated,
            findings_ipv4: f4,
            findings_ipv6: f6,
            findings_domains: fd,
            findings_by_behavior: by_behavior(findings.iter().map(|e| &e.behavior)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use apti_core::{EvidenceKind, Tlp};
    use chrono::Utc;

    fn active(behavior: Behavior, ty: ObservableType, flagged: bool) -> ActiveEntry {
        ActiveEntry {
            observable_type: ty,
            observable_value: "x".into(),
            behavior,
            include_subdomains: false,
            effective_expiry: Utc::now(),
            ttl: 1,
            tlp: Tlp::Clear,
            flagged,
            ports: vec![],
            services: vec![],
        }
    }

    fn finding(behavior: Behavior, origin: TimelineOrigin) -> TimelineEntry {
        TimelineEntry {
            observable_type: ObservableType::Ipv4Addr,
            observable_value: "x".into(),
            behavior,
            kind: EvidenceKind::Sighting,
            origin,
            actor: "a".into(),
            start: Utc::now(),
            end: Utc::now(),
            count: None,
            tlp: Tlp::Clear,
        }
    }

    #[test]
    fn aggregates() {
        let active = vec![
            active(Behavior::Scan, ObservableType::Ipv4Addr, false),
            active(Behavior::Scan, ObservableType::Ipv6Addr, true),
            active(Behavior::Phishing, ObservableType::DomainName, false),
        ];
        let findings = vec![
            finding(Behavior::Scan, TimelineOrigin::Federated),
            finding(Behavior::Scan, TimelineOrigin::Local),
        ];
        let nodes = vec![NodeInfo {
            actor: "a".into(),
            handle: None,
            name: None,
            summary: None,
            operator: None,
            evidence: 41,
            state: "accepted".into(),
        }];
        let s = Stats::compute(&active, &findings, &nodes);
        assert_eq!(s.nodes, 1);
        assert_eq!(s.evidence_ingested, 41);
        assert_eq!((s.active_ipv4, s.active_ipv6, s.active_domains), (1, 1, 1));
        assert_eq!(s.active_flagged, 1);
        assert_eq!(s.active_by_behavior[0], (Behavior::Scan, 2));
        assert_eq!((s.findings_local, s.findings_federated), (1, 1));
        assert_eq!(s.findings_by_behavior[0], (Behavior::Scan, 2));
    }

    #[test]
    fn empty() {
        let s = Stats::compute(&[], &[], &[]);
        assert!(s.active_by_behavior.is_empty());
        assert_eq!(s.evidence_ingested, 0);
    }
}
