//! Effective expiry and suspension (Section 7).

use std::collections::{BTreeMap, BTreeSet, HashSet};

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use crate::model::{Behavior, EvidenceKind, EvidenceObject, ObservableType, Tlp};
use crate::normalize;
use crate::policy::{PolicySet, Threshold};
use crate::FUTURE_TOLERANCE_SECS;

/// An evidence object together with the operator it is attributed to.
#[derive(Debug, Clone)]
pub struct ScoredEvidence {
    pub operator: String,
    pub object: EvidenceObject,
}

/// Result of evaluating one `(O, b)` pair.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Assessment {
    pub observable_type: ObservableType,
    pub observable_value: String,
    pub behavior: Behavior,
    pub e_ind: Option<DateTime<Utc>>,
    pub e_sig: Option<DateTime<Utc>>,
    pub effective_expiry: Option<DateTime<Utc>>,
    pub active: bool,
    /// D > 0: must be reviewed.
    pub flagged: bool,
    pub suspended: bool,
    /// Suspended by a trusted allowlist entry.
    pub allowlisted: bool,
    pub support_weight: f64,
    pub dispute_weight: f64,
    pub supporting_operators: Vec<String>,
    pub disputing_operators: Vec<String>,
    /// Operators whose evidence was ignored because they are not trusted for `b`.
    pub untrusted_operators: Vec<String>,
    /// Most restrictive TLP of the evidence that supports the entry.
    pub tlp: Tlp,
    pub include_subdomains: bool,
    /// Ports and services seen in supporting evidence.
    pub ports: Vec<u16>,
    pub services: Vec<String>,
}

fn targets(
    ty: ObservableType,
    value: &str,
    o: &EvidenceObject,
    indicator_ids: &HashSet<&str>,
) -> bool {
    match o.kind {
        EvidenceKind::ThreatIndicator | EvidenceKind::Sighting => {
            o.observable_type == Some(ty) && o.observable_value.as_deref() == Some(value)
        }
        EvidenceKind::Opinion => {
            let by_observable = o.observable_type == Some(ty)
                && o.observable_value
                    .as_deref()
                    .is_some_and(|c| normalize::covers(ty, c, value, false));
            let by_ref = o
                .indicator_refs
                .iter()
                .any(|r| indicator_ids.contains(r.as_str()));
            by_observable || by_ref
        }
    }
}

/// Behaviours for which Indicators or Sightings exist for the observable.
pub fn behaviours_of(
    ty: ObservableType,
    value: &str,
    evidence: &[ScoredEvidence],
) -> BTreeSet<Behavior> {
    evidence
        .iter()
        .filter(|e| e.object.kind != EvidenceKind::Opinion)
        .filter(|e| {
            e.object.observable_type == Some(ty)
                && e.object.observable_value.as_deref() == Some(value)
        })
        .flat_map(|e| e.object.observed_behavior.iter().copied())
        .collect()
}

/// Evaluate `(O, b)`. `evidence` may be a superset; objects that do not
/// target `O` are ignored. Withdrawn (deleted) objects must not be passed.
pub fn assess(
    ty: ObservableType,
    value: &str,
    b: Behavior,
    evidence: &[ScoredEvidence],
    policy: &PolicySet,
    now: DateTime<Utc>,
) -> Assessment {
    let future = now + TimeDelta::seconds(FUTURE_TOLERANCE_SECS);
    let ttl = policy.ttl(b, ty);
    let max_age = policy.max_age(b, ty);

    let indicator_ids: HashSet<&str> = evidence
        .iter()
        .filter(|e| {
            e.object.kind == EvidenceKind::ThreatIndicator
                && targets(ty, value, &e.object, &HashSet::new())
        })
        .map(|e| e.object.id.as_str())
        .collect();

    let mut untrusted = BTreeSet::new();
    let mut e_ind: Option<DateTime<Utc>> = None;
    let mut last: BTreeMap<&str, DateTime<Utc>> = BTreeMap::new();
    let mut support: BTreeSet<&str> = BTreeSet::new();
    let mut dispute: BTreeSet<&str> = BTreeSet::new();
    let mut allowlisted = false;
    let mut tlp = Tlp::Clear;
    let mut include_subdomains = false;
    let mut ports = BTreeSet::new();
    let mut services = BTreeSet::new();

    for e in evidence {
        let o = &e.object;
        if !o.covers_behavior(b) || !targets(ty, value, o, &indicator_ids) {
            continue;
        }
        if !policy.trusted(&e.operator, b) {
            untrusted.insert(e.operator.clone());
            continue;
        }
        let mut supports = false;
        match o.kind {
            EvidenceKind::ThreatIndicator => {
                let (Some(from), Some(until)) = (o.valid_from, o.valid_until) else {
                    continue;
                };
                if o.is_revoked() || from > now {
                    continue;
                }
                let end = until.min(o.base() + max_age);
                e_ind = Some(e_ind.map_or(end, |x| x.max(end)));
                if now < end {
                    supports = true;
                    include_subdomains |= o.include_subdomains.unwrap_or(false);
                }
            }
            EvidenceKind::Sighting => {
                let Some(seen) = o.last_seen else { continue };
                if seen > future || o.published > future {
                    continue;
                }
                let entry = last.entry(e.operator.as_str()).or_insert(seen);
                *entry = (*entry).max(seen);
                if seen + ttl > now {
                    supports = true;
                }
            }
            EvidenceKind::Opinion => {
                if o.published > future || now >= o.opinion_valid_until() {
                    continue;
                }
                let Some(op) = o.opinion else { continue };
                if op.is_dispute() {
                    dispute.insert(e.operator.as_str());
                    if o.is_allowlist_entry() {
                        allowlisted = true;
                    }
                } else if op.is_support() {
                    support.insert(e.operator.as_str());
                }
            }
        }
        if supports {
            support.insert(e.operator.as_str());
            tlp = tlp.max(o.tlp);
            if let Some(p) = o.port {
                ports.insert(p);
            }
            if let Some(s) = &o.service {
                services.insert(s.clone());
            }
        }
    }

    // Weighted per-operator quorum on recency.
    let e_sig = match policy.k(b) {
        Threshold::Off => None,
        Threshold::Quorum(k) => {
            let mut lasts: Vec<(&str, DateTime<Utc>)> = last.into_iter().collect();
            lasts.sort_by(|a, b| b.1.cmp(&a.1));
            let mut sum = 0.0;
            let mut l = None;
            for (op, t) in lasts {
                sum += policy.weight(op, b);
                if sum >= k {
                    l = Some(t);
                    break;
                }
            }
            l.map(|l| l + ttl.min(max_age))
        }
    };

    let effective_expiry = match (e_ind, e_sig) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    };
    let weight_of = |ops: &BTreeSet<&str>| ops.iter().map(|op| policy.weight(op, b)).sum::<f64>();
    let support_weight = weight_of(&support);
    let dispute_weight = weight_of(&dispute);
    let flagged = dispute_weight > 0.0;
    let suspended = allowlisted || (flagged && dispute_weight >= support_weight);
    let active = effective_expiry.is_some_and(|x| now < x) && !suspended;

    Assessment {
        observable_type: ty,
        observable_value: value.to_string(),
        behavior: b,
        e_ind,
        e_sig,
        effective_expiry,
        active,
        flagged,
        suspended,
        allowlisted,
        support_weight,
        dispute_weight,
        supporting_operators: support.into_iter().map(String::from).collect(),
        disputing_operators: dispute.into_iter().map(String::from).collect(),
        untrusted_operators: untrusted.into_iter().collect(),
        tlp,
        include_subdomains,
        ports: ports.into_iter().collect(),
        services: services.into_iter().collect(),
    }
}

/// Evaluate all behaviours reported for `O`.
pub fn assess_all(
    ty: ObservableType,
    value: &str,
    evidence: &[ScoredEvidence],
    policy: &PolicySet,
    now: DateTime<Utc>,
) -> Vec<Assessment> {
    behaviours_of(ty, value, evidence)
        .into_iter()
        .map(|b| assess(ty, value, b, evidence, policy, now))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::OpinionValue;
    use crate::policy::{BehaviorOverride, OperatorPolicy};

    const IP: &str = "8.8.4.4";

    fn t(s: &str) -> DateTime<Utc> {
        format!("2026-10-{s}Z").parse().unwrap()
    }

    fn base(kind: EvidenceKind, id: &str, published: DateTime<Utc>) -> EvidenceObject {
        EvidenceObject {
            kind,
            id: id.into(),
            attributed_to: "https://x.example/actor".into(),
            published,
            updated: None,
            tlp: Tlp::Green,
            summary: None,
            observable_type: Some(ObservableType::Ipv4Addr),
            observable_value: Some(IP.into()),
            observed_behavior: vec![Behavior::SshBruteforce],
            port: Some(22),
            service: Some("ssh".into()),
            include_subdomains: None,
            valid_from: None,
            valid_until: None,
            confidence: None,
            infrastructure_types: vec![],
            revoked: None,
            tag: vec![],
            first_seen: None,
            last_seen: None,
            count: None,
            indicator_refs: vec![],
            opinion: None,
        }
    }

    fn sighting(op: &str, id: &str, last: DateTime<Utc>) -> ScoredEvidence {
        let mut o = base(EvidenceKind::Sighting, id, last);
        o.first_seen = Some(last);
        o.last_seen = Some(last);
        o.count = Some(1);
        ScoredEvidence {
            operator: op.into(),
            object: o,
        }
    }

    fn indicator(
        op: &str,
        id: &str,
        published: DateTime<Utc>,
        from: DateTime<Utc>,
        until: DateTime<Utc>,
    ) -> ScoredEvidence {
        let mut o = base(EvidenceKind::ThreatIndicator, id, published);
        o.valid_from = Some(from);
        o.valid_until = Some(until);
        o.tlp = Tlp::Clear;
        ScoredEvidence {
            operator: op.into(),
            object: o,
        }
    }

    fn opinion(
        op: &str,
        id: &str,
        value: &str,
        v: OpinionValue,
        published: DateTime<Utc>,
    ) -> ScoredEvidence {
        let mut o = base(EvidenceKind::Opinion, id, published);
        o.observable_value = Some(value.into());
        o.observed_behavior = vec![];
        o.opinion = Some(v);
        ScoredEvidence {
            operator: op.into(),
            object: o,
        }
    }

    fn trusting(ops: &[(&str, f64)]) -> PolicySet {
        let mut p = PolicySet::default();
        for (op, w) in ops {
            p.operators.insert(
                (op.to_string(), None),
                OperatorPolicy {
                    trusted: true,
                    weight: *w,
                },
            );
        }
        p
    }

    fn run(ev: &[ScoredEvidence], p: &PolicySet, now: DateTime<Utc>) -> Assessment {
        assess(
            ObservableType::Ipv4Addr,
            IP,
            Behavior::SshBruteforce,
            ev,
            p,
            now,
        )
    }

    #[test]
    fn single_sighting_below_quorum() {
        let p = trusting(&[("a", 1.0)]);
        let a = run(
            &[sighting("a", "s1", t("03T10:00:00"))],
            &p,
            t("03T11:00:00"),
        );
        assert_eq!(a.e_sig, None);
        assert!(!a.active);
    }

    #[test]
    fn quorum_uses_kth_latest() {
        let p = trusting(&[("a", 1.0), ("b", 1.0), ("c", 1.0)]);
        let ev = [
            sighting("a", "s1", t("03T10:00:00")),
            sighting("a", "s1b", t("03T09:00:00")),
            sighting("b", "s2", t("03T08:00:00")),
            sighting("c", "s3", t("02T08:00:00")),
        ];
        let a = run(&ev, &p, t("03T11:00:00"));
        // last(a)=10:00, last(b)=08:00 -> L = 08:00, T(ssh) = 1 d.
        assert_eq!(a.e_sig, Some(t("04T08:00:00")));
        assert!(a.active);
        assert_eq!(a.supporting_operators, vec!["a", "b"]);
        assert_eq!(a.tlp, Tlp::Green);
        assert_eq!(a.ports, vec![22]);
        // Expires when the quorum's evidence ages out.
        assert!(!run(&ev, &p, t("04T08:00:00")).active);
    }

    #[test]
    fn weight_equal_k_activates_alone() {
        let p = trusting(&[("a", 2.0)]);
        let a = run(
            &[sighting("a", "s1", t("03T10:00:00"))],
            &p,
            t("03T11:00:00"),
        );
        assert_eq!(a.e_sig, Some(t("04T10:00:00")));
        assert!(a.active);
    }

    #[test]
    fn k_off_restricts_to_indicators() {
        let mut p = trusting(&[("a", 5.0)]);
        p.behaviors.insert(
            Behavior::SshBruteforce,
            BehaviorOverride {
                k: Some(Threshold::Off),
                ..Default::default()
            },
        );
        let a = run(
            &[sighting("a", "s1", t("03T10:00:00"))],
            &p,
            t("03T11:00:00"),
        );
        assert_eq!(a.e_sig, None);
        assert!(!a.active);
    }

    #[test]
    fn indicator_capped_by_max_age() {
        let p = trusting(&[("a", 1.0)]);
        // validUntil far in the future, M(ssh) = 14 d.
        let ev = [indicator(
            "a",
            "i1",
            t("01T00:00:00"),
            t("01T00:00:00"),
            "2027-01-01T00:00:00Z".parse().unwrap(),
        )];
        let a = run(&ev, &p, t("03T00:00:00"));
        assert_eq!(a.e_ind, Some(t("15T00:00:00")));
        assert!(a.active);
        assert_eq!(a.tlp, Tlp::Clear);
    }

    #[test]
    fn indicator_not_yet_valid_or_revoked() {
        let p = trusting(&[("a", 1.0)]);
        let mut ev = vec![indicator(
            "a",
            "i1",
            t("01T00:00:00"),
            t("05T00:00:00"),
            t("06T00:00:00"),
        )];
        assert_eq!(run(&ev, &p, t("03T00:00:00")).e_ind, None);
        ev[0].object.valid_from = Some(t("01T00:00:00"));
        ev[0].object.revoked = Some(true);
        assert_eq!(run(&ev, &p, t("03T00:00:00")).e_ind, None);
    }

    #[test]
    fn max_of_indicator_and_sightings() {
        let p = trusting(&[("a", 2.0)]);
        let ev = [
            indicator(
                "a",
                "i1",
                t("01T00:00:00"),
                t("01T00:00:00"),
                t("03T12:00:00"),
            ),
            sighting("a", "s1", t("03T10:00:00")),
        ];
        let a = run(&ev, &p, t("03T11:00:00"));
        assert_eq!(a.effective_expiry, Some(t("04T10:00:00")));
    }

    #[test]
    fn untrusted_is_ignored() {
        let p = trusting(&[("a", 2.0)]);
        let ev = [
            sighting("x", "s1", t("03T10:00:00")),
            sighting("y", "s2", t("03T10:00:00")),
        ];
        let a = run(&ev, &p, t("03T11:00:00"));
        assert!(!a.active);
        assert_eq!(a.untrusted_operators, vec!["x", "y"]);
    }

    #[test]
    fn future_sighting_discarded() {
        let p = trusting(&[("a", 2.0)]);
        let a = run(
            &[sighting("a", "s1", t("03T12:00:00"))],
            &p,
            t("03T11:00:00"),
        );
        assert_eq!(a.e_sig, None);
    }

    #[test]
    fn dispute_flags_and_suspends() {
        let p = trusting(&[("a", 1.0), ("b", 1.0), ("c", 1.0)]);
        let now = t("03T11:00:00");
        let mut ev = vec![
            sighting("a", "s1", t("03T10:00:00")),
            sighting("b", "s2", t("03T10:00:00")),
            opinion("c", "o1", IP, OpinionValue::Disagree, t("03T09:00:00")),
        ];
        let a = run(&ev, &p, now);
        assert!(a.flagged);
        assert!(!a.suspended, "D=1 < S=2");
        assert!(a.active);

        ev.remove(1);
        let a = run(&ev, &p, now);
        assert!(a.suspended, "D=1 >= S=1");
        assert!(!a.active);
    }

    #[test]
    fn allowlist_prefix_suspends() {
        let p = trusting(&[("a", 2.0), ("c", 0.5)]);
        let ev = [
            sighting("a", "s1", t("03T10:00:00")),
            opinion(
                "c",
                "o1",
                "8.8.4.0/24",
                OpinionValue::StronglyDisagree,
                t("03T09:00:00"),
            ),
        ];
        let a = run(&ev, &p, t("03T11:00:00"));
        assert!(a.allowlisted && a.suspended && !a.active);
    }

    #[test]
    fn expired_opinion_has_no_effect() {
        let p = trusting(&[("a", 2.0), ("c", 1.0)]);
        let mut o = opinion(
            "c",
            "o1",
            IP,
            OpinionValue::StronglyDisagree,
            t("01T00:00:00"),
        );
        o.object.valid_until = Some(t("02T00:00:00"));
        let ev = [sighting("a", "s1", t("03T10:00:00")), o];
        let a = run(&ev, &p, t("03T11:00:00"));
        assert!(a.active && !a.flagged);
    }

    #[test]
    fn opinion_via_indicator_ref() {
        let p = trusting(&[("a", 1.0), ("c", 1.0)]);
        let mut o = opinion("c", "o1", IP, OpinionValue::Disagree, t("03T00:00:00"));
        o.object.observable_type = None;
        o.object.observable_value = None;
        o.object.indicator_refs = vec!["i1".into()];
        let ev = [
            indicator(
                "a",
                "i1",
                t("03T00:00:00"),
                t("03T00:00:00"),
                t("05T00:00:00"),
            ),
            o,
        ];
        let a = run(&ev, &p, t("03T11:00:00"));
        assert!(a.flagged && a.suspended);
    }

    #[test]
    fn assess_all_lists_behaviours() {
        let p = trusting(&[("a", 2.0)]);
        let mut s = sighting("a", "s1", t("03T10:00:00"));
        s.object.observed_behavior = vec![Behavior::SshBruteforce, Behavior::Scan];
        let all = assess_all(ObservableType::Ipv4Addr, IP, &[s], &p, t("03T11:00:00"));
        assert_eq!(all.len(), 2);
        assert!(all.iter().all(|a| a.active));
    }
}
