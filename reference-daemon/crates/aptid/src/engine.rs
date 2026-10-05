//! Periodic recomputation of the active list (Sections 7, 9) and the review
//! queue, plus retention cleanup (Section 11).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::time::Duration;

use apti_core::expiry::{self, Assessment, ScoredEvidence};
use apti_core::normalize::{self, NormPolicy};
use apti_core::policy::{BehaviorOverride, OperatorPolicy, PolicySet};
use apti_core::protocol::AllowlistEntry;
use apti_core::{saturating_add, Behavior, EvidenceKind, EvidenceObject, ObservableType, Tlp};
use chrono::{DateTime, TimeDelta, Utc};

use crate::client;
use crate::db;
use crate::state::{AppState, Shared};

/// Merge policy from the TOML file and the database (database wins).
/// Also returns the per-behaviour default TLP for publishing.
pub async fn load_policy(
    state: &AppState,
) -> anyhow::Result<(PolicySet, HashMap<Behavior, Option<Tlp>>)> {
    let cfg = &state.cfg.policy;
    let mut p = PolicySet {
        default_k: cfg.default_k.threshold()?,
        ..Default::default()
    };
    let mut tlps = HashMap::new();
    for (b, bc) in &cfg.behavior {
        p.behaviors.insert(
            *b,
            BehaviorOverride {
                k: bc.k.map(|k| k.threshold()).transpose()?,
                ttl_secs: bc.ttl_secs,
                max_age_secs: bc.max_age_secs,
            },
        );
        tlps.insert(*b, bc.tlp);
    }
    p.operators.insert(
        (state.urls.org.clone(), None),
        OperatorPolicy {
            trusted: true,
            weight: cfg.local_weight,
        },
    );
    for o in &cfg.operator {
        p.operators.insert(
            (o.id.clone(), o.behavior),
            OperatorPolicy {
                trusted: o.trusted,
                weight: o.weight,
            },
        );
    }
    let (ops, behaviors) = state
        .db
        .call(|c| {
            Ok((
                db::list_operator_policies(c)?,
                db::list_behavior_policies(c)?,
            ))
        })
        .await?;
    for (op, b, pol) in ops {
        p.operators.insert((op, b), pol);
    }
    for (b, (o, tlp)) in behaviors {
        p.behaviors.insert(b, o);
        tlps.insert(b, tlp);
    }
    Ok((p, tlps))
}

/// Local allowlist entries: static entries from the config file (domains
/// cover subdomains) plus unexpired local entries from the database.
pub struct LocalAllowlist {
    entries: Vec<(ObservableType, String, Vec<Behavior>, bool)>,
}

impl LocalAllowlist {
    pub fn new(state: &AppState, db_entries: &[AllowlistEntry], now: DateTime<Utc>) -> Self {
        let lenient = NormPolicy {
            min_v4_prefix: 0,
            min_v6_prefix: 0,
            reject_special_purpose: false,
            allow_documentation: true,
        };
        let mut entries = Vec::new();
        for v in &state.cfg.policy.allowlist {
            match normalize::normalise(v, None, &lenient) {
                Ok((ty, value)) => entries.push((ty, value, vec![], true)),
                Err(e) => tracing::warn!("ignoring allowlist entry `{v}`: {e}"),
            }
        }
        for e in db_entries {
            if e.scope == apti_core::protocol::AllowlistScope::Local
                && e.valid_until.is_none_or(|u| u > now)
            {
                entries.push((
                    e.observable_type,
                    e.observable_value.clone(),
                    e.behaviors.clone(),
                    false,
                ));
            }
        }
        Self { entries }
    }

    pub fn covers(&self, ty: ObservableType, value: &str, b: Option<Behavior>) -> bool {
        self.entries.iter().any(|(t, v, bs, subdomains)| {
            *t == ty
                && normalize::covers(ty, v, value, *subdomains)
                && (bs.is_empty() || b.is_none_or(|b| bs.contains(&b)))
        })
    }
}

fn operator_of(map: &HashMap<String, (String, String)>, actor: &str) -> String {
    map.get(actor)
        .map(|(o, _)| o.clone())
        .unwrap_or_else(|| client::fallback_operator(actor))
}

/// Attach operators to evidence objects.
pub fn score(
    evidence: Vec<EvidenceObject>,
    map: &HashMap<String, (String, String)>,
) -> Vec<ScoredEvidence> {
    evidence
        .into_iter()
        .map(|o| ScoredEvidence {
            operator: operator_of(map, &o.attributed_to),
            object: o,
        })
        .collect()
}

/// Evaluate every observable that has Indicators or Sightings.
pub fn evaluate(
    evidence: &[ScoredEvidence],
    policy: &PolicySet,
    allow: &LocalAllowlist,
    now: DateTime<Utc>,
) -> Vec<Assessment> {
    let mut groups: HashMap<(ObservableType, &str), Vec<&ScoredEvidence>> = HashMap::new();
    let mut opinions = Vec::new();
    for e in evidence {
        match (
            e.object.kind,
            e.object.observable_type,
            e.object.observable_value.as_deref(),
        ) {
            (EvidenceKind::Opinion, _, _) => opinions.push(e),
            (_, Some(ty), Some(v)) => groups.entry((ty, v)).or_default().push(e),
            _ => {}
        }
    }
    // Index opinions so that each observable only looks at the opinions that
    // can apply to it; scanning all opinions per observable is quadratic in
    // the amount of remote evidence (Section 10, resource exhaustion).
    let mut opinions_by_value: HashMap<(ObservableType, &str), Vec<usize>> = HashMap::new();
    let mut opinions_by_ref: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, o) in opinions.iter().enumerate() {
        if let (Some(ty), Some(v)) = (
            o.object.observable_type,
            o.object.observable_value.as_deref(),
        ) {
            opinions_by_value.entry((ty, v)).or_default().push(i);
        }
        for r in &o.object.indicator_refs {
            opinions_by_ref.entry(r.as_str()).or_default().push(i);
        }
    }
    let mut out = Vec::new();
    for ((ty, value), items) in groups {
        let indicator_ids: HashSet<&str> = items
            .iter()
            .filter(|e| e.object.kind == EvidenceKind::ThreatIndicator)
            .map(|e| e.object.id.as_str())
            .collect();
        let mut candidates: Vec<ScoredEvidence> = items.into_iter().cloned().collect();
        let mut matched = BTreeSet::new();
        for c in normalize::covering_values(ty, value) {
            if let Some(ix) = opinions_by_value.get(&(ty, c.as_str())) {
                matched.extend(ix.iter().copied());
            }
        }
        for id in &indicator_ids {
            if let Some(ix) = opinions_by_ref.get(id) {
                matched.extend(ix.iter().copied());
            }
        }
        candidates.extend(matched.into_iter().map(|i| (*opinions[i]).clone()));
        for mut a in expiry::assess_all(ty, value, &candidates, policy, now) {
            if allow.covers(ty, value, Some(a.behavior)) {
                a.allowlisted = true;
                a.suspended = true;
                a.active = false;
            }
            out.push(a);
        }
    }
    out.sort_by(|a, b| {
        (a.observable_type, &a.observable_value, a.behavior).cmp(&(
            b.observable_type,
            &b.observable_value,
            b.behavior,
        ))
    });
    out
}

/// Last moment at which evidence can still contribute.
fn relevant_until(o: &EvidenceObject, policy: &PolicySet) -> DateTime<Utc> {
    let ty = o.observable_type.unwrap_or(ObservableType::DomainName);
    let max_age = o
        .observed_behavior
        .iter()
        .map(|b| policy.max_age(*b, ty))
        .max()
        .unwrap_or(TimeDelta::days(180));
    match o.kind {
        EvidenceKind::ThreatIndicator => o
            .valid_until
            .unwrap_or(o.published)
            .min(saturating_add(o.base(), max_age)),
        EvidenceKind::Sighting => saturating_add(o.last_seen.unwrap_or(o.published), max_age),
        EvidenceKind::Opinion => o.opinion_valid_until(),
    }
}

/// Recompute the active table, fill the review queue and apply retention.
pub async fn recompute(state: &AppState) -> anyhow::Result<usize> {
    let now = Utc::now();
    let (policy, _) = load_policy(state).await?;
    let local_actor = state.urls.actor.clone();
    let org = state.urls.org.clone();
    let (evidence, mut map, allow_db) = state
        .db
        .call(|c| {
            Ok((
                db::live_evidence(c)?,
                db::actor_operator_map(c)?,
                db::list_allowlist(c)?,
            ))
        })
        .await?;
    map.insert(local_actor.clone(), (org, "local".into()));

    // Retention (Section 11) for evidence that can no longer contribute.
    // Own Sightings have left activeObjects by then (lastSeen + T); own
    // Opinions stay linked to their allowlist entries.
    let retention = TimeDelta::days(state.cfg.policy.retention_days);
    let stale: Vec<String> = evidence
        .iter()
        .filter(|o| {
            (o.attributed_to != local_actor || o.kind == EvidenceKind::Sighting)
                && saturating_add(relevant_until(o, &policy), retention) < now
        })
        .map(|o| o.id.clone())
        .collect();
    let stale_set: HashSet<&String> = stale.iter().collect();
    let purged: Vec<&EvidenceObject> = evidence
        .iter()
        .filter(|o| stale_set.contains(&o.id))
        .collect();
    let live: Vec<EvidenceObject> = evidence
        .iter()
        .filter(|o| !stale_set.contains(&o.id))
        .cloned()
        .collect();

    let scored = score(live, &map);
    let allow = LocalAllowlist::new(state, &allow_db, now);
    let list = evaluate(&scored, &policy, &allow, now);

    // Review queue (Sections 7, 8, 10).
    let mut reviews = Vec::new();
    for a in &list {
        if a.flagged {
            reviews.push((
                "dispute",
                a.observable_type,
                a.observable_value.clone(),
                Some(a.behavior),
                format!(
                    "D={} by [{}] vs S={} by [{}]{}",
                    a.dispute_weight,
                    a.disputing_operators.join(", "),
                    a.support_weight,
                    a.supporting_operators.join(", "),
                    if a.suspended { " — suspended" } else { "" }
                ),
            ));
        }
        if !a.untrusted_operators.is_empty() && a.supporting_operators.is_empty() {
            reviews.push((
                "untrusted",
                a.observable_type,
                a.observable_value.clone(),
                Some(a.behavior),
                format!(
                    "evidence only from untrusted operators: {}",
                    a.untrusted_operators.join(", ")
                ),
            ));
        }
    }
    for e in &scored {
        let o = &e.object;
        if o.attributed_to != local_actor
            && o.is_allowlist_entry()
            && o.observable_value
                .as_deref()
                .is_some_and(|v| v.contains('/'))
            && Behavior::ALL
                .iter()
                .any(|b| policy.trusted(&e.operator, *b))
        {
            reviews.push((
                "broad-allowlist",
                o.observable_type.unwrap_or(ObservableType::Unknown),
                o.observable_value.clone().unwrap_or_default(),
                None,
                format!(
                    "allowlist entry for a prefix from {} ({})",
                    e.operator, o.id
                ),
            ));
        }
    }

    let n = list.len();
    let cutoff = now - retention;
    let audit = state.audit;
    let (before, list) = state
        .db
        .call(move |c| {
            if !stale.is_empty() {
                db::delete_evidence_ids(c, &stale)?;
            }
            db::purge_expired(c, now, cutoff)?;
            for (kind, ty, value, b, detail) in &reviews {
                db::insert_review(c, kind, *ty, value, *b, detail)?;
            }
            let before = if audit.enabled {
                db::list_active(c, now, None, None, true)?
            } else {
                Vec::new()
            };
            db::replace_active(c, &list)?;
            Ok((before, list))
        })
        .await?;
    for o in purged {
        audit.purged(o);
    }
    audit.active(&before, &list);
    *state
        .last_recompute
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(now);
    Ok(n)
}

pub async fn recompute_loop(state: Shared) {
    let every = Duration::from_secs(state.cfg.policy.recompute_interval_secs.max(1));
    loop {
        match recompute(&state).await {
            Ok(n) => tracing::debug!("recomputed {n} entries"),
            Err(e) => tracing::error!("recompute failed: {e:#}"),
        }
        tokio::select! {
            _ = state.recompute.notified() => {
                // Debounce bursts of changes.
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            _ = tokio::time::sleep(every) => {}
        }
    }
}
