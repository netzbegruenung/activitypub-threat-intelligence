//! Allowlist management shared by the control socket and the REST API.
//!
//! Local entries affect only this consumer. Published entries are
//! `strongly-disagree` Opinions without `indicatorRefs` (Section 4.5) and are
//! federated to followers; removing one sends a `Delete`.

use apti_core::normalize::{self, NormPolicy};
use apti_core::protocol::{AllowlistEntry, AllowlistScope, NewAllowlistEntry};
use apti_core::{EvidenceKind, EvidenceObject, OpinionValue, Tlp};
use chrono::{DateTime, TimeDelta, Utc};

use crate::db;
use crate::publish;
use crate::state::AppState;

#[derive(Debug, thiserror::Error)]
pub enum AllowlistError {
    #[error("{0}")]
    Invalid(String),
    #[error("no allowlist entry {0}")]
    NotFound(i64),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Normalisation for local use: any prefix length, special-purpose allowed.
pub fn lenient_norm() -> NormPolicy {
    NormPolicy::lenient()
}

fn same_behaviors(a: &[apti_core::Behavior], b: &[apti_core::Behavior]) -> bool {
    let (mut a, mut b) = (a.to_vec(), b.to_vec());
    a.sort();
    a.dedup();
    b.sort();
    b.dedup();
    a == b
}

pub async fn list(state: &AppState) -> anyhow::Result<Vec<AllowlistEntry>> {
    state.db.call(|c| db::list_allowlist(c)).await
}

pub async fn get(state: &AppState, id: i64) -> anyhow::Result<Option<AllowlistEntry>> {
    state.db.call(move |c| db::get_allowlist(c, id)).await
}

/// Add an entry. If an unexpired entry with the same scope, observable and
/// behaviours (and, if published, TLP) exists, it is returned instead
/// (`created == false`); a later `valid_until` extends it.
pub async fn add(
    state: &AppState,
    e: NewAllowlistEntry,
) -> Result<(AllowlistEntry, bool), AllowlistError> {
    let now = Utc::now();
    if e.valid_until.is_some_and(|u| u <= now) {
        return Err(AllowlistError::Invalid(
            "validUntil must be in the future".into(),
        ));
    }
    let published = e.scope == AllowlistScope::Published;
    // Published entries must be acceptable to consumers (Section 4.1).
    let norm = if published {
        state.cfg.norm_policy()
    } else {
        lenient_norm()
    };
    let (ty, value) = normalize::normalise(&e.value, None, &norm)
        .map_err(|err| AllowlistError::Invalid(format!("{}: {err}", e.value)))?;
    // The TLP of a published entry decides its audience, so it is part of
    // the entry's identity.
    let tlp = if published {
        Some(match e.tlp {
            Some(Tlp::Red) => {
                return Err(AllowlistError::Invalid(
                    "TLP:RED cannot be published".into(),
                ))
            }
            Some(t) => t,
            None => publish::tlp_settings(state).await?.0,
        })
    } else {
        None
    };
    if let Some(existing) = list(state).await?.into_iter().find(|x| {
        x.scope == e.scope
            && x.observable_type == ty
            && x.observable_value == value
            && same_behaviors(&x.behaviors, &e.behaviors)
            && x.tlp == tlp
            && x.valid_until.is_none_or(|u| u > now)
    }) {
        return match (existing.valid_until, e.valid_until) {
            (Some(old), Some(new)) if new > old => Ok((extend(state, existing, new).await?, false)),
            _ => Ok((existing, false)),
        };
    }
    let mut entry = AllowlistEntry {
        id: 0,
        scope: e.scope,
        observable_type: ty,
        observable_value: value.clone(),
        behaviors: e.behaviors.clone(),
        tlp: None,
        valid_until: e.valid_until,
        summary: e.summary.clone(),
        source: e.source.clone(),
        object_id: None,
        created: now,
    };
    if let Some(tlp) = tlp {
        let valid_until = e.valid_until.unwrap_or(now + TimeDelta::days(90));
        let opinion = EvidenceObject {
            kind: EvidenceKind::Opinion,
            id: state.urls.new_object_id(),
            attributed_to: state.urls.actor.clone(),
            published: now,
            updated: None,
            tlp,
            summary: e.summary.clone(),
            observable_type: Some(ty),
            observable_value: Some(value),
            observed_behavior: e.behaviors.clone(),
            port: None,
            service: None,
            include_subdomains: None,
            valid_from: None,
            valid_until: Some(valid_until),
            confidence: None,
            infrastructure_types: vec![],
            revoked: None,
            tag: vec![],
            first_seen: None,
            last_seen: None,
            count: None,
            indicator_refs: vec![],
            opinion: Some(OpinionValue::StronglyDisagree),
        };
        let audience = publish::audience_for(state, tlp).await?;
        let o = opinion.clone();
        // Federated with the next publish batch (Section 5.3).
        state
            .db
            .call(move |c| {
                db::upsert_evidence(c, &o, true, &audience, Some(valid_until))?;
                db::queue_opinion(c, &o.id, "Create")
            })
            .await?;
        entry.tlp = Some(tlp);
        entry.valid_until = Some(valid_until);
        entry.object_id = Some(opinion.id);
    }
    let e2 = entry.clone();
    entry.id = state.db.call(move |c| db::insert_allowlist(c, &e2)).await?;
    state.recompute.notify_one();
    Ok((entry, true))
}

/// Move the expiry of an entry to `until`; a published entry's Opinion is
/// updated and queued as `Update` (sent to the audience it was published to).
async fn extend(
    state: &AppState,
    mut entry: AllowlistEntry,
    until: DateTime<Utc>,
) -> Result<AllowlistEntry, AllowlistError> {
    if let Some(oid) = entry.object_id.clone() {
        let stored = state
            .db
            .call(move |c| db::get_evidence(c, &oid))
            .await?
            .filter(|s| s.deleted.is_none());
        if let Some(stored) = stored {
            let mut o = stored.object;
            o.valid_until = Some(until);
            o.updated = Some(Utc::now().max(o.base() + TimeDelta::milliseconds(1)));
            state
                .db
                .call(move |c| {
                    db::upsert_evidence(c, &o, true, &stored.audience, Some(until))?;
                    db::queue_opinion(c, &o.id, "Update")
                })
                .await?;
        }
    }
    let id = entry.id;
    state
        .db
        .call(move |c| db::set_allowlist_valid_until(c, id, until))
        .await?;
    entry.valid_until = Some(until);
    state.recompute.notify_one();
    Ok(entry)
}

/// Remove an entry; published entries are withdrawn with `Delete`.
pub async fn remove(state: &AppState, id: i64) -> Result<AllowlistEntry, AllowlistError> {
    let entry = state
        .db
        .call(move |c| db::delete_allowlist(c, id))
        .await?
        .ok_or(AllowlistError::NotFound(id))?;
    if let Some(object_id) = entry.object_id.clone() {
        let actor = state.urls.actor.clone();
        let tombstone_days = state.cfg.publish.tombstone_days;
        // The Delete is sent with the next batch, to the audience the
        // Opinion was published to.
        state
            .db
            .call(move |c| {
                let now = Utc::now();
                let until = now + TimeDelta::days(tombstone_days);
                if db::mark_deleted(c, &object_id, &actor, now, until)? {
                    db::queue_opinion(c, &object_id, "Delete")?;
                }
                Ok(())
            })
            .await?;
    }
    state.recompute.notify_one();
    Ok(entry)
}
