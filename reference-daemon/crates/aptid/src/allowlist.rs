//! Allowlist management shared by the control socket and the REST API.
//!
//! Local entries affect only this consumer. Published entries are
//! `strongly-disagree` Opinions without `indicatorRefs` (Section 4.5) and are
//! federated to followers; removing one sends a `Delete`.

use apti_core::normalize::{self, NormPolicy};
use apti_core::protocol::{AllowlistEntry, AllowlistScope, NewAllowlistEntry};
use apti_core::{EvidenceKind, EvidenceObject, OpinionValue, Tlp};
use chrono::{TimeDelta, Utc};
use serde_json::json;

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
    NormPolicy {
        min_v4_prefix: 0,
        min_v6_prefix: 0,
        reject_special_purpose: false,
        allow_documentation: true,
    }
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
/// behaviours exists, it is returned instead (`created == false`).
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
    if let Some(existing) = list(state).await?.into_iter().find(|x| {
        x.scope == e.scope
            && x.observable_type == ty
            && x.observable_value == value
            && same_behaviors(&x.behaviors, &e.behaviors)
            && x.valid_until.is_none_or(|u| u > now)
    }) {
        return Ok((existing, false));
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
        object_id: None,
        created: now,
    };
    if published {
        let tlp = match e.tlp {
            Some(Tlp::Red) => {
                return Err(AllowlistError::Invalid(
                    "TLP:RED cannot be published".into(),
                ))
            }
            Some(t) => t,
            None => publish::tlp_settings(state).await?.0,
        };
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
        let (o, a) = (opinion.clone(), audience.clone());
        state
            .db
            .call(move |c| db::upsert_evidence(c, &o, true, &a, Some(valid_until)))
            .await?;
        entry.tlp = Some(tlp);
        entry.valid_until = Some(valid_until);
        entry.object_id = Some(opinion.id.clone());
        publish::publish(
            state,
            "Create",
            vec![serde_json::to_value(&opinion).map_err(anyhow::Error::from)?],
            tlp,
            audience,
        )
        .await?;
    }
    let e2 = entry.clone();
    entry.id = state.db.call(move |c| db::insert_allowlist(c, &e2)).await?;
    state.recompute.notify_one();
    Ok((entry, true))
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
        let oid = object_id.clone();
        // The Delete goes to the audience the Opinion was published to.
        let removed = state
            .db
            .call(move |c| {
                let audience = db::get_evidence(c, &oid)?
                    .map(|e| e.audience)
                    .unwrap_or_default();
                let now = Utc::now();
                let removed =
                    db::mark_deleted(c, &oid, &actor, now, now + TimeDelta::days(tombstone_days))?;
                Ok(removed.then_some(audience))
            })
            .await?;
        if let Some(audience) = removed {
            let tlp = entry.tlp.unwrap_or(Tlp::Green);
            publish::publish(state, "Delete", vec![json!(object_id)], tlp, audience).await?;
        }
    }
    state.recompute.notify_one();
    Ok(entry)
}
