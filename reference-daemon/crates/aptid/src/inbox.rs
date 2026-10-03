//! Incoming activities (Sections 5.1, 8) and evidence ingestion.

use apti_core::{EvidenceObject, MAX_BATCH};
use chrono::{DateTime, TimeDelta, Utc};
use serde_json::{json, Value};

use crate::client::{self, as_list, host_of, id_of};
use crate::db::{self, Upsert};
use crate::publish;
use crate::state::AppState;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct IngestReport {
    pub stored: usize,
    pub ignored: usize,
    pub invalid: usize,
    pub deleted: usize,
}

impl IngestReport {
    pub fn changed(&self) -> bool {
        self.stored + self.deleted > 0
    }
}

fn parse_time(v: &Value) -> Option<DateTime<Utc>> {
    v.as_str()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&Utc))
}

/// Sort key of a collection item: `updated`, `published` or `deleted`.
pub fn item_time(v: &Value) -> Option<DateTime<Utc>> {
    parse_time(&v["updated"])
        .or_else(|| parse_time(&v["deleted"]))
        .or_else(|| parse_time(&v["published"]))
}

/// Ingest evidence objects (and Tombstones) published by `actor`.
/// Each object is validated independently; invalid ones are dropped.
/// `require_updated` enforces that objects in an `Update` carry `updated`.
pub async fn ingest_objects(
    state: &AppState,
    actor: &str,
    objects: Vec<Value>,
    require_updated: bool,
) -> anyhow::Result<IngestReport> {
    let now = Utc::now();
    let norm = state.cfg.norm_policy();
    let tombstone_until = now + TimeDelta::days(state.cfg.publish.tombstone_days);
    let actor_host = host_of(actor);
    let mut report = IngestReport::default();
    let mut valid = Vec::new();
    let mut tombstones = Vec::new();
    for v in objects {
        match v["type"].as_str() {
            Some("Tombstone") => {
                if let Some(id) = v["id"].as_str() {
                    let when = parse_time(&v["deleted"]).unwrap_or(now).min(now);
                    tombstones.push((id.to_string(), when));
                }
                continue;
            }
            Some("ThreatIndicator" | "Sighting" | "Opinion") => {}
            // Notes and other types are not evidence (Section 5.3).
            _ => {
                report.ignored += 1;
                continue;
            }
        }
        let o: EvidenceObject = match serde_json::from_value(v) {
            Ok(o) => o,
            Err(e) => {
                tracing::debug!(actor, "invalid evidence object: {e}");
                report.invalid += 1;
                continue;
            }
        };
        // Origin rules (Section 8).
        if o.attributed_to != actor || host_of(&o.id) != actor_host {
            tracing::debug!(actor, id = %o.id, "origin mismatch");
            report.invalid += 1;
            continue;
        }
        if require_updated && o.updated.is_none() {
            report.invalid += 1;
            continue;
        }
        if let Err(e) = o.validate(now, &norm) {
            tracing::debug!(actor, id = %o.id, "rejected: {e}");
            report.invalid += 1;
            continue;
        }
        valid.push(o);
    }
    let actor = actor.to_string();
    let (stored, ignored, deleted) = state
        .db
        .call(move |c| {
            let (mut stored, mut ignored, mut deleted) = (0, 0, 0);
            for o in &valid {
                match db::upsert_evidence(c, o, false, &[], None)? {
                    Upsert::Inserted | Upsert::Updated => stored += 1,
                    Upsert::Ignored => ignored += 1,
                }
            }
            for (id, when) in &tombstones {
                if host_of(id) == host_of(&actor)
                    && db::mark_deleted(c, id, &actor, *when, tombstone_until)?
                {
                    deleted += 1;
                }
            }
            Ok((stored, ignored, deleted))
        })
        .await?;
    report.stored += stored;
    report.ignored += ignored;
    report.deleted += deleted;
    Ok(report)
}

async fn delete_ids(state: &AppState, actor: &str, ids: Vec<String>) -> anyhow::Result<usize> {
    let now = Utc::now();
    let until = now + TimeDelta::days(state.cfg.publish.tombstone_days);
    let actor = actor.to_string();
    state
        .db
        .call(move |c| {
            let mut n = 0;
            for id in &ids {
                if db::mark_deleted(c, id, &actor, now, until)? {
                    n += 1;
                }
            }
            Ok(n)
        })
        .await
}

/// Process a verified activity from `actor` (signature already checked).
pub async fn process(state: &AppState, actor: &str, activity: &Value) -> anyhow::Result<()> {
    let kind = activity["type"].as_str().unwrap_or_default();
    let object = &activity["object"];
    let objects = as_list(object);
    let following = {
        let a = actor.to_string();
        state.db.call(move |c| db::is_following(c, &a)).await?
    };
    let mut changed = false;
    match kind {
        "Follow" => {
            if id_of(object) != Some(state.urls.actor.as_str()) {
                return Ok(());
            }
            let follow_id = activity["id"].as_str().unwrap_or_default().to_string();
            let manual = state.cfg.publish.manually_approves_followers;
            let state_s = if manual { "pending" } else { "accepted" };
            let (a, f) = (actor.to_string(), follow_id.clone());
            state
                .db
                .call(move |c| db::upsert_follower(c, &a, &f, state_s))
                .await?;
            let accepted = {
                let a = actor.to_string();
                state
                    .db
                    .call(move |c| db::is_accepted_follower(c, &a))
                    .await?
            };
            if accepted {
                send_follow_response(state, "Accept", actor, &follow_id).await?;
            }
            tracing::info!(actor, "follow request ({state_s})");
        }
        "Undo" => {
            // Undo{Follow}: embedded Follow, or the id of the stored Follow.
            let undone = id_of(object).map(String::from);
            let embedded_follow = object["type"] == "Follow";
            let a = actor.to_string();
            state
                .db
                .call(move |c| {
                    let matches = db::get_follower(c, &a)?.is_some_and(|(fid, _)| {
                        embedded_follow || undone.as_deref() == Some(fid.as_str())
                    });
                    if matches {
                        db::delete_follower(c, &a)?;
                    }
                    Ok(())
                })
                .await?;
        }
        "Accept" | "Reject" => {
            let follow_id = id_of(object).map(String::from);
            let new_state = if kind == "Accept" {
                "accepted"
            } else {
                "rejected"
            };
            let a = actor.to_string();
            let updated = state
                .db
                .call(move |c| {
                    let ok = db::set_following_state(c, &a, follow_id.as_deref(), new_state)?;
                    if ok && new_state == "accepted" {
                        // Re-read activeObjects with follower visibility.
                        db::reset_full_sync(c, &a)?;
                    }
                    Ok(ok)
                })
                .await?;
            if updated {
                tracing::info!(actor, "follow {new_state}");
                state.sync_now.notify_one();
            }
        }
        "Create" | "Update" => {
            if !following {
                tracing::debug!(actor, "ignoring {kind} from actor we do not follow");
                return Ok(());
            }
            if objects.len() > MAX_BATCH {
                anyhow::bail!("activity exceeds {MAX_BATCH} objects");
            }
            let objs = objects.into_iter().cloned().collect();
            let r = ingest_objects(state, actor, objs, kind == "Update").await?;
            tracing::info!(
                actor,
                kind,
                stored = r.stored,
                invalid = r.invalid,
                ignored = r.ignored,
                "ingested"
            );
            changed = r.changed();
        }
        "Delete" => {
            if objects.len() > MAX_BATCH {
                anyhow::bail!("activity exceeds {MAX_BATCH} objects");
            }
            let ids: Vec<String> = objects
                .iter()
                .filter_map(|v| id_of(v).map(String::from))
                .collect();
            changed = delete_ids(state, actor, ids).await? > 0;
        }
        "Announce" => {
            // Re-fetch each object from its origin (Section 8).
            for v in objects.iter().take(MAX_BATCH) {
                let Some(id) = id_of(v) else { continue };
                let fetched = match client::signed_get(state, id).await {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::debug!("announce re-fetch of {id} failed: {e:#}");
                        continue;
                    }
                };
                if fetched["id"].as_str() != Some(id) {
                    continue;
                }
                let Some(publisher) = fetched["attributedTo"].as_str().map(String::from) else {
                    continue;
                };
                let p = publisher.clone();
                if !state.db.call(move |c| db::is_following(c, &p)).await? {
                    continue;
                }
                let r = ingest_objects(state, &publisher, vec![fetched], false).await?;
                changed |= r.changed();
            }
        }
        _ => {}
    }
    if changed {
        state.recompute.notify_one();
    }
    Ok(())
}

/// Send Accept/Reject for a follower's Follow.
pub async fn send_follow_response(
    state: &AppState,
    kind: &str,
    follower: &str,
    follow_id: &str,
) -> anyhow::Result<()> {
    let activity = json!({
        "type": kind,
        "id": state.urls.new_activity_id(),
        "object": {
            "type": "Follow",
            "id": follow_id,
            "actor": follower,
            "object": state.urls.actor,
        },
    });
    publish::send_direct(state, activity, follower).await
}
