//! Publishing: batching local observations into Sightings (Section 5.3),
//! TLP addressing (Section 5.2) and delivery with retries.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use apti_core::{EvidenceKind, EvidenceObject, Tlp, AS_PUBLIC, MAX_BATCH};
use chrono::{DateTime, TimeDelta, Utc};
use serde_json::{json, Value};

use crate::client;
use crate::db::{self, Observation};
use crate::engine;
use crate::state::{AppState, Shared};

/// TLP settings: global default and AMBER recipients.
pub async fn tlp_settings(state: &AppState) -> anyhow::Result<(Tlp, Vec<String>)> {
    let default = state.cfg.publish.default_tlp;
    state
        .db
        .call(move |c| {
            let tlp = db::get_setting(c, "default_tlp")?
                .and_then(|t| t.parse().ok())
                .unwrap_or(default);
            let recipients = db::get_setting(c, "amber_recipients")?
                .and_then(|r| serde_json::from_str(&r).ok())
                .unwrap_or_default();
            Ok((tlp, recipients))
        })
        .await
}

/// Addressing for a TLP (Section 5.2): `(to, cc, recipient actors)`.
/// For CLEAR and GREEN the recipients are the accepted followers.
pub async fn addressing(
    state: &AppState,
    tlp: Tlp,
) -> anyhow::Result<(Vec<String>, Vec<String>, Vec<String>)> {
    let followers = state.db.call(|c| db::accepted_followers(c)).await?;
    let urls = &state.urls;
    Ok(match tlp {
        Tlp::Clear => (
            vec![AS_PUBLIC.into()],
            vec![urls.followers.clone()],
            followers,
        ),
        Tlp::Green => (vec![urls.followers.clone()], vec![], followers),
        Tlp::Amber | Tlp::AmberStrict => {
            let (_, recipients) = tlp_settings(state).await?;
            (recipients.clone(), vec![], recipients)
        }
        Tlp::Red => anyhow::bail!("TLP:RED must not be shared"),
    })
}

/// Named audience to store with AMBER objects (controls signed-fetch access).
pub async fn audience_for(state: &AppState, tlp: Tlp) -> anyhow::Result<Vec<String>> {
    Ok(match tlp {
        Tlp::Amber | Tlp::AmberStrict => tlp_settings(state).await?.1,
        _ => vec![],
    })
}

fn object_json(o: &EvidenceObject) -> Value {
    serde_json::to_value(o).unwrap_or(Value::Null)
}

/// Store an activity and queue it for delivery to the recipients' inboxes.
pub async fn send_activity(
    state: &AppState,
    activity: Value,
    tlp: Tlp,
    audience: Vec<String>,
    recipients: Vec<String>,
) -> anyhow::Result<()> {
    let id = activity["id"].as_str().unwrap_or_default().to_string();
    let mut inboxes = BTreeSet::new();
    for r in &recipients {
        match client::fetch_actor(state, r, false).await {
            Ok(a) => {
                inboxes.insert(a.delivery_inbox().to_string());
            }
            Err(e) => tracing::warn!(recipient = %r, "cannot resolve recipient: {e:#}"),
        }
    }
    state
        .db
        .call(move |c| {
            db::insert_activity(c, &id, tlp, &audience, &activity)?;
            for inbox in &inboxes {
                db::enqueue_delivery(c, &id, inbox)?;
            }
            Ok(())
        })
        .await?;
    state.deliver_now.notify_one();
    Ok(())
}

/// Publish `Create`/`Update` (with objects) or `Delete` (with ids), all
/// sharing `tlp`. Splits into activities of at most 1000 objects.
pub async fn publish(
    state: &AppState,
    kind: &str,
    objects: Vec<Value>,
    tlp: Tlp,
) -> anyhow::Result<()> {
    if objects.is_empty() {
        return Ok(());
    }
    let (to, cc, recipients) = addressing(state, tlp).await?;
    let audience = audience_for(state, tlp).await?;
    for chunk in objects.chunks(MAX_BATCH) {
        let object = if chunk.len() == 1 {
            chunk[0].clone()
        } else {
            Value::Array(chunk.to_vec())
        };
        let mut activity = json!({
            "@context": apti_core::context(),
            "type": kind,
            "id": state.urls.new_activity_id(),
            "actor": state.urls.actor,
            "published": db::ts(Utc::now()),
            "to": to,
            "object": object,
        });
        if !cc.is_empty() {
            activity["cc"] = json!(cc);
        }
        send_activity(state, activity, tlp, audience.clone(), recipients.clone()).await?;
    }
    Ok(())
}

/// Send a non-evidence activity (Follow, Accept, ...) to one actor.
pub async fn send_direct(state: &AppState, mut activity: Value, to: &str) -> anyhow::Result<()> {
    activity["@context"] = json!(apti_core::AS_CONTEXT);
    activity["actor"] = json!(state.urls.actor);
    activity["to"] = json!([to]);
    send_activity(
        state,
        activity,
        Tlp::Amber,
        vec![to.to_string()],
        vec![to.to_string()],
    )
    .await
}

/// Build a local Sighting from an observation, reusing the existing object.
fn sighting_from(
    state: &AppState,
    obs: &Observation,
    existing: Option<EvidenceObject>,
    tlp: Tlp,
    now: DateTime<Utc>,
) -> (EvidenceObject, bool) {
    match existing {
        Some(mut s) => {
            s.updated = Some(now.max(s.base() + TimeDelta::milliseconds(1)));
            s.first_seen = Some(obs.first_seen);
            s.last_seen = Some(obs.last_seen);
            s.count = Some(obs.count);
            s.port = obs.port;
            s.service = obs.service.clone();
            (s, true)
        }
        None => (
            EvidenceObject {
                kind: EvidenceKind::Sighting,
                id: state.urls.new_object_id(),
                attributed_to: state.urls.actor.clone(),
                published: now,
                updated: None,
                tlp,
                summary: None,
                observable_type: Some(obs.observable_type),
                observable_value: Some(obs.observable_value.clone()),
                observed_behavior: vec![obs.behavior],
                port: obs.port,
                service: obs.service.clone(),
                include_subdomains: None,
                valid_from: None,
                valid_until: None,
                confidence: None,
                infrastructure_types: vec![],
                revoked: None,
                tag: vec![],
                first_seen: Some(obs.first_seen),
                last_seen: Some(obs.last_seen),
                count: Some(obs.count),
                indicator_refs: vec![],
                opinion: None,
            },
            false,
        ),
    }
}

/// Turn pending observations into Sightings and publish them. At most one
/// Sighting update per observable and behaviour per batch.
pub async fn run_batch(state: &AppState) -> anyhow::Result<usize> {
    let pending = state.db.call(|c| db::pending_observations(c)).await?;
    if pending.is_empty() {
        return Ok(0);
    }
    let (policy, behavior_tlp) = engine::load_policy(state).await?;
    let (default_tlp, _) = tlp_settings(state).await?;
    let now = Utc::now();
    let mut groups: BTreeMap<(&'static str, Tlp), Vec<Value>> = BTreeMap::new();
    let n = pending.len();
    for obs in pending {
        let existing_id = obs.sighting_id.clone();
        let existing = match existing_id {
            Some(id) => state
                .db
                .call(move |c| db::get_evidence(c, &id))
                .await?
                .filter(|e| e.deleted.is_none())
                .map(|e| e.object),
            None => None,
        };
        let tlp = existing
            .as_ref()
            .map(|e| e.tlp)
            .or_else(|| behavior_tlp.get(&obs.behavior).copied().flatten())
            .unwrap_or(default_tlp);
        let (sighting, is_update) = sighting_from(state, &obs, existing, tlp, now);
        let listed_until = obs.last_seen + policy.ttl(obs.behavior, obs.observable_type);
        let audience = audience_for(state, tlp).await?;
        let s = sighting.clone();
        state
            .db
            .call(move |c| {
                db::upsert_evidence(c, &s, true, &audience, Some(listed_until))?;
                db::mark_observation_published(c, &obs, &s.id)
            })
            .await?;
        let kind = if is_update { "Update" } else { "Create" };
        groups
            .entry((kind, tlp))
            .or_default()
            .push(object_json(&sighting));
    }
    for ((kind, tlp), objects) in groups {
        publish(state, kind, objects, tlp).await?;
    }
    state.recompute.notify_one();
    Ok(n)
}

pub async fn batch_loop(state: Shared) {
    let mut tick = tokio::time::interval(Duration::from_secs(
        state.cfg.publish.batch_interval_secs.max(1),
    ));
    tick.tick().await;
    loop {
        tick.tick().await;
        match run_batch(&state).await {
            Ok(0) => {}
            Ok(n) => tracing::info!("published {n} sighting(s)"),
            Err(e) => tracing::error!("batch failed: {e:#}"),
        }
    }
}

/// Attempt all due deliveries once.
pub async fn deliver_due(state: &AppState) -> anyhow::Result<()> {
    let due = state
        .db
        .call(|c| db::due_deliveries(c, Utc::now(), 50))
        .await?;
    for d in due {
        let result = client::signed_post(state, &d.inbox, &d.json).await;
        let max = state.cfg.federation.delivery_max_attempts;
        state
            .db
            .call(move |c| match result {
                Ok(()) => db::delivery_done(c, d.id),
                Err(e) => {
                    let attempts = d.attempts + 1;
                    let backoff = TimeDelta::seconds((30i64 << attempts.min(10)).min(6 * 3600));
                    tracing::warn!(inbox = %d.inbox, attempts, "delivery failed: {e:#}");
                    db::delivery_failed(
                        c,
                        d.id,
                        attempts,
                        Utc::now() + backoff,
                        &format!("{e:#}"),
                        max,
                    )
                }
            })
            .await?;
    }
    Ok(())
}

pub async fn delivery_loop(state: Shared) {
    loop {
        if let Err(e) = deliver_due(&state).await {
            tracing::error!("delivery: {e:#}");
        }
        tokio::select! {
            _ = state.deliver_now.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(10)) => {}
        }
    }
}
