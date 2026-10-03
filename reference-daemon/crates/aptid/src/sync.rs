//! Pull synchronisation of followed actors' `activeObjects` (Section 5.3).

use std::time::Duration;

use chrono::{TimeDelta, Utc};
use serde_json::Value;

use crate::client::{self, as_list, id_of};
use crate::db::{self, FollowingRow};
use crate::inbox::{self, IngestReport};
use crate::state::{AppState, Shared};

/// Upper bound on pages read per sync (Section 10, resource exhaustion).
const MAX_PAGES: usize = 1000;

/// Synchronise one followed actor. Returns the ingest report.
pub async fn sync_actor(state: &AppState, row: &FollowingRow) -> anyhow::Result<IngestReport> {
    let actor = client::fetch_actor(state, &row.actor, false).await?;
    let active = actor
        .active_objects
        .clone()
        .ok_or_else(|| anyhow::anyhow!("actor has no activeObjects collection"))?;
    let full = row.last_full_sync.is_none_or(|t| {
        Utc::now() - t > TimeDelta::seconds(state.cfg.federation.full_resync_interval_secs as i64)
    });
    let sync_point = if full {
        None
    } else {
        row.sync_point.as_deref().map(db::parse_ts)
    };

    let collection = client::signed_get(state, &active).await?;
    let mut next: Option<Value> = match &collection["first"] {
        Value::Null => Some(collection.clone()),
        first => Some(first.clone()),
    };
    let mut newest = None;
    let mut report = IngestReport::default();
    let mut pages = 0;
    'pages: while let Some(page_ref) = next.take() {
        pages += 1;
        if pages > MAX_PAGES {
            break;
        }
        let page = match page_ref {
            Value::String(url) => {
                if client::host_of(&url) != client::host_of(&actor.id) {
                    anyhow::bail!("page {url} on foreign origin");
                }
                client::signed_get(state, &url).await?
            }
            obj => obj,
        };
        let items = if page["orderedItems"].is_null() {
            &page["items"]
        } else {
            &page["orderedItems"]
        };
        let mut batch = Vec::new();
        let mut stop = false;
        for item in as_list(items) {
            let item = match item {
                Value::String(id) => match client::signed_get(state, id).await {
                    Ok(v) if v["id"].as_str() == Some(id.as_str()) => v,
                    _ => continue,
                },
                v => v.clone(),
            };
            let t = inbox::item_time(&item);
            if let (Some(t), Some(sp)) = (t, sync_point) {
                if t <= sp {
                    stop = true;
                    break;
                }
            }
            if let Some(t) = t {
                newest = Some(newest.map_or(t, |n: chrono::DateTime<Utc>| n.max(t)));
            }
            batch.push(item);
        }
        let r = inbox::ingest_objects(state, &actor.id, batch, false).await?;
        report.stored += r.stored;
        report.ignored += r.ignored;
        report.invalid += r.invalid;
        report.deleted += r.deleted;
        if stop {
            break 'pages;
        }
        next = page.get("next").filter(|n| id_of(n).is_some()).cloned();
    }
    let sp = newest.map(db::ts);
    let a = row.actor.clone();
    state
        .db
        .call(move |c| db::record_sync(c, &a, sp.as_deref(), full, None))
        .await?;
    if report.changed() {
        state.recompute.notify_one();
    }
    tracing::info!(actor = %row.actor, full, stored = report.stored, deleted = report.deleted, invalid = report.invalid, "synced");
    Ok(report)
}

fn due(state: &AppState, row: &FollowingRow) -> bool {
    if row.state == "rejected" {
        return false;
    }
    let interval = TimeDelta::seconds(state.cfg.federation.sync_interval_secs as i64);
    row.last_full_sync.is_none() || row.last_sync.is_none_or(|t| Utc::now() - t >= interval)
}

pub async fn sync_due(state: &AppState) -> anyhow::Result<()> {
    let rows = state.db.call(|c| db::list_following(c)).await?;
    for row in rows.iter().filter(|r| due(state, r)) {
        if let Err(e) = sync_actor(state, row).await {
            tracing::warn!(actor = %row.actor, "sync failed: {e:#}");
            let (a, msg) = (row.actor.clone(), format!("{e:#}"));
            state
                .db
                .call(move |c| db::record_sync(c, &a, None, false, Some(&msg)))
                .await?;
        }
    }
    Ok(())
}

pub async fn sync_loop(state: Shared) {
    loop {
        if let Err(e) = sync_due(&state).await {
            tracing::error!("sync: {e:#}");
        }
        tokio::select! {
            _ = state.sync_now.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(30)) => {}
        }
    }
}
