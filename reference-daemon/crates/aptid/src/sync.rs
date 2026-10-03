//! Pull synchronisation of followed actors' `activeObjects` (Section 5.3).

use std::sync::Arc;
use std::time::Duration;

use apti_core::MAX_BATCH;
use chrono::{TimeDelta, Utc};
use serde_json::Value;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::client::{self, as_list, id_of};
use crate::db::{self, FollowingRow};
use crate::inbox::{self, IngestReport};
use crate::state::{AppState, Shared};

/// Upper bound on pages read per sync (Section 10, resource exhaustion).
const MAX_PAGES: usize = 1000;
/// Followed actors synchronised in parallel.
const SYNC_CONCURRENCY: usize = 4;

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
        let items = as_list(items);
        if items.len() > MAX_BATCH {
            anyhow::bail!("page exceeds {MAX_BATCH} items");
        }
        let mut batch = Vec::new();
        let mut stop = false;
        for item in items {
            let item = match item {
                // Objects by reference are fetched only from the actor's
                // origin; others could not pass the origin rules anyway.
                Value::String(id) if !client::same_host(id, &actor.id) => continue,
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

/// Synchronise one actor within the configured time budget and record
/// failures.
async fn sync_bounded(state: &AppState, row: &FollowingRow) -> anyhow::Result<()> {
    let budget = Duration::from_secs(state.cfg.federation.sync_budget_secs.max(1));
    let result = match tokio::time::timeout(budget, sync_actor(state, row)).await {
        Ok(r) => r.map(|_| ()),
        Err(_) => Err(anyhow::anyhow!(
            "sync exceeded {}s budget",
            budget.as_secs()
        )),
    };
    if let Err(e) = result {
        tracing::warn!(actor = %row.actor, "sync failed: {e:#}");
        let (a, msg) = (row.actor.clone(), format!("{e:#}"));
        state
            .db
            .call(move |c| db::record_sync(c, &a, None, false, Some(&msg)))
            .await?;
    }
    Ok(())
}

/// Synchronise all due actors, a few at a time, so that one slow or
/// hostile peer cannot hold up the others (Section 10).
pub async fn sync_due(state: &Shared) -> anyhow::Result<()> {
    let rows = state.db.call(|c| db::list_following(c)).await?;
    let permits = Arc::new(Semaphore::new(SYNC_CONCURRENCY));
    let mut tasks = JoinSet::new();
    for row in rows.into_iter().filter(|r| due(state, r)) {
        let (state, permits) = (state.clone(), permits.clone());
        tasks.spawn(async move {
            let _permit = permits.acquire_owned().await?;
            sync_bounded(&state, &row).await
        });
    }
    while let Some(r) = tasks.join_next().await {
        r??;
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
