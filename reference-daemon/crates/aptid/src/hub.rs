//! Hub mode: when a node connects (its follow is accepted), automatically
//! follow it back and trust its operator, so its TLP:CLEAR evidence is
//! ingested and counts toward the quorum without any manual peer management.
//! When the node disconnects again (Undo{Follow} or a rejected follow), the
//! automatic follow-back and trust are withdrawn.
//!
//! Automatic follows and policies are marked as such in the database. Follows
//! and operator policies set by an administrator (control socket or
//! `[[policy.operator]]`) are never overwritten or removed.
//!
//! Both run in the background, so an inbox delivery or control request does
//! not wait on requests to the node's servers, and are serialised by
//! `AppState::hub_lock` so a quick follow and unfollow cannot interleave.

use apti_core::policy::OperatorPolicy;

use crate::client;
use crate::db;
use crate::publish;
use crate::state::{AppState, Shared};

/// Run [`on_incoming_follow`] in the background.
pub fn spawn_on_incoming_follow(state: &Shared, follower: &str) {
    if !state.cfg.federation.auto_follow_back {
        return;
    }
    let (state, follower) = (state.clone(), follower.to_string());
    tokio::spawn(async move { on_incoming_follow(&state, &follower).await });
}

/// Run [`on_follower_gone`] in the background.
pub fn spawn_on_follower_gone(state: &Shared, follower: &str) {
    if !state.cfg.federation.auto_follow_back {
        return;
    }
    let (state, follower) = (state.clone(), follower.to_string());
    tokio::spawn(async move { on_follower_gone(&state, &follower).await });
}

/// A node's follow was accepted. If hub mode is enabled and the node is an
/// AP-TI node, follow it back and (optionally) trust its operator. Failures
/// are logged, never fatal: the original follow is already handled.
pub async fn on_incoming_follow(state: &AppState, follower: &str) {
    if !state.cfg.federation.auto_follow_back {
        return;
    }
    let _guard = state.hub_lock.lock().await;
    follow_back(state, follower).await;
    // The node may have disconnected while we were following it back (its
    // withdrawal ran first and found nothing to undo): undo it now.
    let f = follower.to_string();
    let accepted = state
        .db
        .call(move |c| db::is_accepted_follower(c, &f))
        .await
        .unwrap_or(true);
    if !accepted {
        withdraw(state, follower).await;
    }
}

async fn follow_back(state: &AppState, follower: &str) {
    let follower_owned = follower.to_string();
    let already = match state
        .db
        .call(move |c| db::is_following(c, &follower_owned))
        .await
    {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(follower, "auto-follow: {e:#}");
            return;
        }
    };
    if already {
        return;
    }
    let actor = match client::fetch_actor(state, follower, true).await {
        Ok(a) => a,
        Err(e) => {
            tracing::debug!(follower, "auto-follow: actor fetch failed: {e:#}");
            return;
        }
    };
    // Only follow back AP-TI nodes: they expose an `activeObjects`
    // collection. This keeps random fediverse followers out of the
    // connected-node list.
    if actor.active_objects.is_none() {
        tracing::debug!(
            follower,
            "auto-follow: not an AP-TI node (no activeObjects)"
        );
        return;
    }
    if let Err(e) = publish::follow_actor(state, &actor, actor.preferred_username.as_deref()).await
    {
        tracing::warn!(follower, "auto-follow-back failed: {e:#}");
        return;
    }
    let a = actor.id.clone();
    if let Err(e) = state.db.call(move |c| db::set_following_auto(c, &a)).await {
        tracing::warn!(follower, "auto-follow: {e:#}");
    }
    tracing::info!(follower, "auto-followed back");
    if state.cfg.policy.auto_trust_followers {
        trust_operator(state, follower).await;
    }
}

/// The node behind `follower` stopped following us (or its follow was
/// rejected). Undo our automatic follow-back, and drop the automatic trust
/// of its operator once no other automatically followed node of that
/// operator remains. Follows and trust set by an administrator are kept.
pub async fn on_follower_gone(state: &AppState, follower: &str) {
    if !state.cfg.federation.auto_follow_back {
        return;
    }
    let _guard = state.hub_lock.lock().await;
    withdraw(state, follower).await;
}

async fn withdraw(state: &AppState, follower: &str) {
    let f = follower.to_string();
    let operator = match state
        .db
        .call(move |c| {
            if !db::is_following_auto(c, &f)? {
                return Ok(None);
            }
            Ok(Some(db::actor_operator_map(c)?.remove(&f).map(|(o, _)| o)))
        })
        .await
    {
        Ok(Some(op)) => op,
        Ok(None) => return,
        Err(e) => {
            tracing::warn!(follower, "auto-unfollow: {e:#}");
            return;
        }
    };
    match publish::unfollow_actor(state, follower).await {
        Ok(_) => tracing::info!(follower, "auto-unfollowed disconnected node"),
        // The follow row is already gone; delivery of the Undo is best effort.
        Err(e) => tracing::warn!(follower, "auto-unfollow: {e:#}"),
    }
    let Some(operator) = operator else {
        return;
    };
    let op = operator.clone();
    let removed = state
        .db
        .call(move |c| {
            let map = db::actor_operator_map(c)?;
            let still_connected = db::list_auto_following(c)?
                .iter()
                .any(|a| map.get(a).is_some_and(|(o, _)| *o == op));
            if still_connected {
                return Ok(false);
            }
            db::delete_auto_operator_policy(c, &op)
        })
        .await;
    match removed {
        Ok(true) => {
            state.recompute.notify_one();
            tracing::info!(follower, %operator, "auto-trust withdrawn");
        }
        Ok(false) => {}
        Err(e) => tracing::warn!(follower, "auto-untrust: {e:#}"),
    }
}

/// Trust the follower's operator so its evidence counts toward the quorum,
/// unless the operator already has a policy from the configuration or the
/// database (an administrator's decision always wins).
async fn trust_operator(state: &AppState, follower: &str) {
    let f = follower.to_string();
    // The effective operator as stored by `fetch_actor`, with manual
    // overrides applied.
    let operator = match state
        .db
        .call(move |c| Ok(db::actor_operator_map(c)?.remove(&f).map(|(o, _)| o)))
        .await
    {
        Ok(Some(op)) => op,
        Ok(None) => {
            tracing::warn!(follower, "auto-trust: operator unknown");
            return;
        }
        Err(e) => {
            tracing::warn!(follower, "auto-trust: {e:#}");
            return;
        }
    };
    if operator == state.urls.org || state.cfg.policy.operator.iter().any(|o| o.id == operator) {
        tracing::info!(follower, %operator, "auto-trust skipped: operator policy configured");
        return;
    }
    let policy = OperatorPolicy {
        trusted: true,
        weight: state.cfg.policy.auto_trust_weight,
    };
    let op = operator.clone();
    match state
        .db
        .call(move |c| db::insert_auto_operator_policy(c, &op, policy))
        .await
    {
        Ok(true) => {
            state.recompute.notify_one();
            tracing::info!(follower, %operator, "auto-trusted operator");
        }
        Ok(false) => {
            tracing::info!(follower, %operator, "auto-trust skipped: operator already has a policy");
        }
        Err(e) => tracing::warn!(follower, "auto-trust: {e:#}"),
    }
}
