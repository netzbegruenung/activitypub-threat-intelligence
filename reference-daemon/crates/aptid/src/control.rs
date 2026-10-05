//! Control socket (Appendix D): a unix socket, peer verified via SO_PEERCRED,
//! speaking the line-delimited JSON protocol of `apti_core::protocol`.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

use anyhow::{anyhow, bail};
use apti_core::normalize;
use apti_core::policy::PolicySet;
use apti_core::protocol::*;
use apti_core::{Behavior, EvidenceKind, ObservableType, Tlp};
use chrono::Utc;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::allowlist;
use crate::api;
use crate::audit::Origin;
use crate::client;
use crate::db;
use crate::engine;
use crate::inbox;
use crate::publish;
use crate::state::{AppState, Shared};

/// Bind the socket with the configured mode. Returns the listener and the
/// daemon's uid (the owner of the socket file).
pub fn bind(state: &AppState) -> anyhow::Result<(UnixListener, u32)> {
    let path = &state.cfg.control.socket;
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)?;
        }
    }
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_socket()) {
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(
        path,
        std::fs::Permissions::from_mode(state.cfg.socket_mode()),
    )?;
    let own_uid = std::fs::metadata(path)?.uid();
    Ok((listener, own_uid))
}

fn peer_allowed(state: &AppState, stream: &UnixStream, own_uid: u32) -> bool {
    let Ok(cred) = stream.peer_cred() else {
        return false;
    };
    let c = &state.cfg.control;
    cred.uid() == own_uid
        || cred.uid() == 0
        || c.allowed_uids.contains(&cred.uid())
        || c.allowed_gids.contains(&cred.gid())
}

pub async fn serve(state: Shared, listener: UnixListener, own_uid: u32) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("control accept: {e}");
                continue;
            }
        };
        if !peer_allowed(&state, &stream, own_uid) {
            tracing::warn!("control: rejected peer {:?}", stream.peer_cred().ok());
            continue;
        }
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = connection(state, stream).await {
                tracing::debug!("control connection: {e:#}");
            }
        });
    }
}

async fn connection(state: Shared, stream: UnixStream) -> anyhow::Result<()> {
    let by = Origin::Control(stream.peer_cred().ok().map(|c| c.uid()));
    let (r, mut w) = stream.into_split();
    let mut lines = BufReader::new(r).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Request>(&line) {
            Ok(req) => handle(&state, req, &by)
                .await
                .unwrap_or_else(|e| Reply::Error(format!("{e:#}"))),
            Err(e) => Reply::Error(format!("invalid request: {e}")),
        };
        let mut out = serde_json::to_vec(&reply)?;
        out.push(b'\n');
        w.write_all(&out).await?;
    }
    Ok(())
}

pub async fn handle(state: &AppState, req: Request, by: &Origin) -> anyhow::Result<Reply> {
    Ok(match req {
        Request::Status => Reply::Status(status(state).await?),
        Request::ListFollowing => Reply::Following(list_following(state).await?),
        Request::Follow { handle } => {
            follow(state, &handle).await?;
            Reply::Done
        }
        Request::Unfollow { actor } => {
            let a = actor.clone();
            let row = state.db.call(move |c| db::delete_following(c, &a)).await?;
            let row = row.ok_or_else(|| anyhow!("not following {actor}"))?;
            let undo = json!({
                "type": "Undo",
                "id": state.urls.new_activity_id(),
                "object": {"type": "Follow", "id": row.follow_id, "actor": state.urls.actor, "object": actor},
            });
            publish::send_direct(state, undo, &actor).await?;
            Reply::Done
        }
        Request::Resync { actor } => {
            // Also refresh the cached actor document, e.g. a changed contact.
            client::fetch_actor(state, &actor, true).await?;
            state
                .db
                .call(move |c| db::reset_full_sync(c, &actor))
                .await?;
            state.sync_now.notify_one();
            Reply::Done
        }
        Request::ListFollowers => Reply::Followers(state.db.call(|c| db::list_followers(c)).await?),
        Request::ApproveFollower { actor } => {
            let a = actor.clone();
            let (follow_id, _) = state
                .db
                .call(move |c| db::get_follower(c, &a))
                .await?
                .ok_or_else(|| anyhow!("no follow request from {actor}"))?;
            let a = actor.clone();
            state
                .db
                .call(move |c| db::set_follower_state(c, &a, "accepted"))
                .await?;
            inbox::send_follow_response(state, "Accept", &actor, &follow_id).await?;
            Reply::Done
        }
        Request::RejectFollower { actor } => {
            let a = actor.clone();
            let (follow_id, _) = state
                .db
                .call(move |c| db::get_follower(c, &a))
                .await?
                .ok_or_else(|| anyhow!("no follow request from {actor}"))?;
            let a = actor.clone();
            state.db.call(move |c| db::delete_follower(c, &a)).await?;
            inbox::send_follow_response(state, "Reject", &actor, &follow_id).await?;
            Reply::Done
        }
        Request::ListOperators => Reply::Operators(list_operators(state).await?),
        Request::SetOperatorPolicy {
            operator,
            behavior,
            policy,
        } => {
            if !policy.weight.is_finite() || policy.weight < 0.0 {
                bail!("weight must be >= 0");
            }
            state
                .db
                .call(move |c| db::set_operator_policy(c, &operator, behavior, policy))
                .await?;
            state.recompute.notify_one();
            Reply::Done
        }
        Request::ClearOperatorPolicy { operator, behavior } => {
            state
                .db
                .call(move |c| db::clear_operator_policy(c, &operator, behavior))
                .await?;
            state.recompute.notify_one();
            Reply::Done
        }
        Request::MapActor { actor, operator } => {
            state
                .db
                .call(move |c| db::set_operator_override(c, &actor, operator.as_deref()))
                .await?;
            state.recompute.notify_one();
            Reply::Done
        }
        Request::ListBehaviorPolicies => Reply::BehaviorPolicies(list_behaviors(state).await?),
        Request::SetBehaviorPolicy {
            behavior,
            overrides,
            default_tlp,
        } => {
            if default_tlp == Some(Tlp::Red) {
                bail!("TLP:RED cannot be published");
            }
            if overrides.ttl_secs.is_some_and(|t| t <= 0)
                || overrides.max_age_secs.is_some_and(|t| t <= 0)
            {
                bail!("T and M must be positive");
            }
            state
                .db
                .call(move |c| db::set_behavior_policy(c, behavior, &overrides, default_tlp))
                .await?;
            state.recompute.notify_one();
            Reply::Done
        }
        Request::GetTlpSettings => {
            let (default_tlp, amber_recipients) = publish::tlp_settings(state).await?;
            Reply::TlpSettings(TlpSettings {
                default_tlp,
                amber_recipients,
            })
        }
        Request::SetTlpSettings(s) => {
            if s.default_tlp == Tlp::Red {
                bail!("TLP:RED cannot be published");
            }
            for r in &s.amber_recipients {
                client::check_url(state, r)?;
            }
            let recipients = serde_json::to_string(&s.amber_recipients)?;
            state
                .db
                .call(move |c| {
                    db::set_setting(c, "default_tlp", s.default_tlp.as_str())?;
                    db::set_setting(c, "amber_recipients", &recipients)
                })
                .await?;
            Reply::Done
        }
        Request::ListReview { include_resolved } => Reply::Review(
            state
                .db
                .call(move |c| db::list_review(c, include_resolved))
                .await?,
        ),
        Request::ResolveReview { id, action } => {
            resolve_review(state, id, action, by).await?;
            Reply::Done
        }
        Request::ListAllowlist => Reply::Allowlist(state.db.call(|c| db::list_allowlist(c)).await?),
        Request::AddAllowlist(entry) => {
            allowlist::add(state, entry, by).await?;
            Reply::Done
        }
        Request::RemoveAllowlist { id } => {
            allowlist::remove(state, id, by).await?;
            Reply::Done
        }
        Request::ListActive {
            observable_type,
            behavior,
            include_inactive,
        } => Reply::Active(
            state
                .db
                .call(move |c| {
                    db::list_active(c, Utc::now(), observable_type, behavior, include_inactive)
                })
                .await?,
        ),
        Request::Lookup { value } => Reply::Lookup(lookup(state, &value).await?),
        Request::Recompute => {
            engine::recompute(state).await?;
            Reply::Done
        }
        Request::ListTokens => Reply::Tokens(state.db.call(|c| db::list_api_tokens(c)).await?),
        Request::CreateToken(t) => {
            let name = t.name.trim().to_string();
            check_token_name(&name)?;
            let scopes = check_scopes(t.scopes)?;
            let secret = api::generate_token();
            let hash = api::hash_token(&secret);
            let token = state
                .db
                .call(move |c| db::insert_api_token(c, &name, &hash, &scopes, t.max_tlp))
                .await?;
            tracing::info!(token = %token.name, "API token created");
            Reply::TokenCreated { token, secret }
        }
        Request::UpdateToken {
            id,
            scopes,
            max_tlp,
        } => {
            let scopes = check_scopes(scopes)?;
            let token = state
                .db
                .call(move |c| db::update_api_token(c, id, &scopes, max_tlp))
                .await?
                .ok_or_else(|| anyhow!("no token {id}"))?;
            tracing::info!(token = %token.name, "API token updated");
            Reply::Done
        }
        Request::RotateToken { id } => {
            let secret = api::generate_token();
            let hash = api::hash_token(&secret);
            let token = state
                .db
                .call(move |c| db::set_api_token_hash(c, id, &hash))
                .await?
                .ok_or_else(|| anyhow!("no token {id}"))?;
            tracing::info!(token = %token.name, "API token rotated");
            Reply::TokenCreated { token, secret }
        }
        Request::DeleteToken { id } => {
            let token = state
                .db
                .call(move |c| db::delete_api_token(c, id))
                .await?
                .ok_or_else(|| anyhow!("no token {id}"))?;
            tracing::info!(token = %token.name, "API token deleted");
            Reply::Done
        }
    })
}

/// Token names appear in logs; keep them short and printable.
fn check_token_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
    {
        bail!("token name must be 1-64 characters of [A-Za-z0-9_.-]");
    }
    Ok(())
}

fn check_scopes(mut scopes: Vec<ApiScope>) -> anyhow::Result<Vec<ApiScope>> {
    scopes.sort();
    scopes.dedup();
    if scopes.is_empty() {
        bail!("a token needs at least one scope");
    }
    Ok(scopes)
}

async fn status(state: &AppState) -> anyhow::Result<StatusInfo> {
    let last_recompute = *state
        .last_recompute
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let actor_id = state.urls.actor.clone();
    let operator_id = state.urls.org.clone();
    state
        .db
        .call(move |c| {
            let followers = db::list_followers(c)?;
            let (active, flagged) = db::count_active(c, Utc::now())?;
            Ok(StatusInfo {
                version: env!("CARGO_PKG_VERSION").to_string(),
                actor_id,
                operator_id,
                following: db::list_following(c)?.len() as u64,
                followers: followers.iter().filter(|f| f.state == "accepted").count() as u64,
                pending_followers: followers.iter().filter(|f| f.state == "pending").count() as u64,
                evidence: db::count_evidence(c)?,
                active,
                flagged,
                review_open: db::count_open_review(c)?,
                pending_observations: db::count_pending_observations(c)?,
                delivery_queue: db::count_deliveries(c)?,
                last_recompute,
            })
        })
        .await
}

async fn list_following(state: &AppState) -> anyhow::Result<Vec<FollowingInfo>> {
    state
        .db
        .call(|c| {
            let map = db::actor_operator_map(c)?;
            db::list_following(c)?
                .into_iter()
                .map(|f| {
                    let remote = db::get_remote_actor(c, &f.actor)?;
                    let (name, summary) = remote.map(|a| (a.name, a.summary)).unwrap_or_default();
                    Ok(FollowingInfo {
                        name,
                        summary,
                        operator: map.get(&f.actor).map(|(o, _)| o.clone()),
                        evidence: db::count_evidence_by_publisher(c, &f.actor)?,
                        actor: f.actor,
                        handle: f.handle,
                        state: f.state,
                        last_sync: f.last_sync,
                        last_full_sync: f.last_full_sync,
                        last_error: f.last_error,
                    })
                })
                .collect()
        })
        .await
}

async fn follow(state: &AppState, handle: &str) -> anyhow::Result<()> {
    let handle = handle.trim();
    let (actor_url, handle_opt) = if handle.starts_with("https://") || handle.starts_with("http://")
    {
        (handle.to_string(), None)
    } else {
        (
            client::webfinger(state, handle).await?,
            Some(handle.trim_start_matches('@').to_string()),
        )
    };
    let actor = client::fetch_actor(state, &actor_url, true).await?;
    let follow_id = state.urls.new_activity_id();
    let (a, f) = (actor.id.clone(), follow_id.clone());
    state
        .db
        .call(move |c| db::upsert_following(c, &a, handle_opt.as_deref(), &f, "pending"))
        .await?;
    let activity = json!({
        "type": "Follow",
        "id": follow_id,
        "object": actor.id,
    });
    publish::send_direct(state, activity, &actor.id).await?;
    // Consumers MUST read activeObjects on first follow (Section 5.3).
    state.sync_now.notify_one();
    Ok(())
}

async fn list_operators(state: &AppState) -> anyhow::Result<Vec<OperatorInfo>> {
    let (policy, _) = engine::load_policy(state).await?;
    let mut map = state.db.call(|c| db::actor_operator_map(c)).await?;
    map.insert(
        state.urls.actor.clone(),
        (state.urls.org.clone(), "local".into()),
    );
    let mut ops: BTreeMap<String, (BTreeSet<String>, String)> = BTreeMap::new();
    for (actor, (op, source)) in map {
        let e = ops
            .entry(op)
            .or_insert_with(|| (BTreeSet::new(), source.clone()));
        e.0.insert(actor);
        if source == "manual" {
            e.1 = source;
        }
    }
    for (op, _) in policy.operators.keys() {
        ops.entry(op.clone())
            .or_insert_with(|| (BTreeSet::new(), "policy".into()));
    }
    Ok(ops
        .into_iter()
        .map(|(id, (actors, source))| OperatorInfo {
            default_policy: policy.operators.get(&(id.clone(), None)).copied(),
            behavior_policies: Behavior::ALL
                .iter()
                .filter_map(|b| {
                    policy
                        .operators
                        .get(&(id.clone(), Some(*b)))
                        .map(|p| (*b, *p))
                })
                .collect(),
            id,
            source,
            actors: actors.into_iter().collect(),
        })
        .collect())
}

fn behavior_info(
    policy: &PolicySet,
    b: Behavior,
    default_tlp: Option<Tlp>,
    global_tlp: Tlp,
) -> BehaviorPolicyInfo {
    BehaviorPolicyInfo {
        behavior: b,
        overrides: policy.behaviors.get(&b).copied().unwrap_or_default(),
        k: policy.k(b),
        ttl_ip_secs: policy.ttl(b, ObservableType::Ipv4Addr).num_seconds(),
        max_age_ip_secs: policy.max_age(b, ObservableType::Ipv4Addr).num_seconds(),
        ttl_domain_secs: policy.ttl(b, ObservableType::DomainName).num_seconds(),
        max_age_domain_secs: policy.max_age(b, ObservableType::DomainName).num_seconds(),
        default_tlp,
        effective_tlp: default_tlp.unwrap_or(global_tlp),
    }
}

async fn list_behaviors(state: &AppState) -> anyhow::Result<Vec<BehaviorPolicyInfo>> {
    let (policy, tlps) = engine::load_policy(state).await?;
    let (global, _) = publish::tlp_settings(state).await?;
    Ok(Behavior::ALL
        .iter()
        .map(|b| behavior_info(&policy, *b, tlps.get(b).copied().flatten(), global))
        .collect())
}

async fn resolve_review(
    state: &AppState,
    id: i64,
    action: ReviewAction,
    by: &Origin,
) -> anyhow::Result<()> {
    let resolution = match action {
        ReviewAction::Dismiss => "dismissed",
        ReviewAction::Suspend => "suspended",
        ReviewAction::Allowlist => "allowlisted",
    };
    let item = state
        .db
        .call(move |c| db::resolve_review(c, id, resolution))
        .await?
        .ok_or_else(|| anyhow!("no review item {id}"))?;
    state.audit.review(by, &item);
    let behaviors = match action {
        ReviewAction::Dismiss => return Ok(()),
        ReviewAction::Suspend => item.behavior.into_iter().collect(),
        ReviewAction::Allowlist => vec![],
    };
    let mut entry = AllowlistEntry {
        id: 0,
        scope: AllowlistScope::Local,
        observable_type: item.observable_type,
        observable_value: item.observable_value,
        behaviors,
        tlp: None,
        valid_until: None,
        summary: Some(format!("review #{id}: {resolution}")),
        source: None,
        object_id: None,
        created: Utc::now(),
    };
    let e = entry.clone();
    entry.id = state.db.call(move |c| db::insert_allowlist(c, &e)).await?;
    state.audit.allowlist(by, &entry, "allowlist added");
    state.recompute.notify_one();
    Ok(())
}

async fn lookup(state: &AppState, value: &str) -> anyhow::Result<LookupResult> {
    let (ty, value) = normalize::normalise(value, None, &allowlist::lenient_norm())?;
    let v = value.clone();
    let local_actor = state.urls.actor.clone();
    let org = state.urls.org.clone();
    let (evidence, assessments, mut map, allow) = state
        .db
        .call(move |c| {
            let assessments: Vec<_> = db::list_active(c, Utc::now(), Some(ty), None, true)?
                .into_iter()
                .filter(|a| a.observable_value == v)
                .collect();
            Ok((
                db::evidence_for_observable(c, ty, &v)?,
                assessments,
                db::actor_operator_map(c)?,
                db::list_allowlist(c)?,
            ))
        })
        .await?;
    map.insert(local_actor, (org, "local".into()));
    let evidence = evidence
        .into_iter()
        .map(|e| {
            let o = &e.object;
            let detail = match o.kind {
                EvidenceKind::ThreatIndicator => format!(
                    "valid {} → {}{}{}",
                    o.valid_from.map(db::ts).unwrap_or_default(),
                    o.valid_until.map(db::ts).unwrap_or_default(),
                    o.confidence
                        .map(|c| format!(", confidence {c}"))
                        .unwrap_or_default(),
                    if o.is_revoked() { ", REVOKED" } else { "" }
                ),
                EvidenceKind::Sighting => format!(
                    "seen {} → {}, count {}",
                    o.first_seen.map(db::ts).unwrap_or_default(),
                    o.last_seen.map(db::ts).unwrap_or_default(),
                    o.count.unwrap_or(1)
                ),
                EvidenceKind::Opinion => format!(
                    "{} until {}",
                    o.opinion.map(|v| v.as_str()).unwrap_or("?"),
                    db::ts(o.opinion_valid_until())
                ),
            };
            EvidenceSummary {
                id: o.id.clone(),
                kind: o.kind.as_str().to_string(),
                operator: map
                    .get(&o.attributed_to)
                    .map(|(op, _)| op.clone())
                    .unwrap_or_else(|| client::fallback_operator(&o.attributed_to)),
                publisher: o.attributed_to.clone(),
                tlp: o.tlp,
                behaviors: o.observed_behavior.clone(),
                detail,
                withdrawn: e.deleted.is_some(),
            }
        })
        .collect();
    let local_allowlist = allow
        .into_iter()
        .filter(|a| {
            a.observable_type == ty && normalize::covers(ty, &a.observable_value, &value, false)
        })
        .collect();
    Ok(LookupResult {
        observable_type: ty,
        observable_value: value,
        assessments,
        evidence,
        local_allowlist,
    })
}
