//! Organisation-internal REST API (Appendix D): sensors push observations,
//! enforcement points read the active list (Section 9), and automation
//! manages the allowlist.

use apti_core::normalize;
use apti_core::protocol::{AllowlistEntry, AllowlistScope, NewAllowlistEntry};
use apti_core::{Behavior, ObservableType, Tlp, FUTURE_TOLERANCE_SECS, MAX_BATCH};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use crate::allowlist::{self, AllowlistError};
use crate::config::{ApiToken, Scope};
use crate::db::{self, Observation};
use crate::engine::LocalAllowlist;
use crate::state::Shared;

pub fn router(state: Shared) -> Router {
    Router::new()
        .route(
            "/api/v1/health",
            get(|| async { Json(serde_json::json!({"status": "ok"})) }),
        )
        .route("/api/v1/observations", post(push))
        .route("/api/v1/active", get(active))
        .route("/api/v1/allowlist", get(allowlist_list).post(allowlist_add))
        .route(
            "/api/v1/allowlist/{id}",
            get(allowlist_get).delete(allowlist_remove),
        )
        .with_state(state)
}

fn error(code: StatusCode, msg: &str) -> Response {
    (code, Json(serde_json::json!({ "error": msg }))).into_response()
}

/// Constant-time comparison of two byte strings.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn authorise<'a>(
    state: &'a Shared,
    headers: &HeaderMap,
    scope: Scope,
) -> Result<&'a ApiToken, Response> {
    authorise_any(state, headers, &[scope])
}

/// Authorise a token holding at least one of `scopes`.
fn authorise_any<'a>(
    state: &'a Shared,
    headers: &HeaderMap,
    scopes: &[Scope],
) -> Result<&'a ApiToken, Response> {
    let presented = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "missing bearer token"))?;
    let token = state
        .cfg
        .api
        .tokens
        .iter()
        .find(|t| ct_eq(t.token.as_bytes(), presented.trim().as_bytes()))
        .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "invalid token"))?;
    if !scopes.iter().any(|s| token.scopes.contains(s)) {
        return Err(error(StatusCode::FORBIDDEN, "token lacks scope"));
    }
    Ok(token)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObservationIn {
    /// IP address, prefix or domain; normalised by the daemon.
    pub value: String,
    pub observable_type: Option<ObservableType>,
    pub behavior: String,
    pub port: Option<u16>,
    pub service: Option<String>,
    /// Defaults to now.
    pub seen_at: Option<DateTime<Utc>>,
    /// Defaults to 1.
    pub count: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany {
    Many(Vec<ObservationIn>),
    One(ObservationIn),
}

#[derive(Debug, Serialize)]
pub struct Rejected {
    pub index: usize,
    pub value: String,
    pub error: String,
}

#[derive(Debug, Serialize)]
pub struct PushResult {
    pub accepted: usize,
    pub rejected: Vec<Rejected>,
}

async fn push(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<OneOrMany>,
) -> Response {
    if let Err(r) = authorise(&state, &headers, Scope::Push) {
        return r;
    }
    let items = match body {
        OneOrMany::Many(v) => v,
        OneOrMany::One(o) => vec![o],
    };
    if items.len() > MAX_BATCH {
        return error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "at most 1000 observations per request",
        );
    }
    let now = Utc::now();
    let norm = state.cfg.norm_policy();
    let allow_db = match state.db.call(|c| db::list_allowlist(c)).await {
        Ok(a) => a,
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e:#}")),
    };
    let allow = LocalAllowlist::new(&state, &allow_db, now);
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    for (index, o) in items.into_iter().enumerate() {
        let reject = |error: String| Rejected {
            index,
            value: o.value.clone(),
            error,
        };
        let behavior: Behavior = match o.behavior.parse() {
            Ok(b) => b,
            Err(e) => {
                rejected.push(reject(e));
                continue;
            }
        };
        let (ty, value) = match normalize::normalise(&o.value, o.observable_type, &norm) {
            Ok(v) => v,
            Err(e) => {
                rejected.push(reject(e.to_string()));
                continue;
            }
        };
        if allow.covers(ty, &value, Some(behavior)) {
            rejected.push(reject("allowlisted".into()));
            continue;
        }
        let seen = o.seen_at.unwrap_or(now);
        if seen > now + TimeDelta::seconds(FUTURE_TOLERANCE_SECS) {
            rejected.push(reject("seenAt is in the future".into()));
            continue;
        }
        if o.count == Some(0) {
            rejected.push(reject("count must be >= 1".into()));
            continue;
        }
        if o.service.as_ref().is_some_and(|s| {
            s.is_empty()
                || s.len() > 63
                || !s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        }) {
            rejected.push(reject("invalid service name".into()));
            continue;
        }
        accepted.push(Observation {
            observable_type: ty,
            observable_value: value,
            behavior,
            port: o.port,
            service: o.service.map(|s| s.to_ascii_lowercase()),
            first_seen: seen,
            last_seen: seen,
            count: o.count.unwrap_or(1),
            sighting_id: None,
        });
    }
    let n = accepted.len();
    if let Err(e) = state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            for o in &accepted {
                db::add_observation(&tx, o)?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
    {
        return error(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e:#}"));
    }
    Json(PushResult {
        accepted: n,
        rejected,
    })
    .into_response()
}

#[derive(Debug, Deserialize)]
pub struct ActiveQuery {
    #[serde(rename = "type")]
    pub observable_type: Option<ObservableType>,
    pub behavior: Option<String>,
    pub port: Option<u16>,
    pub service: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveEntry {
    pub observable_type: ObservableType,
    pub observable_value: String,
    pub behavior: Behavior,
    pub include_subdomains: bool,
    pub effective_expiry: DateTime<Utc>,
    /// Seconds until expiry, e.g. for nftables element timeouts.
    pub ttl: i64,
    pub tlp: Tlp,
    pub flagged: bool,
    pub ports: Vec<u16>,
    pub services: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveList {
    pub generated: DateTime<Utc>,
    pub last_recompute: Option<DateTime<Utc>>,
    pub entries: Vec<ActiveEntry>,
}

async fn active(
    State(state): State<Shared>,
    headers: HeaderMap,
    Query(q): Query<ActiveQuery>,
) -> Response {
    let token = match authorise(&state, &headers, Scope::Read) {
        Ok(t) => t,
        Err(r) => return r,
    };
    let max_tlp = token.max_tlp;
    let behavior = match q
        .behavior
        .as_deref()
        .map(str::parse::<Behavior>)
        .transpose()
    {
        Ok(b) => b,
        Err(e) => return error(StatusCode::BAD_REQUEST, &e),
    };
    let now = Utc::now();
    let ty = q.observable_type;
    let list = match state
        .db
        .call(move |c| db::list_active(c, now, ty, behavior, false))
        .await
    {
        Ok(l) => l,
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e:#}")),
    };
    let entries = list
        .into_iter()
        .filter(|a| a.tlp <= max_tlp)
        .filter(|a| q.port.is_none_or(|p| a.ports.contains(&p)))
        .filter(|a| q.service.as_ref().is_none_or(|s| a.services.contains(s)))
        .filter_map(|a| {
            let exp = a.effective_expiry?;
            Some(ActiveEntry {
                observable_type: a.observable_type,
                observable_value: a.observable_value,
                behavior: a.behavior,
                include_subdomains: a.include_subdomains,
                effective_expiry: exp,
                ttl: (exp - now).num_seconds().max(0),
                tlp: a.tlp,
                flagged: a.flagged,
                ports: a.ports,
                services: a.services,
            })
        })
        .collect();
    let last_recompute = *state
        .last_recompute
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    Json(ActiveList {
        generated: now,
        last_recompute,
        entries,
    })
    .into_response()
}

// ---------------------------------------------------------------- allowlist

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowlistOut {
    pub id: i64,
    pub scope: AllowlistScope,
    pub observable_type: apti_core::ObservableType,
    pub observable_value: String,
    /// Empty = all behaviours.
    pub behaviors: Vec<Behavior>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tlp: Option<Tlp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Id of the published Opinion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    pub created: DateTime<Utc>,
}

impl From<AllowlistEntry> for AllowlistOut {
    fn from(e: AllowlistEntry) -> Self {
        Self {
            id: e.id,
            scope: e.scope,
            observable_type: e.observable_type,
            observable_value: e.observable_value,
            behaviors: e.behaviors,
            tlp: e.tlp,
            valid_until: e.valid_until,
            summary: e.summary,
            object_id: e.object_id,
            created: e.created,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AllowlistIn {
    /// IP address, prefix or domain.
    pub value: String,
    #[serde(default)]
    pub scope: Option<AllowlistScope>,
    #[serde(default)]
    pub behaviors: Vec<String>,
    pub tlp: Option<Tlp>,
    pub valid_until: Option<DateTime<Utc>>,
    pub summary: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AllowlistQuery {
    pub scope: Option<AllowlistScope>,
}

fn allowlist_error(e: AllowlistError) -> Response {
    match e {
        AllowlistError::Invalid(m) => error(StatusCode::BAD_REQUEST, &m),
        AllowlistError::NotFound(_) => error(StatusCode::NOT_FOUND, &e.to_string()),
        AllowlistError::Internal(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e:#}")),
    }
}

/// Published entries are federated and need the `publish` scope as well.
fn check_publish(token: &ApiToken, scope: AllowlistScope) -> Result<(), Response> {
    if scope == AllowlistScope::Published && !token.scopes.contains(&Scope::Publish) {
        return Err(error(
            StatusCode::FORBIDDEN,
            "published entries require the `publish` scope",
        ));
    }
    Ok(())
}

async fn allowlist_list(
    State(state): State<Shared>,
    headers: HeaderMap,
    Query(q): Query<AllowlistQuery>,
) -> Response {
    if let Err(r) = authorise_any(&state, &headers, &[Scope::Read, Scope::Allowlist]) {
        return r;
    }
    match allowlist::list(&state).await {
        Ok(list) => Json(
            list.into_iter()
                .filter(|e| q.scope.is_none_or(|s| s == e.scope))
                .map(AllowlistOut::from)
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e:#}")),
    }
}

async fn allowlist_get(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    if let Err(r) = authorise_any(&state, &headers, &[Scope::Read, Scope::Allowlist]) {
        return r;
    }
    match allowlist::get(&state, id).await {
        Ok(Some(e)) => Json(AllowlistOut::from(e)).into_response(),
        Ok(None) => allowlist_error(AllowlistError::NotFound(id)),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e:#}")),
    }
}

async fn allowlist_add(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<AllowlistIn>,
) -> Response {
    let token = match authorise(&state, &headers, Scope::Allowlist) {
        Ok(t) => t,
        Err(r) => return r,
    };
    let scope = body.scope.unwrap_or(AllowlistScope::Local);
    if let Err(r) = check_publish(token, scope) {
        return r;
    }
    let behaviors = match body
        .behaviors
        .iter()
        .map(|b| b.parse::<Behavior>())
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(b) => b,
        Err(e) => return error(StatusCode::BAD_REQUEST, &e),
    };
    let entry = NewAllowlistEntry {
        scope,
        value: body.value,
        behaviors,
        tlp: body.tlp,
        valid_until: body.valid_until,
        summary: body.summary,
    };
    match allowlist::add(&state, entry).await {
        Ok((e, created)) => {
            tracing::info!(token = %token.name, value = %e.observable_value, created, "allowlist add via API");
            let code = if created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            };
            (code, Json(AllowlistOut::from(e))).into_response()
        }
        Err(e) => allowlist_error(e),
    }
}

async fn allowlist_remove(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    let token = match authorise(&state, &headers, Scope::Allowlist) {
        Ok(t) => t,
        Err(r) => return r,
    };
    let existing = match allowlist::get(&state, id).await {
        Ok(Some(e)) => e,
        Ok(None) => return allowlist_error(AllowlistError::NotFound(id)),
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e:#}")),
    };
    if let Err(r) = check_publish(token, existing.scope) {
        return r;
    }
    match allowlist::remove(&state, id).await {
        Ok(e) => {
            tracing::info!(token = %token.name, value = %e.observable_value, "allowlist remove via API");
            Json(AllowlistOut::from(e)).into_response()
        }
        Err(e) => allowlist_error(e),
    }
}

#[cfg(test)]
mod tests {
    use super::ct_eq;

    #[test]
    fn constant_time_eq() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
