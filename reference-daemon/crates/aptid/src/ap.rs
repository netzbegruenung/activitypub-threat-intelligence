//! Public ActivityPub endpoints: WebFinger, actors, inbox, outbox,
//! collections and objects (Sections 3, 5).

use apti_core::Tlp;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{TimeDelta, Utc};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::client::{self, id_of, AP_CONTENT_TYPE};
use crate::db::{self, StoredEvidence};
use crate::httpsig;
use crate::inbox;
use crate::state::Shared;

const PAGE_SIZE: usize = apti_core::MAX_BATCH;

pub fn router(state: Shared) -> Router {
    let limit = state.cfg.public.max_body_bytes;
    Router::new()
        .route("/.well-known/webfinger", get(webfinger))
        .route("/actor", get(actor))
        .route("/actor/inbox", post(inbox_post))
        .route("/inbox", post(inbox_post))
        .route("/actor/outbox", get(outbox))
        .route("/actor/followers", get(followers))
        .route("/actor/following", get(following))
        .route("/actor/active", get(active_objects))
        .route("/org", get(organization))
        .route("/org/inbox", post(|| async { StatusCode::ACCEPTED }))
        .route("/org/outbox", get(org_outbox))
        .route("/objects/{id}", get(object))
        .route("/activities/{id}", get(activity))
        .route(
            "/ns/ti",
            get(|| async { ap_json(apti_core::context_document()) }),
        )
        .layer(DefaultBodyLimit::max(limit))
        .with_state(state)
}

pub fn ap_json(v: Value) -> Response {
    ([(header::CONTENT_TYPE, AP_CONTENT_TYPE)], Json(v)).into_response()
}

fn status(code: StatusCode, msg: &str) -> Response {
    (code, msg.to_string()).into_response()
}

fn path_and_query(uri: &Uri) -> String {
    uri.path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| uri.path().to_string())
}

/// Verify the HTTP signature of a request and return the signing actor id.
pub async fn authenticate(
    state: &Shared,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: Option<&[u8]>,
) -> Result<String, Response> {
    let sig = httpsig::signature_from_headers(headers)
        .map_err(|e| status(StatusCode::UNAUTHORIZED, &e.to_string()))?;
    let pq = path_and_query(uri);
    let max_age = TimeDelta::seconds(state.cfg.federation.signature_max_age_secs);
    // Try the cached key first, then refetch once (key rotation). A key that
    // was just fetched is not fetched again.
    for force in [false, true] {
        let (actor, fresh) = match client::actor_for_key(state, &sig.key_id, force).await {
            Ok(a) => a,
            Err(e) => {
                tracing::debug!(key = %sig.key_id, "key lookup failed: {e:#}");
                return Err(status(StatusCode::UNAUTHORIZED, "unknown key"));
            }
        };
        let Some(pem) = actor.public_key_pem.as_deref() else {
            if fresh {
                break;
            }
            continue;
        };
        match httpsig::verify(
            &sig,
            method.as_str(),
            &pq,
            headers,
            body,
            pem,
            Utc::now(),
            max_age,
        ) {
            Ok(()) => return Ok(actor.id),
            Err(e @ (httpsig::SigError::Invalid | httpsig::SigError::Key)) if !fresh => {
                tracing::debug!("signature check failed with cached key: {e}");
            }
            Err(e) => return Err(status(StatusCode::UNAUTHORIZED, &e.to_string())),
        }
    }
    Err(status(
        StatusCode::UNAUTHORIZED,
        "signature verification failed",
    ))
}

/// Optional authentication: unsigned requests yield `None`.
async fn requester(
    state: &Shared,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<Option<String>, Response> {
    if headers.contains_key("signature") || headers.contains_key("authorization") {
        authenticate(state, method, uri, headers, None)
            .await
            .map(Some)
    } else {
        Ok(None)
    }
}

/// TLP visibility for a requesting actor (Sections 3.1, 5.2).
async fn visibility(
    state: &Shared,
    requester: Option<&str>,
) -> anyhow::Result<impl Fn(Tlp, &[String]) -> bool> {
    let follower = match requester {
        Some(r) => {
            let r = r.to_string();
            state
                .db
                .call(move |c| db::is_accepted_follower(c, &r))
                .await?
        }
        None => false,
    };
    let requester = requester.map(String::from);
    Ok(move |tlp: Tlp, audience: &[String]| match tlp {
        Tlp::Clear => true,
        Tlp::Green => follower,
        Tlp::Amber | Tlp::AmberStrict => requester.as_ref().is_some_and(|r| audience.contains(r)),
        Tlp::Red => false,
    })
}

#[derive(Deserialize)]
struct WebfingerQuery {
    resource: String,
}

async fn webfinger(State(state): State<Shared>, Query(q): Query<WebfingerQuery>) -> Response {
    let acct = format!(
        "acct:{}@{}",
        state.cfg.instance.username,
        state.cfg.authority()
    );
    if q.resource != acct && q.resource != state.urls.actor {
        return status(StatusCode::NOT_FOUND, "unknown resource");
    }
    (
        [(header::CONTENT_TYPE, "application/jrd+json")],
        Json(json!({
            "subject": acct,
            "aliases": [state.urls.actor],
            "links": [{"rel": "self", "type": AP_CONTENT_TYPE, "href": state.urls.actor}]
        })),
    )
        .into_response()
}

pub fn actor_document(state: &Shared) -> Value {
    let u = &state.urls;
    let mut summary = format!(
        "AP-TI threat intelligence feed operated by {}.",
        state.cfg.instance.organization
    );
    if let Some(c) = &state.cfg.instance.contact {
        summary.push_str(&format!(" Removal requests: {c}"));
    }
    json!({
        "@context": [apti_core::AS_CONTEXT, "https://w3id.org/security/v1", apti_core::TI_CONTEXT],
        "type": "Service",
        "id": u.actor,
        "preferredUsername": state.cfg.instance.username,
        "name": state.cfg.instance.name,
        "summary": summary,
        "inbox": u.inbox,
        "outbox": u.outbox,
        "followers": u.followers,
        "following": u.following,
        "endpoints": {"sharedInbox": u.shared_inbox},
        "manuallyApprovesFollowers": state.cfg.publish.manually_approves_followers,
        "operator": u.org,
        "activeObjects": u.active,
        "publicKey": {
            "id": u.key_id,
            "owner": u.actor,
            "publicKeyPem": state.keys.public_pem,
        }
    })
}

async fn actor(State(state): State<Shared>) -> Response {
    ap_json(actor_document(&state))
}

async fn organization(State(state): State<Shared>) -> Response {
    let u = &state.urls;
    ap_json(json!({
        "@context": [apti_core::AS_CONTEXT, apti_core::TI_CONTEXT],
        "type": "Organization",
        "id": u.org,
        "name": state.cfg.instance.organization,
        "inbox": u.org_inbox,
        "outbox": u.org_outbox,
        "operatedActors": [u.actor],
    }))
}

async fn org_outbox(State(state): State<Shared>) -> Response {
    ap_json(json!({
        "@context": apti_core::AS_CONTEXT,
        "type": "OrderedCollection",
        "id": state.urls.org_outbox,
        "totalItems": 0,
        "orderedItems": [],
    }))
}

async fn inbox_post(
    State(state): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let activity: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return status(StatusCode::BAD_REQUEST, "invalid JSON"),
    };
    let signer = match authenticate(&state, &method, &uri, &headers, Some(&body)).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    if id_of(&activity["actor"]) != Some(signer.as_str()) {
        return status(StatusCode::FORBIDDEN, "actor does not match signature");
    }
    if !state.rate_limit(&signer, state.cfg.federation.inbox_rate_per_minute) {
        return status(StatusCode::TOO_MANY_REQUESTS, "rate limited");
    }
    let Some(id) = activity["id"].as_str().map(String::from) else {
        return status(StatusCode::BAD_REQUEST, "activity without id");
    };
    if client::host_of(&id) != client::host_of(&signer) {
        return status(StatusCode::FORBIDDEN, "activity id origin mismatch");
    }
    match state.db.call(move |c| db::mark_processed(c, &id)).await {
        Ok(true) => {}
        Ok(false) => return StatusCode::ACCEPTED.into_response(),
        Err(e) => {
            tracing::error!("inbox: {e:#}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }
    if let Err(e) = inbox::process(&state, &signer, &activity).await {
        tracing::warn!(actor = %signer, "inbox processing failed: {e:#}");
        return status(StatusCode::BAD_REQUEST, &format!("{e:#}"));
    }
    StatusCode::ACCEPTED.into_response()
}

fn render_evidence(e: &StoredEvidence) -> Value {
    match e.deleted {
        Some(when) => json!({
            "type": "Tombstone",
            "id": e.object.id,
            "formerType": e.object.kind.as_str(),
            "deleted": db::ts(when),
        }),
        None => serde_json::to_value(&e.object).unwrap_or(Value::Null),
    }
}

#[derive(Deserialize)]
struct PageQuery {
    page: Option<String>,
    before: Option<String>,
}

/// `activeObjects` (Section 5.3): signed fetch required, TLP-filtered.
async fn active_objects(
    State(state): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Response {
    let requester = match authenticate(&state, &method, &uri, &headers, None).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    let base = &state.urls.active;
    if q.page.is_none() && q.before.is_none() {
        return ap_json(json!({
            "@context": apti_core::context(),
            "type": "OrderedCollection",
            "id": base,
            "first": format!("{base}?page=true"),
        }));
    }
    let cursor = q.before.as_deref().and_then(|b| b.split_once('|'));
    let cursor_owned = cursor.map(|(k, i)| (k.to_string(), i.to_string()));
    let rows = match state
        .db
        .call(move |c| {
            let before = cursor_owned.as_ref().map(|(k, i)| (k.as_str(), i.as_str()));
            db::local_listed(c, Utc::now(), before, PAGE_SIZE)
        })
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("activeObjects: {e:#}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let visible = match visibility(&state, Some(&requester)).await {
        Ok(v) => v,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let items: Vec<Value> = rows
        .iter()
        .filter(|e| visible(e.object.tlp, &e.audience))
        .map(render_evidence)
        .collect();
    let id = match &q.before {
        Some(b) => format!("{base}?before={}", urlencode(b)),
        None => format!("{base}?page=true"),
    };
    let mut page = json!({
        "@context": apti_core::context(),
        "type": "OrderedCollectionPage",
        "id": id,
        "partOf": base,
        "orderedItems": items,
    });
    if rows.len() == PAGE_SIZE {
        if let Some(last) = rows.last() {
            let cursor = format!("{}|{}", last.sort_key, last.object.id);
            page["next"] = json!(format!("{base}?before={}", urlencode(&cursor)));
        }
    }
    ap_json(page)
}

fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

async fn object(
    State(state): State<Shared>,
    Path(id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let full = format!("{}/objects/{}", state.urls.base, id);
    let Ok(Some(e)) = state.db.call(move |c| db::get_evidence(c, &full)).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !e.local {
        return StatusCode::NOT_FOUND.into_response();
    }
    // Non-clear objects require signed fetch (Section 3.1).
    let who = if e.object.tlp == Tlp::Clear {
        None
    } else {
        match authenticate(&state, &method, &uri, &headers, None).await {
            Ok(r) => Some(r),
            Err(r) => return r,
        }
    };
    let Ok(visible) = visibility(&state, who.as_deref()).await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if !visible(e.object.tlp, &e.audience) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let mut v = render_evidence(&e);
    v["@context"] = apti_core::context();
    ap_json(v)
}

async fn activity(
    State(state): State<Shared>,
    Path(id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let full = format!("{}/activities/{}", state.urls.base, id);
    let Ok(Some(a)) = state.db.call(move |c| db::get_activity(c, &full)).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let who = if a.tlp == Tlp::Clear {
        None
    } else {
        match authenticate(&state, &method, &uri, &headers, None).await {
            Ok(r) => Some(r),
            Err(r) => return r,
        }
    };
    let Ok(visible) = visibility(&state, who.as_deref()).await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if !visible(a.tlp, &a.audience) {
        return StatusCode::NOT_FOUND.into_response();
    }
    ap_json(a.json)
}

/// Outbox: the most recent activities visible to the requester.
async fn outbox(
    State(state): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let who = match requester(&state, &method, &uri, &headers).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let Ok(visible) = visibility(&state, who.as_deref()).await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let Ok(acts) = state.db.call(|c| db::recent_activities(c, 200)).await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let items: Vec<Value> = acts
        .into_iter()
        .filter(|a| visible(a.tlp, &a.audience))
        .take(50)
        .map(|a| a.json)
        .collect();
    ap_json(json!({
        "@context": apti_core::AS_CONTEXT,
        "type": "OrderedCollection",
        "id": state.urls.outbox,
        "orderedItems": items,
    }))
}

/// Followers and following: only the count is disclosed.
async fn followers(State(state): State<Shared>) -> Response {
    let n = state
        .db
        .call(|c| db::accepted_followers(c))
        .await
        .map(|f| f.len())
        .unwrap_or(0);
    ap_json(json!({
        "@context": apti_core::AS_CONTEXT,
        "type": "OrderedCollection",
        "id": state.urls.followers,
        "totalItems": n,
    }))
}

async fn following(State(state): State<Shared>) -> Response {
    let n = state
        .db
        .call(|c| db::list_following(c))
        .await
        .map(|f| f.len())
        .unwrap_or(0);
    ap_json(json!({
        "@context": apti_core::AS_CONTEXT,
        "type": "OrderedCollection",
        "id": state.urls.following,
        "totalItems": n,
    }))
}
