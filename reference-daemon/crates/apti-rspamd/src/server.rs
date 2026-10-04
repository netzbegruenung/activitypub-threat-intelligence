//! Local HTTP endpoint: scan reports from the Lua plugin and map files for
//! Rspamd's multimap module.

use std::time::{Duration, SystemTime};

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;

use crate::maps::SharedMaps;
use crate::push::{lock, SharedIngest};
use crate::reputation::{Outcome, Report};

#[derive(Clone)]
pub struct AppState {
    /// Ingest state and the shared secret of the Lua plugin.
    pub ingest: Option<(SharedIngest, String)>,
    /// Rendered maps and how often they are refreshed.
    pub maps: Option<(SharedMaps, Duration)>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(|| async { Json(json!({"status": "ok"})) }))
        .route("/v1/report", post(report))
        .route("/maps/{name}", get(map))
        .with_state(state)
}

fn error(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({ "error": msg }))).into_response()
}

/// Compare without leaking the position of the first difference.
fn secret_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    Many(Vec<Report>),
    One(Report),
}

async fn report(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let Some((ingest, secret)) = &state.ingest else {
        return error(StatusCode::NOT_FOUND, "ingest is not configured");
    };
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .unwrap_or("");
    if !secret_eq(presented.as_bytes(), secret.as_bytes()) {
        return error(StatusCode::UNAUTHORIZED, "invalid secret");
    }
    // Parsed only after authentication, so parse errors are not exposed to
    // unauthenticated callers.
    let body = match serde_json::from_slice::<OneOrMany>(&body) {
        Ok(b) => b,
        Err(e) => return error(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string()),
    };
    let reports = match body {
        OneOrMany::Many(v) => v,
        OneOrMany::One(r) => vec![r],
    };
    let now = Utc::now();
    // (counted, reported) for IPs and for envelope-from domains.
    let (mut ips, mut domains) = ((0, 0), (0, 0));
    let tally = |o: Outcome, t: &mut (usize, usize)| match o {
        Outcome::Counted => t.0 += 1,
        Outcome::Reported => {
            t.0 += 1;
            t.1 += 1;
        }
        Outcome::Good | Outcome::Skipped(_) => {}
    };
    let mut ingest = lock(ingest);
    for r in &reports {
        let h = ingest.handle(r, now);
        tracing::debug!(ip = %r.ip, score = r.score, from_domain = ?r.from_domain, ?h, "report");
        tally(h.ip, &mut ips);
        if let Some(o) = h.domain {
            tally(o, &mut domains);
        }
    }
    Json(json!({
        "received": reports.len(),
        "counted": ips.0,
        "reported": ips.1,
        "countedDomains": domains.0,
        "reportedDomains": domains.1,
    }))
    .into_response()
}

/// Whether the client's cached copy is still current.
fn not_modified(headers: &HeaderMap, etag: &str, modified: SystemTime) -> bool {
    // If-None-Match takes precedence over If-Modified-Since (RFC 9110).
    if let Some(inm) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    {
        return inm.split(',').any(|t| {
            let t = t.trim();
            t == "*" || t.trim_start_matches("W/") == etag
        });
    }
    headers
        .get(header::IF_MODIFIED_SINCE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| httpdate::parse_http_date(v).ok())
        .is_some_and(|since| modified <= since)
}

async fn map(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    let Some((maps, refresh)) = &state.maps else {
        return error(StatusCode::NOT_FOUND, "maps are not configured");
    };
    let Some(m) = maps
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(&name)
        .cloned()
    else {
        return error(StatusCode::NOT_FOUND, "unknown map");
    };
    let common = [
        (header::ETAG, m.etag.clone()),
        (header::LAST_MODIFIED, httpdate::fmt_http_date(m.modified)),
        // Rspamd schedules its next check of an HTTP map by `Expires`.
        (
            header::EXPIRES,
            httpdate::fmt_http_date(SystemTime::now() + *refresh),
        ),
        (header::CACHE_CONTROL, "no-cache".to_string()),
    ];
    if not_modified(&headers, &m.etag, m.modified) {
        return (StatusCode::NOT_MODIFIED, common).into_response();
    }
    (
        StatusCode::OK,
        common,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        m.body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn secrets() {
        assert!(secret_eq(b"abc", b"abc"));
        assert!(!secret_eq(b"abc", b"abd"));
        assert!(!secret_eq(b"abc", b"abcd"));
        assert!(!secret_eq(b"", b"abc"));
    }

    #[test]
    fn conditional_requests() {
        let modified = SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000);
        let etag = "\"abc\"";
        let mut h = HeaderMap::new();
        assert!(!not_modified(&h, etag, modified));
        h.insert(
            header::IF_MODIFIED_SINCE,
            HeaderValue::from_str(&httpdate::fmt_http_date(modified)).unwrap(),
        );
        assert!(not_modified(&h, etag, modified));
        assert!(!not_modified(&h, etag, modified + Duration::from_secs(1)));
        // A non-matching ETag wins over a matching date.
        h.insert(header::IF_NONE_MATCH, HeaderValue::from_static("\"old\""));
        assert!(!not_modified(&h, etag, modified));
        h.insert(header::IF_NONE_MATCH, HeaderValue::from_static("W/\"abc\""));
        assert!(not_modified(&h, etag, modified + Duration::from_secs(1)));
    }
}
