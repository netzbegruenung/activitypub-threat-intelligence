//! Public HTTP surface of apti-statsd.
//!
//! Serves the aggregate statistics page and the hub's connected-node
//! directory to anyone, with no authentication. Individual observables are
//! never served (personal data even at TLP:CLEAR, Section 11). Responses
//! carry ETags and `Last-Modified` so reverse proxies and clients can cache,
//! are rate-limited per client, and set defensive security headers. The last
//! snapshot keeps being served while the hub is unreachable.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;

use crate::config::Server;
use crate::poll::{self, Blob, SharedSnapshot, Snapshot};

#[derive(Clone)]
pub struct AppState {
    pub snapshot: SharedSnapshot,
    pub cfg: Server,
    pub window_days: u32,
    pub interval: Duration,
    pub limiter: Arc<RateLimiter>,
}

/// Most clients tracked at once. When the table is full the oldest windows
/// are evicted, so memory stays bounded however many addresses a client
/// cycles through, without ever refusing a client that has not been seen.
pub const MAX_CLIENTS: usize = 65_536;

/// Share of the table evicted at once when it is full. Evicting a batch
/// keeps the cost of the scan amortised over many requests.
const EVICT_FRACTION: usize = 8;

/// Fixed-window per-client request limiter with a bounded client table.
pub struct RateLimiter {
    limit: usize,
    window: Duration,
    inner: Mutex<Buckets>,
}

struct Buckets {
    /// client -> (window start, requests in that window)
    hits: HashMap<IpAddr, (Instant, usize)>,
    last_purge: Instant,
}

impl RateLimiter {
    pub fn new(limit: usize, window: Duration) -> Self {
        Self {
            limit,
            window,
            inner: Mutex::new(Buckets {
                hits: HashMap::new(),
                last_purge: Instant::now(),
            }),
        }
    }

    /// Record a request from `ip`; return whether it is allowed.
    pub fn check(&self, ip: IpAddr) -> bool {
        self.check_at(ip, Instant::now(), MAX_CLIENTS)
    }

    fn check_at(&self, ip: IpAddr, now: Instant, max_clients: usize) -> bool {
        let key = client_key(ip);
        let mut b = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if !b.hits.contains_key(&key) && b.hits.len() >= max_clients {
            // Drop expired windows, at most once per second so a full table
            // does not cost a full scan on every request.
            if now.duration_since(b.last_purge) >= Duration::from_secs(1) {
                let window = self.window;
                b.hits
                    .retain(|_, (start, _)| now.duration_since(*start) < window);
                b.last_purge = now;
            }
            // Still full: make room by dropping the oldest windows. A client
            // cycling through addresses loses its own entries along with the
            // rest and cannot lock unseen clients out of the service.
            if b.hits.len() >= max_clients {
                evict_oldest(&mut b.hits, (max_clients / EVICT_FRACTION).max(1));
            }
        }
        let (start, n) = b.hits.entry(key).or_insert((now, 0));
        if now.duration_since(*start) >= self.window {
            (*start, *n) = (now, 0);
        }
        if *n >= self.limit {
            return false;
        }
        *n += 1;
        true
    }
}

/// Remove the `n` entries whose windows started earliest.
fn evict_oldest(hits: &mut HashMap<IpAddr, (Instant, usize)>, n: usize) {
    if n == 0 {
        return;
    }
    let mut by_age: Vec<(Instant, IpAddr)> =
        hits.iter().map(|(ip, (start, _))| (*start, *ip)).collect();
    if n >= by_age.len() {
        hits.clear();
        return;
    }
    by_age.select_nth_unstable(n - 1);
    for (_, ip) in &by_age[..n] {
        hits.remove(ip);
    }
}

/// The rate-limit key of a client: its IPv4 address, or the /64 of an IPv6
/// address (one subscriber usually holds a whole /64).
fn client_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
    }
}

/// Client address: the peer socket address, or, when the peer is a trusted
/// reverse proxy (`server.trust_forwarded_for`), the last `X-Forwarded-For`
/// entry, i.e. the address that proxy saw. Earlier entries are set by the
/// client and are never used.
fn client_ip(req: &Request<Body>, trust_forwarded_for: bool) -> Option<IpAddr> {
    if trust_forwarded_for {
        let last = req
            .headers()
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .last()
            .and_then(|ip| ip.trim().parse::<IpAddr>().ok());
        if last.is_some() {
            return last;
        }
    }
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
}

async fn rate_limit(State(state): State<AppState>, req: Request<Body>, next: Next) -> Response {
    if let Some(ip) = client_ip(&req, state.cfg.trust_forwarded_for) {
        if !state.limiter.check(ip) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [
                    (header::RETRY_AFTER, "1"),
                    (header::CACHE_CONTROL, "no-store"),
                ],
                Json(json!({ "error": "too many requests; retry in a second" })),
            )
                .into_response();
        }
    }
    next.run(req).await
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/", get(index))
        .route("/api/v1/nodes", get(nodes))
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(state, rate_limit))
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

fn service_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::RETRY_AFTER, "5")],
        Json(json!({ "error": "waiting for the first fetch from the hub" })),
    )
        .into_response()
}

/// The current snapshot, or `None` before the first successful fetch.
fn get_snapshot(state: &AppState) -> Option<Arc<Snapshot>> {
    state.snapshot.read().ok()?.as_ref().cloned()
}

/// `true` when the client's conditional headers match the current body.
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
    // HTTP dates have whole-second resolution, so compare `modified` as it
    // was sent in `Last-Modified`.
    headers
        .get(header::IF_MODIFIED_SINCE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| httpdate::parse_http_date(v).ok())
        .is_some_and(|since| whole_seconds(modified) <= since)
}

fn whole_seconds(t: SystemTime) -> SystemTime {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

/// Common response headers for a cacheable snapshot body.
fn cache_headers(
    etag: &str,
    modified: SystemTime,
    interval: Duration,
) -> [(header::HeaderName, String); 6] {
    [
        (header::ETAG, etag.to_string()),
        (
            header::LAST_MODIFIED,
            httpdate::fmt_http_date(modified).to_string(),
        ),
        // The next poll is due one interval after this snapshot's fetch.
        (
            header::EXPIRES,
            httpdate::fmt_http_date(modified + interval).to_string(),
        ),
        (header::CACHE_CONTROL, "no-cache".to_string()),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
        (header::REFERRER_POLICY, "no-referrer".to_string()),
    ]
}

/// Serve a pre-rendered data blob (JSON) with ETag/304 support.
fn serve_json(state: &AppState, blob: &Blob, fetched: SystemTime, headers: &HeaderMap) -> Response {
    if not_modified(headers, &blob.etag, fetched) {
        return (
            StatusCode::NOT_MODIFIED,
            cache_headers(&blob.etag, fetched, state.interval),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        cache_headers(&blob.etag, fetched, state.interval),
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        blob.body.clone(),
    )
        .into_response()
}

/// Serve the aggregate statistics page with ETag/304 support.
fn serve_index(state: &AppState, snap: &Snapshot, headers: &HeaderMap) -> Response {
    let body = snap
        .page(&state.cfg.title, state.window_days, state.interval)
        .into_bytes();
    let etag = poll::etag(&body);
    if not_modified(headers, &etag, snap.fetched) {
        return (
            StatusCode::NOT_MODIFIED,
            cache_headers(&etag, snap.fetched, state.interval),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        cache_headers(&etag, snap.fetched, state.interval),
        [(header::CONTENT_TYPE, "text/html; charset=utf-8".to_string())],
        body,
    )
        .into_response()
}

async fn index(State(state): State<AppState>, headers: HeaderMap) -> Response {
    match get_snapshot(&state) {
        Some(snap) => serve_index(&state, &snap, &headers),
        None => service_unavailable(),
    }
}

async fn nodes(State(state): State<AppState>, headers: HeaderMap) -> Response {
    match get_snapshot(&state) {
        Some(snap) => serve_json(&state, &snap.nodes, snap.fetched, &headers),
        None => service_unavailable(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter() {
        let rl = RateLimiter::new(2, Duration::from_secs(60));
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(rl.check(ip));
        assert!(rl.check(ip));
        assert!(!rl.check(ip), "third request within the window is limited");
        let other: IpAddr = "5.6.7.8".parse().unwrap();
        assert!(rl.check(other), "other clients are independent");
        // Addresses in one IPv6 /64 share a bucket.
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        assert!(rl.check(a));
        assert!(rl.check(b));
        assert!(!rl.check(a));
    }

    #[test]
    fn rate_limiter_window_resets() {
        let rl = RateLimiter::new(1, Duration::from_secs(60));
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let t0 = Instant::now();
        assert!(rl.check_at(ip, t0, 10));
        assert!(!rl.check_at(ip, t0 + Duration::from_secs(59), 10));
        assert!(rl.check_at(ip, t0 + Duration::from_secs(60), 10));
    }

    #[test]
    fn rate_limiter_table_is_bounded() {
        let rl = RateLimiter::new(100, Duration::from_secs(60));
        let t0 = Instant::now();
        let ip = |i: u8| IpAddr::from([10, 0, 0, i]);
        for i in 0..4 {
            assert!(rl.check_at(ip(i), t0, 4));
        }
        // Full and nothing expired: a new client is still served, and the
        // table stays bounded because the oldest window is evicted.
        assert!(rl.check_at(ip(9), t0 + Duration::from_secs(2), 4));
        assert!(rl.inner.lock().unwrap().hits.len() <= 4);
        // A client cycling through addresses cannot lock others out.
        for i in 10..40 {
            assert!(rl.check_at(ip(i), t0 + Duration::from_secs(2), 4));
        }
        assert!(rl.check_at(ip(0), t0 + Duration::from_secs(2), 4));
        assert!(rl.inner.lock().unwrap().hits.len() <= 4);
        // Once the windows expire, the table is purged and accepts again.
        assert!(rl.check_at(ip(9), t0 + Duration::from_secs(61), 4));
        assert!(rl.inner.lock().unwrap().hits.len() <= 4);
    }

    fn request(xff: &[&str], peer: &str) -> Request<Body> {
        let mut req = Request::new(Body::empty());
        for v in xff {
            req.headers_mut()
                .append("x-forwarded-for", v.parse().unwrap());
        }
        req.extensions_mut()
            .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        req
    }

    #[test]
    fn client_ip_from_forwarded_for() {
        let peer = "127.0.0.1:5000";
        let spoofed = request(&["6.6.6.6, 9.9.9.9"], peer);
        // Untrusted: the header is ignored entirely.
        assert_eq!(
            client_ip(&spoofed, false),
            Some("127.0.0.1".parse().unwrap())
        );
        // Trusted proxy appended the real address; the client-set first
        // entry is ignored.
        assert_eq!(client_ip(&spoofed, true), Some("9.9.9.9".parse().unwrap()));
        let multi = request(&["6.6.6.6", "9.9.9.9"], peer);
        assert_eq!(client_ip(&multi, true), Some("9.9.9.9".parse().unwrap()));
        let none = request(&[], peer);
        assert_eq!(client_ip(&none, true), Some("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn conditional_requests() {
        let modified = SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000);
        let etag = "\"abc\"";
        let mut h = HeaderMap::new();
        assert!(!not_modified(&h, etag, modified));
        h.insert(
            header::IF_MODIFIED_SINCE,
            axum::http::HeaderValue::from_str(&httpdate::fmt_http_date(modified)).unwrap(),
        );
        assert!(not_modified(&h, etag, modified));
        // Sub-second precision in the snapshot time is not sent in
        // Last-Modified, so it must not defeat the comparison.
        assert!(not_modified(
            &h,
            etag,
            modified + Duration::from_millis(750)
        ));
        assert!(!not_modified(&h, etag, modified + Duration::from_secs(1)));
        // A non-matching ETag wins over a matching date.
        h.insert(
            header::IF_NONE_MATCH,
            axum::http::HeaderValue::from_static("\"old\""),
        );
        assert!(!not_modified(&h, etag, modified));
        h.insert(
            header::IF_NONE_MATCH,
            axum::http::HeaderValue::from_static("W/\"abc\""),
        );
        assert!(not_modified(&h, etag, modified + Duration::from_secs(1)));
    }
}
