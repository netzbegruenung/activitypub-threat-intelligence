//! Outgoing ActivityPub requests: signed fetch, delivery, WebFinger, actor
//! discovery and operator resolution (Section 3.2).

use anyhow::{anyhow, bail, Context};
use chrono::{TimeDelta, Utc};
use serde_json::Value;
use url::Url;

use crate::db::{self, RemoteActor};
use crate::httpsig;
use crate::state::AppState;

pub const AP_ACCEPT: &str =
    "application/activity+json, application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"";
pub const AP_CONTENT_TYPE: &str = "application/activity+json";

/// Maximum size of a fetched document.
const MAX_RESPONSE: usize = 8 * 1024 * 1024;

pub fn check_url(state: &AppState, url: &str) -> anyhow::Result<Url> {
    let u = Url::parse(url).with_context(|| format!("invalid URL `{url}`"))?;
    match u.scheme() {
        "https" => {}
        "http" if state.cfg.federation.allow_http => {}
        s => bail!("URL scheme `{s}` not allowed: {url}"),
    }
    if u.host_str().is_none() {
        bail!("URL without host: {url}");
    }
    Ok(u)
}

pub fn host_of(url: &str) -> Option<String> {
    let u = Url::parse(url).ok()?;
    let host = u.host_str()?.to_ascii_lowercase();
    Some(match u.port() {
        Some(p) => format!("{host}:{p}"),
        None => host,
    })
}

async fn read_limited(resp: reqwest::Response) -> anyhow::Result<Vec<u8>> {
    if resp
        .content_length()
        .is_some_and(|l| l as usize > MAX_RESPONSE)
    {
        bail!("response too large");
    }
    let bytes = resp.bytes().await?;
    if bytes.len() > MAX_RESPONSE {
        bail!("response too large");
    }
    Ok(bytes.to_vec())
}

/// GET with an HTTP signature (signed fetch, Section 3.1).
pub async fn signed_get(state: &AppState, url: &str) -> anyhow::Result<Value> {
    let u = check_url(state, url)?;
    let mut req = state.http.get(u.clone()).header("accept", AP_ACCEPT);
    for (k, v) in httpsig::sign_request(&state.keys, &state.urls.key_id, "GET", &u, None) {
        req = req.header(k, v);
    }
    let resp = req.send().await.with_context(|| format!("GET {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        bail!("GET {url}: HTTP {status}");
    }
    let body = read_limited(resp).await?;
    serde_json::from_slice(&body).with_context(|| format!("GET {url}: invalid JSON"))
}

/// POST an activity with an HTTP signature.
pub async fn signed_post(state: &AppState, url: &str, body: &Value) -> anyhow::Result<()> {
    let u = check_url(state, url)?;
    let bytes = serde_json::to_vec(body)?;
    let mut req = state
        .http
        .post(u.clone())
        .header("content-type", AP_CONTENT_TYPE)
        .header("accept", AP_ACCEPT);
    for (k, v) in httpsig::sign_request(&state.keys, &state.urls.key_id, "POST", &u, Some(&bytes)) {
        req = req.header(k, v);
    }
    let resp = req
        .body(bytes)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        bail!("POST {url}: HTTP {status}");
    }
    Ok(())
}

/// Resolve `user@host` (optionally prefixed by `@` or `acct:`) via WebFinger.
pub async fn webfinger(state: &AppState, handle: &str) -> anyhow::Result<String> {
    let h = handle
        .trim()
        .trim_start_matches("acct:")
        .trim_start_matches('@');
    let (_, host) = h
        .split_once('@')
        .ok_or_else(|| anyhow!("expected user@host"))?;
    let scheme = if state.cfg.federation.allow_http && host.contains(':') {
        "http"
    } else {
        "https"
    };
    let mut u = Url::parse(&format!("{scheme}://{host}/.well-known/webfinger"))?;
    u.query_pairs_mut()
        .append_pair("resource", &format!("acct:{h}"));
    let resp = state
        .http
        .get(u.clone())
        .header("accept", "application/jrd+json, application/json")
        .send()
        .await?;
    if !resp.status().is_success() {
        bail!("WebFinger {u}: HTTP {}", resp.status());
    }
    let jrd: Value = serde_json::from_slice(&read_limited(resp).await?)?;
    jrd["links"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|l| {
            l["rel"] == "self"
                && l["type"]
                    .as_str()
                    .is_some_and(|t| t.contains("activity+json") || t.contains("ld+json"))
        })
        .and_then(|l| l["href"].as_str())
        .map(String::from)
        .ok_or_else(|| anyhow!("WebFinger: no ActivityPub actor link"))
}

/// The `id` of a JSON value that is either a string or an object with `id`.
pub fn id_of(v: &Value) -> Option<&str> {
    v.as_str().or_else(|| v["id"].as_str())
}

/// Values of a property that may be a single value or an array.
pub fn as_list(v: &Value) -> Vec<&Value> {
    match v {
        Value::Null => vec![],
        Value::Array(a) => a.iter().collect(),
        other => vec![other],
    }
}

fn parse_actor(id: &str, doc: &Value) -> anyhow::Result<RemoteActor> {
    if doc["id"].as_str() != Some(id) {
        bail!("actor document id does not match {id}");
    }
    let inbox = doc["inbox"]
        .as_str()
        .ok_or_else(|| anyhow!("actor without inbox"))?;
    let key = as_list(&doc["publicKey"])
        .into_iter()
        .find(|k| k["owner"].as_str().is_none_or(|o| o == id))
        .cloned()
        .unwrap_or(Value::Null);
    let key_id = key["id"].as_str().map(String::from);
    if let Some(k) = &key_id {
        if host_of(k) != host_of(id) {
            bail!("actor key is hosted on a different origin");
        }
    }
    Ok(RemoteActor {
        id: id.to_string(),
        inbox: inbox.to_string(),
        shared_inbox: doc["endpoints"]["sharedInbox"].as_str().map(String::from),
        followers: doc["followers"].as_str().map(String::from),
        active_objects: id_of(&doc["activeObjects"]).map(String::from),
        key_id,
        public_key_pem: key["publicKeyPem"].as_str().map(String::from),
        operator_claim: id_of(&doc["operator"]).map(String::from),
        preferred_username: doc["preferredUsername"].as_str().map(String::from),
        fetched_at: Utc::now(),
    })
}

/// Fetch (or return the cached copy of) a remote actor, and resolve its
/// operator. Cached copies older than a day are refreshed.
pub async fn fetch_actor(state: &AppState, id: &str, force: bool) -> anyhow::Result<RemoteActor> {
    let id = id.split('#').next().unwrap_or(id).to_string();
    if id == state.urls.actor {
        bail!("refusing to fetch own actor");
    }
    if !force {
        let id2 = id.clone();
        if let Some(a) = state
            .db
            .call(move |c| db::get_remote_actor(c, &id2))
            .await?
        {
            if Utc::now() - a.fetched_at < TimeDelta::days(1) {
                return Ok(a);
            }
        }
    }
    let doc = signed_get(state, &id).await?;
    let actor = parse_actor(&id, &doc)?;
    let (operator, source) = resolve_operator(state, &actor).await;
    let a = actor.clone();
    state
        .db
        .call(move |c| {
            db::upsert_remote_actor(c, &a)?;
            db::set_actor_operator(c, &a.id, &operator, source)
        })
        .await?;
    Ok(actor)
}

/// Find the actor owning `key_id`, from cache or by fetching it.
pub async fn actor_for_key(
    state: &AppState,
    key_id: &str,
    force: bool,
) -> anyhow::Result<RemoteActor> {
    if !force {
        let k = key_id.to_string();
        if let Some(a) = state
            .db
            .call(move |c| db::find_actor_by_key_id(c, &k))
            .await?
        {
            return Ok(a);
        }
    }
    let actor = fetch_actor(state, key_id, true).await?;
    if actor.key_id.as_deref() != Some(key_id) {
        bail!("key {key_id} is not the key of {}", actor.id);
    }
    Ok(actor)
}

/// Fallback operator for an actor: its registrable domain per the PSL.
pub fn fallback_operator(actor: &str) -> String {
    let Some(url) = Url::parse(actor).ok() else {
        return format!("domain:{actor}");
    };
    match url.host() {
        Some(url::Host::Domain(d)) => {
            let host = d.to_ascii_lowercase();
            format!("domain:{}", psl::domain_str(&host).unwrap_or(&host))
        }
        Some(ip) => format!("domain:{ip}"),
        None => format!("domain:{actor}"),
    }
}

/// Resolve the operator: a bidirectional `operator`/`operatedActors` link
/// is `verified`; otherwise the registrable domain (`psl`).
pub async fn resolve_operator(state: &AppState, actor: &RemoteActor) -> (String, &'static str) {
    if let Some(claim) = &actor.operator_claim {
        match signed_get(state, claim).await {
            Ok(org) => {
                let lists_actor = as_list(&org["operatedActors"])
                    .into_iter()
                    .any(|v| id_of(v) == Some(actor.id.as_str()));
                if org["id"].as_str() == Some(claim.as_str()) && lists_actor {
                    return (claim.clone(), "verified");
                }
                tracing::warn!(actor = %actor.id, operator = %claim, "operator link not confirmed");
            }
            Err(e) => {
                tracing::warn!(actor = %actor.id, operator = %claim, "operator fetch failed: {e:#}")
            }
        }
    }
    (fallback_operator(&actor.id), "psl")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psl_fallback() {
        assert_eq!(
            fallback_operator("https://ti.example.co.uk/actor"),
            "domain:example.co.uk"
        );
        assert_eq!(
            fallback_operator("https://a.b.example.net/actor"),
            "domain:example.net"
        );
        assert_eq!(
            fallback_operator("http://127.0.0.1:8080/actor"),
            "domain:127.0.0.1"
        );
    }

    #[test]
    fn parses_actor() {
        let doc = serde_json::json!({
            "id": "https://ti.example.net/actor", "type": "Service",
            "inbox": "https://ti.example.net/actor/inbox",
            "endpoints": {"sharedInbox": "https://ti.example.net/inbox"},
            "activeObjects": "https://ti.example.net/actor/active",
            "operator": "https://example.net/org",
            "publicKey": {"id": "https://ti.example.net/actor#main-key",
                          "owner": "https://ti.example.net/actor", "publicKeyPem": "PEM"}
        });
        let a = parse_actor("https://ti.example.net/actor", &doc).unwrap();
        assert_eq!(a.delivery_inbox(), "https://ti.example.net/inbox");
        assert_eq!(a.operator_claim.as_deref(), Some("https://example.net/org"));
        assert!(parse_actor("https://other.example/actor", &doc).is_err());
    }
}
