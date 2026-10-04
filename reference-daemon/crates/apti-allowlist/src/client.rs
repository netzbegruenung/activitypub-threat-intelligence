//! Minimal client for the allowlist endpoints of the aptid REST API.

use std::time::Duration;

use anyhow::{anyhow, Context};
use apti_core::protocol::AllowlistScope;
use apti_core::{ObservableType, Tlp};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;

use crate::config::Config;

/// Error class of a failed request.
#[derive(Debug)]
pub enum ApiError {
    /// Retry later (network, 5xx, 429, auth misconfiguration).
    Transient(anyhow::Error),
    /// The request itself is bad; retrying will not help.
    Rejected(anyhow::Error),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transient(e) => write!(f, "{e:#}"),
            Self::Rejected(e) => write!(f, "rejected: {e:#}"),
        }
    }
}

/// An allowlist entry as returned by `GET /api/v1/allowlist`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub id: i64,
    pub observable_type: ObservableType,
    pub observable_value: String,
    /// Empty = all behaviours.
    #[serde(default)]
    pub behaviors: Vec<String>,
    pub tlp: Option<Tlp>,
    pub valid_until: Option<DateTime<Utc>>,
    pub summary: Option<String>,
    /// Who manages the entry (internal).
    pub source: Option<String>,
}

pub struct AptidClient {
    http: reqwest::Client,
    base: String,
    token: String,
}

fn classify(status: reqwest::StatusCode, body: String) -> ApiError {
    match status.as_u16() {
        400 | 413 | 422 => ApiError::Rejected(anyhow!("HTTP {status}: {body}")),
        403 => ApiError::Rejected(anyhow!(
            "HTTP {status}: {body} (the token needs the `allowlist` scope, and `publish` for published entries)"
        )),
        _ => ApiError::Transient(anyhow!("HTTP {status}: {body}")),
    }
}

impl AptidClient {
    pub fn new(cfg: &Config) -> anyhow::Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder()
                .user_agent(concat!("apti-allowlist/", env!("CARGO_PKG_VERSION")))
                .timeout(Duration::from_secs(cfg.aptid.timeout_secs))
                .build()?,
            base: cfg.aptid.url.trim_end_matches('/').to_string(),
            token: cfg.token()?,
        })
    }

    /// All entries of `scope`, including expired ones.
    pub async fn list(&self, scope: AllowlistScope) -> Result<Vec<Entry>, ApiError> {
        let scope = match scope {
            AllowlistScope::Local => "local",
            AllowlistScope::Published => "published",
        };
        let resp = self
            .http
            .get(format!("{}/api/v1/allowlist?scope={scope}", self.base))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| ApiError::Transient(e.into()))?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(classify(status, body));
        }
        serde_json::from_str(&body)
            .with_context(|| format!("invalid allowlist: {body}"))
            .map_err(ApiError::Transient)
    }

    /// Add an entry for all behaviours. Returns whether it was created
    /// (`false`: an identical entry already existed; aptid extends it if
    /// `valid_until` is later).
    pub async fn add(
        &self,
        value: &str,
        source: &str,
        summary: Option<&str>,
        scope: AllowlistScope,
        tlp: Option<Tlp>,
        valid_until: Option<DateTime<Utc>>,
    ) -> Result<bool, ApiError> {
        let mut body = json!({"value": value, "scope": scope, "source": source});
        if let Some(s) = summary {
            body["summary"] = json!(s);
        }
        if let Some(t) = tlp {
            body["tlp"] = json!(t);
        }
        if let Some(u) = valid_until {
            body["validUntil"] = json!(u);
        }
        let resp = self
            .http
            .post(format!("{}/api/v1/allowlist", self.base))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| ApiError::Transient(e.into()))?;
        let status = resp.status();
        match status.as_u16() {
            201 => Ok(true),
            200 => Ok(false),
            _ => Err(classify(status, resp.text().await.unwrap_or_default())),
        }
    }

    /// Remove an entry. An entry that is already gone counts as removed.
    pub async fn remove(&self, id: i64) -> Result<(), ApiError> {
        let resp = self
            .http
            .delete(format!("{}/api/v1/allowlist/{id}", self.base))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| ApiError::Transient(e.into()))?;
        let status = resp.status();
        if status.is_success() || status == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        Err(classify(status, resp.text().await.unwrap_or_default()))
    }
}
