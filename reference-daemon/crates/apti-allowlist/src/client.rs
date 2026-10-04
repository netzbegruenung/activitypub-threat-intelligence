//! Minimal client for the allowlist endpoints of the aptid REST API.

use std::time::Duration;

use anyhow::{anyhow, Context};
use apti_core::ObservableType;
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

/// A local allowlist entry as returned by `GET /api/v1/allowlist`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub id: i64,
    pub observable_type: ObservableType,
    pub observable_value: String,
    /// Empty = all behaviours.
    #[serde(default)]
    pub behaviors: Vec<String>,
    pub valid_until: Option<DateTime<Utc>>,
    pub summary: Option<String>,
}

pub struct AptidClient {
    http: reqwest::Client,
    base: String,
    token: String,
}

fn classify(status: reqwest::StatusCode, body: String) -> ApiError {
    match status.as_u16() {
        400 | 413 | 422 => ApiError::Rejected(anyhow!("HTTP {status}: {body}")),
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

    /// All local entries, including expired ones.
    pub async fn list(&self) -> Result<Vec<Entry>, ApiError> {
        let resp = self
            .http
            .get(format!("{}/api/v1/allowlist?scope=local", self.base))
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

    /// Add a local entry for all behaviours. Returns whether it was created
    /// (`false`: an identical entry already existed).
    pub async fn add(&self, value: &str, summary: &str) -> Result<bool, ApiError> {
        let resp = self
            .http
            .post(format!("{}/api/v1/allowlist", self.base))
            .bearer_auth(&self.token)
            .json(&json!({"value": value, "scope": "local", "summary": summary}))
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
