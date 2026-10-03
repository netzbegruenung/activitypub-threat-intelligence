//! Minimal client for the aptid internal REST API.

use std::time::Duration;

use anyhow::{anyhow, Context};
use apti_core::{Behavior, ObservableType, MAX_BATCH};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;

use crate::config::Aptid;

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

#[derive(Debug, Deserialize)]
pub struct PushResponse {
    pub accepted: usize,
    #[serde(default)]
    pub rejected: Vec<Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveEntry {
    pub observable_type: ObservableType,
    pub observable_value: String,
    pub behavior: Behavior,
    pub effective_expiry: DateTime<Utc>,
    #[serde(default)]
    pub ports: Vec<u16>,
}

#[derive(Debug, Deserialize)]
struct ActiveList {
    entries: Vec<ActiveEntry>,
}

pub struct AptidClient {
    http: reqwest::Client,
    base: String,
    push_token: Option<String>,
    read_token: Option<String>,
}

impl AptidClient {
    pub fn new(cfg: &Aptid) -> anyhow::Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder()
                .user_agent(concat!("apti-fail2ban/", env!("CARGO_PKG_VERSION")))
                .timeout(Duration::from_secs(cfg.timeout_secs))
                .build()?,
            base: cfg.url.trim_end_matches('/').to_string(),
            push_token: cfg.push_token.clone(),
            read_token: cfg.read_token.clone(),
        })
    }

    /// Submit up to 1000 observations.
    pub async fn push(&self, items: &[Value]) -> Result<PushResponse, ApiError> {
        assert!(items.len() <= MAX_BATCH);
        let token = self
            .push_token
            .as_deref()
            .ok_or_else(|| ApiError::Rejected(anyhow!("no push_token configured")))?;
        let resp = self
            .http
            .post(format!("{}/api/v1/observations", self.base))
            .bearer_auth(token)
            .json(items)
            .send()
            .await
            .map_err(|e| ApiError::Transient(e.into()))?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        match status.as_u16() {
            200..=299 => serde_json::from_str(&body)
                .with_context(|| format!("invalid response: {body}"))
                .map_err(ApiError::Transient),
            400 | 413 | 422 => Err(ApiError::Rejected(anyhow!("HTTP {status}: {body}"))),
            _ => Err(ApiError::Transient(anyhow!("HTTP {status}: {body}"))),
        }
    }

    /// The active list (all entries the read token may see).
    pub async fn active(&self) -> anyhow::Result<Vec<ActiveEntry>> {
        let token = self
            .read_token
            .as_deref()
            .ok_or_else(|| anyhow!("no read_token configured"))?;
        let resp = self
            .http
            .get(format!("{}/api/v1/active", self.base))
            .bearer_auth(token)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("GET /api/v1/active: HTTP {status}: {body}");
        }
        let list: ActiveList = resp.json().await.context("invalid active list")?;
        Ok(list.entries)
    }
}
