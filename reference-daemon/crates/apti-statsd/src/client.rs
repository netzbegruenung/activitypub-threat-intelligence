//! Minimal read-only client for the aptid internal REST API.
//!
//! The client is authenticated with a `read` token whose `max_tlp` is
//! `clear`; the hub therefore only ever returns TLP:CLEAR entries.

use std::time::Duration;

use anyhow::Context;
use apti_core::{Behavior, EvidenceKind, ObservableType, Tlp};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use crate::config::Aptid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveEntry {
    pub observable_type: ObservableType,
    pub observable_value: String,
    pub behavior: Behavior,
    #[serde(default)]
    pub include_subdomains: bool,
    pub effective_expiry: DateTime<Utc>,
    #[serde(default)]
    pub ttl: i64,
    pub tlp: Tlp,
    #[serde(default)]
    pub flagged: bool,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub services: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveList {
    pub generated: DateTime<Utc>,
    #[serde(default)]
    pub last_recompute: Option<DateTime<Utc>>,
    #[serde(default)]
    pub entries: Vec<ActiveEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TimelineOrigin {
    Local,
    Federated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineEntry {
    pub observable_type: ObservableType,
    pub observable_value: String,
    pub behavior: Behavior,
    pub kind: EvidenceKind,
    pub origin: TimelineOrigin,
    pub actor: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    #[serde(default)]
    pub count: Option<u64>,
    pub tlp: Tlp,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineActor {
    #[serde(default)]
    pub handle: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Timeline {
    #[serde(default)]
    pub generated: DateTime<Utc>,
    #[serde(default)]
    pub since: DateTime<Utc>,
    #[serde(default)]
    pub until: DateTime<Utc>,
    #[serde(default)]
    pub entries: Vec<TimelineEntry>,
    #[serde(default)]
    pub actors: std::collections::BTreeMap<String, TimelineActor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeInfo {
    pub actor: String,
    #[serde(default)]
    pub handle: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub operator: Option<String>,
    #[serde(default)]
    pub evidence: u64,
    #[serde(default)]
    pub state: String,
}

pub struct AptidClient {
    http: reqwest::Client,
    base: String,
    token: String,
}

impl AptidClient {
    pub fn new(cfg: &Aptid) -> anyhow::Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder()
                .user_agent(concat!("apti-statsd/", env!("CARGO_PKG_VERSION")))
                .timeout(Duration::from_secs(cfg.timeout_secs))
                .build()?,
            base: cfg.url.trim_end_matches('/').to_string(),
            token: cfg.read_token.clone(),
        })
    }

    /// The hub's active list (TLP:CLEAR entries only, per the token).
    pub async fn active(&self) -> anyhow::Result<ActiveList> {
        let resp = self
            .http
            .get(format!("{}/api/v1/active", self.base))
            .bearer_auth(&self.token)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("GET /api/v1/active: HTTP {status}: {body}");
        }
        resp.json().await.context("invalid active list")
    }

    /// Findings whose observation period overlaps `[since, now]`.
    pub async fn timeline(&self, since: DateTime<Utc>) -> anyhow::Result<Timeline> {
        let resp = self
            .http
            .get(format!("{}/api/v1/timeline", self.base))
            .query(&[("since", since.to_rfc3339_opts(SecondsFormat::Millis, true))])
            .bearer_auth(&self.token)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("GET /api/v1/timeline: HTTP {status}: {body}");
        }
        resp.json().await.context("invalid timeline")
    }

    /// The hub's connected nodes (its follow list).
    pub async fn nodes(&self) -> anyhow::Result<Vec<NodeInfo>> {
        let resp = self
            .http
            .get(format!("{}/api/v1/nodes", self.base))
            .bearer_auth(&self.token)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("GET /api/v1/nodes: HTTP {status}: {body}");
        }
        resp.json().await.context("invalid node list")
    }
}
