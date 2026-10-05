//! Minimal client for the aptid timeline API.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::Context;
use apti_core::{Behavior, ObservableType, Tlp};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Deserialize;

use crate::config::Aptid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    Local,
    Federated,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineEntry {
    pub observable_type: ObservableType,
    pub observable_value: String,
    pub behavior: Behavior,
    pub origin: Origin,
    /// Actor that published the evidence.
    #[serde(default)]
    pub actor: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    /// Sighting count; `None` for indicators.
    #[serde(default)]
    pub count: Option<u64>,
    pub tlp: Tlp,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct TimelineActor {
    pub handle: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct Timeline {
    pub entries: Vec<TimelineEntry>,
    /// Display details by actor id.
    #[serde(default)]
    pub actors: BTreeMap<String, TimelineActor>,
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
                .user_agent(concat!("apti-dashboard/", env!("CARGO_PKG_VERSION")))
                .timeout(Duration::from_secs(cfg.timeout_secs))
                .build()?,
            base: cfg.url.trim_end_matches('/').to_string(),
            token: cfg.read_token.clone(),
        })
    }

    /// Evidence whose observation period overlaps `[since, now]`. `until`
    /// is left to aptid, so clock skew does not hide the newest entries.
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
}
