//! Shared daemon state.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use tokio::sync::Notify;

use crate::config::Config;
use crate::db::Db;
use crate::keys::Keys;

/// URLs of the local actors and collections.
#[derive(Debug, Clone)]
pub struct Urls {
    pub base: String,
    pub actor: String,
    pub key_id: String,
    pub inbox: String,
    pub shared_inbox: String,
    pub outbox: String,
    pub followers: String,
    pub following: String,
    pub active: String,
    pub org: String,
    pub org_inbox: String,
    pub org_outbox: String,
    pub context: String,
}

impl Urls {
    pub fn new(cfg: &Config) -> Self {
        let base = cfg
            .instance
            .base_url
            .as_str()
            .trim_end_matches('/')
            .to_string();
        let actor = format!("{base}/actor");
        Self {
            key_id: format!("{actor}#main-key"),
            inbox: format!("{actor}/inbox"),
            shared_inbox: format!("{base}/inbox"),
            outbox: format!("{actor}/outbox"),
            followers: format!("{actor}/followers"),
            following: format!("{actor}/following"),
            active: format!("{actor}/active"),
            org: format!("{base}/org"),
            org_inbox: format!("{base}/org/inbox"),
            org_outbox: format!("{base}/org/outbox"),
            context: format!("{base}/ns/ti"),
            actor,
            base,
        }
    }

    pub fn new_object_id(&self) -> String {
        format!("{}/objects/{}", self.base, uuid::Uuid::new_v4())
    }

    pub fn new_activity_id(&self) -> String {
        format!("{}/activities/{}", self.base, uuid::Uuid::new_v4())
    }
}

pub struct AppState {
    pub cfg: Config,
    pub db: Db,
    pub keys: Keys,
    pub http: reqwest::Client,
    pub urls: Urls,
    /// Wake the recompute task.
    pub recompute: Notify,
    /// Wake the sync task.
    pub sync_now: Notify,
    /// Wake the delivery task.
    pub deliver_now: Notify,
    pub last_recompute: Mutex<Option<DateTime<Utc>>>,
    rate: Mutex<HashMap<String, (Instant, u32)>>,
}

pub type Shared = Arc<AppState>;

impl AppState {
    pub fn new(cfg: Config, db: Db, keys: Keys) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("aptid/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(cfg.federation.request_timeout_secs))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            urls: Urls::new(&cfg),
            cfg,
            db,
            keys,
            http,
            recompute: Notify::new(),
            sync_now: Notify::new(),
            deliver_now: Notify::new(),
            last_recompute: Mutex::new(None),
            rate: Mutex::new(HashMap::new()),
        })
    }

    /// Fixed-window rate limiter per key (Section 10, resource exhaustion).
    pub fn rate_limit(&self, key: &str, per_minute: u32) -> bool {
        let mut map = self.rate.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if map.len() > 10_000 {
            map.retain(|_, (t, _)| now.duration_since(*t) < Duration::from_secs(60));
        }
        let entry = map.entry(key.to_string()).or_insert((now, 0));
        if now.duration_since(entry.0) >= Duration::from_secs(60) {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= per_minute
    }
}
