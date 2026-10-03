//! AP-TI reference daemon.
//!
//! Components (Appendix D):
//! - public ActivityPub listener ([`ap`], [`inbox`], [`sync`], [`publish`]),
//! - organisation-internal REST API ([`api`]),
//! - control socket for the TUI ([`control`]),
//! - effective-expiry engine ([`engine`]) on top of SQLite ([`db`]).

pub mod allowlist;
pub mod ap;
pub mod api;
pub mod client;
pub mod config;
pub mod control;
pub mod db;
pub mod engine;
pub mod httpsig;
pub mod inbox;
pub mod keys;
pub mod publish;
pub mod state;
pub mod sync;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::config::Config;
use crate::db::Db;
use crate::keys::Keys;
use crate::state::{AppState, Shared};

/// A running daemon.
pub struct Daemon {
    pub state: Shared,
    pub public_addr: SocketAddr,
    pub api_addr: SocketAddr,
    tasks: Vec<JoinHandle<()>>,
}

impl Daemon {
    /// Stop all tasks and remove the control socket.
    pub fn shutdown(self) {
        for t in &self.tasks {
            t.abort();
        }
        let _ = std::fs::remove_file(&self.state.cfg.control.socket);
    }
}

/// Start the daemon, binding the listeners from the configuration.
pub async fn start(cfg: Config) -> anyhow::Result<Daemon> {
    let public = TcpListener::bind(cfg.public.bind)
        .await
        .with_context(|| format!("binding public listener {}", cfg.public.bind))?;
    let api = TcpListener::bind(cfg.api.bind)
        .await
        .with_context(|| format!("binding API listener {}", cfg.api.bind))?;
    start_with_listeners(cfg, public, api).await
}

/// Start the daemon on already bound listeners.
pub async fn start_with_listeners(
    cfg: Config,
    public: TcpListener,
    api: TcpListener,
) -> anyhow::Result<Daemon> {
    let db = Db::open(&cfg.storage.database)?;
    let keys = Keys::load_or_generate(&cfg.storage.key_file)?;
    let state: Shared = Arc::new(AppState::new(cfg, db, keys)?);
    let (control, own_uid) = control::bind(&state).context("binding control socket")?;

    let public_addr = public.local_addr()?;
    let api_addr = api.local_addr()?;
    let mut tasks = Vec::new();

    let app = ap::router(state.clone());
    tasks.push(tokio::spawn(async move {
        if let Err(e) = axum::serve(public, app).await {
            tracing::error!("public listener: {e}");
        }
    }));
    let app = api::router(state.clone());
    tasks.push(tokio::spawn(async move {
        if let Err(e) = axum::serve(api, app).await {
            tracing::error!("API listener: {e}");
        }
    }));
    tasks.push(tokio::spawn(control::serve(
        state.clone(),
        control,
        own_uid,
    )));
    tasks.push(tokio::spawn(engine::recompute_loop(state.clone())));
    tasks.push(tokio::spawn(publish::batch_loop(state.clone())));
    tasks.push(tokio::spawn(publish::delivery_loop(state.clone())));
    tasks.push(tokio::spawn(sync::sync_loop(state.clone())));

    tracing::info!(
        actor = %state.urls.actor,
        public = %public_addr,
        api = %api_addr,
        socket = %state.cfg.control.socket.display(),
        "aptid started"
    );
    Ok(Daemon {
        state,
        public_addr,
        api_addr,
        tasks,
    })
}
