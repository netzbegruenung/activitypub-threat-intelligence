use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use apti_rspamd::client::AptidClient;
use apti_rspamd::config::Config;
use apti_rspamd::maps::Puller;
use apti_rspamd::push::Pusher;
use apti_rspamd::reputation::Ingest;
use apti_rspamd::server::{self, AppState};
use clap::{Parser, Subcommand};
use tokio::signal::unix::{signal, SignalKind};

/// Rspamd connector for the AP-TI reference daemon.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "/etc/apti-rspamd/config.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the report endpoint and the maps, push reports to aptid.
    Run,
    /// Fetch the active list once and print all maps.
    Maps,
    /// Validate the configuration and exit.
    Check,
}

async fn run(cfg: Config) -> anyhow::Result<()> {
    if !cfg.server.bind.ip().is_loopback() {
        tracing::warn!(bind = %cfg.server.bind, "server is not bound to a loopback address; restrict access to it");
    }
    let mut state = AppState {
        ingest: None,
        maps: None,
    };
    let mut pusher = None;
    if let Some(e) = cfg.ingest.as_ref().and_then(|i| i.envelope_from.as_ref()) {
        if e.require_symbols.is_empty() {
            tracing::warn!("ingest.envelope_from.require_symbols is empty: forged envelope senders will be reported");
        }
    }
    if let Some(i) = cfg.ingest.clone() {
        let secret = i.report_secret.clone();
        let batch = i.batch_interval_secs;
        let ingest = Arc::new(Mutex::new(Ingest::new(i)?));
        pusher = Some(Pusher::new(
            ingest.clone(),
            AptidClient::new(&cfg.aptid)?,
            batch,
        ));
        state.ingest = Some((ingest, secret));
    }
    let mut puller = None;
    if let Some(m) = cfg.maps.clone() {
        let refresh = Duration::from_secs(m.interval_secs);
        let mut p = Puller::new(m, AptidClient::new(&cfg.aptid)?)?;
        if let Err(e) = p.step().await {
            tracing::warn!("initial fetch of the active list failed: {e:#}");
        }
        state.maps = Some((p.maps(), refresh));
        puller = Some(p);
    }
    let listener = tokio::net::TcpListener::bind(cfg.server.bind).await?;
    tracing::info!(bind = %cfg.server.bind, "listening");
    let serve = async {
        axum::serve(listener, server::router(state))
            .await
            .map_err(anyhow::Error::from)
    };
    let push = async {
        match pusher {
            Some(p) => p.run().await,
            None => std::future::pending().await,
        }
    };
    let pull = async {
        match puller {
            Some(p) => p.run().await,
            None => std::future::pending().await,
        }
    };
    tokio::try_join!(serve, push, pull).map(|_| ())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    let cfg = Config::load(&args.config)?;

    let work = async {
        match args.command {
            Command::Check => {
                println!("configuration OK: {}", args.config.display());
                Ok(())
            }
            Command::Maps => {
                let m = cfg
                    .maps
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("no [maps] section in config"))?;
                let mut p = Puller::new(m.clone(), AptidClient::new(&cfg.aptid)?)?;
                p.step().await?;
                let maps = p.maps();
                let maps = maps.read().unwrap_or_else(|e| e.into_inner());
                for d in &m.maps {
                    print!("{}", maps[&d.name].body);
                }
                Ok(())
            }
            Command::Run => run(cfg.clone()).await,
        }
    };
    let mut term = signal(SignalKind::terminate())?;
    tokio::select! {
        r = work => r,
        _ = tokio::signal::ctrl_c() => Ok(()),
        _ = term.recv() => Ok(()),
    }
}
