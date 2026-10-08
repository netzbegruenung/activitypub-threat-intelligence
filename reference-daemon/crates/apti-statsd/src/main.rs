use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use apti_statsd::client::AptidClient;
use apti_statsd::config::Config;
use apti_statsd::poll::Poller;
use apti_statsd::render::Renderer;
use apti_statsd::server::{self, AppState, RateLimiter};
use apti_statsd::stats::Stats;
use chrono::{TimeDelta, Utc};
use clap::{Parser, Subcommand};

/// Public statistics page for an AP-TI hub.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "/etc/apti-statsd/config.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Poll the hub and publish the page and node directory, by rendering
    /// them into `server.output_dir` or, with `server.bind` set, over HTTP.
    Run,
    /// Validate the configuration and exit.
    Check,
    /// Fetch the hub once and print the aggregate statistics.
    Summary,
}

async fn run(cfg: Config) -> anyhow::Result<()> {
    let client = AptidClient::new(&cfg.aptid)?;
    let interval = Duration::from_secs(cfg.poll.interval_secs);
    let poller = Poller::new(client, interval, cfg.poll.window_days as i64);
    match cfg.server.bind.clone() {
        Some(bind) => serve(&cfg, poller, &bind, interval).await,
        None => {
            let renderer = Renderer::new(
                &cfg.server,
                poller.snapshot(),
                cfg.poll.window_days,
                interval,
            );
            let updated = poller.updated();
            tokio::try_join!(poller.run(), renderer.run(updated)).map(|_| ())
        }
    }
}

/// Serve the page over HTTP instead of rendering it to disk.
async fn serve(cfg: &Config, poller: Poller, bind: &str, interval: Duration) -> anyhow::Result<()> {
    if !bind.contains("127.0.0.1") && !bind.contains("[::1]") {
        tracing::info!(
            bind,
            "public server: serve it behind a TLS-terminating reverse proxy"
        );
    }
    let state = AppState {
        snapshot: poller.snapshot(),
        window_days: cfg.poll.window_days,
        interval,
        limiter: Arc::new(RateLimiter::new(
            cfg.server.rate_limit_per_min as usize,
            Duration::from_secs(60),
        )),
        cfg: cfg.server.clone(),
    };
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(bind, "listening");
    let app = server::router(state);
    let serve = async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .map_err(anyhow::Error::from)
    };
    tokio::try_join!(poller.run(), serve).map(|_| ())
}

async fn summary(cfg: &Config) -> anyhow::Result<()> {
    let client = AptidClient::new(&cfg.aptid)?;
    let since = Utc::now() - TimeDelta::days(cfg.poll.window_days as i64);
    let (active, timeline, nodes) =
        tokio::try_join!(client.active(), client.timeline(since), client.nodes())?;
    let s: Stats = Stats::compute(&active.entries, &timeline.entries, &nodes);
    println!("connected nodes:   {}", s.nodes);
    println!("evidence ingested: {}", s.evidence_ingested);
    println!(
        "active observables:  {} (ipv4 {}, ipv6 {}, domains {})",
        s.active_total, s.active_ipv4, s.active_ipv6, s.active_domains
    );
    println!("findings in window: {}", s.findings_total);
    Ok(())
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
            Command::Summary => summary(&cfg).await,
            Command::Run => run(cfg).await,
        }
    };
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        r = work => r,
        _ = tokio::signal::ctrl_c() => Ok(()),
        _ = term.recv() => Ok(()),
    }
}
