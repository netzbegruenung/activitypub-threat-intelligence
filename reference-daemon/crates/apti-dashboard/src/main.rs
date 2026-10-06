use std::path::PathBuf;
use std::time::Duration;

use apti_dashboard::config::Config;
use clap::Parser;
use tokio::signal::unix::{signal, SignalKind};

/// Static HTML threat map for the AP-TI reference daemon.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "/etc/apti-dashboard/config.toml")]
    config: PathBuf,
    /// Validate the configuration and exit.
    #[arg(long)]
    check: bool,
    /// Re-render every SECS seconds instead of once.
    #[arg(long, value_name = "SECS")]
    interval: Option<u64>,
}

async fn render(cfg: &Config) -> anyhow::Result<()> {
    let r = apti_dashboard::run_once(cfg).await?;
    tracing::info!(
        output = %cfg.dashboard.output.display(),
        entries = r.entries,
        located = r.located,
        skipped_domains = r.skipped_domains,
        bytes = r.bytes,
        "dashboard written"
    );
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
    if args.check {
        println!("configuration OK: {}", args.config.display());
        return Ok(());
    }
    if cfg.dns.resolve_domains {
        tracing::warn!("dns.resolve_domains is enabled: DNS queries for listed domains may reach name servers run by attackers");
    }
    let Some(secs) = args.interval else {
        return render(&cfg).await;
    };
    let work = async {
        let mut tick = tokio::time::interval(Duration::from_secs(secs.max(1)));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            // Keep the previous page if a run fails.
            if let Err(e) = render(&cfg).await {
                tracing::warn!("rendering failed: {e:#}");
            }
        }
    };
    let mut term = signal(SignalKind::terminate())?;
    tokio::select! {
        () = work => Ok(()),
        _ = tokio::signal::ctrl_c() => Ok(()),
        _ = term.recv() => Ok(()),
    }
}
