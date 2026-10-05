use std::path::PathBuf;

use clap::Parser;
use tokio::signal::unix::{signal, SignalKind};

/// AP-TI reference daemon.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "/etc/aptid/config.toml")]
    config: PathBuf,
    /// Validate the configuration and exit.
    #[arg(long)]
    check: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let cfg = aptid::config::Config::load(&args.config)?;
    let mut filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    if cfg.audit.enabled {
        // The audit log does not depend on RUST_LOG.
        filter = filter.add_directive(format!("{}=info", aptid::audit::TARGET).parse()?);
    }
    tracing_subscriber::fmt().with_env_filter(filter).init();
    if args.check {
        println!("configuration OK: {}", args.config.display());
        return Ok(());
    }
    let daemon = aptid::start(cfg).await?;
    let mut term = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    tracing::info!("shutting down");
    daemon.shutdown();
    Ok(())
}
