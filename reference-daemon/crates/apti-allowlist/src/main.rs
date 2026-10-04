use std::path::PathBuf;

use apti_allowlist::client::AptidClient;
use apti_allowlist::config::Config;
use apti_allowlist::reconcile::Mode;
use apti_allowlist::sync::Syncer;
use clap::error::ErrorKind;
use clap::{CommandFactory, Parser};
use tokio::signal::unix::{signal, SignalKind};

/// Keeps the aptid allowlist in sync with a text file.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "/etc/apti-allowlist/config.toml")]
    config: PathBuf,
    /// Add values from the file; never remove entries.
    #[arg(long, conflicts_with = "source_of_truth")]
    append: bool,
    /// Add values from the file and remove entries this tool created whose
    /// value is no longer in the file.
    #[arg(long)]
    source_of_truth: bool,
    /// Reconcile once and exit (e.g. from cron).
    #[arg(long)]
    once: bool,
    /// Validate the configuration and exit.
    #[arg(long, conflicts_with_all = ["append", "source_of_truth", "once"])]
    check: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    let cfg = Config::load(&args.config)?;
    if args.check {
        cfg.token()?;
        println!("configuration OK: {}", args.config.display());
        return Ok(());
    }
    let mode = match (args.append, args.source_of_truth) {
        (true, _) => Mode::Append,
        (_, true) => Mode::SourceOfTruth,
        _ => Args::command()
            .error(
                ErrorKind::MissingRequiredArgument,
                "one of --append or --source-of-truth is required",
            )
            .exit(),
    };
    let mut syncer = Syncer::new(&cfg, mode, AptidClient::new(&cfg)?);

    let work = async {
        if args.once {
            let r = syncer.sync_once().await?;
            println!("{r}");
            return Ok(());
        }
        tracing::info!(file = %cfg.file.path.display(), ?mode, marker = %cfg.marker(), "watching allowlist file");
        syncer.run().await
    };
    let mut term = signal(SignalKind::terminate())?;
    tokio::select! {
        r = work => r,
        _ = tokio::signal::ctrl_c() => Ok(()),
        _ = term.recv() => Ok(()),
    }
}
