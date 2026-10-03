use std::path::PathBuf;

use apti_fail2ban::client::AptidClient;
use apti_fail2ban::config::Config;
use apti_fail2ban::pull::Puller;
use apti_fail2ban::push::Pusher;
use clap::{Parser, Subcommand};
use tokio::signal::unix::{signal, SignalKind};

/// fail2ban connector for the AP-TI reference daemon.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "/etc/apti-fail2ban/config.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Follow the fail2ban log and push bans to aptid.
    Push,
    /// Poll aptid's active list and write ban files for fail2ban.
    Pull {
        /// Update the files once and exit (e.g. from cron).
        #[arg(long)]
        once: bool,
    },
    /// Run push and pull together.
    Run,
    /// Validate the configuration and exit.
    Check,
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

    let pusher = || -> anyhow::Result<Pusher> {
        let push = cfg
            .push
            .clone()
            .ok_or_else(|| anyhow::anyhow!("no [push] section in config"))?;
        Pusher::new(push, AptidClient::new(&cfg.aptid)?)
    };
    let puller = || -> anyhow::Result<Puller> {
        let pull = cfg
            .pull
            .clone()
            .ok_or_else(|| anyhow::anyhow!("no [pull] section in config"))?;
        Puller::new(pull, AptidClient::new(&cfg.aptid)?)
    };

    let work = async {
        match args.command {
            Command::Check => {
                println!("configuration OK: {}", args.config.display());
                Ok(())
            }
            Command::Push => pusher()?.run().await,
            Command::Pull { once: true } => {
                let n = puller()?.step().await?;
                println!("{n} line(s) written");
                Ok(())
            }
            Command::Pull { once: false } => puller()?.run().await,
            Command::Run => {
                let (push, pull) = (pusher()?, puller()?);
                tokio::try_join!(push.run(), pull.run()).map(|_| ())
            }
        }
    };
    let mut term = signal(SignalKind::terminate())?;
    tokio::select! {
        r = work => r,
        _ = tokio::signal::ctrl_c() => Ok(()),
        _ = term.recv() => Ok(()),
    }
}
