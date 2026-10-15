//! Veilleur multi-sites.
//!
//! Sur le veilleur, toujours appeler le binaire par son chemin complet
//! (`~/monitor/bin/monitor`) : les tâches planifiées n'ont pas le PATH du shell.

mod config;
mod serve;
mod store;
mod tick;

use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::config::ConfigError;

/// Code de retour d'une configuration invalide ou introuvable.
const EXIT_CONFIG: u8 = 2;

#[derive(Debug, Parser)]
#[command(name = "monitor", version, about = "Veilleur multi-sites")]
struct Cli {
    /// Fichier de configuration (sinon $MONITOR_CONFIG, sinon ~/monitor/config.toml)
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Point d'entrée HTTP (service systemd derrière Caddy)
    Serve {
        /// Adresse d'écoute, fournie par l'unité systemd dans $IP
        #[arg(long, env = "IP")]
        ip: IpAddr,
        /// Port d'écoute, fourni par l'unité systemd dans $PORT
        #[arg(long, env = "PORT")]
        port: u16,
    },
    /// Passage lancé par le timer systemd (chaque minute)
    Tick,
    /// État du veilleur
    Status,
    /// Sites surveillés
    Site {
        #[command(subcommand)]
        action: SiteAction,
    },
    /// Acquitte un incident
    Ack {
        /// Identifiant de l'incident
        id: String,
    },
}

#[derive(Debug, Subcommand)]
enum SiteAction {
    /// Liste les sites de la configuration
    List,
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("erreur : {err:#}");
            if err.downcast_ref::<ConfigError>().is_some() {
                ExitCode::from(EXIT_CONFIG)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let path = config::resolve_path(cli.config)?;
    let config = config::load(&path)?;
    match cli.command {
        Command::Serve { ip, port } => serve::run(config.database, ip, port),
        Command::Tick => tick::run(&config, now()),
        Command::Status => status(&config),
        Command::Site {
            action: SiteAction::List,
        } => {
            for site in &config.sites {
                println!("{}\t{}", site.id, site.url);
            }
            Ok(())
        }
        Command::Ack { id } => {
            if !config::is_valid_id(&id) {
                anyhow::bail!("identifiant d'incident invalide : {id}");
            }
            anyhow::bail!(
                "aucun incident « {id} » : les incidents arrivent avec les contrôles (phase 2)"
            )
        }
    }
}

fn status(config: &config::Config) -> anyhow::Result<()> {
    // Lecteur : `status` ne crée pas la base et ne la migre pas.
    let last_tick = match store::Store::open_read(&config.database)? {
        Some(store) => {
            println!(
                "base : {} (schéma v{})",
                config.database.display(),
                store.schema_version()?
            );
            store.last_tick()?
        }
        None => {
            println!("base : {} (absente)", config.database.display());
            None
        }
    };
    let (code, health) = serve::health(last_tick, now());
    match (health.last_tick, health.age_seconds) {
        (Some(at), Some(age)) => {
            println!("dernier tick : {at} (il y a {age} s) → {}", health.status)
        }
        _ => println!("dernier tick : aucun → {}", health.status),
    }
    println!("sites : {}", config.sites.len());
    if code.is_success() {
        Ok(())
    } else {
        anyhow::bail!("tick en retard ou absent")
    }
}
