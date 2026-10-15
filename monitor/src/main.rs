//! Veilleur multi-sites.
//!
//! Sur le veilleur, toujours appeler le binaire par son chemin complet
//! (`~/monitor/bin/monitor`) : les tâches planifiées n'ont pas le PATH du shell.

use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::bail;
use clap::{Parser, Subcommand};

use monitor::alert::{self, Notifier, SmtpNotifier};
use monitor::config::{self, ConfigError};
use monitor::finding::Severity;
use monitor::store::{AckOutcome, SCHEMA_INCIDENTS, Store};
use monitor::{human_age, iso_utc, now, serve, tick};

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
    /// Lance tous les contrôles d'un site et affiche les constats, sans rien
    /// écrire ni envoyer
    Check {
        /// Identifiant du site
        site: String,
        /// Obligatoire : rappelle que rien n'est enregistré
        #[arg(long, required = true)]
        once: bool,
    },
    /// État du veilleur : sites, incidents ouverts, dernier passage
    Status,
    /// Sites surveillés
    Site {
        #[command(subcommand)]
        action: SiteAction,
    },
    /// Acquitte un incident : plus de rappel, clôture automatique conservée
    Ack {
        /// Numéro de l'incident (dans l'e-mail ou dans `status`)
        id: i64,
    },
    /// Envoie un e-mail de test par le relais SMTP configuré
    TestAlert,
}

#[derive(Debug, Subcommand)]
enum SiteAction {
    /// Liste les sites de la configuration
    List,
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
        Command::Check { site, once: _ } => check(&config, &site),
        Command::Status => status(&config),
        Command::Site {
            action: SiteAction::List,
        } => {
            for site in &config.sites {
                println!("{}\t{}", site.id, site.url);
            }
            Ok(())
        }
        Command::Ack { id } => ack(&config, id),
        Command::TestAlert => {
            let notifier = SmtpNotifier::new(config.alerts.clone());
            notifier
                .send(&alert::test_email(now()), Duration::from_secs(30))
                .map_err(anyhow::Error::msg)?;
            println!("e-mail de test envoyé à {}", config.alerts.to);
            Ok(())
        }
    }
}

fn check(config: &config::Config, site: &str) -> anyhow::Result<()> {
    let report = tick::check_once(config, site, &tick::Options::default())?;
    let mut alarming = 0;
    for (kind, result) in report {
        match result {
            Ok(findings) if findings.is_empty() => println!("{:<10} ok", kind.name()),
            Ok(findings) => {
                for f in findings {
                    if f.severity > Severity::Info {
                        alarming += 1;
                    }
                    println!(
                        "{:<10} {} [{}] {}",
                        kind.name(),
                        f.severity,
                        f.key,
                        f.detail
                    );
                }
            }
            Err(err) => println!("{:<10} non concluant : {err}", kind.name()),
        }
    }
    if alarming > 0 {
        bail!("{alarming} constat(s) à traiter");
    }
    Ok(())
}

fn ack(config: &config::Config, id: i64) -> anyhow::Result<()> {
    let mut store = Store::open(&config.database)?;
    match store.ack(id, now())? {
        AckOutcome::Acked => println!("incident {id} acquitté : plus de rappel"),
        AckOutcome::AlreadyAcked => println!("incident {id} déjà acquitté"),
        AckOutcome::AlreadyClosed => println!("incident {id} déjà clos"),
        AckOutcome::NotFound => bail!("aucun incident {id}"),
    }
    Ok(())
}

fn status(config: &config::Config) -> anyhow::Result<()> {
    let now = now();
    // Lecteur : `status` ne crée pas la base et ne la migre pas.
    let store = Store::open_read(&config.database)?;
    let last_tick = match &store {
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
    let (code, health) = serve::health(last_tick, now);
    match (health.last_tick, health.age_seconds) {
        (Some(at), Some(age)) => println!(
            "dernier tick : {} (il y a {}) → {}",
            iso_utc(at),
            human_age(age),
            health.status
        ),
        _ => println!("dernier tick : aucun → {}", health.status),
    }
    // Pendant un déploiement, la base peut précéder les incidents.
    let store = store.filter(|s| s.schema_version().is_ok_and(|v| v >= SCHEMA_INCIDENTS));
    let runs = match &store {
        Some(store) => store.check_runs()?,
        None => Vec::new(),
    };
    println!("sites : {}", config.sites.len());
    for site in &config.sites {
        let last = runs
            .iter()
            .filter(|(s, _, _)| *s == site.id)
            .map(|(_, _, at)| *at)
            .max();
        let last = last.map_or("jamais contrôlé".into(), |at| {
            format!("contrôlé il y a {}", human_age(now - at))
        });
        println!("  {}  {}  {last}", site.id, site.url);
    }
    if let Some(store) = &store {
        let open = store.open_incidents()?;
        let (info, alarming): (Vec<_>, Vec<_>) =
            open.iter().partition(|i| i.severity == Severity::Info);
        if alarming.is_empty() {
            println!("incidents ouverts : aucun");
        } else {
            println!("incidents ouverts : {}", alarming.len());
            for i in alarming {
                let acked = if i.acked_at.is_some() {
                    ", acquitté"
                } else {
                    ""
                };
                println!(
                    "  #{} {} {} {} : {} (depuis {}{acked})",
                    i.id,
                    i.site,
                    i.check_name,
                    i.severity,
                    i.detail,
                    human_age(now - i.opened_at)
                );
            }
        }
        if !info.is_empty() {
            println!("en-têtes manquants :");
            for i in info {
                println!("  {} : {}", i.site, i.detail);
            }
        }
        println!(
            "notifications en attente : {}",
            store.pending_notifications(now)?
        );
    }
    if code.is_success() {
        Ok(())
    } else {
        bail!("tick en retard ou absent")
    }
}
