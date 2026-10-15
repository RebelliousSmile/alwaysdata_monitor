//! Veilleur multi-sites.
//!
//! Sur le veilleur, toujours appeler le binaire par son chemin complet
//! (`~/monitor/bin/monitor`) : les tâches planifiées n'ont pas le PATH du shell.

use std::io::BufRead;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use clap::{Parser, Subcommand};
use ed25519_dalek::VerifyingKey;

use monitor::alert::{self, Notifier, SmtpNotifier};
use monitor::config::{self, ConfigError};
use monitor::finding::Severity;
use monitor::store::{AckOutcome, Agent, KeyOutcome, SCHEMA_AGENTS, SCHEMA_INCIDENTS, Store};
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
    /// Sites surveillés et clés de leurs agents
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
    /// Liste les sites de la configuration et l'état de leur agent
    List,
    /// Enregistre la clé publique de l'agent d'un site de la configuration
    Add {
        /// Identifiant du site
        id: String,
        /// Clé publique Ed25519 de l'agent, 32 octets en base64
        #[arg(long)]
        pubkey: String,
    },
    /// Remplace la clé de l'agent : l'ancienne ne fait plus rien accepter
    RotateKey {
        /// Identifiant du site
        id: String,
        /// Nouvelle clé publique Ed25519, 32 octets en base64
        #[arg(long)]
        pubkey: String,
    },
    /// Retire la clé de l'agent et l'état de ses rapports
    Remove {
        /// Identifiant du site
        id: String,
        /// Sans confirmation (sinon, retaper l'identifiant)
        #[arg(long)]
        yes: bool,
    },
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
        Command::Serve { ip, port } => {
            let sites = config.sites.iter().map(|s| s.id.clone()).collect();
            serve::run(config.database, sites, ip, port)
        }
        Command::Tick => tick::run(&config, now()),
        Command::Check { site, once: _ } => check(&config, &site),
        Command::Status => status(&config),
        Command::Site { action } => site(&config, action),
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

/// Clé publique Ed25519 en base64 : 32 octets, point valide de la courbe.
fn parse_pubkey(encoded: &str) -> anyhow::Result<[u8; 32]> {
    let raw = STANDARD
        .decode(encoded.trim())
        .context("clé publique : base64 illisible")?;
    let Ok(key) = <[u8; 32]>::try_from(raw.as_slice()) else {
        bail!(
            "clé publique : {} octet(s) au lieu de 32 (clé Ed25519 brute)",
            raw.len()
        );
    };
    VerifyingKey::from_bytes(&key).context("clé publique : point Ed25519 invalide")?;
    Ok(key)
}

fn require_site(config: &config::Config, id: &str) -> anyhow::Result<()> {
    if !config.sites.iter().any(|s| s.id == id) {
        bail!("aucun site « {id} » dans la configuration : l'y ajouter d'abord");
    }
    Ok(())
}

/// Agents enregistrés, ou aucun si la base est absente ou précède les agents.
fn read_agents(config: &config::Config) -> anyhow::Result<Vec<Agent>> {
    match Store::open_read(&config.database)? {
        Some(store) if store.schema_version()? >= SCHEMA_AGENTS => store.agents(),
        _ => Ok(Vec::new()),
    }
}

/// État de l'agent d'un site, pour `site list` et `status`.
fn agent_state(agent: Option<&Agent>, now: i64) -> String {
    let Some(agent) = agent else {
        return "sans agent".into();
    };
    let name = agent.agent.as_deref().unwrap_or("agent");
    match agent.last_valid_at {
        Some(at) => format!(
            "{name}, dernier rapport il y a {} (seq {})",
            human_age(now - at),
            agent.last_seq
        ),
        None => format!(
            "clé enregistrée il y a {}, aucun rapport",
            human_age(now - agent.rotated_at.unwrap_or(agent.added_at))
        ),
    }
}

fn site(config: &config::Config, action: SiteAction) -> anyhow::Result<()> {
    let now = now();
    match action {
        SiteAction::List => {
            let agents = read_agents(config)?;
            for site in &config.sites {
                let agent = agents.iter().find(|a| a.site == site.id);
                println!("{}\t{}\t{}", site.id, site.url, agent_state(agent, now));
            }
        }
        SiteAction::Add { id, pubkey } => {
            require_site(config, &id)?;
            let key = parse_pubkey(&pubkey)?;
            let mut store = Store::open(&config.database)?;
            match store.add_key(&id, &key, now)? {
                KeyOutcome::Done => println!("clé de l'agent de {id} enregistrée"),
                KeyOutcome::AlreadyPresent => {
                    bail!("{id} a déjà une clé : `monitor site rotate-key {id}` pour la remplacer")
                }
                other => bail!("issue inattendue : {other:?}"),
            }
        }
        SiteAction::RotateKey { id, pubkey } => {
            require_site(config, &id)?;
            let key = parse_pubkey(&pubkey)?;
            let mut store = Store::open(&config.database)?;
            match store.rotate_key(&id, &key, now)? {
                KeyOutcome::Done => {
                    println!("clé de l'agent de {id} remplacée : l'ancienne est refusée")
                }
                KeyOutcome::Missing => {
                    bail!("{id} n'a pas de clé : `monitor site add {id}` pour en enregistrer une")
                }
                KeyOutcome::Unchanged => bail!("{id} : cette clé est déjà la clé actuelle"),
                other => bail!("issue inattendue : {other:?}"),
            }
        }
        SiteAction::Remove { id, yes } => {
            if !config.database.is_file() {
                bail!("{id} n'a pas de clé (base absente)");
            }
            if !yes {
                eprint!("retirer la clé de l'agent de {id} ? retaper « {id} » pour confirmer : ");
                let mut line = String::new();
                std::io::stdin()
                    .lock()
                    .read_line(&mut line)
                    .context("lecture de la confirmation")?;
                if line.trim() != id {
                    bail!("confirmation différente : rien n'est retiré");
                }
            }
            let mut store = Store::open(&config.database)?;
            if !store.remove_key(&id)? {
                bail!("{id} n'a pas de clé");
            }
            println!("clé de l'agent de {id} retirée : ses incidents seront clos au prochain tick");
        }
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
    let agents = match &store {
        Some(store) if store.schema_version()? >= SCHEMA_AGENTS => store.agents()?,
        _ => Vec::new(),
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
        let agent = agents.iter().find(|a| a.site == site.id);
        println!("    agent : {}", agent_state(agent, now));
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
            println!("informations :");
            for i in info {
                println!("  {} {} : {}", i.site, i.check_name, i.detail);
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
