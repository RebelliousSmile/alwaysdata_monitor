//! Veilleur multi-sites.
//!
//! Sur le veilleur, toujours appeler le binaire par son chemin complet
//! (`~/vigie/bin/vigie`) : les tâches planifiées n'ont pas le PATH du shell.

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

use vigie::alert::{self, Notifier, SmtpNotifier};
use vigie::capability;
use vigie::clock::{Clock, SystemClock};
use vigie::config::{self, ConfigError, Runtime};
use vigie::device::{self, PAIRING_TTL};
use vigie::finding::Severity;
use vigie::store::{
    AckOutcome, Agent, KeyOutcome, META_TYPOLOGY_SERVE, META_TYPOLOGY_TICK, RevokeOutcome,
    SCHEMA_AGENTS, SCHEMA_DEVICES, SCHEMA_INCIDENTS, SCHEMA_META, Store,
};
use vigie::{human_age, iso_utc, serve, tick};

/// Code de retour d'une configuration invalide ou introuvable.
const EXIT_CONFIG: u8 = 2;

#[derive(Debug, Parser)]
#[command(name = "vigie", version, about = "Veilleur multi-sites")]
struct Cli {
    /// Fichier de configuration (sinon $VIGIE_CONFIG, sinon ~/vigie/config.toml)
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
    /// Appareils de la console : appairage et révocation
    Device {
        #[command(subcommand)]
        action: DeviceAction,
    },
}

#[derive(Debug, Subcommand)]
enum DeviceAction {
    /// Crée un code d'appairage valable 10 min, affiché en QR code et en lien
    Pair {
        /// Nom de l'appareil, repris par `device list`
        #[arg(long)]
        name: String,
    },
    /// Liste les appareils et les codes en attente, sans aucun secret
    List,
    /// Révoque un appareil : son jeton est refusé dès maintenant
    Revoke {
        /// Numéro de l'appareil (dans `device list`)
        id: i64,
    },
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
    /// Prend les empreintes du dernier rapport comme référence : à lancer
    /// après une modification voulue d'un fichier critique
    Accept {
        /// Identifiant du site
        id: String,
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
    // Une seule lecture de l'heure par commande (`clock.rs`).
    let now = SystemClock.unix();
    match cli.command {
        Command::Serve { ip, port } => serve::run(config, path, ip, port),
        Command::Tick => tick::run(&config, now),
        Command::Check { site, once: _ } => check(&config, &site, now),
        Command::Status => status(&config, now),
        Command::Site { action } => site(&config, action, now),
        Command::Ack { id } => ack(&config, id, now),
        Command::Device { action } => device(&config, action, now),
        Command::TestAlert => {
            let notifier = SmtpNotifier::new(config.alerts.clone());
            notifier
                .send(&alert::test_email(now), Duration::from_secs(30))
                .map_err(anyhow::Error::msg)?;
            println!("e-mail de test envoyé à {}", config.alerts.to);
            Ok(())
        }
    }
}

fn check(config: &config::Config, site: &str, now: i64) -> anyhow::Result<()> {
    let report = tick::check_once(config, site, &tick::Options::default(), now)?;
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

fn site(config: &config::Config, action: SiteAction, now: i64) -> anyhow::Result<()> {
    match action {
        SiteAction::List => {
            let agents = read_agents(config)?;
            for site in &config.sites {
                let agent = agents.iter().find(|a| a.site == site.id);
                println!(
                    "{}\t{}\t{}\t{}",
                    site.id,
                    site.url,
                    agent_state(agent, now),
                    site.effective_runtime().map_or("-", Runtime::as_str)
                );
            }
        }
        SiteAction::Add { id, pubkey } => {
            require_site(config, &id)?;
            let key = parse_pubkey(&pubkey)?;
            let mut store = Store::open(&config.database)?;
            match store.add_key(&id, &key, now)? {
                KeyOutcome::Done => {
                    println!("clé de l'agent de {id} enregistrée");
                    let site = config.sites.iter().find(|s| s.id == id);
                    if site.is_some_and(|s| capability::allowed(s).is_empty()) {
                        eprintln!(
                            "attention : {id} n'admet aucune commande (runtime absent ou non admis) ; \
                             poser `runtime = \"php\"` dans config.toml pour un site PHP déclaré generic"
                        );
                    }
                }
                KeyOutcome::AlreadyPresent => {
                    bail!("{id} a déjà une clé : `vigie site rotate-key {id}` pour la remplacer")
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
                    bail!("{id} n'a pas de clé : `vigie site add {id}` pour en enregistrer une")
                }
                KeyOutcome::Unchanged => bail!("{id} : cette clé est déjà la clé actuelle"),
                other => bail!("issue inattendue : {other:?}"),
            }
        }
        SiteAction::Accept { id } => {
            require_site(config, &id)?;
            let mut store = Store::open(&config.database)?;
            if !store.accept_baseline(&id, now)? {
                bail!("{id} n'a encore envoyé aucun rapport : rien à accepter");
            }
            println!(
                "empreintes actuelles de {id} prises comme référence : incidents d'intégrité clos"
            );
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

fn ack(config: &config::Config, id: i64, now: i64) -> anyhow::Result<()> {
    let mut store = Store::open(&config.database)?;
    match store.ack(id, now)? {
        AckOutcome::Acked => println!("incident {id} acquitté : plus de rappel"),
        AckOutcome::AlreadyAcked => println!("incident {id} déjà acquitté"),
        AckOutcome::AlreadyClosed => println!("incident {id} déjà clos"),
        AckOutcome::NotFound => bail!("aucun incident {id}"),
    }
    Ok(())
}

fn device(config: &config::Config, action: DeviceAction, now: i64) -> anyhow::Result<()> {
    match action {
        DeviceAction::Pair { name } => {
            let Some(api) = &config.api else {
                bail!(
                    "aucune section [api] dans la configuration : y ajouter public_url (voir config.example.toml)"
                );
            };
            // Avant toute écriture : aucun code n'est créé pour une adresse refusée.
            device::check_public_url(&api.public_url)?;
            let name = device::check_name(&name)?;
            let code = device::new_code()?;
            let link = device::pair_link(&api.public_url, &code);
            let qr = device::render_qr(&link)?;
            let expires_at = now + PAIRING_TTL;
            let mut store = Store::open(&config.database)?;
            store.create_pairing(&device::hash(&code), name, now, expires_at)?;
            println!("{qr}");
            println!();
            println!("{link}");
            println!();
            println!(
                "appairage de « {name} » : à scanner ou à coller dans la console avant {} ({} min), une seule fois",
                iso_utc(expires_at),
                PAIRING_TTL / 60
            );
        }
        DeviceAction::List => {
            let store = match Store::open_read(&config.database)? {
                Some(store) if store.schema_version()? >= SCHEMA_DEVICES => Some(store),
                _ => None,
            };
            let (devices, pending) = match &store {
                Some(store) => (store.devices()?, store.pending_pairings(now)?),
                None => (Vec::new(), Vec::new()),
            };
            if devices.is_empty() {
                println!("appareils : aucun");
            } else {
                println!("appareils : {}", devices.len());
                for d in &devices {
                    let seen = d.seen_at.map_or("jamais vu".into(), |at| {
                        format!("vu il y a {}", human_age(now - at))
                    });
                    let state = match d.revoked_at {
                        Some(at) => format!("révoqué le {}", iso_utc(at)),
                        None => format!("actif, {seen}"),
                    };
                    println!(
                        "  #{}  {}  {state}  (appairé le {})",
                        d.id,
                        d.name,
                        iso_utc(d.created_at)
                    );
                }
            }
            if !pending.is_empty() {
                println!("en attente d'appairage : {}", pending.len());
                for p in &pending {
                    println!(
                        "  {}  code créé le {}, expire dans {}",
                        p.name,
                        iso_utc(p.created_at),
                        human_age(p.expires_at - now)
                    );
                }
            }
        }
        DeviceAction::Revoke { id } => {
            if !config.database.is_file() {
                bail!("aucun appareil {id} (base absente)");
            }
            let mut store = Store::open(&config.database)?;
            match store.revoke_device(id, now)? {
                RevokeOutcome::Revoked => {
                    println!("appareil {id} révoqué : son jeton est refusé dès maintenant")
                }
                RevokeOutcome::AlreadyRevoked => println!("appareil {id} déjà révoqué"),
                RevokeOutcome::NotFound => bail!("aucun appareil {id}"),
            }
        }
    }
    Ok(())
}

/// Empreinte de la typologie du fichier, de `tick` et de `serve` : `serve` lit
/// la configuration une seule fois, à son démarrage.
fn print_typology(config: &config::Config, store: Option<&Store>) -> anyhow::Result<()> {
    let file = config::typology_fingerprint(config);
    println!("typologie : {}", short(&file));
    let Some(store) = store.filter(|s| s.schema_version().is_ok_and(|v| v >= SCHEMA_META)) else {
        println!(
            "  tick : inconnue ; serve : inconnue (base absente ou antérieure au schéma {SCHEMA_META})"
        );
        return Ok(());
    };
    let read = |key| -> anyhow::Result<Option<(String, i64)>> {
        Ok(store.meta(key)?.and_then(|(value, at)| {
            serde_json::from_str::<config::TypologyRecord>(&value)
                .ok()
                .map(|record| (record.fingerprint, at))
        }))
    };
    for (who, key) in [("tick", META_TYPOLOGY_TICK), ("serve", META_TYPOLOGY_SERVE)] {
        match read(key)? {
            Some((fingerprint, at)) => println!(
                "  {who} : {}{} (notée le {})",
                short(&fingerprint),
                if fingerprint == file {
                    ""
                } else {
                    ", différente du fichier"
                },
                iso_utc(at)
            ),
            None => println!("  {who} : aucune"),
        }
    }
    if read(META_TYPOLOGY_SERVE)?.is_none_or(|(fingerprint, _)| fingerprint != file) {
        println!("  serve à redémarrer : sa typologie n'est pas celle du fichier");
    }
    Ok(())
}

fn short(fingerprint: &str) -> &str {
    &fingerprint[..fingerprint.len().min(12)]
}

fn status(config: &config::Config, now: i64) -> anyhow::Result<()> {
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
    print_typology(config, store.as_ref())?;
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
