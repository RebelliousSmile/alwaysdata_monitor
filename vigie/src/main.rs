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
use vigie::command;
use vigie::config::{self, ConfigError, Runtime};
use vigie::device::{self, PAIRING_TTL};
use vigie::finding::Severity;
use vigie::store::{
    AckOutcome, Agent, KeyOutcome, META_TYPOLOGY_SERVE, META_TYPOLOGY_TICK, RevokeOutcome,
    SCHEMA_AGENT_SOURCES, SCHEMA_AGENTS, SCHEMA_COMMANDS, SCHEMA_DEVICES, SCHEMA_FINDINGS,
    SCHEMA_INCIDENTS, SCHEMA_META, Store,
};
use vigie::vulns::{self, store as vulns_store};
use vigie::{human_age, iso_utc, recommend, serve, tick};

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
    /// Clés du canal de commandes (docs/protocole-commandes.md)
    Commands {
        #[command(subcommand)]
        action: CommandsAction,
    },
    /// Failles connues : synchronisation des bases (timer systemd), sources,
    /// détail d'une faille, rapprochement d'un composant (docs/failles.md)
    Vulns {
        #[command(subcommand)]
        action: VulnsAction,
    },
}

#[derive(Debug, Subcommand)]
enum VulnsAction {
    /// Synchronise les bases de [vulns] sources (lancé chaque jour par
    /// vigie-vulns-sync.timer) ; code 1 si une source a échoué
    Sync {
        /// Une seule source de [vulns] sources
        #[arg(long)]
        source: Option<String>,
        /// Accepte une fois un dump qui rétrécit de plus de 20 % (exige
        /// --source) ; il devient la nouvelle référence
        #[arg(long, requires = "source")]
        accept_shrink: bool,
    },
    /// Sources de failles : licence, âge, entrées, écarts par raison, état
    /// de synchronisation
    Sources,
    /// Détail d'une faille, par identifiant ou alias (CVE-…)
    Show {
        /// Identifiant (GHSA-…, RUSTSEC-…) ou alias
        id: String,
    },
    /// Failles d'un composant : pkg:type/namespace/nom@version
    Match {
        /// purl, version comprise ; sans version, chaque faille du paquet est
        /// en « version inconnue »
        purl: String,
    },
}

#[derive(Debug, Subcommand)]
enum CommandsAction {
    /// Crée la clé de commandes et la clé d'audit de [commands] (jamais
    /// écrasées) et affiche la clé publique à épingler par les agents
    InitKeys,
    /// Affiche la clé publique de commandes, à épingler par les agents
    Pubkey,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum Switch {
    Enable,
    Disable,
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
    /// Active ou coupe le canal de commandes d'un site (coupé par défaut ;
    /// couper annule la commande en vol)
    Commands {
        /// Identifiant du site
        id: String,
        switch: Switch,
    },
    /// Prépare une commande : aperçu sans rien écrire, puis --apply pour la
    /// mettre en file
    Command {
        /// Identifiant du site
        id: String,
        /// ping, rotate-key ou htaccess-rollback (htaccess-apply passe par
        /// `site recommend`)
        name: String,
        /// Met la commande en file
        #[arg(long)]
        apply: bool,
        /// Rejoue une commande non idempotente dont la précédente a une issue
        /// inconnue
        #[arg(long)]
        force: bool,
    },
    /// Propositions tirées de la dernière analyse de logs : robots.txt à
    /// poser à la main, bloc `# BEGIN vigie` du .htaccess ; aperçu sans rien
    /// écrire, puis --apply (calcul par l'agent, puis application)
    Recommend {
        /// Identifiant du site
        id: String,
        /// Met en file htaccess-apply : d'abord le calcul de l'empreinte par
        /// l'agent, puis, relancé après son résultat, l'application
        #[arg(long)]
        apply: bool,
        /// Remplace un bloc dont les règles en place sont inconnues
        #[arg(long)]
        replace: bool,
        /// Ignore un calcul déjà préparé et en demande un nouveau
        #[arg(long)]
        recompute: bool,
        /// Rejoue une commande dont la précédente a une issue inconnue
        #[arg(long)]
        force: bool,
    },
    /// Annule la commande en vol d'un site
    CommandCancel {
        /// Identifiant du site
        id: String,
    },
    /// Journal d'audit des commandes d'un site, en JSONL
    Audit {
        /// Identifiant du site
        id: String,
        /// Vérifie la chaîne et les signatures (code 1 sinon) au lieu d'exporter
        #[arg(long)]
        verify: bool,
        /// Tête attendue (reçue par e-mail) : détecte une chaîne tronquée
        #[arg(long, requires = "verify")]
        head: Option<String>,
    },
    /// Clé d'inventaire du site (vigie-inventory en CI, issue #20) : ne
    /// vérifie que /r/v1/inventory ; exige `ci` dans [sites.inventory]
    InventoryKey {
        /// Identifiant du site
        id: String,
        #[command(subcommand)]
        action: InventoryKeyAction,
    },
    /// Retire les clés du site (agent et inventaire), l'état de ses rapports
    /// et tout ce qu'il a envoyé
    Remove {
        /// Identifiant du site
        id: String,
        /// Sans confirmation (sinon, retaper l'identifiant)
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
enum InventoryKeyAction {
    /// Enregistre la clé publique d'inventaire (sortie de `vigie-inventory keygen`)
    Add {
        /// Clé publique Ed25519, 32 octets en base64
        #[arg(long)]
        pubkey: String,
    },
    /// Remplace la clé d'inventaire : l'ancienne est refusée, l'inventaire reste
    Rotate {
        /// Nouvelle clé publique Ed25519, 32 octets en base64
        #[arg(long)]
        pubkey: String,
    },
    /// Retire la clé d'inventaire ; l'inventaire reçu reste
    Remove {
        /// Sans confirmation (sinon, retaper l'identifiant)
        #[arg(long)]
        yes: bool,
    },
}

/// Refus d'une écriture de clé (site sans `ci`, clé déjà enregistrée) :
/// rendu avec le code 2, comme une erreur de configuration.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct KeyRefused(String);

/// Une clé publique ne sert qu'une fois, toutes tables et tous sites
/// confondus : le message ne dit ni quel site ni quel usage.
fn in_use() -> anyhow::Error {
    KeyRefused(
        "clé déjà enregistrée (agent ou inventaire d'un site) : une clé ne sert qu'un usage, \
         en générer une autre"
            .into(),
    )
    .into()
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("erreur : {err:#}");
            if err.downcast_ref::<ConfigError>().is_some()
                || err.downcast_ref::<vulns::UsageError>().is_some()
                || err.downcast_ref::<KeyRefused>().is_some()
            {
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
        Command::Commands { action } => commands_keys(&config, action),
        Command::Vulns { action } => vulns_cli(&config, action, now),
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

/// Une clé d'agent n'est enregistrée que pour un site au runtime effectif
/// `php` : ailleurs, le registre ne surveillerait rien de l'agent.
fn require_php_site(config: &config::Config, id: &str) -> anyhow::Result<()> {
    require_site(config, id)?;
    let site = config.sites.iter().find(|s| s.id == id);
    if site.and_then(config::Site::effective_runtime) != Some(Runtime::Php) {
        bail!(
            "{id} n'a pas de runtime php : l'agent PHP n'y serait pas surveillé ; \
             déclarer `runtime = \"php\"` dans config.toml (implicite pour wordpress et prestashop), \
             puis relancer serve"
        );
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

/// État de l'agent d'un site, pour `site list` et `status`, avec le
/// verdict du registre des capacités : une clé sur un site sans runtime
/// `php` n'ouvre aucun contrôle d'agent.
fn agent_state(site: &config::Site, agent: Option<&Agent>, now: i64) -> String {
    let Some(agent) = agent else {
        return "sans agent".into();
    };
    let ctx = capability::Ctx {
        agent: true,
        baseline: false,
    };
    let state = agent_activity(agent, now);
    if capability::Control::Heartbeat.watched(site, &ctx) {
        state
    } else {
        format!("{state} ; non surveillé : runtime php absent")
    }
}

fn agent_activity(agent: &Agent, now: i64) -> String {
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
            let keys = match Store::open_read(&config.database)? {
                Some(store) => store.sites_with_keys()?,
                None => Vec::new(),
            };
            for site in &config.sites {
                let agent = agents.iter().find(|a| a.site == site.id);
                let keys = keys.iter().find(|k| k.site == site.id);
                println!(
                    "{}\t{}\t{}\tinventaire : {}\t{}",
                    site.id,
                    site.url,
                    agent_state(site, agent, now),
                    inventory_state(site, keys),
                    site.effective_runtime().map_or("-", Runtime::as_str)
                );
            }
        }
        SiteAction::Add { id, pubkey } => {
            require_php_site(config, &id)?;
            let key = parse_pubkey(&pubkey)?;
            let mut store = Store::open(&config.database)?;
            match store.add_key(&id, &key, now)? {
                KeyOutcome::Done => println!("clé de l'agent de {id} enregistrée"),
                KeyOutcome::AlreadyPresent => {
                    bail!("{id} a déjà une clé : `vigie site rotate-key {id}` pour la remplacer")
                }
                KeyOutcome::InUse { .. } => return Err(in_use()),
                other => bail!("issue inattendue : {other:?}"),
            }
        }
        SiteAction::RotateKey { id, pubkey } => {
            require_php_site(config, &id)?;
            let key = parse_pubkey(&pubkey)?;
            let mut store = Store::open(&config.database)?;
            store.reset_commands(&id, now, audit_key(config)?.as_ref(), "site rotate-key")?;
            match store.rotate_key(&id, &key, now)? {
                KeyOutcome::Done => {
                    println!("clé de l'agent de {id} remplacée : l'ancienne est refusée")
                }
                KeyOutcome::Missing => {
                    bail!("{id} n'a pas de clé : `vigie site add {id}` pour en enregistrer une")
                }
                KeyOutcome::Unchanged => bail!("{id} : cette clé est déjà la clé actuelle"),
                KeyOutcome::InUse { .. } => return Err(in_use()),
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
        SiteAction::Commands { id, switch } => {
            require_site(config, &id)?;
            let key = audit_key(config)?.context("[commands] absent de la configuration")?;
            let mut store = Store::open(&config.database)?;
            let enable = matches!(switch, Switch::Enable);
            let cancelled = store.set_commands_enabled(&id, enable, now, &key)?;
            println!(
                "canal de commandes de {id} {}",
                if enable { "activé" } else { "coupé" }
            );
            for c in cancelled {
                println!("commande {c} annulée");
            }
        }
        SiteAction::Command {
            id,
            name,
            apply,
            force,
        } => command(config, &id, &name, apply, force, now)?,
        SiteAction::Recommend {
            id,
            apply,
            replace,
            recompute,
            force,
        } => recommend(
            config,
            &id,
            RecommendFlags {
                apply,
                replace,
                recompute,
                force,
            },
            now,
        )?,
        SiteAction::CommandCancel { id } => {
            require_site(config, &id)?;
            let key = audit_key(config)?.context("[commands] absent de la configuration")?;
            let cancelled = Store::open(&config.database)?.cancel_command(&id, now, &key)?;
            if cancelled.is_empty() {
                bail!("{id} n'a aucune commande en vol");
            }
            for c in cancelled {
                println!("commande {c} annulée");
            }
        }
        SiteAction::Audit { id, verify, head } => audit(config, &id, verify, head.as_deref())?,
        SiteAction::InventoryKey { id, action } => inventory_key(config, &id, action, now)?,
        SiteAction::Remove { id, yes } => {
            if !config.database.is_file() {
                bail!("{id} n'a pas de clé (base absente)");
            }
            if !yes {
                confirm(
                    &format!(
                        "retirer les clés et inventaires de {id} ? retaper « {id} » pour confirmer : "
                    ),
                    &id,
                )?;
            }
            let mut store = Store::open(&config.database)?;
            store.reset_commands(&id, now, audit_key(config)?.as_ref(), "site remove")?;
            if !store.remove_key(&id)? {
                bail!("{id} n'a pas de clé");
            }
            println!(
                "clés et inventaires de {id} retirés : ses incidents seront clos au prochain tick"
            );
        }
    }
    Ok(())
}

/// Confirmation par l'identifiant retapé ; sinon rien n'est retiré.
fn confirm(prompt: &str, id: &str) -> anyhow::Result<()> {
    eprint!("{prompt}");
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("lecture de la confirmation")?;
    if line.trim() != id {
        bail!("confirmation différente : rien n'est retiré");
    }
    Ok(())
}

/// Sources d'inventaire du site dont la clé est enregistrée, pour `site
/// list` : `agent`, `ci`, `agent+ci` ou `—`.
fn inventory_state(site: &config::Site, keys: Option<&vigie::store::SiteKeys>) -> String {
    let ready: Vec<&str> = capability::inventory_sources(site)
        .into_iter()
        .filter(|source| match source {
            config::InventorySource::AgentPhp => keys.is_some_and(|k| k.agent),
            config::InventorySource::Ci => keys.is_some_and(|k| k.inventory),
        })
        .map(|source| vigie::inventory::Source::from(source).as_str())
        .collect();
    if ready.is_empty() {
        "—".into()
    } else {
        ready.join("+")
    }
}

/// `site inventory-key` : clé d'inventaire d'un site qui déclare `ci`.
fn inventory_key(
    config: &config::Config,
    id: &str,
    action: InventoryKeyAction,
    now: i64,
) -> anyhow::Result<()> {
    let Some(site) = config.sites.iter().find(|s| s.id == id) else {
        return Err(KeyRefused(format!(
            "aucun site « {id} » dans la configuration : l'y ajouter d'abord"
        ))
        .into());
    };
    let ci = capability::inventory_sources(site).contains(&config::InventorySource::Ci);
    let writes = matches!(
        action,
        InventoryKeyAction::Add { .. } | InventoryKeyAction::Rotate { .. }
    );
    if writes && !ci {
        return Err(KeyRefused(format!(
            "{id} ne déclare pas la source ci : ajouter `sources = [\"ci\"]` à \
             [sites.inventory] dans config.toml, puis relancer serve"
        ))
        .into());
    }
    match action {
        InventoryKeyAction::Add { pubkey } => {
            let key = parse_pubkey(&pubkey)?;
            let mut store = Store::open(&config.database)?;
            match store.add_inventory_key(id, &key, now)? {
                KeyOutcome::Done => {
                    println!("clé d'inventaire de {id} enregistrée");
                    Ok(())
                }
                KeyOutcome::AlreadyPresent => bail!(
                    "{id} a déjà une clé d'inventaire : `vigie site inventory-key {id} rotate` pour la remplacer"
                ),
                KeyOutcome::InUse { .. } => Err(in_use()),
                other => bail!("issue inattendue : {other:?}"),
            }
        }
        InventoryKeyAction::Rotate { pubkey } => {
            let key = parse_pubkey(&pubkey)?;
            let mut store = Store::open(&config.database)?;
            match store.rotate_inventory_key(id, &key, now)? {
                KeyOutcome::Done => {
                    println!(
                        "clé d'inventaire de {id} remplacée : l'ancienne est refusée, l'inventaire reste"
                    );
                    Ok(())
                }
                KeyOutcome::Missing => bail!(
                    "{id} n'a pas de clé d'inventaire : `vigie site inventory-key {id} add` pour en enregistrer une"
                ),
                KeyOutcome::Unchanged => {
                    bail!("{id} : cette clé est déjà la clé d'inventaire actuelle")
                }
                KeyOutcome::InUse { .. } => Err(in_use()),
                other => bail!("issue inattendue : {other:?}"),
            }
        }
        InventoryKeyAction::Remove { yes } => {
            if !config.database.is_file() {
                bail!("{id} n'a pas de clé d'inventaire (base absente)");
            }
            if !yes {
                confirm(
                    &format!(
                        "retirer la clé d'inventaire de {id} ? retaper « {id} » pour confirmer : "
                    ),
                    id,
                )?;
            }
            if !Store::open(&config.database)?.remove_inventory_key(id)? {
                bail!("{id} n'a pas de clé d'inventaire");
            }
            println!("clé d'inventaire de {id} retirée : l'inventaire reçu reste");
            Ok(())
        }
    }
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
    let drops = match &store {
        Some(store) => store.report_drops()?,
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
        let agent = agents.iter().find(|a| a.site == site.id);
        println!("    agent : {}", agent_state(site, agent, now));
        if let Some((_, dropped)) = drops.iter().find(|(s, _)| *s == site.id) {
            println!(
                "    constats écartés au dernier rapport : {dropped} (famille hors du registre des capacités ou non admise pour le site)"
            );
        }
    }
    print_vulns_status(config, store.as_ref(), now)?;
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

/// Une ligne par source de `[vulns] sources` : dernière réussite, dernière
/// issue, bail en cours. Rien sans `[vulns]`.
fn print_vulns_status(
    config: &config::Config,
    store: Option<&Store>,
    now: i64,
) -> anyhow::Result<()> {
    let declared = vulns::sync::registry::declared(config);
    if declared.is_empty() {
        return Ok(());
    }
    let states = match store {
        Some(store) if vulns_store::sync_available(store)? => vulns_store::sync_states(store)?,
        _ => {
            println!("failles : aucune base de failles");
            return Ok(());
        }
    };
    for id in declared {
        let state = states.iter().find(|(s, _)| s == id).map(|(_, st)| st);
        let mut line = match state.and_then(|s| s.last_success_at) {
            Some(t) => format!("failles : {id} réussie il y a {}", human_age(now - t)),
            None => format!("failles : {id} jamais synchronisée"),
        };
        let mut notes = Vec::new();
        if let Some(outcome) = state.and_then(|s| s.last_outcome) {
            notes.push(format!("dernière issue : {}", outcome.as_str()));
        }
        if let Some(since) = state.and_then(|s| s.loading_since) {
            notes.push(format!("bail en cours depuis {}", human_age(now - since)));
        }
        if !notes.is_empty() {
            line.push_str(&format!(" ({})", notes.join(" ; ")));
        }
        println!("{line}");
    }
    Ok(())
}

/// Clé d'audit de `[commands]`, si le canal est configuré.
fn audit_key(config: &config::Config) -> anyhow::Result<Option<ed25519_dalek::SigningKey>> {
    match &config.commands {
        Some(commands) => Ok(Some(
            command::key::load(&commands.audit_key_file).context("clé d'audit")?,
        )),
        None => Ok(None),
    }
}

fn commands_keys(config: &config::Config, action: CommandsAction) -> anyhow::Result<()> {
    let commands = config
        .commands
        .as_ref()
        .context("[commands] absent de la configuration : key_file et audit_key_file")?;
    let public = match action {
        CommandsAction::InitKeys => {
            let public = command::key::create(&commands.key_file).context("clé de commandes")?;
            command::key::create(&commands.audit_key_file).context("clé d'audit")?;
            println!(
                "clés créées : {} et {}",
                commands.key_file.display(),
                commands.audit_key_file.display()
            );
            public
        }
        CommandsAction::Pubkey => command::key::load(&commands.key_file)
            .context("clé de commandes")?
            .verifying_key(),
    };
    println!(
        "clé publique de commandes (à épingler par chaque agent) :\n{}",
        STANDARD.encode(public.to_bytes())
    );
    Ok(())
}

/// Aperçu d'une commande, puis mise en file avec --apply.
fn command(
    config: &config::Config,
    id: &str,
    name: &str,
    apply: bool,
    force: bool,
    now: i64,
) -> anyhow::Result<()> {
    let site = config
        .sites
        .iter()
        .find(|s| s.id == id)
        .with_context(|| format!("aucun site « {id} » dans la configuration"))?;
    let kind = capability::CommandKind::from_name(name).with_context(|| {
        format!(
            "commande inconnue « {} » : {}",
            command::neutralize(name),
            capability::CommandKind::ALL.map(|k| k.name()).join(", ")
        )
    })?;
    if let Err(refusal) = capability::permit(kind, site) {
        bail!("{id} : {kind} refusée : {refusal}");
    }
    let params = match kind {
        capability::CommandKind::HtaccessApply => bail!(
            "{id} : htaccess-apply se prépare par `vigie site recommend {id}`, qui construit et valide le bloc"
        ),
        capability::CommandKind::HtaccessRollback => rollback_params(config, id)?,
        _ => command::params_json(kind).context("paramètres indisponibles")?,
    };
    let effect = match kind {
        capability::CommandKind::Ping => "aucun ; prouve que le canal fonctionne",
        capability::CommandKind::RotateKey => {
            "l'agent crée une nouvelle paire de clés de rapport et la prouve ; ce n'est pas un remède à une compromission"
        }
        capability::CommandKind::HtaccessRollback => {
            "l'agent remet sa copie privée du .htaccess d'avant la dernière application, si le fichier n'a pas changé depuis, puis contrôle l'accueil"
        }
        capability::CommandKind::HtaccessApply => "remplace le bloc # BEGIN vigie",
    };
    enqueue(config, site, kind, &params, effect, apply, force, now)
}

/// Aperçu d'une commande aux paramètres validés, puis mise en file avec
/// --apply.
#[allow(clippy::too_many_arguments)]
fn enqueue(
    config: &config::Config,
    site: &config::Site,
    kind: capability::CommandKind,
    params: &str,
    effect: &str,
    apply: bool,
    force: bool,
    now: i64,
) -> anyhow::Result<()> {
    let id = site.id.as_str();
    let runtime = site.effective_runtime().context("runtime absent")?;
    let typology = config::typology_fingerprint(config);
    println!("site : {id} ({})", site.url);
    println!("runtime : {}", runtime.as_str());
    println!("commande : {kind}");
    println!("paramètres : {params}");
    println!("effet : {effect}");
    println!("typologie : {}", &typology[..12]);
    if !apply {
        println!("aperçu seulement : rien n'est écrit ; relancer avec --apply");
        return Ok(());
    }
    let key = audit_key(config)?.context("[commands] absent de la configuration")?;
    let command_id = command::uuid_v7(SystemClock.unix_ms())?;
    let mut store = Store::open(&config.database)?;
    match store.enqueue_command(
        id,
        kind,
        runtime,
        params,
        &typology,
        &command_id,
        now,
        force,
        &key,
    )? {
        Ok(queued) => println!(
            "commande {} en file (seq {}), servie au prochain retrait de l'agent, expire le {}",
            queued.id,
            queued.seq,
            iso_utc(queued.expires_at)
        ),
        Err(refusal) => bail!("{id} : {refusal}"),
    }
    Ok(())
}

/// Paramètres de `htaccess-rollback` : empreinte du dernier rapport et
/// empreinte d'avant le dernier `htaccess-apply` en place.
fn rollback_params(config: &config::Config, id: &str) -> anyhow::Result<String> {
    let store = Store::open_read(&config.database)?
        .filter(|s| s.schema_version().is_ok_and(|v| v >= SCHEMA_COMMANDS))
        .context("aucune commande (base absente ou trop ancienne)")?;
    let reported = recommend::history::reported_htaccess(&store, id)?
        .context("aucune empreinte de .htaccess dans le dernier rapport (agent sans rapport, ou .htaccess hors de critical)")?
        .context("le .htaccess est absent du dernier rapport : rien à défaire")?;
    let params = recommend::history::rollback_params(&store, id, &reported)?.context(
        "aucune application de Vigie en place (le .htaccess n'a l'empreinte d'aucun htaccess-apply réussi) : rien à défaire",
    )?;
    Ok(serde_json::to_string(&params)?)
}

#[derive(Debug, Clone, Copy)]
struct RecommendFlags {
    apply: bool,
    replace: bool,
    recompute: bool,
    force: bool,
}

/// `site recommend` : propositions, bloc cumulatif et diff, puis --apply.
fn recommend(
    config: &config::Config,
    id: &str,
    flags: RecommendFlags,
    now: i64,
) -> anyhow::Result<()> {
    use recommend::htaccess;
    let site = config
        .sites
        .iter()
        .find(|s| s.id == id)
        .with_context(|| format!("aucun site « {id} » dans la configuration"))?;
    let store = Store::open_read(&config.database)?
        .filter(|s| s.schema_version().is_ok_and(|v| v >= SCHEMA_FINDINGS))
        .context("aucune analyse de logs (base absente ou antérieure à l'analyse)")?;
    let analysis = vigie::analysis::findings::latest(&store, id)?.with_context(|| {
        format!("aucune analyse de logs pour {id} : [sites.logs] et un passage de tick")
    })?;
    let logs = site.logs.clone().unwrap_or_default();
    let tz = logs.time_zone();
    let mut protected: std::collections::BTreeSet<IpAddr> = config
        .logs
        .protect_ips
        .iter()
        .chain(&logs.protect_ips)
        .copied()
        .collect();
    if store.schema_version()? >= SCHEMA_AGENT_SOURCES {
        protected.extend(store.agent_sources(id, now)?);
    }
    let inputs = recommend::Inputs {
        analysis: &analysis,
        tz: tz.as_ref(),
        behind_proxy: logs.behind_proxy,
        protected_ips: &protected,
    };
    let proposals = recommend::recommend(&inputs, &mut |ips| recommend::rdns::reverse(ips));
    println!(
        "site : {id} ({}), analyse du {}",
        site.url,
        iso_utc(analysis.generated_at)
    );
    let robots = recommend::robots_txt(&proposals);
    if robots.is_empty() {
        println!("robots.txt : rien à proposer");
    } else {
        println!("robots.txt, à poser à la main :\n\n{robots}");
    }
    for p in &proposals {
        match p {
            recommend::Proposal::UserAgent { bot, .. } => {
                println!("règle d'UA : {bot} (ne respecte pas robots.txt), 30 jours")
            }
            recommend::Proposal::Ip {
                ip,
                rdns,
                own_score,
            } => println!("règle d'IP : {ip} ({rdns}, hébergeur, score propre {own_score}), 24 h"),
            recommend::Proposal::Robots { .. } => {}
        }
    }
    let Some(tz) = tz else {
        println!(
            "[sites.logs] tz absent : aucune règle d'UA ni d'IP (%{{TIME}} s'écrit dans le fuseau du site)"
        );
        return Ok(());
    };
    let reported = recommend::history::reported_htaccess(&store, id)?.context(
        "aucune empreinte de .htaccess dans le dernier rapport : agent sans rapport, ou .htaccess hors de critical",
    )?;
    let in_place = match &reported {
        Some(hash) => recommend::history::block_in_place(&store, id, hash)?,
        None => None,
    };
    let current = match &in_place {
        Some(applied) => htaccess::parse(applied.params.block.as_bytes(), &tz)
            .map_err(|r| anyhow::anyhow!("bloc en place illisible : {r}"))?,
        None => Vec::new(),
    };
    let plan =
        recommend::plan(&current, &proposals, now, &tz).context("heure hors du fuseau du site")?;
    let block = plan.block();
    if let Err(refusal) = htaccess::validate(block.as_bytes(), now, &tz) {
        bail!("bloc généré refusé par la validation : {refusal}");
    }
    println!();
    match &in_place {
        Some(applied) => println!(
            "bloc en place : celui de la commande {} (empreinte du dernier rapport)",
            applied.command_id
        ),
        None => println!(
            "règles en place inconnues : fichier modifié hors de Vigie, retour arrière ou première application"
        ),
    }
    for g in &plan.kept {
        println!("  = reprise   {}", recommend::describe(g));
    }
    for g in &plan.expired {
        println!("  - retirée   {} (expirée)", recommend::describe(g));
    }
    for g in &plan.added {
        println!("  + nouvelle  {}", recommend::describe(g));
    }
    println!("\nbloc :\n{block}");
    println!(
        "previous_sha256 : {} (dernier rapport)",
        reported.as_deref().unwrap_or("null, .htaccess absent")
    );
    if in_place.is_some() && !plan.changes() {
        println!("rien à appliquer : le bloc en place est à jour");
        return Ok(());
    }
    let prepared = if flags.recompute {
        None
    } else {
        recommend::history::prepared(&store, id, reported.as_deref())?
            .filter(|p| htaccess::validate(p.params.block.as_bytes(), now, &tz).is_ok())
    };
    drop(store);
    let params = match &prepared {
        Some(p) => {
            println!(
                "new_sha256 : {} (calculé par l'agent, commande {} du {})",
                p.params.new_sha256.as_deref().unwrap_or("?"),
                p.command_id,
                iso_utc(p.created_at)
            );
            if p.params.block != block {
                println!(
                    "attention : le bloc préparé diffère du bloc ci-dessus ; c'est lui qui sera appliqué (--recompute pour en préparer un nouveau) :\n{}",
                    p.params.block
                );
            }
            p.params.clone()
        }
        None => {
            println!(
                "new_sha256 : à calculer par l'agent (premier --apply), puis appliquer (second --apply)"
            );
            command::HtaccessApply {
                block,
                previous_sha256: reported.clone(),
                new_sha256: None,
            }
        }
    };
    if flags.apply && in_place.is_none() && !flags.replace {
        bail!(
            "{id} : règles en place inconnues : --replace pour remplacer le bloc vigie du .htaccess"
        );
    }
    let effect = if params.new_sha256.is_some() {
        "l'agent revalide le bloc, l'essaie en bac à sable, bascule le .htaccess avec copie privée et contrôle l'accueil ; retour automatique en cas d'échec"
    } else {
        "calcul seul : l'agent revalide le bloc et rend l'empreinte du nouveau .htaccess, sans rien écrire ; relancer --apply après son résultat"
    };
    let kind = capability::CommandKind::HtaccessApply;
    if let Err(refusal) = capability::permit(kind, site) {
        bail!("{id} : {kind} refusée : {refusal}");
    }
    println!();
    enqueue(
        config,
        site,
        kind,
        &serde_json::to_string(&params)?,
        effect,
        flags.apply,
        flags.force,
        now,
    )
}

fn audit(
    config: &config::Config,
    id: &str,
    verify: bool,
    head: Option<&str>,
) -> anyhow::Result<()> {
    require_site(config, id)?;
    let Some(store) = Store::open_read(&config.database)?
        .filter(|s| s.schema_version().is_ok_and(|v| v >= SCHEMA_COMMANDS))
    else {
        bail!("aucun journal d'audit (base absente ou antérieure au schéma {SCHEMA_COMMANDS})");
    };
    let records = store.audit_records(id)?;
    if !verify {
        for record in &records {
            println!("{}", serde_json::to_string(record)?);
        }
        return Ok(());
    }
    let key = audit_key(config)?.context("[commands] absent de la configuration")?;
    match command::audit::verify(id, &records, &key.verifying_key(), head) {
        Ok(()) => {
            println!(
                "journal de {id} intact : {} entrée(s), tête {}",
                records.len(),
                store.audit_head(id)?
            );
            Ok(())
        }
        Err(broken) => bail!("journal de {id} altéré : {broken}"),
    }
}

/// Base des failles lisible, sinon « aucune base de failles » (base absente
/// ou antérieure à la migration 15).
fn vulns_store_read(config: &config::Config) -> anyhow::Result<Store> {
    match Store::open_read(&config.database)? {
        Some(store) if vulns_store::available(&store)? => Ok(store),
        _ => bail!("aucune base de failles"),
    }
}

/// Texte relu de la base, assaini pour le terminal.
fn clean(raw: &str) -> String {
    vigie::api::log_text::LogText::detail(raw).into()
}

/// Score en dixièmes, écrit à la française : `9,8`.
fn tenths(t: u8) -> String {
    format!("{},{}", t / 10, t % 10)
}

fn vulns_cli(config: &config::Config, action: VulnsAction, now: i64) -> anyhow::Result<()> {
    match action {
        VulnsAction::Sync {
            source,
            accept_shrink,
        } => {
            let declared = vulns::sync::registry::declared(config);
            if source.is_none() && declared.is_empty() {
                println!("aucune source de failles déclarée");
                return Ok(());
            }
            let report = vulns::sync::run(
                config,
                &vulns::sync::SyncOptions::default(),
                &SystemClock,
                source.as_deref(),
                accept_shrink,
            )?;
            for s in &report.sources {
                println!("{}", clean(&s.line));
            }
            let failures = report.failures();
            if failures > 0 {
                bail!("{failures} source(s) de failles en échec");
            }
            Ok(())
        }
        VulnsAction::Sources => {
            let store = vulns_store_read(config)?;
            let sources = vulns_store::sources(&store)?;
            let states: std::collections::HashMap<String, vulns_store::SyncState> =
                if vulns_store::sync_available(&store)? {
                    vulns_store::sync_states(&store)?.into_iter().collect()
                } else {
                    Default::default()
                };
            if sources.is_empty() {
                println!("aucune source de failles");
            }
            for s in sources {
                let age = s.last_success_at.map_or("jamais chargée".to_owned(), |t| {
                    format!("chargée il y a {}", human_age(now - t))
                });
                let license = if s.license.is_empty() {
                    "par enregistrement".to_owned()
                } else {
                    clean(&s.license)
                };
                println!(
                    "{}  licence {license}  {age}  entrées {}  écartées {}  hors périmètre {}",
                    clean(&s.id),
                    s.entries,
                    s.dropped,
                    s.out_of_scope
                );
                let detail: Vec<String> = s
                    .dropped_detail
                    .iter()
                    .map(|(reason, n)| format!("{} {n}", clean(reason)))
                    .collect();
                if !detail.is_empty() {
                    println!("  compteurs : {}", detail.join(", "));
                }
                if let Some(n) = s.dropped_detail.get("unknown_license").filter(|n| **n > 0) {
                    println!("  licence inconnue : {n} faille(s) gardée(s), licence à résoudre");
                }
                if let Some(since) = s.loading_since {
                    println!("  chargement en cours depuis {}", human_age(now - since));
                }
                if let Some(state) = states.get(&s.id) {
                    print_sync_state(state, now);
                }
                if let Some(err) = s.last_error {
                    println!("  dernière erreur : {}", clean(&err));
                }
                if !s.attribution.is_empty() {
                    println!("  attribution : {}", clean(&s.attribution));
                }
            }
            Ok(())
        }
        VulnsAction::Show { id } => {
            if vulns::advisory::normalize_alias(&id).is_none() {
                return Err(vulns::UsageError(
                    "identifiant mal formé : [A-Za-z0-9][A-Za-z0-9._:-]{0,63} attendu".into(),
                )
                .into());
            }
            let store = vulns_store_read(config)?;
            let found = vulns_store::advisory(&store, &id)?;
            if found.is_empty() {
                bail!("aucune faille {}", clean(&id));
            }
            for (i, s) in found.iter().enumerate() {
                if i > 0 {
                    println!();
                }
                print_advisory(s);
            }
            Ok(())
        }
        VulnsAction::Match { purl } => {
            let purl = vulns::Purl::parse(&purl).map_err(|e| vulns::UsageError(format!("{e}")))?;
            let store = vulns_store_read(config)?;
            let matches = vulns_store::match_purl(&store, &purl)?;
            let mut shown = 0;
            for (c, verdict) in &matches {
                let a = &c.advisory;
                let mut line = format!("{}  ", clean(&a.id));
                match verdict {
                    vulns::Verdict::NotAffected => continue,
                    vulns::Verdict::Affected {
                        fixed,
                        divergence,
                        beyond_last_known,
                    } => {
                        line.push_str("touché");
                        match fixed {
                            Some(f) => line.push_str(&format!("  corrigée en {}", clean(f))),
                            None => line.push_str("  aucun correctif connu"),
                        }
                        if *divergence {
                            line.push_str("  [divergence : listée hors plages]");
                        }
                        if *beyond_last_known {
                            line.push_str("  [au-delà de la dernière version connue]");
                        }
                    }
                    vulns::Verdict::Unknown(vulns::UnknownReason::VersionUnknown) => {
                        line.push_str("version inconnue");
                    }
                    vulns::Verdict::Unknown(vulns::UnknownReason::RangeUnknown) => {
                        line.push_str("plage inconnue");
                    }
                }
                match a.score {
                    Some(s) => line.push_str(&format!(
                        "  score {} ({})",
                        tenths(s.tenths),
                        s.origin.as_str()
                    )),
                    None => line.push_str("  score inconnu"),
                }
                if a.malicious {
                    line.push_str("  [paquet malveillant]");
                }
                if a.informational {
                    line.push_str("  [informational]");
                }
                line.push_str(&format!("  source {}", clean(&c.source)));
                println!("{line}");
                shown += 1;
            }
            if shown == 0 {
                println!(
                    "aucune faille connue pour {} ({} faille(s) du paquet examinée(s))",
                    purl,
                    matches.len()
                );
            }
            Ok(())
        }
    }
}

/// État de synchronisation d'une source, pour `vigie vulns sources`.
fn print_sync_state(state: &vulns_store::SyncState, now: i64) {
    let success = state.last_success_at.map_or("jamais".to_owned(), |t| {
        format!("il y a {} ({})", human_age(now - t), iso_utc(t))
    });
    let attempt = match (state.last_attempt_at, state.last_outcome) {
        (Some(t), Some(o)) => format!("il y a {} : {}", human_age(now - t), o.as_str()),
        (Some(t), None) => format!("il y a {}", human_age(now - t)),
        _ => "aucune".to_owned(),
    };
    println!("  dernière réussite : {success}  dernière tentative : {attempt}");
    let size = |b: Option<i64>| b.map_or("-".to_owned(), |b| format!("{b} o"));
    println!(
        "  dump {}  décompressé {}  durée {}  ETag {}  lecteur {}",
        size(state.dump_bytes),
        size(state.unpacked_bytes),
        state
            .last_duration_ms
            .map_or("-".to_owned(), |ms| format!("{ms} ms")),
        if state.etag.is_some() { "oui" } else { "non" },
        state
            .loader_version
            .map_or("-".to_owned(), |v| v.to_string())
    );
    if let Some(until) = state.retry_after_until.filter(|u| *u > now) {
        println!(
            "  Retry-After : pas de requête avant {} (dans {})",
            iso_utc(until),
            human_age(until - now)
        );
    }
}

fn print_advisory(s: &vulns_store::Stored) {
    let a = &s.advisory;
    println!("{}  (source {})", clean(&a.id), clean(&s.source));
    if !a.aliases.is_empty() {
        let aliases: Vec<String> = a.aliases.iter().map(|x| clean(x)).collect();
        println!("  alias : {}", aliases.join(", "));
    }
    if !a.summary.is_empty() {
        println!("  résumé : {}", clean(&a.summary));
    }
    match a.score {
        Some(score) => println!(
            "  score : {} ({})",
            tenths(score.tenths),
            score.origin.as_str()
        ),
        None => println!("  score : inconnu"),
    }
    for sev in &a.severity {
        println!("  {} : {}", clean(&sev.kind), clean(&sev.vector));
    }
    if a.malicious {
        println!("  paquet malveillant");
    }
    if a.informational {
        println!("  informational (Wordfence)");
    }
    if !a.cwe.is_empty() {
        let cwe: Vec<String> = a.cwe.iter().map(|x| clean(x)).collect();
        println!("  CWE : {}", cwe.join(", "));
    }
    if let Some(p) = a.published {
        println!("  publiée : {}", iso_utc(p));
    }
    println!("  modifiée : {}", iso_utc(a.modified));
    for line in &a.affected {
        let state = if line.unevaluable {
            "  [plage inconnue]"
        } else {
            ""
        };
        println!(
            "  composant : {} ({}){state}",
            line.purl,
            line.scheme.as_str()
        );
    }
    for r in &a.references {
        println!("  {} : {}", clean(&r.kind), clean(&r.url));
    }
    println!("  licence : {}", clean(&a.license));
    println!("  attribution : {}", clean(&a.attribution));
    println!("  lien : {}", clean(&a.source_url));
}
