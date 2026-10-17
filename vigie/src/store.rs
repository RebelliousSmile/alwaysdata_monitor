//! Base SQLite partagée par `serve` et `tick`.
//!
//! WAL pour que `serve` lise pendant que `tick` écrit. Le WAL n'est sûr que si
//! les deux processus tournent sur le même hôte et sur un système de fichiers
//! local : c'est le cas sur le disque du VPS (`docs/hebergement.md`).

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rusqlite::{Connection, ErrorCode, OpenFlags, OptionalExtension, TransactionBehavior, params};

use crate::capability;
use crate::device::{self, Hash};
use crate::facts;
use crate::finding::{Finding, Severity};
use crate::logs::Entry;

/// Une entrée par version de schéma, jouée dans l'ordre. Le SQL vit dans
/// `migrations/`, embarqué à la compilation. Ne jamais modifier une migration
/// déjà publiée : en ajouter une.
const MIGRATIONS: &[&str] = &[
    // 1 : passages de `tick`, en secondes Unix.
    include_str!("../migrations/0001.sql"),
    // 2 : dernier passage de chaque contrôle, et incidents. Un seul incident
    // ouvert par clé ; les dates sont en secondes Unix.
    include_str!("../migrations/0002.sql"),
    // 3 : clé publique de l'agent de chaque site (Ed25519, 32 octets), et état
    // de ses rapports : dernier `seq` accepté, date de réception, dernier relevé.
    include_str!("../migrations/0003.sql"),
    // 4 : empreintes des fichiers critiques du dernier rapport, et référence
    // à laquelle elles sont comparées (`facts.rs`), en JSON.
    include_str!("../migrations/0004.sql"),
    // 5 : appareils de la console et codes d'appairage (`device.rs`). Seules
    // les empreintes SHA-256 sont gardées, jamais un jeton ni un code.
    // AUTOINCREMENT : l'id d'un appareil révoqué n'est jamais redonné.
    include_str!("../migrations/0005.sql"),
    // 6 : résultat du dernier passage de chaque contrôle, pour la console :
    // `ok`, `finding` ou `error`, gravité et détail du constat le plus grave,
    // durée, valeurs observées en JSON. NULL pour un passage antérieur.
    include_str!("../migrations/0006.sql"),
    // 7 : valeurs isolées du veilleur (clé, valeur, date), dont l'empreinte de
    // la typologie vue par `serve` et par `tick` (`config::typology_fingerprint`).
    include_str!("../migrations/0007.sql"),
    // 8 : canal de commandes (`command/`) : activation et séquences par site,
    // file des commandes (une seule non close par site, index unique partiel),
    // journal d'audit en ajout seul (déclencheurs) chaîné par site, et dernier
    // hash envoyé par e-mail comme ancre externe.
    include_str!("../migrations/0008.sql"),
    // 9 : logs poussés par les agents (`logs/receive.rs`, issue #1) : `seq`
    // des lots par site, limite haute par (site, fichier, génération), lots
    // reçus et leurs rejets, entrées normalisées. AUTOINCREMENT : après une
    // purge totale, un id n'est jamais redonné sous le curseur d'une source.
    include_str!("../migrations/0009.sql"),
    // 10 : agrégats de l'analyse de logs (`analysis/store.rs`) : seaux par
    // minute des règles, profils d'IP par heure (index couvrant du compte de
    // classement), robots et charge par heure, curseur et heure de référence.
    include_str!("../migrations/0010.sql"),
    // 11 : analyse de logs, phase 3 : signatures d'UA de robots partagées
    // entre sites (jamais d'IP), instantanés de l'analyse (résumé sans IP) et
    // verdicts d'IP moyens et élevés, index par score décroissant.
    include_str!("../migrations/0011.sql"),
    // 12 : index des incidents clos d'un site, pour leur pagination par clé
    // (`/api/v1/sites/{id}/incidents`, issue #5).
    include_str!("../migrations/0012.sql"),
    // 13 : recommandations htaccess (#13) : adresses source des retraits
    // signés de l'agent, protégées des règles d'IP, 30 jours.
    include_str!("../migrations/0013.sql"),
    // 14 : registre des capacités (#4) : constats écartés du dernier rapport
    // d'agent, et raison de la clôture d'un incident (« plus surveillé »).
    include_str!("../migrations/0014.sql"),
];

/// Version de schéma à partir de laquelle les incidents existent.
pub const SCHEMA_INCIDENTS: usize = 2;
/// Version de schéma à partir de laquelle les clés d'agent existent.
pub const SCHEMA_AGENTS: usize = 3;
/// Version de schéma à partir de laquelle les références d'empreintes existent.
pub const SCHEMA_BASELINE: usize = 4;
/// Version de schéma à partir de laquelle les appareils de la console existent.
pub const SCHEMA_DEVICES: usize = 5;
/// Version de schéma à partir de laquelle le résultat des passages existe.
pub const SCHEMA_CHECK_RESULTS: usize = 6;
/// Version de schéma à partir de laquelle la table `meta` existe.
pub const SCHEMA_META: usize = 7;
/// Version de schéma à partir de laquelle le canal de commandes existe.
pub const SCHEMA_COMMANDS: usize = 8;
/// Version de schéma à partir de laquelle les logs reçus existent.
pub const SCHEMA_LOGS: usize = 9;
/// Version de schéma à partir de laquelle les agrégats de l'analyse de logs
/// existent.
pub const SCHEMA_ANALYSIS: usize = 10;
/// Version de schéma à partir de laquelle les signatures partagées et les
/// instantanés de l'analyse de logs existent.
pub const SCHEMA_FINDINGS: usize = 11;
/// Version de schéma à partir de laquelle les incidents clos sont indexés
/// par site, date de clôture et id.
pub const SCHEMA_CLOSED_INDEX: usize = 12;
/// Version de schéma à partir de laquelle les adresses source des retraits
/// existent.
pub const SCHEMA_AGENT_SOURCES: usize = 13;
/// Version de schéma à partir de laquelle les constats écartés d'un rapport
/// et la raison de clôture d'un incident existent (registre, #4).
pub const SCHEMA_REGISTRY: usize = 14;
/// Une adresse source de retrait est oubliée 30 jours après le dernier.
pub const AGENT_SOURCE_RETENTION: i64 = 30 * 86_400;

/// Empreinte de la typologie chargée par `serve` à son démarrage.
pub const META_TYPOLOGY_SERVE: &str = "typology.serve";
/// Empreinte de la typologie vue par le dernier `tick`.
pub const META_TYPOLOGY_TICK: &str = "typology.tick";

/// « Vu le » d'un appareil n'est réécrit qu'après ce délai, en secondes.
pub const SEEN_PERIOD: i64 = 60;

/// Au plus un rapport accepté par site pendant cette durée, en secondes.
pub const REPORT_MIN_GAP: i64 = 60;

/// Préfixe des contrôles rapportés par un agent.
pub const AGENT_PREFIX: &str = "agent:";

/// Délai entre deux rappels d'un incident ouvert et non acquitté.
pub const REMINDER_PERIOD: i64 = 24 * 3600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incident {
    pub id: i64,
    pub key: String,
    pub site: String,
    pub check_name: String,
    pub severity: Severity,
    pub detail: String,
    pub opened_at: i64,
    pub closed_at: Option<i64>,
    pub acked_at: Option<i64>,
    pub open_notified_at: Option<i64>,
    pub close_notified_at: Option<i64>,
    pub last_reminder_at: Option<i64>,
    /// `None` tant que l'incident est ouvert.
    pub close_reason: Option<CloseReason>,
}

/// Pourquoi un incident a été clos : l'e-mail de clôture part plus tard
/// (`pending_closes`), la raison est donc en base.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    /// Le contrôle ne voit plus le constat.
    Resolved,
    /// Le contrôle n'est plus surveillé (`close_unwatched`) : site retiré,
    /// typologie changée, clé d'agent retirée. Jamais « rétabli ».
    Unwatched,
}

impl CloseReason {
    const UNWATCHED: &'static str = "unwatched";

    fn parse(closed_at: Option<i64>, raw: Option<&str>) -> Option<Self> {
        closed_at?;
        Some(match raw {
            Some(Self::UNWATCHED) => Self::Unwatched,
            // NULL, ou une valeur d'un binaire plus récent : la clôture
            // ordinaire.
            _ => Self::Resolved,
        })
    }
}

/// Issue du dernier passage d'un contrôle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunResult {
    /// Concluant, sans constat.
    Ok,
    /// Concluant, avec au moins un constat.
    Finding,
    /// Non concluant.
    Error,
}

impl RunResult {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Finding => "finding",
            Self::Error => "error",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "ok" => Some(Self::Ok),
            "finding" => Some(Self::Finding),
            "error" => Some(Self::Error),
            _ => None,
        }
    }
}

/// Résultat d'un passage, à enregistrer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRecord {
    pub result: RunResult,
    /// Gravité du constat le plus grave.
    pub severity: Option<Severity>,
    /// Détail du constat le plus grave, ou raison de l'échec.
    pub detail: Option<String>,
    pub duration_ms: Option<i64>,
    /// Valeurs observées, en JSON.
    pub observed: Option<String>,
}

impl RunRecord {
    /// Passage concluant : le constat le plus grave le résume.
    pub fn concluded(findings: &[Finding]) -> Self {
        // `max_by_key` garde le dernier des ex æquo : on veut le premier.
        let worst = findings
            .iter()
            .fold(None::<&Finding>, |kept, f| match kept {
                Some(kept) if kept.severity >= f.severity => Some(kept),
                _ => Some(f),
            });
        Self {
            result: if worst.is_some() {
                RunResult::Finding
            } else {
                RunResult::Ok
            },
            severity: worst.map(|f| f.severity),
            detail: worst.map(|f| f.detail.clone()),
            duration_ms: None,
            observed: None,
        }
    }

    /// Passage non concluant.
    pub fn failed(message: &str) -> Self {
        Self {
            result: RunResult::Error,
            severity: None,
            detail: Some(message.to_owned()),
            duration_ms: None,
            observed: None,
        }
    }

    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration_ms = Some(i64::try_from(duration.as_millis()).unwrap_or(i64::MAX));
        self
    }

    pub fn with_observed(mut self, observed: Option<String>) -> Self {
        self.observed = observed;
        self
    }
}

/// Dernier passage d'un contrôle, tel qu'enregistré.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckRun {
    pub site: String,
    pub check_name: String,
    pub last_run: i64,
    /// `None` pour un passage antérieur au schéma 6, ou marqué sans résultat.
    pub result: Option<RunResult>,
    pub severity: Option<Severity>,
    pub detail: Option<String>,
    pub duration_ms: Option<i64>,
    /// Valeurs observées, en JSON.
    pub observed: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckOutcome {
    NotFound,
    AlreadyClosed,
    AlreadyAcked,
    Acked,
}

/// Appareil de la console. Son jeton n'est connu que de lui.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub id: i64,
    pub name: String,
    pub created_at: i64,
    pub seen_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

/// Code d'appairage ni utilisé ni expiré.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pairing {
    pub id: i64,
    pub name: String,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeOutcome {
    NotFound,
    AlreadyRevoked,
    Revoked,
}

const DEVICE_COLUMNS: &str = "id, name, created_at, seen_at, revoked_at";

fn device_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Device> {
    Ok(Device {
        id: row.get(0)?,
        name: row.get(1)?,
        created_at: row.get(2)?,
        seen_at: row.get(3)?,
        revoked_at: row.get(4)?,
    })
}

/// Agent déclaré d'un site, et état de ses rapports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agent {
    pub site: String,
    pub pubkey: [u8; 32],
    pub added_at: i64,
    pub rotated_at: Option<i64>,
    /// 0 avant le premier rapport, et après une rotation de clé.
    pub last_seq: i64,
    pub last_valid_at: Option<i64>,
    pub agent: Option<String>,
}

impl Agent {
    /// Point de départ du silence : dernier rapport accepté, sinon déclaration.
    pub fn last_sign_of_life(&self) -> i64 {
        self.last_valid_at.unwrap_or(self.added_at)
    }
}

/// Rapport authentifié et à l'heure, prêt à être enregistré.
#[derive(Debug, Clone, Copy)]
pub struct AcceptedReport<'a> {
    pub site: &'a str,
    pub pubkey: &'a [u8; 32],
    pub seq: i64,
    pub agent: &'a str,
    /// Relevé, en JSON.
    pub facts: &'a str,
    /// Empreintes des fichiers critiques, en JSON (`{}` si l'agent n'en envoie pas).
    pub files: &'a str,
    /// Contrôles déjà préfixés par `agent:`, déjà filtrés par le registre.
    pub findings: &'a [Finding],
    /// Constats écartés par l'appelant : famille inconnue ou non admise pour
    /// le CMS du site (`capability::admits_agent_finding`).
    pub dropped: usize,
}

/// Issue de l'enregistrement d'un rapport déjà authentifié.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportOutcome {
    Accepted,
    /// Clé retirée ou remplacée entre la vérification et l'écriture.
    UnknownSite,
    /// `seq` inférieur ou égal au dernier accepté.
    Replay {
        last_seq: i64,
    },
    /// Moins de `REPORT_MIN_GAP` secondes depuis le dernier rapport accepté.
    TooSoon {
        last_valid_at: i64,
    },
}

/// Lot de logs authentifié, à l'heure et normalisé (`logs/receive.rs`), prêt
/// à écrire. Les octets reçus n'y sont plus : seulement des [`Entry`].
#[derive(Debug, Clone, Copy)]
pub struct LogBatch<'a> {
    pub site: &'a str,
    /// Clé qui a vérifié la signature.
    pub pubkey: &'a [u8; 32],
    pub seq: i64,
    /// `http-AAAA-MM-JJ.log`.
    pub file: &'a str,
    pub generation: i64,
    pub start: i64,
    pub end: i64,
    /// Octets du `chunk` décodé, comptés dans le plafond quotidien.
    pub bytes: i64,
    pub skipped_files: i64,
    pub entries: &'a [Entry],
    /// Rejets par motif, en JSON.
    pub rejected: &'a str,
}

/// Issue de l'écriture d'un lot de logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogsOutcome {
    /// Écrit ; `gap` : octets sautés depuis la limite haute (0 sans trou).
    Accepted { gap: i64 },
    /// Plage déjà couverte : rien d'écrit sauf le `seq`.
    Duplicate,
    /// Clé retirée ou remplacée entre la vérification et l'écriture.
    UnknownSite,
    /// `seq` inférieur ou égal au dernier lot accepté.
    Replay { last_seq: i64 },
    /// La plage commence sous la limite haute et finit au-delà.
    Overlap { high: i64 },
    /// Plafond quotidien du site atteint.
    Quota { used: i64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOutcome {
    Done,
    /// `add` : le site a déjà une clé.
    AlreadyPresent,
    /// `rotate` : le site n'a pas de clé.
    Missing,
    /// `rotate` : la nouvelle clé est l'actuelle.
    Unchanged,
}

const AGENT_COLUMNS: &str = "k.site, k.pubkey, k.added_at, k.rotated_at,
     COALESCE(r.last_seq, 0), r.last_valid_at, r.agent";

fn agent_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Agent> {
    let raw: Vec<u8> = row.get(1)?;
    // La contrainte CHECK de la table garantit 32 octets.
    let mut pubkey = [0u8; 32];
    if raw.len() == 32 {
        pubkey.copy_from_slice(&raw);
    }
    Ok(Agent {
        site: row.get(0)?,
        pubkey,
        added_at: row.get(2)?,
        rotated_at: row.get(3)?,
        last_seq: row.get(4)?,
        last_valid_at: row.get(5)?,
        agent: row.get(6)?,
    })
}

const INCIDENT_COLUMNS: &str = "id, key, site, check_name, severity, detail, opened_at, closed_at,
     acked_at, open_notified_at, close_notified_at, last_reminder_at, close_reason";
/// Avant le schéma 14, la raison de clôture n'existe pas : un lecteur
/// (`status` pendant un déploiement) la lit NULL.
const INCIDENT_COLUMNS_V13: &str =
    "id, key, site, check_name, severity, detail, opened_at, closed_at,
     acked_at, open_notified_at, close_notified_at, last_reminder_at, NULL";

fn incident_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Incident> {
    let severity: String = row.get(4)?;
    Ok(Incident {
        id: row.get(0)?,
        key: row.get(1)?,
        site: row.get(2)?,
        check_name: row.get(3)?,
        // Une gravité inconnue vient d'un binaire plus récent : traitée comme
        // critique plutôt que tue.
        severity: Severity::parse(&severity).unwrap_or(Severity::Critical),
        detail: row.get(5)?,
        opened_at: row.get(6)?,
        closed_at: row.get(7)?,
        acked_at: row.get(8)?,
        open_notified_at: row.get(9)?,
        close_notified_at: row.get(10)?,
        last_reminder_at: row.get(11)?,
        close_reason: CloseReason::parse(row.get(7)?, row.get::<_, Option<String>>(12)?.as_deref()),
    })
}

fn check_run_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CheckRun> {
    let result: Option<String> = row.get(3)?;
    let severity: Option<String> = row.get(4)?;
    Ok(CheckRun {
        site: row.get(0)?,
        check_name: row.get(1)?,
        last_run: row.get(2)?,
        result: result.as_deref().and_then(RunResult::parse),
        severity: severity.as_deref().and_then(Severity::parse),
        detail: row.get(5)?,
        duration_ms: row.get(6)?,
        observed: row.get(7)?,
    })
}

/// Enregistre le dernier passage d'un contrôle, à la place du précédent.
fn record_result_in(
    conn: &Connection,
    site: &str,
    check: &str,
    now: i64,
    record: &RunRecord,
) -> Result<()> {
    conn.execute(
        "INSERT INTO check_runs
           (site, check_name, last_run, result, severity, detail, duration_ms, observed)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT (site, check_name) DO UPDATE SET last_run = excluded.last_run,
           result = excluded.result, severity = excluded.severity,
           detail = excluded.detail, duration_ms = excluded.duration_ms,
           observed = excluded.observed",
        params![
            site,
            check,
            now,
            record.result.as_str(),
            record.severity.map(Severity::as_str),
            record.detail,
            record.duration_ms,
            record.observed
        ],
    )?;
    Ok(())
}

/// Historique des passages conservé, en secondes.
const TICK_RETENTION: i64 = 7 * 24 * 3600;

pub struct Store {
    pub(crate) conn: Connection,
}

/// Au-delà, une base toujours occupée fait échouer l'ouverture.
const OPEN_PATIENCE: Duration = Duration::from_secs(5);

/// SQLite rend « occupé » sans passer par `busy_timeout` dans certains cas,
/// dont le passage en WAL d'une base neuve ouverte par deux processus à la fois.
fn is_busy(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<rusqlite::Error>(),
            Some(rusqlite::Error::SqliteFailure(failure, _))
                if matches!(failure.code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
        )
    })
}

impl Store {
    /// Ouvre la base, la crée et la migre au besoin. Une base occupée (premier
    /// démarrage simultané de `serve` et `tick`) est réessayée pendant 5 s.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("création de {}", parent.display()))?;
        }
        let give_up = Instant::now() + OPEN_PATIENCE;
        loop {
            match Self::open_once(path) {
                Err(err) if is_busy(&err) && Instant::now() < give_up => {
                    std::thread::sleep(Duration::from_millis(25));
                }
                result => return result,
            }
        }
    }

    fn open_once(path: &Path) -> Result<Self> {
        let conn =
            Connection::open(path).with_context(|| format!("ouverture de {}", path.display()))?;
        Self::tune_writer(&conn, path)?;
        let mut store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    /// Réglages d'une connexion qui écrit : attente du verrou, WAL, durabilité
    /// et clés étrangères.
    fn tune_writer(conn: &Connection, path: &Path) -> Result<()> {
        conn.busy_timeout(Duration::from_secs(5))?;
        let mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        if !mode.eq_ignore_ascii_case("wal") {
            anyhow::bail!(
                "{} refuse le mode WAL (journal_mode={mode})",
                path.display()
            );
        }
        conn.execute_batch("PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;")?;
        Ok(())
    }

    /// Ouverture en écrivain pour `serve` (`writer.rs`) : ne crée ni le fichier
    /// ni son dossier, ne migre pas, et tolère un schéma plus récent que le
    /// binaire, comme [`Store::open_read`]. La base est créée et migrée par
    /// `tick` ou la CLI, et migrée au démarrage de `serve`. `None` si la base
    /// n'existe pas encore.
    pub fn open_write(path: &Path) -> Result<Option<Self>> {
        if !path.is_file() {
            return Ok(None);
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(path, flags)
            .with_context(|| format!("ouverture de {}", path.display()))?;
        Self::tune_writer(&conn, path)?;
        Ok(Some(Self { conn }))
    }

    /// Ouverture en lecteur, pour `/health`, `status` et les lectures de l'API :
    /// ne crée ni le fichier ni son dossier, ne migre pas, ne change pas le mode
    /// de journal, refuse toute écriture (`query_only`), et tolère un schéma plus
    /// récent que le binaire (pendant un déploiement, `serve` garde l'ancien
    /// binaire en mémoire). `None` si la base n'existe pas encore.
    pub fn open_read(path: &Path) -> Result<Option<Self>> {
        if !path.is_file() {
            return Ok(None);
        }
        // Lecture-écriture sans création : un lecteur d'une base WAL doit
        // pouvoir créer le fichier -shm si le dernier processus l'a supprimé.
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(path, flags)
            .with_context(|| format!("ouverture de {}", path.display()))?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA query_only=ON;")?;
        Ok(Some(Self { conn }))
    }

    pub fn schema_version(&self) -> Result<usize> {
        let version: i64 = self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))?;
        Ok(usize::try_from(version).unwrap_or(0))
    }

    /// Idempotent : une base déjà à jour n'est pas touchée. Chaque migration se
    /// joue dans une transaction IMMEDIATE qui relit `user_version` : si `serve`
    /// et `tick` démarrent ensemble, le second attend le verrou puis voit la
    /// version déjà montée, au lieu de rejouer la même migration.
    fn migrate(&mut self) -> Result<()> {
        loop {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let current: i64 = tx.query_row("PRAGMA user_version", [], |row| row.get(0))?;
            let current = usize::try_from(current).unwrap_or(0);
            if current > MIGRATIONS.len() {
                anyhow::bail!(
                    "base en version {current}, ce binaire ne connaît que la version {} : binaire trop ancien",
                    MIGRATIONS.len()
                );
            }
            if current == MIGRATIONS.len() {
                return Ok(());
            }
            let version = current + 1;
            tx.execute_batch(MIGRATIONS[current])
                .with_context(|| format!("migration {version}"))?;
            tx.pragma_update(None, "user_version", version as i64)?;
            tx.commit()?;
            log::info!("base migrée en version {version}");
        }
    }

    pub fn record_tick(&mut self, now: i64) -> Result<()> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("INSERT INTO ticks (at) VALUES (?1)", [now])?;
        tx.execute("DELETE FROM ticks WHERE at < ?1", [now - TICK_RETENTION])?;
        tx.commit()?;
        Ok(())
    }

    /// Valeur et date d'écriture d'une clé de `meta`.
    pub fn meta(&self, key: &str) -> Result<Option<(String, i64)>> {
        Ok(self
            .conn
            .query_row(
                "SELECT value, updated_at FROM meta WHERE key = ?1",
                [key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }

    pub fn set_meta(&mut self, key: &str, value: &str, now: i64) -> Result<()> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO meta (key, value, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            rusqlite::params![key, value, now],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn last_tick(&self) -> Result<Option<i64>> {
        Ok(self
            .conn
            .query_row("SELECT MAX(at) FROM ticks", [], |row| {
                row.get::<_, Option<i64>>(0)
            })
            .optional()?
            .flatten())
    }

    pub fn last_run(&self, site: &str, check: &str) -> Result<Option<i64>> {
        Ok(self
            .conn
            .query_row(
                "SELECT last_run FROM check_runs WHERE site = ?1 AND check_name = ?2",
                [site, check],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Marque un passage sans résultat connu (préparation des tests, reprise).
    pub fn record_run(&mut self, site: &str, check: &str, now: i64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO check_runs (site, check_name, last_run) VALUES (?1, ?2, ?3)
             ON CONFLICT (site, check_name) DO UPDATE SET last_run = excluded.last_run,
               result = NULL, severity = NULL, detail = NULL, duration_ms = NULL,
               observed = NULL",
            params![site, check, now],
        )?;
        Ok(())
    }

    /// Enregistre le dernier passage d'un contrôle et son résultat.
    pub fn record_result(
        &mut self,
        site: &str,
        check: &str,
        now: i64,
        record: &RunRecord,
    ) -> Result<()> {
        record_result_in(&self.conn, site, check, now, record)
    }

    /// Dernier passage de chaque contrôle, avec son résultat, par site.
    pub fn check_results(&self) -> Result<Vec<CheckRun>> {
        let mut stmt = self.conn.prepare(
            "SELECT site, check_name, last_run, result, severity, detail, duration_ms, observed
             FROM check_runs ORDER BY site, check_name",
        )?;
        let rows = stmt.query_map([], check_run_from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Dernier passage de chaque contrôle, par site.
    pub fn check_runs(&self) -> Result<Vec<(String, String, i64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT site, check_name, last_run FROM check_runs ORDER BY site, check_name",
        )?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Applique le résultat concluant d'un contrôle : un constat nouveau ouvre
    /// un incident, un constat déjà connu le met à jour, un incident ouvert de
    /// ce contrôle sans constat est clos. Tout ou rien.
    pub fn reconcile(
        &mut self,
        site: &str,
        check: &str,
        findings: &[Finding],
        now: i64,
    ) -> Result<()> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        reconcile_in(&tx, site, check, findings, now)?;
        tx.commit()?;
        Ok(())
    }

    /// Clôt les incidents ouverts dont le couple (site, contrôle) n'est plus
    /// surveillé : site retiré de la configuration, typologie changée, ou
    /// clé d'agent retirée. La raison `unwatched` choisit l'e-mail « plus
    /// surveillé », jamais « rétabli ».
    pub fn close_unwatched(
        &mut self,
        is_watched: impl Fn(&str, &str) -> bool,
        now: i64,
    ) -> Result<usize> {
        let stale: Vec<i64> = self
            .open_incidents()?
            .into_iter()
            .filter(|i| !is_watched(&i.site, &i.check_name))
            .map(|i| i.id)
            .collect();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for id in &stale {
            tx.execute(
                "UPDATE incidents SET closed_at = ?2, close_reason = 'unwatched' WHERE id = ?1",
                params![id, now],
            )?;
        }
        tx.commit()?;
        Ok(stale.len())
    }

    /// Colonnes d'un incident selon le schéma de la base.
    fn incident_columns(&self) -> Result<&'static str> {
        Ok(if self.schema_version()? >= SCHEMA_REGISTRY {
            INCIDENT_COLUMNS
        } else {
            INCIDENT_COLUMNS_V13
        })
    }

    fn incidents_where(
        &self,
        clause: &str,
        args: &[&dyn rusqlite::ToSql],
    ) -> Result<Vec<Incident>> {
        let columns = self.incident_columns()?;
        let sql = format!("SELECT {columns} FROM incidents WHERE {clause} ORDER BY id");
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(args, incident_from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn incident(&self, id: i64) -> Result<Option<Incident>> {
        Ok(self.incidents_where("id = ?1", &[&id])?.into_iter().next())
    }

    pub fn open_incidents(&self) -> Result<Vec<Incident>> {
        self.incidents_where("closed_at IS NULL", &[])
    }

    /// Incidents d'un site clos depuis `since`, les plus récents d'abord.
    pub fn closed_incidents(&self, site: &str, since: i64) -> Result<Vec<Incident>> {
        let mut found = self.incidents_where(
            "site = ?1 AND closed_at IS NOT NULL AND closed_at >= ?2",
            &[&site, &since],
        )?;
        found.sort_by(|a, b| b.closed_at.cmp(&a.closed_at).then(b.id.cmp(&a.id)));
        Ok(found)
    }

    /// Page d'incidents clos d'un site depuis `since`, les plus récents
    /// d'abord (`closed_at DESC, id DESC`), après le curseur `after`
    /// (`closed_at`, `id`) du dernier incident de la page précédente : au
    /// plus `limit` incidents. Index `incidents_site_closed`.
    pub fn closed_incidents_page(
        &self,
        site: &str,
        since: i64,
        after: Option<(i64, i64)>,
        limit: usize,
    ) -> Result<Vec<Incident>> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        // Valeur de ligne : SQLite en fait une borne de l'index, sans relire
        // les pages déjà servies. Sans curseur, ?3 et ?4 restent inutilisés
        // (le nombre de paramètres suit le plus grand indice, ?5).
        let (after_clause, closed_at, id) = match after {
            Some((closed_at, id)) => ("AND (closed_at, id) < (?3, ?4)", Some(closed_at), Some(id)),
            None => ("", None, None),
        };
        let columns = self.incident_columns()?;
        let mut stmt = self.conn.prepare_cached(&format!(
            "SELECT {columns} FROM incidents
             WHERE site = ?1 AND closed_at >= ?2 {after_clause}
             ORDER BY closed_at DESC, id DESC
             LIMIT ?5"
        ))?;
        let rows = stmt.query_map(
            params![site, since, closed_at, id, limit],
            incident_from_row,
        )?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// E-mails d'ouverture à envoyer, y compris pour un incident déjà clos :
    /// son e-mail de clôture suivra, et l'historique reste complet.
    pub fn pending_opens(&self) -> Result<Vec<Incident>> {
        self.incidents_where("open_notified_at IS NULL AND severity != 'info'", &[])
    }

    /// E-mails de clôture à envoyer : seulement si l'ouverture a été annoncée.
    pub fn pending_closes(&self) -> Result<Vec<Incident>> {
        self.incidents_where(
            "closed_at IS NOT NULL AND close_notified_at IS NULL
             AND open_notified_at IS NOT NULL AND severity != 'info'",
            &[],
        )
    }

    pub fn due_reminders(&self, now: i64) -> Result<Vec<Incident>> {
        self.incidents_where(
            "closed_at IS NULL AND acked_at IS NULL AND open_notified_at IS NOT NULL
             AND severity != 'info'
             AND COALESCE(last_reminder_at, open_notified_at) <= ?1",
            &[&(now - REMINDER_PERIOD)],
        )
    }

    pub fn pending_notifications(&self, now: i64) -> Result<usize> {
        Ok(self.pending_opens()?.len()
            + self.pending_closes()?.len()
            + self.due_reminders(now)?.len())
    }

    pub fn mark_open_notified(&mut self, id: i64, now: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE incidents SET open_notified_at = ?2 WHERE id = ?1",
            params![id, now],
        )?;
        Ok(())
    }

    pub fn mark_close_notified(&mut self, id: i64, now: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE incidents SET close_notified_at = ?2 WHERE id = ?1",
            params![id, now],
        )?;
        Ok(())
    }

    pub fn mark_reminded(&mut self, id: i64, now: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE incidents SET last_reminder_at = ?2 WHERE id = ?1",
            params![id, now],
        )?;
        Ok(())
    }

    /// Arrête les rappels ; la clôture automatique et son e-mail restent.
    pub fn ack(&mut self, id: i64, now: i64) -> Result<AckOutcome> {
        let Some(incident) = self.incident(id)? else {
            return Ok(AckOutcome::NotFound);
        };
        if incident.closed_at.is_some() {
            return Ok(AckOutcome::AlreadyClosed);
        }
        if incident.acked_at.is_some() {
            return Ok(AckOutcome::AlreadyAcked);
        }
        self.conn.execute(
            "UPDATE incidents SET acked_at = ?2 WHERE id = ?1",
            params![id, now],
        )?;
        Ok(AckOutcome::Acked)
    }

    /// Agents déclarés, par site.
    pub fn agents(&self) -> Result<Vec<Agent>> {
        let sql = format!(
            "SELECT {AGENT_COLUMNS} FROM site_keys k LEFT JOIN reports r ON r.site = k.site
             ORDER BY k.site"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([], agent_from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn agent(&self, site: &str) -> Result<Option<Agent>> {
        let sql = format!(
            "SELECT {AGENT_COLUMNS} FROM site_keys k LEFT JOIN reports r ON r.site = k.site
             WHERE k.site = ?1"
        );
        Ok(self
            .conn
            .query_row(&sql, [site], agent_from_row)
            .optional()?)
    }

    pub fn add_key(&mut self, site: &str, pubkey: &[u8; 32], now: i64) -> Result<KeyOutcome> {
        let inserted = self.conn.execute(
            "INSERT INTO site_keys (site, pubkey, added_at) VALUES (?1, ?2, ?3)
             ON CONFLICT (site) DO NOTHING",
            params![site, pubkey.as_slice(), now],
        )?;
        Ok(if inserted == 1 {
            KeyOutcome::Done
        } else {
            KeyOutcome::AlreadyPresent
        })
    }

    /// Remplace la clé : l'ancienne ne fait plus rien accepter, et la séquence
    /// repart de zéro pour le nouvel agent. Le silence reste mesuré depuis le
    /// dernier rapport accepté.
    pub fn rotate_key(&mut self, site: &str, pubkey: &[u8; 32], now: i64) -> Result<KeyOutcome> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: Option<Vec<u8>> = tx
            .query_row(
                "SELECT pubkey FROM site_keys WHERE site = ?1",
                [site],
                |row| row.get(0),
            )
            .optional()?;
        let outcome = match current {
            None => KeyOutcome::Missing,
            Some(current) if current == pubkey.as_slice() => KeyOutcome::Unchanged,
            Some(_) => {
                tx.execute(
                    "UPDATE site_keys SET pubkey = ?2, rotated_at = ?3, last_logs_seq = 0
                     WHERE site = ?1",
                    params![site, pubkey.as_slice(), now],
                )?;
                tx.execute("UPDATE reports SET last_seq = 0 WHERE site = ?1", [site])?;
                KeyOutcome::Done
            }
        };
        tx.commit()?;
        Ok(outcome)
    }

    /// Retire la clé et l'état des rapports, et purge les logs reçus du site
    /// (entrées, lots, limites hautes) et son analyse (agrégats, curseur,
    /// instantanés, signatures notées). `false` si le site n'avait pas de clé.
    /// Les incidents de l'agent sont clos par le `tick` suivant.
    pub fn remove_key(&mut self, site: &str) -> Result<bool> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let removed = tx.execute("DELETE FROM site_keys WHERE site = ?1", [site])?;
        tx.execute("DELETE FROM reports WHERE site = ?1", [site])?;
        tx.execute("DELETE FROM baselines WHERE site = ?1", [site])?;
        tx.execute("DELETE FROM log_entries WHERE site = ?1", [site])?;
        tx.execute("DELETE FROM log_batches WHERE site = ?1", [site])?;
        tx.execute("DELETE FROM log_marks WHERE site = ?1", [site])?;
        // Agrégats, curseur, instantanés et signatures de l'analyse (#8).
        for table in [
            "log_buckets",
            "log_profiles",
            "log_bots",
            "log_load",
            "log_cursors",
            "log_analysis",
            "log_verdicts",
            "log_signatures",
            // Adresses source des retraits (#13).
            "agent_sources",
        ] {
            tx.execute(&format!("DELETE FROM {table} WHERE site = ?1"), [site])?;
        }
        tx.commit()?;
        Ok(removed == 1)
    }

    /// Prend les empreintes du dernier rapport comme référence et clôt les
    /// incidents d'intégrité. `false` si le site n'a encore aucun rapport.
    pub fn accept_baseline(&mut self, site: &str, now: i64) -> Result<bool> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let files: Option<String> = tx
            .query_row("SELECT files FROM reports WHERE site = ?1", [site], |row| {
                row.get(0)
            })
            .optional()?;
        let Some(files) = files else {
            return Ok(false);
        };
        tx.execute(
            "INSERT INTO baselines (site, files, set_at) VALUES (?1, ?2, ?3)
             ON CONFLICT (site) DO UPDATE SET files = excluded.files, set_at = excluded.set_at",
            params![site, files, now],
        )?;
        reconcile_in(&tx, site, &facts::check_name(), &[], now)?;
        tx.commit()?;
        Ok(true)
    }

    /// Référence d'empreintes d'un site, en JSON, et sa date.
    pub fn baseline(&self, site: &str) -> Result<Option<(String, i64)>> {
        Ok(self
            .conn
            .query_row(
                "SELECT files, set_at FROM baselines WHERE site = ?1",
                [site],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }

    /// Sites qui ont une référence d'empreintes (contexte du registre).
    pub fn baseline_sites(&self) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT site FROM baselines ORDER BY site")?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Constats écartés du dernier rapport accepté de chaque site qui en a
    /// écarté (registre, #4). Vide avant le schéma 14.
    pub fn report_drops(&self) -> Result<Vec<(String, i64)>> {
        if self.schema_version()? < SCHEMA_REGISTRY {
            return Ok(Vec::new());
        }
        let mut stmt = self
            .conn
            .prepare("SELECT site, dropped FROM reports WHERE dropped > 0 ORDER BY site")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Enregistre un rapport authentifié et à l'heure : vérifie la séquence
    /// puis le débit, et, s'il est accepté, fait passer ses constats dans le
    /// cycle des incidents et clôt le silence de l'agent. Tout ou rien, sous
    /// verrou d'écriture : deux rapports simultanés ne passent pas tous deux.
    ///
    /// `pubkey` est la clé qui a vérifié la signature : si elle a changé ou
    /// disparu entre-temps, le rapport est refusé comme d'un site inconnu.
    ///
    /// `findings` décrit l'état complet vu par l'agent : un contrôle `agent:`
    /// ouvert et absent du rapport est clos.
    ///
    /// `watched` est le verdict du registre pour ce site
    /// (`capability::watched`) : seuls les contrôles surveillés sont
    /// réconciliés et reçoivent un passage. Un incident d'un contrôle qui ne
    /// l'est plus n'est donc ni clos « rétabli » ni noté « ok » ici :
    /// `close_unwatched` le clôt « plus surveillé ». Le contexte porte la
    /// référence d'empreintes lue dans la transaction, où le premier rapport
    /// la crée.
    pub fn accept_report(
        &mut self,
        report: &AcceptedReport<'_>,
        now: i64,
        watched: &dyn Fn(&str, &capability::Ctx) -> bool,
    ) -> Result<ReportOutcome> {
        let AcceptedReport {
            site,
            pubkey,
            seq,
            agent,
            facts,
            files,
            findings,
            dropped,
        } = *report;
        let reported: facts::Files =
            serde_json::from_str(files).context("empreintes du rapport illisibles")?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: Option<Vec<u8>> = tx
            .query_row(
                "SELECT pubkey FROM site_keys WHERE site = ?1",
                [site],
                |row| row.get(0),
            )
            .optional()?;
        if current.as_deref() != Some(pubkey.as_slice()) {
            return Ok(ReportOutcome::UnknownSite);
        }
        let last: Option<(i64, i64)> = tx
            .query_row(
                "SELECT last_seq, last_valid_at FROM reports WHERE site = ?1",
                [site],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((last_seq, last_valid_at)) = last {
            if seq <= last_seq {
                return Ok(ReportOutcome::Replay { last_seq });
            }
            if now - last_valid_at < REPORT_MIN_GAP {
                return Ok(ReportOutcome::TooSoon { last_valid_at });
            }
        }
        tx.execute(
            "INSERT INTO reports (site, last_seq, last_valid_at, agent, facts, files, dropped)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT (site) DO UPDATE SET last_seq = excluded.last_seq,
               last_valid_at = excluded.last_valid_at, agent = excluded.agent,
               facts = excluded.facts, files = excluded.files, dropped = excluded.dropped",
            params![
                site,
                seq,
                now,
                agent,
                facts,
                files,
                i64::try_from(dropped).unwrap_or(i64::MAX)
            ],
        )?;
        let mut findings = findings.to_vec();
        let baseline: Option<String> = tx
            .query_row(
                "SELECT files FROM baselines WHERE site = ?1",
                [site],
                |row| row.get(0),
            )
            .optional()?;
        match baseline {
            // Le premier rapport qui porte des empreintes pose la référence.
            None if !reported.is_empty() => {
                tx.execute(
                    "INSERT INTO baselines (site, files, set_at) VALUES (?1, ?2, ?3)",
                    params![site, files, now],
                )?;
            }
            None => {}
            Some(baseline) => {
                let baseline: facts::Files =
                    serde_json::from_str(&baseline).context("référence d'empreintes illisible")?;
                let admitted = std::collections::BTreeMap::from([(
                    crate::command::HTACCESS.to_owned(),
                    crate::command::store::htaccess_admitted(&tx, site)?,
                )]);
                let (drift, next) = facts::compare_admitting(site, &baseline, &reported, &admitted);
                findings.extend(drift);
                if next != baseline {
                    tx.execute(
                        "UPDATE baselines SET files = ?2 WHERE site = ?1",
                        params![site, serde_json::to_string(&next)?],
                    )?;
                }
            }
        }
        // Contrôles touchés : ceux du rapport, ceux qui ont un incident
        // ouvert, et ceux déjà passés, pour qu'un contrôle redevenu sain
        // garde un résultat « ok ». L'intégrité dès qu'une référence existe.
        let mut checks: Vec<String> = {
            let mut stmt = tx.prepare(
                "SELECT DISTINCT check_name FROM incidents
                 WHERE site = ?1 AND closed_at IS NULL AND check_name LIKE 'agent:%'
                 UNION
                 SELECT check_name FROM check_runs
                 WHERE site = ?1 AND check_name LIKE 'agent:%'",
            )?;
            let rows = stmt.query_map([site], |row| row.get(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        checks.extend(findings.iter().map(|f| f.check.clone()));
        let has_baseline: bool = tx
            .query_row(
                "SELECT 1 FROM baselines WHERE site = ?1",
                [site],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if has_baseline {
            checks.push(facts::check_name());
        }
        let ctx = capability::Ctx {
            agent: true,
            baseline: has_baseline,
        };
        checks.retain(|check| watched(check, &ctx));
        checks.sort();
        checks.dedup();
        for check in &checks {
            let of_check: Vec<Finding> = findings
                .iter()
                .filter(|f| f.check == *check)
                .cloned()
                .collect();
            reconcile_in(&tx, site, check, &of_check, now)?;
            record_result_in(&tx, site, check, now, &RunRecord::concluded(&of_check))?;
        }
        if watched(crate::checks::heartbeat::NAME, &ctx) {
            reconcile_in(&tx, site, crate::checks::heartbeat::NAME, &[], now)?;
        }
        tx.commit()?;
        Ok(ReportOutcome::Accepted)
    }

    /// Enregistre un code d'appairage, par son empreinte.
    pub fn create_pairing(
        &mut self,
        code_hash: &Hash,
        name: &str,
        now: i64,
        expires_at: i64,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO pairings (code_hash, name, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![code_hash.as_slice(), name, now, expires_at],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Échange un code contre un appareil, en une transaction : le code est
    /// marqué utilisé et l'appareil créé avec l'empreinte de son jeton. `None`
    /// si le code est inconnu, déjà utilisé ou expiré ; rien n'est écrit.
    pub fn consume_pairing(
        &mut self,
        code_hash: &Hash,
        token_hash: &Hash,
        now: i64,
    ) -> Result<Option<Device>> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // id, empreinte, nom, expiration, utilisation.
        type PairingRow = (i64, Vec<u8>, String, i64, Option<i64>);
        let pairing: Option<PairingRow> = tx
            .query_row(
                "SELECT id, code_hash, name, expires_at, used_at FROM pairings
                 WHERE code_hash = ?1",
                [code_hash.as_slice()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((pairing_id, stored, name, expires_at, used_at)) = pairing else {
            return Ok(None);
        };
        if !same_hash(&stored, code_hash) || used_at.is_some() || now >= expires_at {
            return Ok(None);
        }
        tx.execute(
            "INSERT INTO devices (name, token_hash, created_at) VALUES (?1, ?2, ?3)",
            params![name, token_hash.as_slice(), now],
        )?;
        let device_id = tx.last_insert_rowid();
        tx.execute(
            "UPDATE pairings SET used_at = ?2, device_id = ?3 WHERE id = ?1",
            params![pairing_id, now, device_id],
        )?;
        tx.commit()?;
        Ok(Some(Device {
            id: device_id,
            name,
            created_at: now,
            seen_at: None,
            revoked_at: None,
        }))
    }

    /// Appareil actif (non révoqué) dont le jeton a cette empreinte.
    pub fn device_by_token_hash(&self, token_hash: &Hash) -> Result<Option<Device>> {
        let sql = format!(
            "SELECT {DEVICE_COLUMNS}, token_hash FROM devices
             WHERE token_hash = ?1 AND revoked_at IS NULL"
        );
        let found = self
            .conn
            .query_row(&sql, [token_hash.as_slice()], |row| {
                Ok((device_from_row(row)?, row.get::<_, Vec<u8>>(5)?))
            })
            .optional()?;
        Ok(found
            .filter(|(_, stored)| same_hash(stored, token_hash))
            .map(|(device, _)| device))
    }

    /// Met à jour « vu le », au plus une fois par [`SEEN_PERIOD`].
    pub fn touch_seen(&mut self, id: i64, now: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE devices SET seen_at = ?2
             WHERE id = ?1 AND (seen_at IS NULL OR seen_at <= ?2 - ?3)",
            params![id, now, SEEN_PERIOD],
        )?;
        Ok(())
    }

    pub fn devices(&self) -> Result<Vec<Device>> {
        let sql = format!("SELECT {DEVICE_COLUMNS} FROM devices ORDER BY id");
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([], device_from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Codes d'appairage encore utilisables.
    pub fn pending_pairings(&self, now: i64) -> Result<Vec<Pairing>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, created_at, expires_at FROM pairings
             WHERE used_at IS NULL AND expires_at > ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map([now], |row| {
            Ok(Pairing {
                id: row.get(0)?,
                name: row.get(1)?,
                created_at: row.get(2)?,
                expires_at: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Révoque un appareil : son jeton est refusé dès la requête suivante.
    pub fn revoke_device(&mut self, id: i64, now: i64) -> Result<RevokeOutcome> {
        let revoked: Option<Option<i64>> = self
            .conn
            .query_row(
                "SELECT revoked_at FROM devices WHERE id = ?1",
                [id],
                |row| row.get(0),
            )
            .optional()?;
        match revoked {
            None => Ok(RevokeOutcome::NotFound),
            Some(Some(_)) => Ok(RevokeOutcome::AlreadyRevoked),
            Some(None) => {
                self.conn.execute(
                    "UPDATE devices SET revoked_at = ?2 WHERE id = ?1",
                    params![id, now],
                )?;
                Ok(RevokeOutcome::Revoked)
            }
        }
    }

    /// Adresses source des retraits signés de l'agent d'un site, vues
    /// depuis 30 jours.
    pub fn agent_sources(&self, site: &str, now: i64) -> Result<Vec<std::net::IpAddr>> {
        let mut stmt = self.conn.prepare(
            "SELECT ip FROM agent_sources WHERE site = ?1 AND last_seen >= ?2 ORDER BY ip",
        )?;
        let rows = stmt.query_map(params![site, now - AGENT_SOURCE_RETENTION], |row| {
            row.get::<_, String>(0)
        })?;
        let mut ips = Vec::new();
        for row in rows {
            if let Ok(ip) = row?.parse() {
                ips.push(ip);
            }
        }
        Ok(ips)
    }

    /// Empreintes des fichiers critiques du dernier rapport accepté, en JSON.
    pub fn last_files(&self, site: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT files FROM reports WHERE site = ?1", [site], |row| {
                row.get(0)
            })
            .optional()?)
    }

    /// Dernier relevé (`facts`) accepté d'un site, en JSON.
    pub fn last_facts(&self, site: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT facts FROM reports WHERE site = ?1", [site], |row| {
                row.get(0)
            })
            .optional()?)
    }
}

/// Empreinte lue en base, comparée en temps constant.
impl Store {
    /// Écrit un lot de logs, tout ou rien, sous verrou d'écriture : clé
    /// inchangée, `seq` strictement croissant (avancé même quand le lot est un
    /// doublon), limite haute de `(site, file, gen)`, plafond quotidien, puis
    /// entrées, lot et nouvelle limite dans la même transaction.
    pub fn accept_logs(&mut self, batch: &LogBatch<'_>, now: i64) -> Result<LogsOutcome> {
        use crate::logs::receive::MAX_DAILY_BYTES;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: Option<(Vec<u8>, i64)> = tx
            .query_row(
                "SELECT pubkey, last_logs_seq FROM site_keys WHERE site = ?1",
                [batch.site],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let last_seq = match current {
            Some((key, last_seq)) if key == batch.pubkey.as_slice() => last_seq,
            _ => return Ok(LogsOutcome::UnknownSite),
        };
        if batch.seq <= last_seq {
            return Ok(LogsOutcome::Replay { last_seq });
        }
        let high: Option<i64> = tx
            .query_row(
                "SELECT high FROM log_marks WHERE site = ?1 AND file = ?2 AND gen = ?3",
                params![batch.site, batch.file, batch.generation],
                |row| row.get(0),
            )
            .optional()?;
        let high = high.unwrap_or(0);
        let set_seq = |tx: &rusqlite::Transaction<'_>| {
            tx.execute(
                "UPDATE site_keys SET last_logs_seq = ?2 WHERE site = ?1",
                params![batch.site, batch.seq],
            )
        };
        if batch.end <= high {
            set_seq(&tx)?;
            tx.commit()?;
            return Ok(LogsOutcome::Duplicate);
        }
        if batch.start < high {
            return Ok(LogsOutcome::Overlap { high });
        }
        let day = now.div_euclid(86_400) * 86_400;
        let used: i64 = tx.query_row(
            "SELECT COALESCE(SUM(bytes), 0) FROM log_batches WHERE site = ?1 AND received_at >= ?2",
            params![batch.site, day],
            |row| row.get(0),
        )?;
        if used.saturating_add(batch.bytes) > MAX_DAILY_BYTES {
            return Ok(LogsOutcome::Quota { used });
        }
        set_seq(&tx)?;
        let gap = batch.start - high;
        tx.execute(
            "INSERT INTO log_batches (site, file, gen, range_start, range_end, bytes, gap,
               skipped_files, received_at, accepted, rejected)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                batch.site,
                batch.file,
                batch.generation,
                batch.start,
                batch.end,
                batch.bytes,
                gap,
                batch.skipped_files,
                now,
                i64::try_from(batch.entries.len()).unwrap_or(i64::MAX),
                batch.rejected
            ],
        )?;
        let id = tx.last_insert_rowid();
        {
            let mut insert = tx.prepare(
                "INSERT INTO log_entries (site, batch, timestamp_ms, host, ip, method, path,
                   query_keys, status, size, referer_present, referer_host, user_agent, duration_us)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            )?;
            for e in batch.entries {
                insert.execute(params![
                    batch.site,
                    id,
                    e.timestamp_ms,
                    e.host,
                    e.ip.map(|ip| ip.to_string()),
                    e.method,
                    e.path,
                    serde_json::to_string(&e.query_keys)?,
                    e.status,
                    e.size.and_then(|s| i64::try_from(s).ok()),
                    e.referer_present,
                    e.referer_host,
                    e.user_agent,
                    e.duration_us.and_then(|d| i64::try_from(d).ok()),
                ])?;
            }
        }
        tx.execute(
            "INSERT INTO log_marks (site, file, gen, high, received_at) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (site, file, gen) DO UPDATE SET high = excluded.high,
               received_at = excluded.received_at",
            params![batch.site, batch.file, batch.generation, batch.end, now],
        )?;
        tx.commit()?;
        Ok(LogsOutcome::Accepted { gap })
    }

    /// Conservation de 30 jours (`decisions.md`) : entrées datées d'avant
    /// `now − 30 j`, lots et limites hautes reçus avant. Rend le nombre
    /// d'entrées et de lots effacés.
    pub fn purge_logs(&mut self, now: i64) -> Result<(usize, usize)> {
        use crate::logs::receive::RETENTION;
        let limit = now.saturating_sub(RETENTION);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let entries = tx.execute(
            "DELETE FROM log_entries WHERE timestamp_ms < ?1",
            [limit.saturating_mul(1000)],
        )?;
        let batches = tx.execute("DELETE FROM log_batches WHERE received_at < ?1", [limit])?;
        tx.execute("DELETE FROM log_marks WHERE received_at < ?1", [limit])?;
        tx.commit()?;
        Ok((entries, batches))
    }

    /// Entrées d'un site d'id supérieur à `after`, dans l'ordre des id (ordre
    /// d'arrivée), `limit` au plus, avec leur id.
    pub fn log_entries_after(
        &self,
        site: &str,
        after: i64,
        limit: usize,
    ) -> Result<Vec<(i64, Entry)>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT id, timestamp_ms, host, ip, method, path, query_keys, status, size,
               referer_present, referer_host, user_agent, duration_us
             FROM log_entries WHERE site = ?1 AND id > ?2 ORDER BY id LIMIT ?3",
        )?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let rows = stmt.query_map(params![site, after, limit], |row| {
            let ip: Option<String> = row.get(3)?;
            let keys: String = row.get(6)?;
            let size: Option<i64> = row.get(8)?;
            let duration: Option<i64> = row.get(12)?;
            Ok((
                row.get::<_, i64>(0)?,
                Entry {
                    timestamp_ms: row.get(1)?,
                    host: row.get(2)?,
                    ip: ip.and_then(|ip| ip.parse().ok()),
                    method: row.get(4)?,
                    path: row.get(5)?,
                    query_keys: serde_json::from_str(&keys).unwrap_or_default(),
                    status: row.get(7)?,
                    size: size.and_then(|s| u64::try_from(s).ok()),
                    referer_present: row.get(9)?,
                    referer_host: row.get(10)?,
                    user_agent: row.get(11)?,
                    duration_us: duration.and_then(|d| u64::try_from(d).ok()),
                },
            ))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
}

fn same_hash(stored: &[u8], expected: &Hash) -> bool {
    <&Hash>::try_from(stored).is_ok_and(|stored| device::ct_eq(stored, expected))
}

/// Cœur de [`Store::reconcile`], dans une transaction ouverte par l'appelant.
fn reconcile_in(
    conn: &Connection,
    site: &str,
    check: &str,
    findings: &[Finding],
    now: i64,
) -> Result<()> {
    let mut by_key: HashMap<String, &Finding> = HashMap::new();
    for finding in findings {
        // Deux constats de même clé : le plus grave l'emporte.
        let key = finding.incident_key();
        match by_key.get(&key) {
            Some(kept) if kept.severity >= finding.severity => {}
            _ => {
                by_key.insert(key, finding);
            }
        }
    }
    let open: Vec<(i64, String, String)> = {
        let mut stmt = conn.prepare(
            "SELECT id, key, severity FROM incidents
             WHERE site = ?1 AND check_name = ?2 AND closed_at IS NULL",
        )?;
        let rows = stmt.query_map([site, check], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    for (id, key, severity) in &open {
        match by_key.remove(key) {
            Some(finding) => {
                let before = Severity::parse(severity).unwrap_or(Severity::Critical);
                // Une gravité qui monte vaut un nouvel e-mail d'ouverture.
                let raised = finding.severity > before;
                conn.execute(
                    "UPDATE incidents SET severity = ?2, detail = ?3,
                       open_notified_at = CASE WHEN ?4 THEN NULL ELSE open_notified_at END,
                       last_reminder_at = CASE WHEN ?4 THEN NULL ELSE last_reminder_at END
                     WHERE id = ?1",
                    params![id, finding.severity.as_str(), finding.detail, raised],
                )?;
            }
            None => {
                conn.execute(
                    "UPDATE incidents SET closed_at = ?2 WHERE id = ?1",
                    params![id, now],
                )?;
            }
        }
    }
    let mut fresh: Vec<_> = by_key.into_iter().collect();
    fresh.sort_by(|a, b| a.0.cmp(&b.0));
    for (key, finding) in fresh {
        conn.execute(
            "INSERT INTO incidents (key, site, check_name, severity, detail, opened_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                key,
                site,
                check,
                finding.severity.as_str(),
                finding.detail,
                now
            ],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrates_an_empty_database() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&dir.path().join("vigie.db")).expect("open");
        assert_eq!(store.schema_version().expect("version"), MIGRATIONS.len());
        assert_eq!(store.last_tick().expect("last"), None);
    }

    #[test]
    fn migrations_are_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vigie.db");
        {
            let mut store = Store::open(&path).expect("open");
            store.record_tick(1_000).expect("tick");
        }
        let store = Store::open(&path).expect("reopen");
        assert_eq!(store.schema_version().expect("version"), MIGRATIONS.len());
        assert_eq!(store.last_tick().expect("last"), Some(1_000));
    }

    #[test]
    fn upgrades_a_filled_v4_database_without_loss() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vigie.db");
        {
            let conn = Connection::open(&path).expect("raw");
            for migration in &MIGRATIONS[..SCHEMA_BASELINE] {
                conn.execute_batch(migration).expect("migration");
            }
            conn.pragma_update(None, "user_version", SCHEMA_BASELINE as i64)
                .expect("v4");
            conn.execute_batch(
                "INSERT INTO ticks (at) VALUES (1000);
                 INSERT INTO incidents (key, site, check_name, severity, detail, opened_at)
                   VALUES ('site-a/content/', 'site-a', 'content', 'critical', 'absent', 900);
                 INSERT INTO site_keys (site, pubkey, added_at) VALUES ('site-a', zeroblob(32), 800);
                 INSERT INTO reports (site, last_seq, last_valid_at, agent, facts, files)
                   VALUES ('site-a', 7, 950, 'php/1', '{}', '{\"a\":\"b\"}');
                 INSERT INTO baselines (site, files, set_at) VALUES ('site-a', '{}', 960);",
            )
            .expect("données v4");
        }
        let store = Store::open(&path).expect("open");
        assert_eq!(store.schema_version().expect("version"), MIGRATIONS.len());
        assert_eq!(store.last_tick().expect("tick"), Some(1000));
        let open = store.open_incidents().expect("incidents");
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].detail, "absent");
        let agent = store.agent("site-a").expect("agent").expect("présent");
        assert_eq!(agent.last_seq, 7);
        assert_eq!(
            store.baseline("site-a").expect("baseline").map(|b| b.1),
            Some(960)
        );
        assert!(store.devices().expect("devices").is_empty());
    }

    #[test]
    fn upgrades_a_filled_v5_database_without_loss() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vigie.db");
        {
            let conn = Connection::open(&path).expect("raw");
            for migration in &MIGRATIONS[..SCHEMA_DEVICES] {
                conn.execute_batch(migration).expect("migration");
            }
            conn.pragma_update(None, "user_version", SCHEMA_DEVICES as i64)
                .expect("v5");
            conn.execute_batch(
                "INSERT INTO check_runs (site, check_name, last_run) VALUES ('site-a', 'content', 900);
                 INSERT INTO devices (name, token_hash, created_at) VALUES ('pc', zeroblob(32), 800);",
            )
            .expect("données v5");
        }
        let store = Store::open(&path).expect("open");
        assert_eq!(store.schema_version().expect("version"), MIGRATIONS.len());
        let runs = store.check_results().expect("runs");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].last_run, 900);
        // Passage antérieur : aucun résultat inventé.
        assert_eq!(runs[0].result, None);
        assert_eq!(runs[0].severity, None);
        assert_eq!(runs[0].duration_ms, None);
        assert_eq!(runs[0].observed, None);
        assert_eq!(store.devices().expect("devices").len(), 1);
    }

    #[test]
    fn upgrades_a_filled_v13_database_to_the_registry_without_loss() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vigie.db");
        {
            let conn = Connection::open(&path).expect("raw");
            for migration in &MIGRATIONS[..SCHEMA_AGENT_SOURCES] {
                conn.execute_batch(migration).expect("migration");
            }
            conn.pragma_update(None, "user_version", SCHEMA_AGENT_SOURCES as i64)
                .expect("v13");
            conn.execute_batch(
                "INSERT INTO incidents (key, site, check_name, severity, detail, opened_at)
                   VALUES ('site-a/agent:php/x', 'site-a', 'agent:php', 'critical', 'ouvert', 900);
                 INSERT INTO incidents (key, site, check_name, severity, detail, opened_at, closed_at)
                   VALUES ('site-a/content/k', 'site-a', 'content', 'warning', 'clos', 800, 850);
                 INSERT INTO site_keys (site, pubkey, added_at) VALUES ('site-a', zeroblob(32), 800);
                 INSERT INTO reports (site, last_seq, last_valid_at, agent, facts, files)
                   VALUES ('site-a', 7, 950, 'php/1', '{}', '{}');",
            )
            .expect("données v13");
        }
        // Lecteur d'une base encore en v13 (`status` pendant un déploiement).
        let reader = Store::open_read(&path).expect("lecteur").expect("base");
        let open = reader.open_incidents().expect("incidents v13");
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].close_reason, None);
        assert!(reader.report_drops().expect("drops v13").is_empty());
        drop(reader);

        let mut store = Store::open(&path).expect("open");
        assert_eq!(store.schema_version().expect("version"), SCHEMA_REGISTRY);
        let closed = store.closed_incidents("site-a", 0).expect("clos");
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].close_reason, Some(CloseReason::Resolved));
        let dropped: i64 = store
            .conn
            .query_row(
                "SELECT dropped FROM reports WHERE site = 'site-a'",
                [],
                |r| r.get(0),
            )
            .expect("dropped");
        assert_eq!(dropped, 0);
        assert_eq!(
            store.agent("site-a").expect("agent").expect("clé").last_seq,
            7
        );

        // L'incident d'une famille retirée est clos « plus surveillé ».
        assert_eq!(
            store.close_unwatched(|_, _| false, 1_000).expect("close"),
            1
        );
        let closed = store.incident(open[0].id).expect("lu").expect("présent");
        assert_eq!(closed.closed_at, Some(1_000));
        assert_eq!(closed.close_reason, Some(CloseReason::Unwatched));
        let raw: Option<String> = store
            .conn
            .query_row(
                "SELECT close_reason FROM incidents WHERE id = ?1",
                [closed.id],
                |r| r.get(0),
            )
            .expect("raison");
        assert_eq!(raw.as_deref(), Some("unwatched"));
        assert!(
            store
                .conn
                .execute(
                    "UPDATE incidents SET close_reason = 'autre' WHERE id = ?1",
                    [closed.id]
                )
                .is_err(),
            "raison hors liste refusée par la base"
        );
    }

    #[test]
    fn records_the_result_of_a_run() {
        let (_dir, mut store) = temp_store();
        let findings = [
            Finding::new("site-a", "exposed", Severity::Warning, "a", "premier"),
            Finding::new("site-a", "exposed", Severity::Critical, "b", "grave"),
            Finding::new("site-a", "exposed", Severity::Critical, "c", "grave aussi"),
        ];
        let record = RunRecord::concluded(&findings)
            .with_duration(Duration::from_millis(42))
            .with_observed(Some("{\"http_status\":200}".into()));
        store
            .record_result("site-a", "exposed", 100, &record)
            .expect("record");
        let run = &store.check_results().expect("runs")[0];
        assert_eq!(run.result, Some(RunResult::Finding));
        assert_eq!(run.severity, Some(Severity::Critical));
        assert_eq!(run.detail.as_deref(), Some("grave"));
        assert_eq!(run.duration_ms, Some(42));
        assert_eq!(run.observed.as_deref(), Some("{\"http_status\":200}"));

        store
            .record_result("site-a", "exposed", 200, &RunRecord::failed("délai"))
            .expect("failed");
        let run = &store.check_results().expect("runs")[0];
        assert_eq!(run.last_run, 200);
        assert_eq!(run.result, Some(RunResult::Error));
        assert_eq!(run.severity, None);
        assert_eq!(run.detail.as_deref(), Some("délai"));
        assert_eq!(run.observed, None);

        store.record_run("site-a", "exposed", 300).expect("run");
        let run = &store.check_results().expect("runs")[0];
        assert_eq!((run.last_run, run.result), (300, None));
    }

    #[test]
    fn a_pairing_code_gives_one_device_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = Store::open(&dir.path().join("vigie.db")).expect("open");
        let code = device::hash("code");
        store
            .create_pairing(&code, "téléphone", 1_000, 1_600)
            .expect("pairing");
        assert_eq!(store.pending_pairings(1_000).expect("pending").len(), 1);
        let token = device::hash("jeton");
        let device = store
            .consume_pairing(&code, &token, 1_100)
            .expect("consume")
            .expect("appareil");
        assert_eq!(device.name, "téléphone");
        assert!(store.pending_pairings(1_100).expect("pending").is_empty());
        // Rejoué : rien, et le jeton déjà remis reste valable.
        let other = device::hash("autre");
        assert_eq!(
            store.consume_pairing(&code, &other, 1_200).expect("replay"),
            None
        );
        assert_eq!(store.devices().expect("devices").len(), 1);
        assert_eq!(
            store
                .device_by_token_hash(&token)
                .expect("lookup")
                .map(|d| d.id),
            Some(device.id)
        );
        assert_eq!(store.device_by_token_hash(&other).expect("lookup"), None);
        // Inconnu, puis expiré.
        assert_eq!(
            store
                .consume_pairing(&device::hash("inconnu"), &other, 1_200)
                .expect("unknown"),
            None
        );
        let late = device::hash("tard");
        store
            .create_pairing(&late, "pc", 1_000, 1_600)
            .expect("pairing");
        assert_eq!(
            store
                .consume_pairing(&late, &other, 1_600)
                .expect("expired"),
            None
        );
        assert_eq!(store.devices().expect("devices").len(), 1);
    }

    #[test]
    fn seen_is_rewritten_once_a_minute_and_revocation_is_immediate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = Store::open(&dir.path().join("vigie.db")).expect("open");
        let code = device::hash("code");
        let token = device::hash("jeton");
        store
            .create_pairing(&code, "pc", 1_000, 1_600)
            .expect("pairing");
        let id = store
            .consume_pairing(&code, &token, 1_000)
            .expect("consume")
            .expect("appareil")
            .id;
        let seen = |store: &Store| store.devices().expect("devices")[0].seen_at;
        store.touch_seen(id, 1_010).expect("touch");
        assert_eq!(seen(&store), Some(1_010));
        store
            .touch_seen(id, 1_010 + SEEN_PERIOD - 1)
            .expect("touch");
        assert_eq!(seen(&store), Some(1_010));
        store.touch_seen(id, 1_010 + SEEN_PERIOD).expect("touch");
        assert_eq!(seen(&store), Some(1_010 + SEEN_PERIOD));

        assert_eq!(
            store.revoke_device(id, 2_000).expect("revoke"),
            RevokeOutcome::Revoked
        );
        assert_eq!(store.device_by_token_hash(&token).expect("lookup"), None);
        assert_eq!(
            store.revoke_device(id, 2_001).expect("revoke"),
            RevokeOutcome::AlreadyRevoked
        );
        assert_eq!(
            store.revoke_device(99, 2_001).expect("revoke"),
            RevokeOutcome::NotFound
        );
    }

    #[test]
    fn refuses_a_newer_schema() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vigie.db");
        drop(Store::open(&path).expect("open"));
        let conn = Connection::open(&path).expect("raw");
        conn.pragma_update(None, "user_version", 99).expect("bump");
        drop(conn);
        assert!(Store::open(&path).is_err());
    }

    #[test]
    fn concurrent_opens_migrate_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vigie.db");
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || Store::open(&path).map(|_| ()))
            })
            .collect();
        for handle in handles {
            handle.join().expect("thread").expect("open");
        }
        let store = Store::open(&path).expect("reopen");
        assert_eq!(store.schema_version().expect("version"), MIGRATIONS.len());
    }

    #[test]
    fn open_read_does_not_create_a_missing_database() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("absent").join("vigie.db");
        assert!(Store::open_read(&path).expect("open_read").is_none());
        assert!(!path.exists());
        assert!(!dir.path().join("absent").exists());
    }

    #[test]
    fn open_read_tolerates_a_newer_schema() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vigie.db");
        Store::open(&path)
            .expect("open")
            .record_tick(1_000)
            .expect("tick");
        let conn = Connection::open(&path).expect("raw");
        conn.pragma_update(None, "user_version", 99).expect("bump");
        drop(conn);
        let store = Store::open_read(&path)
            .expect("open_read")
            .expect("present");
        assert_eq!(store.schema_version().expect("version"), 99);
        assert_eq!(store.last_tick().expect("last"), Some(1_000));
    }

    #[test]
    fn uses_wal_and_prunes_old_ticks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = Store::open(&dir.path().join("vigie.db")).expect("open");
        let mode: String = store
            .conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .expect("mode");
        assert_eq!(mode.to_lowercase(), "wal");
        store.record_tick(10).expect("old");
        store.record_tick(10 + TICK_RETENTION + 1).expect("new");
        let count: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM ticks", [], |row| row.get(0))
            .expect("count");
        assert_eq!(count, 1);
    }

    fn crit(key: &str) -> Finding {
        Finding::new(
            "site-a",
            "exposed",
            Severity::Critical,
            key,
            format!("{key} servi"),
        )
    }

    fn temp_store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&dir.path().join("vigie.db")).expect("open");
        (dir, store)
    }

    #[test]
    fn a_repeated_finding_is_one_incident_closed_when_it_disappears() {
        let (_dir, mut store) = temp_store();
        store
            .reconcile("site-a", "exposed", &[crit(".env")], 100)
            .expect("1");
        store
            .reconcile("site-a", "exposed", &[crit(".env"), crit(".env")], 160)
            .expect("2");
        let open = store.open_incidents().expect("open");
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].opened_at, 100);
        assert_eq!(store.pending_opens().expect("pending").len(), 1);
        store.mark_open_notified(open[0].id, 100).expect("mark");
        assert!(store.pending_opens().expect("pending").is_empty());

        store.reconcile("site-a", "exposed", &[], 220).expect("3");
        assert!(store.open_incidents().expect("open").is_empty());
        let closes = store.pending_closes().expect("closes");
        assert_eq!(closes.len(), 1);
        assert_eq!(closes[0].closed_at, Some(220));
        store.mark_close_notified(closes[0].id, 220).expect("mark");
        assert!(store.pending_closes().expect("closes").is_empty());

        // Le même constat qui revient ouvre un nouvel incident.
        store
            .reconcile("site-a", "exposed", &[crit(".env")], 300)
            .expect("4");
        let open = store.open_incidents().expect("open");
        assert_eq!(open.len(), 1);
        assert_ne!(open[0].id, closes[0].id);
    }

    #[test]
    fn reconcile_leaves_other_checks_alone() {
        let (_dir, mut store) = temp_store();
        store
            .reconcile("site-a", "exposed", &[crit(".env")], 100)
            .expect("1");
        store.reconcile("site-a", "content", &[], 100).expect("2");
        store.reconcile("site-b", "exposed", &[], 100).expect("3");
        assert_eq!(store.open_incidents().expect("open").len(), 1);
    }

    #[test]
    fn a_raised_severity_is_announced_again() {
        let (_dir, mut store) = temp_store();
        let warn = Finding::new("site-a", "tls", Severity::Warning, "expiry", "7 j");
        store.reconcile("site-a", "tls", &[warn], 100).expect("1");
        let id = store.open_incidents().expect("open")[0].id;
        store.mark_open_notified(id, 100).expect("mark");
        let critical = Finding::new("site-a", "tls", Severity::Critical, "expiry", "2 j");
        store
            .reconcile("site-a", "tls", &[critical], 200)
            .expect("2");
        let pending = store.pending_opens().expect("pending");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, id);
        assert_eq!(pending[0].detail, "2 j");
    }

    #[test]
    fn info_findings_are_never_notified() {
        let (_dir, mut store) = temp_store();
        let info = Finding::new("site-a", "headers", Severity::Info, "hsts", "absent");
        store
            .reconcile("site-a", "headers", &[info], 100)
            .expect("1");
        assert!(store.pending_opens().expect("pending").is_empty());
        store.reconcile("site-a", "headers", &[], 200).expect("2");
        assert!(store.pending_closes().expect("closes").is_empty());
    }

    #[test]
    fn reminders_stop_once_acknowledged() {
        let (_dir, mut store) = temp_store();
        store
            .reconcile("site-a", "exposed", &[crit(".env"), crit("db.sql")], 0)
            .expect("1");
        let open = store.open_incidents().expect("open");
        for incident in &open {
            store.mark_open_notified(incident.id, 0).expect("mark");
        }
        assert!(
            store
                .due_reminders(REMINDER_PERIOD - 1)
                .expect("due")
                .is_empty()
        );
        assert_eq!(store.ack(open[0].id, 10).expect("ack"), AckOutcome::Acked);
        assert_eq!(
            store.ack(open[0].id, 11).expect("ack"),
            AckOutcome::AlreadyAcked
        );
        assert_eq!(store.ack(999, 11).expect("ack"), AckOutcome::NotFound);
        let due = store.due_reminders(REMINDER_PERIOD).expect("due");
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, open[1].id);
        store
            .mark_reminded(due[0].id, REMINDER_PERIOD)
            .expect("mark");
        assert!(
            store
                .due_reminders(REMINDER_PERIOD + 60)
                .expect("due")
                .is_empty()
        );
        store
            .reconcile("site-a", "exposed", &[], 50)
            .expect("close");
        assert_eq!(
            store.ack(open[1].id, 60).expect("ack"),
            AckOutcome::AlreadyClosed
        );
    }

    #[test]
    fn closes_incidents_of_unwatched_checks() {
        let (_dir, mut store) = temp_store();
        store
            .reconcile("site-a", "exposed", &[crit(".env")], 0)
            .expect("1");
        assert_eq!(
            store
                .close_unwatched(|site, check| site == "site-a" && check == "exposed", 10)
                .expect("kept"),
            0
        );
        assert_eq!(
            store
                .close_unwatched(|site, check| site == "site-b" && check == "exposed", 10)
                .expect("closed"),
            1
        );
        assert!(store.open_incidents().expect("open").is_empty());
    }

    const KEY_A: [u8; 32] = [1; 32];
    const KEY_B: [u8; 32] = [2; 32];

    fn agent_finding(key: &str) -> Finding {
        Finding::new("site-a", "agent:php", Severity::Critical, key, "x")
    }

    fn send(
        store: &mut Store,
        pubkey: &[u8; 32],
        seq: i64,
        agent: &str,
        facts: &str,
        findings: &[Finding],
        now: i64,
    ) -> ReportOutcome {
        let report = AcceptedReport {
            site: "site-a",
            pubkey,
            seq,
            agent,
            facts,
            files: "{}",
            findings,
            dropped: 0,
        };
        store
            .accept_report(&report, now, &|_, _| true)
            .expect("accept_report")
    }

    /// Rapport sans constat de l'agent, avec ces empreintes.
    fn send_files(store: &mut Store, seq: i64, files: &str, now: i64) -> ReportOutcome {
        let report = AcceptedReport {
            site: "site-a",
            pubkey: &KEY_A,
            seq,
            agent: "a/1",
            facts: "{}",
            files,
            findings: &[],
            dropped: 0,
        };
        store
            .accept_report(&report, now, &|_, _| true)
            .expect("accept_report")
    }

    const H1: &str = "33bf0cf98fa40b5f4c44e053816b75487245c5fc01e66dd65470e2e70cbee0d8";
    const H2: &str = "8978bc0aa6aece0fc74de901712dd160c804917cda1ade8afb59f29f526ff94a";

    fn htaccess(hash: &str) -> String {
        format!(r#"{{".htaccess":"{hash}"}}"#)
    }

    fn integrity_incidents(store: &Store) -> Vec<Incident> {
        store
            .open_incidents()
            .expect("open")
            .into_iter()
            .filter(|i| i.check_name == "agent:integrity")
            .collect()
    }

    #[test]
    fn the_first_report_sets_the_baseline_and_a_change_opens_a_warning() {
        let (_dir, mut store) = temp_store();
        store.add_key("site-a", &KEY_A, 0).expect("add");
        // Sans empreintes : pas de référence.
        assert_eq!(
            send_files(&mut store, 1, "{}", 100),
            ReportOutcome::Accepted
        );
        assert_eq!(store.baseline("site-a").expect("baseline"), None);

        assert_eq!(
            send_files(&mut store, 2, &htaccess(H1), 200),
            ReportOutcome::Accepted
        );
        assert_eq!(
            store.baseline("site-a").expect("baseline"),
            Some((htaccess(H1), 200))
        );
        assert!(integrity_incidents(&store).is_empty());

        send_files(&mut store, 3, &htaccess(H2), 300);
        let open = integrity_incidents(&store);
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].severity, Severity::Warning);
        assert_eq!(open[0].key, "site-a/agent:integrity/modified:.htaccess");
        // Toujours différent : le même incident reste ouvert.
        send_files(&mut store, 4, &htaccess(H2), 400);
        assert_eq!(integrity_incidents(&store), open);
        // Restauré : clos.
        send_files(&mut store, 5, &htaccess(H1), 500);
        assert!(integrity_incidents(&store).is_empty());
    }

    #[test]
    fn accepting_the_baseline_closes_the_drift() {
        let (_dir, mut store) = temp_store();
        store.add_key("site-a", &KEY_A, 0).expect("add");
        assert!(!store.accept_baseline("site-a", 50).expect("no report"));
        send_files(&mut store, 1, &htaccess(H1), 100);
        send_files(&mut store, 2, &htaccess(H2), 200);
        assert_eq!(integrity_incidents(&store).len(), 1);

        assert!(store.accept_baseline("site-a", 250).expect("accept"));
        assert!(integrity_incidents(&store).is_empty());
        assert_eq!(
            store.baseline("site-a").expect("baseline"),
            Some((htaccess(H2), 250))
        );
        send_files(&mut store, 3, &htaccess(H2), 300);
        assert!(integrity_incidents(&store).is_empty());
    }

    #[test]
    fn new_paths_join_the_baseline_and_removing_the_key_drops_it() {
        let (_dir, mut store) = temp_store();
        store.add_key("site-a", &KEY_A, 0).expect("add");
        send_files(&mut store, 1, &htaccess(H1), 100);
        let both = format!(r#"{{".htaccess":"{H1}","index.php":"{H2}"}}"#);
        send_files(&mut store, 2, &both, 200);
        assert!(integrity_incidents(&store).is_empty());
        assert_eq!(
            store.baseline("site-a").expect("baseline"),
            Some((both, 100))
        );
        assert!(store.remove_key("site-a").expect("remove"));
        assert_eq!(store.baseline("site-a").expect("baseline"), None);
    }

    #[test]
    fn keys_are_added_once_rotated_and_removed() {
        let (_dir, mut store) = temp_store();
        assert!(store.agent("site-a").expect("none").is_none());
        assert_eq!(
            store.add_key("site-a", &KEY_A, 100).expect("add"),
            KeyOutcome::Done
        );
        assert_eq!(
            store.add_key("site-a", &KEY_B, 110).expect("dup"),
            KeyOutcome::AlreadyPresent
        );
        let agent = store.agent("site-a").expect("agent").expect("some");
        assert_eq!(agent.pubkey, KEY_A);
        assert_eq!(agent.last_seq, 0);
        assert_eq!(agent.last_sign_of_life(), 100);

        assert_eq!(
            send(&mut store, &KEY_A, 5, "a/1", "{}", &[], 200),
            ReportOutcome::Accepted
        );
        assert_eq!(
            store.rotate_key("site-a", &KEY_A, 300).expect("same"),
            KeyOutcome::Unchanged
        );
        assert_eq!(
            store.rotate_key("site-b", &KEY_B, 300).expect("missing"),
            KeyOutcome::Missing
        );
        assert_eq!(
            store.rotate_key("site-a", &KEY_B, 300).expect("rotate"),
            KeyOutcome::Done
        );
        let agent = store.agent("site-a").expect("agent").expect("some");
        assert_eq!(agent.pubkey, KEY_B);
        assert_eq!(agent.rotated_at, Some(300));
        assert_eq!(agent.last_seq, 0);
        assert_eq!(agent.last_sign_of_life(), 200);
        // Vérifié avec l'ancienne clé juste avant la rotation : refusé.
        assert_eq!(
            send(&mut store, &KEY_A, 6, "a/1", "{}", &[], 400),
            ReportOutcome::UnknownSite
        );
        assert_eq!(
            send(&mut store, &KEY_B, 1, "a/1", "{}", &[], 400),
            ReportOutcome::Accepted
        );

        assert!(store.remove_key("site-a").expect("remove"));
        assert!(!store.remove_key("site-a").expect("again"));
        assert!(store.agents().expect("agents").is_empty());
        assert_eq!(store.last_facts("site-a").expect("facts"), None);
    }

    #[test]
    fn reports_need_a_key_a_growing_seq_and_a_gap() {
        let (_dir, mut store) = temp_store();
        assert_eq!(
            send(&mut store, &KEY_A, 1, "a/1", "{}", &[], 100),
            ReportOutcome::UnknownSite
        );
        store.add_key("site-a", &KEY_A, 0).expect("add");
        assert_eq!(
            send(&mut store, &KEY_A, 3, "a/1", r#"{"php":"8.3"}"#, &[], 100),
            ReportOutcome::Accepted
        );
        assert_eq!(
            send(&mut store, &KEY_A, 3, "a/1", "{}", &[], 200),
            ReportOutcome::Replay { last_seq: 3 }
        );
        assert_eq!(
            send(
                &mut store,
                &KEY_A,
                4,
                "a/1",
                "{}",
                &[],
                100 + REPORT_MIN_GAP - 1
            ),
            ReportOutcome::TooSoon { last_valid_at: 100 }
        );
        assert_eq!(
            store.last_facts("site-a").expect("facts").as_deref(),
            Some(r#"{"php":"8.3"}"#)
        );
        assert_eq!(
            send(
                &mut store,
                &KEY_A,
                4,
                "a/2",
                "{}",
                &[],
                100 + REPORT_MIN_GAP
            ),
            ReportOutcome::Accepted
        );
        let agent = store.agent("site-a").expect("agent").expect("some");
        assert_eq!(agent.last_seq, 4);
        assert_eq!(agent.agent.as_deref(), Some("a/2"));
    }

    #[test]
    fn a_report_is_the_full_state_of_the_agent_checks() {
        let (_dir, mut store) = temp_store();
        store.add_key("site-a", &KEY_A, 0).expect("add");
        let silent = Finding::new("site-a", "heartbeat", Severity::Critical, "silent", "x");
        store
            .reconcile("site-a", "heartbeat", &[silent], 50)
            .expect("silent");
        store
            .reconcile("site-a", "exposed", &[crit(".env")], 50)
            .expect("external");
        let findings = [agent_finding("debug"), agent_finding("debug")];
        send(&mut store, &KEY_A, 1, "a/1", "{}", &findings, 100);
        let open = store.open_incidents().expect("open");
        let checks: Vec<_> = open.iter().map(|i| i.check_name.as_str()).collect();
        // Le silence est clos, le contrôle externe intact, le constat ouvert.
        assert_eq!(checks.len(), 2, "{checks:?}");
        assert!(checks.contains(&"exposed"));
        assert!(checks.contains(&"agent:php"));

        send(&mut store, &KEY_A, 2, "a/1", "{}", &[], 200);
        let open = store.open_incidents().expect("open");
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].check_name, "exposed");
    }

    #[test]
    fn closed_incidents_are_paged_by_key_on_their_index() {
        let (_dir, store) = temp_store();
        // Deux incidents clos à la même seconde : l'id départage.
        for (key, site, closed_at) in [
            ("a", "site-a", Some(100)),
            ("b", "site-a", Some(300)),
            ("c", "site-a", Some(300)),
            ("d", "site-a", Some(200)),
            ("e", "site-a", None),
            ("f", "site-b", Some(400)),
            ("g", "site-a", Some(50)),
        ] {
            store
                .conn
                .execute(
                    "INSERT INTO incidents (key, site, check_name, severity, detail, opened_at, closed_at)
                     VALUES (?1, ?2, 'content', 'warning', '', 10, ?3)",
                    params![key, site, closed_at],
                )
                .expect("insert");
        }
        let keys = |page: &[Incident]| page.iter().map(|i| i.key.clone()).collect::<Vec<_>>();
        let first = store
            .closed_incidents_page("site-a", 60, None, 2)
            .expect("page 1");
        assert_eq!(keys(&first), ["c", "b"]);
        let last = first.last().expect("dernier");
        let second = store
            .closed_incidents_page("site-a", 60, Some((last.closed_at.unwrap(), last.id)), 2)
            .expect("page 2");
        assert_eq!(keys(&second), ["d", "a"]);
        let last = second.last().expect("dernier");
        let third = store
            .closed_incidents_page("site-a", 60, Some((last.closed_at.unwrap(), last.id)), 2)
            .expect("page 3");
        assert!(third.is_empty());

        for after in ["", "AND (closed_at, id) < (?3, ?4)"] {
            let plan: Vec<String> = store
                .conn
                .prepare(&format!(
                    "EXPLAIN QUERY PLAN SELECT {INCIDENT_COLUMNS} FROM incidents
                     WHERE site = ?1 AND closed_at >= ?2 {after}
                     ORDER BY closed_at DESC, id DESC LIMIT ?5"
                ))
                .expect("plan")
                .query_map(params!["site-a", 0, 1, 1, 1], |row| row.get(3))
                .expect("plan")
                .collect::<rusqlite::Result<_>>()
                .expect("plan");
            let plan = plan.join(" ; ");
            assert!(plan.contains("incidents_site_closed"), "{plan}");
            assert!(!plan.contains("TEMP B-TREE"), "tri hors index : {plan}");
        }
    }

    #[test]
    fn records_check_runs() {
        let (_dir, mut store) = temp_store();
        assert_eq!(store.last_run("site-a", "content").expect("none"), None);
        store.record_run("site-a", "content", 100).expect("1");
        store.record_run("site-a", "content", 400).expect("2");
        assert_eq!(
            store.last_run("site-a", "content").expect("some"),
            Some(400)
        );
        assert_eq!(store.check_runs().expect("runs").len(), 1);
    }

    #[test]
    fn migration_files_build_the_expected_schema() {
        // `include_str!` donne le même texte sous Windows et sous Linux.
        for (i, migration) in MIGRATIONS.iter().enumerate() {
            assert!(!migration.contains('\r'), "migration {} en CRLF", i + 1);
        }
        let (_dir, store) = temp_store();
        assert_eq!(store.schema_version().expect("version"), SCHEMA_REGISTRY);
        let mut stmt = store
            .conn
            .prepare("SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name")
            .expect("prepare");
        let objects: Vec<(String, String)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("query")
            .collect::<rusqlite::Result<_>>()
            .expect("rows");
        let expected = [
            ("index", "command_audit_site"),
            ("index", "commands_one_open"),
            ("index", "incidents_open_key"),
            ("index", "incidents_site_check"),
            ("index", "incidents_site_closed"),
            ("index", "log_batches_received"),
            ("index", "log_batches_site"),
            ("index", "log_buckets_key"),
            ("index", "log_buckets_minute"),
            ("index", "log_entries_site"),
            ("index", "log_entries_time"),
            ("index", "log_marks_received"),
            ("index", "log_profiles_rank"),
            ("index", "log_signatures_expires"),
            ("index", "log_signatures_site"),
            ("index", "log_verdicts_generated"),
            ("index", "log_verdicts_score"),
            ("index", "ticks_at"),
            ("table", "agent_sources"),
            ("table", "audit_notified"),
            ("table", "baselines"),
            ("table", "check_runs"),
            ("table", "command_audit"),
            ("table", "command_sites"),
            ("table", "commands"),
            ("table", "devices"),
            ("table", "incidents"),
            ("table", "log_analysis"),
            ("table", "log_batches"),
            ("table", "log_bots"),
            ("table", "log_buckets"),
            ("table", "log_cursors"),
            ("table", "log_entries"),
            ("table", "log_load"),
            ("table", "log_marks"),
            ("table", "log_profiles"),
            ("table", "log_signatures"),
            ("table", "log_verdicts"),
            ("table", "meta"),
            ("table", "pairings"),
            ("table", "reports"),
            ("table", "site_keys"),
            ("table", "ticks"),
            ("trigger", "command_audit_no_delete"),
            ("trigger", "command_audit_no_update"),
        ];
        let objects: Vec<(&str, &str)> = objects
            .iter()
            .map(|(kind, name)| (kind.as_str(), name.as_str()))
            .collect();
        assert_eq!(objects, expected);
        // Colonnes ajoutées par ALTER TABLE (migrations 4 et 6).
        let columns = |table: &str| -> Vec<String> {
            let mut stmt = store
                .conn
                .prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))
                .expect("prepare");
            stmt.query_map([], |row| row.get(0))
                .expect("query")
                .collect::<rusqlite::Result<_>>()
                .expect("rows")
        };
        assert_eq!(
            columns("check_runs")[3..],
            ["result", "severity", "detail", "duration_ms", "observed"]
        );
        // Migration 14 : constats écartés, raison de clôture.
        assert_eq!(
            columns("reports").last().map(String::as_str),
            Some("dropped")
        );
        assert_eq!(
            columns("incidents").last().map(String::as_str),
            Some("close_reason")
        );
        // Migration 9 : `seq` des lots de logs, à côté de la clé.
        assert_eq!(
            columns("site_keys").last().map(String::as_str),
            Some("last_logs_seq")
        );
        assert_eq!(columns("log_entries")[0], "id");
    }

    #[test]
    fn open_read_refuses_writes_and_enforces_foreign_keys() {
        let (_dir, store) = temp_store();
        let path = store.conn.path().expect("chemin").to_owned();
        let reader = Store::open_read(Path::new(&path))
            .expect("open_read")
            .expect("présente");
        let err = reader
            .conn
            .execute("INSERT INTO ticks (at) VALUES (1)", [])
            .expect_err("écriture refusée");
        assert!(err.to_string().contains("readonly"), "{err}");
        assert_eq!(foreign_keys(&reader), 1);
        assert_eq!(reader.last_tick().expect("lecture"), None);
    }

    fn foreign_keys(store: &Store) -> i64 {
        store
            .conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .expect("foreign_keys")
    }

    #[test]
    fn every_kind_of_connection_enforces_foreign_keys() {
        let (_dir, store) = temp_store();
        let path = store.conn.path().expect("chemin").to_owned();
        assert_eq!(foreign_keys(&store), 1);
        let writer = Store::open_write(Path::new(&path))
            .expect("open_write")
            .expect("présente");
        assert_eq!(foreign_keys(&writer), 1);
        let reader = Store::open_read(Path::new(&path))
            .expect("open_read")
            .expect("présente");
        assert_eq!(foreign_keys(&reader), 1);
    }

    #[test]
    fn open_write_does_not_create_or_migrate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("absent").join("vigie.db");
        assert!(Store::open_write(&path).expect("open_write").is_none());
        assert!(!path.exists());
        assert!(!dir.path().join("absent").exists());

        // Un fichier sans schéma reste sans schéma : `open_write` ne migre pas.
        let empty = dir.path().join("vide.db");
        Connection::open(&empty).expect("raw");
        let store = Store::open_write(&empty)
            .expect("open_write")
            .expect("présente");
        assert_eq!(store.schema_version().expect("version"), 0);
    }
}
