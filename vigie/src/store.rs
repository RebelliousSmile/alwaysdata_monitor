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

use crate::facts;
use crate::finding::{Finding, Severity};

/// Une entrée par version de schéma, jouée dans l'ordre. Ne jamais modifier une
/// migration déjà publiée : en ajouter une.
const MIGRATIONS: &[&str] = &[
    // 1 : passages de `tick`, en secondes Unix.
    "CREATE TABLE ticks (
        id INTEGER PRIMARY KEY,
        at INTEGER NOT NULL
    );
    CREATE INDEX ticks_at ON ticks(at);",
    // 2 : dernier passage de chaque contrôle, et incidents. Un seul incident
    // ouvert par clé ; les dates sont en secondes Unix.
    "CREATE TABLE check_runs (
        site TEXT NOT NULL,
        check_name TEXT NOT NULL,
        last_run INTEGER NOT NULL,
        PRIMARY KEY (site, check_name)
    );
    CREATE TABLE incidents (
        id INTEGER PRIMARY KEY,
        key TEXT NOT NULL,
        site TEXT NOT NULL,
        check_name TEXT NOT NULL,
        severity TEXT NOT NULL,
        detail TEXT NOT NULL,
        opened_at INTEGER NOT NULL,
        closed_at INTEGER,
        acked_at INTEGER,
        open_notified_at INTEGER,
        close_notified_at INTEGER,
        last_reminder_at INTEGER
    );
    CREATE UNIQUE INDEX incidents_open_key ON incidents(key) WHERE closed_at IS NULL;
    CREATE INDEX incidents_site_check ON incidents(site, check_name);",
    // 3 : clé publique de l'agent de chaque site (Ed25519, 32 octets), et état
    // de ses rapports : dernier `seq` accepté, date de réception, dernier relevé.
    "CREATE TABLE site_keys (
        site TEXT PRIMARY KEY,
        pubkey BLOB NOT NULL CHECK (length(pubkey) = 32),
        added_at INTEGER NOT NULL,
        rotated_at INTEGER
    );
    CREATE TABLE reports (
        site TEXT PRIMARY KEY,
        last_seq INTEGER NOT NULL,
        last_valid_at INTEGER NOT NULL,
        agent TEXT NOT NULL,
        facts TEXT NOT NULL
    );",
    // 4 : empreintes des fichiers critiques du dernier rapport, et référence
    // à laquelle elles sont comparées (`facts.rs`), en JSON.
    "ALTER TABLE reports ADD COLUMN files TEXT NOT NULL DEFAULT '{}';
    CREATE TABLE baselines (
        site TEXT PRIMARY KEY,
        files TEXT NOT NULL,
        set_at INTEGER NOT NULL
    );",
];

/// Version de schéma à partir de laquelle les incidents existent.
pub const SCHEMA_INCIDENTS: usize = 2;
/// Version de schéma à partir de laquelle les clés d'agent existent.
pub const SCHEMA_AGENTS: usize = 3;
/// Version de schéma à partir de laquelle les références d'empreintes existent.
pub const SCHEMA_BASELINE: usize = 4;

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckOutcome {
    NotFound,
    AlreadyClosed,
    AlreadyAcked,
    Acked,
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
    /// Contrôles déjà préfixés par `agent:`.
    pub findings: &'a [Finding],
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

const INCIDENT_COLUMNS: &str =
    "id, key, site, check_name, severity, detail, opened_at, closed_at, acked_at";

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
    })
}

/// Historique des passages conservé, en secondes.
const TICK_RETENTION: i64 = 7 * 24 * 3600;

pub struct Store {
    conn: Connection,
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
        conn.busy_timeout(Duration::from_secs(5))?;
        let mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        if !mode.eq_ignore_ascii_case("wal") {
            anyhow::bail!(
                "{} refuse le mode WAL (journal_mode={mode})",
                path.display()
            );
        }
        conn.execute_batch("PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;")?;
        let mut store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    /// Ouverture en lecteur, pour `/health` et `status` : ne crée ni le fichier
    /// ni son dossier, ne migre pas, ne change pas le mode de journal, et tolère
    /// un schéma plus récent que le binaire (pendant un déploiement, `serve`
    /// garde l'ancien binaire en mémoire). `None` si la base n'existe pas encore.
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
        let tx = self.conn.transaction()?;
        tx.execute("INSERT INTO ticks (at) VALUES (?1)", [now])?;
        tx.execute("DELETE FROM ticks WHERE at < ?1", [now - TICK_RETENTION])?;
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

    pub fn record_run(&mut self, site: &str, check: &str, now: i64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO check_runs (site, check_name, last_run) VALUES (?1, ?2, ?3)
             ON CONFLICT (site, check_name) DO UPDATE SET last_run = excluded.last_run",
            params![site, check, now],
        )?;
        Ok(())
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
        let tx = self.conn.transaction()?;
        reconcile_in(&tx, site, check, findings, now)?;
        tx.commit()?;
        Ok(())
    }

    /// Clôt les incidents ouverts dont le couple (site, contrôle) n'est plus
    /// surveillé : site retiré de la configuration, type de site changé, ou
    /// clé d'agent retirée.
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
        let tx = self.conn.transaction()?;
        for id in &stale {
            tx.execute(
                "UPDATE incidents SET closed_at = ?2 WHERE id = ?1",
                params![id, now],
            )?;
        }
        tx.commit()?;
        Ok(stale.len())
    }

    fn incidents_where(
        &self,
        clause: &str,
        args: &[&dyn rusqlite::ToSql],
    ) -> Result<Vec<Incident>> {
        let sql = format!("SELECT {INCIDENT_COLUMNS} FROM incidents WHERE {clause} ORDER BY id");
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
                    "UPDATE site_keys SET pubkey = ?2, rotated_at = ?3 WHERE site = ?1",
                    params![site, pubkey.as_slice(), now],
                )?;
                tx.execute("UPDATE reports SET last_seq = 0 WHERE site = ?1", [site])?;
                KeyOutcome::Done
            }
        };
        tx.commit()?;
        Ok(outcome)
    }

    /// Retire la clé et l'état des rapports. `false` si le site n'avait pas de
    /// clé. Les incidents de l'agent sont clos par le `tick` suivant.
    pub fn remove_key(&mut self, site: &str) -> Result<bool> {
        let tx = self.conn.transaction()?;
        let removed = tx.execute("DELETE FROM site_keys WHERE site = ?1", [site])?;
        tx.execute("DELETE FROM reports WHERE site = ?1", [site])?;
        tx.execute("DELETE FROM baselines WHERE site = ?1", [site])?;
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
    pub fn accept_report(
        &mut self,
        report: &AcceptedReport<'_>,
        now: i64,
    ) -> Result<ReportOutcome> {
        let AcceptedReport {
            site,
            pubkey,
            seq,
            agent,
            facts,
            files,
            findings,
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
            "INSERT INTO reports (site, last_seq, last_valid_at, agent, facts, files)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (site) DO UPDATE SET last_seq = excluded.last_seq,
               last_valid_at = excluded.last_valid_at, agent = excluded.agent,
               facts = excluded.facts, files = excluded.files",
            params![site, seq, now, agent, facts, files],
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
                let (drift, next) = facts::compare(site, &baseline, &reported);
                findings.extend(drift);
                if next != baseline {
                    tx.execute(
                        "UPDATE baselines SET files = ?2 WHERE site = ?1",
                        params![site, serde_json::to_string(&next)?],
                    )?;
                }
            }
        }
        let mut checks: Vec<String> = {
            let mut stmt = tx.prepare(
                "SELECT DISTINCT check_name FROM incidents
                 WHERE site = ?1 AND closed_at IS NULL AND check_name LIKE 'agent:%'",
            )?;
            let rows = stmt.query_map([site], |row| row.get(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        checks.extend(findings.iter().map(|f| f.check.clone()));
        checks.sort();
        checks.dedup();
        for check in &checks {
            let of_check: Vec<Finding> = findings
                .iter()
                .filter(|f| f.check == *check)
                .cloned()
                .collect();
            reconcile_in(&tx, site, check, &of_check, now)?;
        }
        reconcile_in(&tx, site, crate::checks::heartbeat::NAME, &[], now)?;
        tx.commit()?;
        Ok(ReportOutcome::Accepted)
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
        };
        store.accept_report(&report, now).expect("accept_report")
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
        };
        store.accept_report(&report, now).expect("accept_report")
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
}
