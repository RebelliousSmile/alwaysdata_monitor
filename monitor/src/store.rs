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
];

/// Version de schéma à partir de laquelle les incidents existent.
pub const SCHEMA_INCIDENTS: usize = 2;

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
        let tx = self.conn.transaction()?;
        let open: Vec<(i64, String, String)> = {
            let mut stmt = tx.prepare(
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
                    tx.execute(
                        "UPDATE incidents SET severity = ?2, detail = ?3,
                           open_notified_at = CASE WHEN ?4 THEN NULL ELSE open_notified_at END,
                           last_reminder_at = CASE WHEN ?4 THEN NULL ELSE last_reminder_at END
                         WHERE id = ?1",
                        params![id, finding.severity.as_str(), finding.detail, raised],
                    )?;
                }
                None => {
                    tx.execute(
                        "UPDATE incidents SET closed_at = ?2 WHERE id = ?1",
                        params![id, now],
                    )?;
                }
            }
        }
        let mut fresh: Vec<_> = by_key.into_iter().collect();
        fresh.sort_by(|a, b| a.0.cmp(&b.0));
        for (key, finding) in fresh {
            tx.execute(
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
        tx.commit()?;
        Ok(())
    }

    /// Clôt les incidents ouverts dont le couple (site, contrôle) n'est plus
    /// surveillé : site retiré de la configuration, ou type de site changé.
    pub fn close_unwatched(&mut self, watched: &[(&str, &str)], now: i64) -> Result<usize> {
        let stale: Vec<i64> = self
            .open_incidents()?
            .into_iter()
            .filter(|i| {
                !watched
                    .iter()
                    .any(|(site, check)| i.site == *site && i.check_name == *check)
            })
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrates_an_empty_database() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&dir.path().join("monitor.db")).expect("open");
        assert_eq!(store.schema_version().expect("version"), MIGRATIONS.len());
        assert_eq!(store.last_tick().expect("last"), None);
    }

    #[test]
    fn migrations_are_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("monitor.db");
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
        let path = dir.path().join("monitor.db");
        drop(Store::open(&path).expect("open"));
        let conn = Connection::open(&path).expect("raw");
        conn.pragma_update(None, "user_version", 99).expect("bump");
        drop(conn);
        assert!(Store::open(&path).is_err());
    }

    #[test]
    fn concurrent_opens_migrate_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("monitor.db");
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
        let path = dir.path().join("absent").join("monitor.db");
        assert!(Store::open_read(&path).expect("open_read").is_none());
        assert!(!path.exists());
        assert!(!dir.path().join("absent").exists());
    }

    #[test]
    fn open_read_tolerates_a_newer_schema() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("monitor.db");
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
        let mut store = Store::open(&dir.path().join("monitor.db")).expect("open");
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
        let store = Store::open(&dir.path().join("monitor.db")).expect("open");
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
                .close_unwatched(&[("site-a", "exposed")], 10)
                .expect("kept"),
            0
        );
        assert_eq!(
            store
                .close_unwatched(&[("site-b", "exposed")], 10)
                .expect("closed"),
            1
        );
        assert!(store.open_incidents().expect("open").is_empty());
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
