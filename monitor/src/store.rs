//! Base SQLite partagée par `serve` et `tick`.
//!
//! WAL pour que `serve` lise pendant que `tick` écrit. Le WAL n'est sûr que si
//! les deux processus tournent sur le même hôte et sur un système de fichiers
//! local : c'est le cas sur le disque du VPS (`docs/hebergement.md`).

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior};

/// Une entrée par version de schéma, jouée dans l'ordre. Ne jamais modifier une
/// migration déjà publiée : en ajouter une.
const MIGRATIONS: &[&str] = &[
    // 1 : passages de `tick`, en secondes Unix.
    "CREATE TABLE ticks (
        id INTEGER PRIMARY KEY,
        at INTEGER NOT NULL
    );
    CREATE INDEX ticks_at ON ticks(at);",
];

/// Historique des passages conservé, en secondes.
const TICK_RETENTION: i64 = 7 * 24 * 3600;

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("création de {}", parent.display()))?;
        }
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
}
