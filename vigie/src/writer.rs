//! Écrivain unique de `serve`.
//!
//! Dans `serve`, toutes les écritures (rapports d'agent, appairage, « vu le »,
//! acquittement, révocation) passent par une seule connexion, gardée sous
//! `Mutex` : elles sont sérialisées, et aucune ne rejoue `migrate()` comme le
//! ferait un `Store::open` par requête. Entre processus (`serve`, `tick`, la
//! CLI), la sérialisation reste celle de SQLite : WAL, `busy_timeout` et
//! transactions d'écriture IMMEDIATE (`store.rs`).
//!
//! La connexion s'ouvre à la première écriture, par [`Store::open_write`] : sans
//! créer la base et sans la migrer. `serve` ne crée pas la base, et tolère un
//! schéma plus récent pendant un déploiement.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Result, anyhow};

use crate::store::Store;

pub struct Writer {
    path: PathBuf,
    conn: Mutex<Option<Store>>,
    /// Nombre d'ouvertures de connexion, pour prouver qu'il n'y en a qu'une.
    #[cfg(test)]
    opens: AtomicUsize,
}

impl Writer {
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            conn: Mutex::new(None),
            #[cfg(test)]
            opens: AtomicUsize::new(0),
        }
    }

    /// Exécute `f` sur la connexion d'écriture. `Ok(None)` si la base n'existe
    /// pas (ou plus) : l'appelant la traite comme une base absente.
    ///
    /// Bloque jusqu'à la fin des écritures déjà en cours, puis `f` : à appeler
    /// depuis `tokio::task::spawn_blocking`, jamais depuis une tâche async.
    pub fn write<R>(&self, f: impl FnOnce(&mut Store) -> Result<R>) -> Result<Option<R>> {
        let mut guard = self
            .conn
            .lock()
            .map_err(|_| anyhow!("verrou de l'écrivain empoisonné"))?;
        // Une base supprimée n'est plus celle que la connexion garde.
        if !self.path.is_file() {
            *guard = None;
            return Ok(None);
        }
        if guard.is_none() {
            let Some(store) = Store::open_write(&self.path)? else {
                return Ok(None);
            };
            #[cfg(test)]
            self.opens.fetch_add(1, Ordering::Relaxed);
            *guard = Some(store);
        }
        match guard.as_mut() {
            Some(store) => f(store).map(Some),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn migrated_database() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vigie.db");
        drop(Store::open(&path).expect("open"));
        (dir, path)
    }

    #[test]
    fn two_writes_open_one_connection() {
        let (_dir, path) = migrated_database();
        let writer = Writer::new(&path);
        assert_eq!(writer.opens.load(Ordering::Relaxed), 0);
        for now in [1_000, 1_001] {
            writer
                .write(|store| store.record_tick(now))
                .expect("write")
                .expect("base présente");
        }
        assert_eq!(writer.opens.load(Ordering::Relaxed), 1);
        let store = Store::open_read(&path).expect("open_read").expect("base");
        assert_eq!(store.last_tick().expect("last"), Some(1_001));
    }

    #[test]
    fn a_missing_database_is_reported_and_not_created() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("absent").join("vigie.db");
        let writer = Writer::new(&path);
        let outcome = writer.write(|store| store.record_tick(1_000));
        assert!(matches!(outcome, Ok(None)));
        assert!(!path.exists());
        assert!(!dir.path().join("absent").exists());
        assert_eq!(writer.opens.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_newer_schema_is_written_without_migrating() {
        let (_dir, path) = migrated_database();
        let conn = rusqlite::Connection::open(&path).expect("raw");
        conn.pragma_update(None, "user_version", 7).expect("bump");
        drop(conn);
        let writer = Writer::new(&path);
        writer
            .write(|store| store.record_tick(1_000))
            .expect("écriture acceptée")
            .expect("base présente");
        let store = Store::open_read(&path).expect("open_read").expect("base");
        assert_eq!(store.schema_version().expect("version"), 7);
        assert_eq!(store.last_tick().expect("last"), Some(1_000));
    }

    #[test]
    fn a_poisoned_lock_is_an_error_not_a_panic() {
        let (_dir, path) = migrated_database();
        let writer = std::sync::Arc::new(Writer::new(&path));
        let poisoner = std::sync::Arc::clone(&writer);
        let _ = std::thread::spawn(move || {
            let _ = poisoner.write(|_| -> Result<()> { panic!("écriture interrompue") });
        })
        .join();
        assert!(writer.write(|store| store.record_tick(1_000)).is_err());
    }
}
