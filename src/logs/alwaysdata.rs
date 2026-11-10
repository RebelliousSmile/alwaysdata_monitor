//! `AlwaysdataSource` : les entrées reçues de l'agent d'un site Alwaysdata
//! (`logs/receive.rs`), servies à l'analyseur par le contrat [`LogSource`].
//!
//! Le curseur est le dernier id de `log_entries` servi, en décimal ; vide au
//! début. `log_entries.id` est en AUTOINCREMENT : après une purge totale, les
//! entrées nouvelles ont des id plus grands que tout curseur rendu, rien
//! n'est sauté. L'ordre des id est l'ordre d'arrivée, pas celui du temps
//! (rattrapage d'un retard, `docs/logs.md`).
//!
//! Les rejets restent comptés par lot dans `log_batches` : `rejected` est
//! toujours vide ici.
//!
//! La lecture est courte et indexée (`(site, id)`) : elle se fait dans le
//! future, sur une connexion en lecture seule ouverte à chaque appel.

use std::path::PathBuf;

use super::source::{BoxFuture, Cursor, Fetched, LogSource, SourceError};
use crate::store::Store;

#[derive(Debug, Clone)]
pub struct AlwaysdataSource {
    id: String,
    site: String,
    database: PathBuf,
}

impl AlwaysdataSource {
    /// Source du site `site`, lue dans la base du veilleur.
    pub fn new(site: impl Into<String>, database: impl Into<PathBuf>) -> Self {
        let site = site.into();
        Self {
            id: format!("alwaysdata:{site}"),
            site,
            database: database.into(),
        }
    }

    fn read(&self, from: &Cursor, max_entries: usize) -> Result<Fetched, SourceError> {
        let after = if from.0.is_empty() {
            0
        } else {
            from.0
                .parse::<i64>()
                .ok()
                .filter(|&id| id >= 0)
                .ok_or_else(|| SourceError::CursorInvalid {
                    restart: Cursor::start(),
                })?
        };
        let store = Store::open_read(&self.database)
            .map_err(|e| SourceError::Unavailable(format!("{e:#}")))?;
        let Some(store) = store else {
            // Base pas encore créée : rien reçu.
            return Ok(Fetched {
                next: from.clone(),
                ..Fetched::default()
            });
        };
        let mut rows = store
            .log_entries_after(&self.site, after, max_entries.saturating_add(1))
            .map_err(|e| SourceError::Internal(format!("{e:#}")))?;
        let more = rows.len() > max_entries;
        rows.truncate(max_entries);
        let next = match rows.last() {
            Some((id, _)) => Cursor(id.to_string()),
            None => from.clone(),
        };
        Ok(Fetched {
            entries: rows.into_iter().map(|(_, entry)| entry).collect(),
            rejected: Default::default(),
            next,
            more,
        })
    }
}

impl LogSource for AlwaysdataSource {
    fn id(&self) -> &str {
        &self.id
    }

    fn fetch<'a>(
        &'a self,
        from: &'a Cursor,
        max_entries: usize,
    ) -> BoxFuture<'a, Result<Fetched, SourceError>> {
        Box::pin(async move { self.read(from, max_entries) })
    }
}
