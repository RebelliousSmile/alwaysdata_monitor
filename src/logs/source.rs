//! Trait `LogSource` : ce qu'un adaptateur rend à l'analyseur.
//!
//! Dyn-compatible (`Vec<Box<dyn LogSource>>`) : la méthode asynchrone rend un
//! [`BoxFuture`] au lieu d'être une `async fn` de trait. Les entrées rendues
//! sont possédées, jamais des vues sur un tampon interne.
//!
//! Un lot est borné par `max_entries` ; `more` dit s'il en reste. L'appelant
//! persiste les entrées d'un lot et le curseur suivant dans une même
//! transaction : côté veilleur, chaque entrée est vue une fois par curseur.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use super::{Entry, Rejection};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Position opaque, propre à l'adaptateur ; le veilleur la persiste sans
/// l'interpréter.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Cursor(pub String);

impl Cursor {
    /// Début de la source.
    pub fn start() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Fetched {
    /// `max_entries` au plus.
    pub entries: Vec<Entry>,
    /// Lignes rejetées dans ce lot, par motif.
    pub rejected: BTreeMap<Rejection, u64>,
    /// Où reprendre.
    pub next: Cursor,
    /// Il reste des entrées après `next`.
    pub more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SourceError {
    #[error("source indisponible : {0}")]
    Unavailable(String),
    /// La position ne vaut plus rien (rotation, fichier remplacé) : reprendre
    /// à `restart`.
    #[error("position invalide, reprise à « {} »", restart.0)]
    CursorInvalid { restart: Cursor },
    #[error("source corrompue : {0}")]
    Corrupt(String),
    #[error("erreur interne : {0}")]
    Internal(String),
}

pub trait LogSource: Send + Sync {
    /// Identifiant stable de la source, pour le journal et le curseur.
    fn id(&self) -> &str;

    fn fetch<'a>(
        &'a self,
        from: &'a Cursor,
        max_entries: usize,
    ) -> BoxFuture<'a, Result<Fetched, SourceError>>;
}

/// Source en mémoire, d'entrées déjà normalisées ; le curseur est le rang de
/// la prochaine entrée. Sert aux tests de l'analyseur (#8) et de #13.
#[derive(Debug, Clone)]
pub struct MemorySource {
    id: String,
    entries: Vec<Entry>,
}

impl MemorySource {
    pub fn new(id: impl Into<String>, entries: Vec<Entry>) -> Self {
        Self {
            id: id.into(),
            entries,
        }
    }
}

impl LogSource for MemorySource {
    fn id(&self) -> &str {
        &self.id
    }

    fn fetch<'a>(
        &'a self,
        from: &'a Cursor,
        max_entries: usize,
    ) -> BoxFuture<'a, Result<Fetched, SourceError>> {
        Box::pin(async move {
            let start = if from.0.is_empty() {
                0
            } else {
                from.0
                    .parse::<usize>()
                    .ok()
                    .filter(|&rank| rank <= self.entries.len())
                    .ok_or_else(|| SourceError::CursorInvalid {
                        restart: Cursor::start(),
                    })?
            };
            let end = start.saturating_add(max_entries).min(self.entries.len());
            Ok(Fetched {
                entries: self.entries[start..end].to_vec(),
                rejected: BTreeMap::new(),
                next: Cursor(end.to_string()),
                more: end < self.entries.len(),
            })
        })
    }
}
