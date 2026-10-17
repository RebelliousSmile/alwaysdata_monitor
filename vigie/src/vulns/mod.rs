//! Failles connues (issues #14 à #22) : modèle interne, comparateurs de
//! versions et rapprochement d'un composant (purl et version) avec les
//! failles d'une source.
//!
//! Sources, standards et conventions : `docs/failles.md`. Ce module ne
//! télécharge rien (F2, F3) : il porte le modèle sur lequel les imports
//! s'appuient.

pub mod advisory;
pub mod cvss;
pub mod purl;
pub mod range;
pub mod store;
pub mod version;

pub use advisory::{Advisory, Draft, Reason, Score, ScoreOrigin, Tally, from_osv};
pub use purl::Purl;
pub use range::{UnknownReason, Verdict, match_advisory};

/// Erreur d'usage de la CLI (`vigie vulns`) : purl ou identifiant mal formé.
/// Rendue avec le code 2, comme une erreur de configuration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct UsageError(pub String);
