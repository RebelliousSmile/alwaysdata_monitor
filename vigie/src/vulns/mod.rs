//! Failles connues (issues #14 à #22) : modèle interne, comparateurs de
//! versions et rapprochement d'un composant (purl et version) avec les
//! failles d'une source.
//!
//! Sources, standards et conventions : `docs/failles.md`. Le modèle ne
//! télécharge rien : la synchronisation des bases ([`sync`], F2) l'alimente.

pub mod advisory;
pub mod corrections;
pub mod cvss;
pub mod purl;
pub mod range;
pub mod sources;
pub mod store;
pub mod sync;
pub mod version;

pub use advisory::{Advisory, Draft, Reason, Score, ScoreOrigin, Tally, from_osv};
pub use purl::Purl;
pub use range::{UnknownReason, Verdict, match_advisory};

/// Erreur d'usage de la CLI (`vigie vulns`) : purl ou identifiant mal formé.
/// Rendue avec le code 2, comme une erreur de configuration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct UsageError(pub String);
