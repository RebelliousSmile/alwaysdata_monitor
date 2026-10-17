//! Failles connues (issues #14 à #22) : modèle interne, comparateurs de
//! versions et rapprochement d'un composant (purl et version) avec les
//! failles d'une source.
//!
//! Sources, standards et conventions : `docs/failles.md`. Ce module ne
//! télécharge rien (F2, F3) : il porte le modèle sur lequel les imports
//! s'appuient.

pub mod version;
