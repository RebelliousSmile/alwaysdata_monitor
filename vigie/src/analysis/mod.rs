//! Analyseur de logs (issue #8) : invariant quelle que soit la source, il ne
//! voit que des [`crate::logs::Entry`].
//!
//! Phase 1 : le catalogue des robots et le classement d'un UA ([`catalog`]),
//! le glob de chemin des règles ([`glob`]) et les règles déclaratives
//! elles-mêmes ([`rules`]), validées au chargement de `config.toml`.
//!
//! Phase 2 : le repli incrémental d'un lot d'entrées ([`fold`]) dans des
//! agrégats persistés ([`store`]) : seaux par minute des règles, profils
//! d'IP glissants sur 24 h plafonnés par Space-Saving ([`profile`]), score
//! de suspicion porté du module ([`score`]), robots et charge par heure
//! ([`load`]).

pub mod catalog;
pub mod fold;
pub mod glob;
pub mod load;
pub mod profile;
pub mod rules;
pub mod score;
pub mod store;

#[cfg(test)]
mod fold_tests;
#[cfg(test)]
mod tests;
