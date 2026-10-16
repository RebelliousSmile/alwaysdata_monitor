//! Analyseur de logs (issue #8) : invariant quelle que soit la source, il ne
//! voit que des [`crate::logs::Entry`].
//!
//! Phase 1 : le catalogue des robots et le classement d'un UA ([`catalog`]),
//! le glob de chemin des règles ([`glob`]) et les règles déclaratives
//! elles-mêmes ([`rules`]), validées au chargement de `config.toml`.

pub mod catalog;
pub mod glob;
pub mod rules;

#[cfg(test)]
mod tests;
