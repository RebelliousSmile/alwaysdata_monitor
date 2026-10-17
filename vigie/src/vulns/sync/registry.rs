//! Sources connues du veilleur : liste fermée, seule admise dans
//! `[vulns] sources`.
//!
//! Point d'extension : une source (F3 : `wordfence`, `friends-of-presta` ;
//! F4 : `kev`, `epss`) entre dans [`KNOWN`] à sa place d'exécution et dans
//! [`build`] ; un test exige que chaque identifiant de [`KNOWN`] se
//! construise sous ce même identifiant.

use super::VulnSource;
use crate::config::Config;
use crate::vulns::sources::osv::OsvSource;
use crate::vulns::version::SourceEcosystem;

/// Identifiants admis, dans l'ordre de synchronisation (petites sources
/// d'abord : une source lente ne prive pas les autres).
pub const KNOWN: &[&str] = &["osv-crates-io", "osv-packagist", "osv-npm"];

/// Source d'un identifiant de [`KNOWN`].
pub fn build(id: &str) -> Option<Box<dyn VulnSource>> {
    let ecosystem = match id {
        "osv-crates-io" => SourceEcosystem::CratesIo,
        "osv-packagist" => SourceEcosystem::Packagist,
        "osv-npm" => SourceEcosystem::Npm,
        _ => return None,
    };
    Some(Box::new(OsvSource { ecosystem }))
}

/// Sources de `[vulns] sources`, dans l'ordre de [`KNOWN`] ; vide sans
/// section.
pub fn declared(config: &Config) -> Vec<&'static str> {
    let Some(vulns) = &config.vulns else {
        return Vec::new();
    };
    KNOWN
        .iter()
        .copied()
        .filter(|id| vulns.sources.iter().any(|s| s == id))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_known_source_builds_under_its_id() {
        for id in KNOWN {
            let source = build(id).unwrap_or_else(|| panic!("{id}"));
            assert_eq!(source.id(), *id);
        }
        assert!(build("osv-pypi").is_none());
    }
}
