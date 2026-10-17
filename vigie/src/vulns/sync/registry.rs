//! Sources connues du veilleur : liste fermée, seule admise dans
//! `[vulns] sources`.
//!
//! Point d'extension : une source (F3 : `wordfence`, `friends-of-presta` ;
//! F4 : `kev`, `epss`) entre dans [`KNOWN`] à sa place d'exécution, dans
//! [`build`] et dans [`redistribution`] ; un test exige que chaque
//! identifiant de [`KNOWN`] se construise sous ce même identifiant et ait un
//! niveau de redistribution.

use super::VulnSource;
use crate::config::Config;
use crate::vulns::sources::Redistribution;
use crate::vulns::sources::friends_of_presta::FriendsOfPresta;
use crate::vulns::sources::osv::OsvSource;
use crate::vulns::sources::wordfence::Wordfence;
use crate::vulns::version::SourceEcosystem;

/// Identifiants admis, dans l'ordre de synchronisation (petites sources
/// d'abord : une source lente ne prive pas les autres).
pub const KNOWN: &[&str] = &[
    "osv-crates-io",
    "osv-packagist",
    "friends-of-presta",
    "wordfence",
    "osv-npm",
];

/// Source d'un identifiant de [`KNOWN`], sans sa configuration (Wordfence
/// sans `[vulns.wordfence]` refuse toute synchronisation).
pub fn build(id: &str) -> Option<Box<dyn VulnSource>> {
    let ecosystem = match id {
        "osv-crates-io" => SourceEcosystem::CratesIo,
        "osv-packagist" => SourceEcosystem::Packagist,
        "osv-npm" => SourceEcosystem::Npm,
        "friends-of-presta" => return Some(Box::new(FriendsOfPresta)),
        "wordfence" => return Some(Box::new(Wordfence::new(None))),
        _ => return None,
    };
    Some(Box::new(OsvSource { ecosystem }))
}

/// Source d'un identifiant de [`KNOWN`] avec sa section de configuration
/// (`[vulns.wordfence]`).
pub fn build_with(config: &Config, id: &str) -> Option<Box<dyn VulnSource>> {
    match id {
        "wordfence" => Some(Box::new(Wordfence::new(
            config.vulns.as_ref().and_then(|v| v.wordfence.clone()),
        ))),
        _ => build(id),
    }
}

/// Ce que les failles d'une source permettent de transmettre à un tiers
/// (F7 : API, rapports). `None` pour un identifiant inconnu du binaire, que
/// l'appelant traite comme [`Redistribution::Internal`] (fail-closed). Un
/// bras explicite par identifiant de [`KNOWN`], F4 comprises.
pub fn redistribution(source_id: &str) -> Option<Redistribution> {
    match source_id {
        "wordfence" => Some(Redistribution::Internal),
        "friends-of-presta" => Some(Redistribution::FactsOnly),
        "osv-crates-io" => Some(Redistribution::Free),
        "osv-packagist" => Some(Redistribution::Free),
        "osv-npm" => Some(Redistribution::Free),
        "kev" => Some(Redistribution::Free),
        "epss" => Some(Redistribution::Free),
        _ => None,
    }
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

    #[test]
    fn redistribution_covers_known() {
        for id in KNOWN {
            let level = redistribution(id).unwrap_or_else(|| panic!("{id} sans niveau"));
            assert_eq!(build(id).unwrap().meta().redistribution, level, "{id}");
        }
        assert_eq!(redistribution("wordfence"), Some(Redistribution::Internal));
        assert_eq!(
            redistribution("friends-of-presta"),
            Some(Redistribution::FactsOnly)
        );
        assert_eq!(redistribution("osv-packagist"), Some(Redistribution::Free));
        assert_eq!(redistribution("kev"), Some(Redistribution::Free));
        assert_eq!(redistribution("inconnue"), None);
        assert_eq!(redistribution(""), None);
    }
}
