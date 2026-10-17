//! Sources connues du veilleur : liste fermée, seule admise dans
//! `[vulns] sources`.
//!
//! Point d'extension : une source (F3 : `wordfence`, `friends-of-presta`)
//! entre dans [`KNOWN`] à sa place d'exécution et dans [`build`] ; un test
//! exige que chaque identifiant de [`KNOWN`] se construise sous ce même
//! identifiant. Les tables d'enrichissement de F4 ([`ENRICHMENT`] : `kev`,
//! `epss`) viennent en dernier et sont déclarées **d'office** dès qu'une
//! source de failles l'est : une gravité calculée sans KEV serait trop
//! basse en silence.

use super::VulnSource;
use super::enrichment::EnrichmentSource;
use crate::config::Config;
use crate::vulns::sources::epss::EpssSource;
use crate::vulns::sources::kev::KevSource;
use crate::vulns::sources::osv::OsvSource;
use crate::vulns::version::SourceEcosystem;

/// Identifiants admis, dans l'ordre de synchronisation : sources de
/// failles (petites d'abord : une source lente ne prive pas les autres),
/// puis tables d'enrichissement.
pub const KNOWN: &[&str] = &["osv-crates-io", "osv-packagist", "osv-npm", "kev", "epss"];

/// Tables d'enrichissement de [`KNOWN`] (F4), déclarées d'office.
pub const ENRICHMENT: &[&str] = &["kev", "epss"];

/// Source construite : de failles, ou table d'enrichissement.
pub enum Registered {
    Vulns(Box<dyn VulnSource>),
    Enrichment(Box<dyn EnrichmentSource>),
}

impl Registered {
    pub fn id(&self) -> &'static str {
        match self {
            Self::Vulns(s) => s.id(),
            Self::Enrichment(s) => s.id(),
        }
    }
}

/// Source d'un identifiant de [`KNOWN`].
pub fn build(id: &str) -> Option<Registered> {
    let ecosystem = match id {
        "osv-crates-io" => SourceEcosystem::CratesIo,
        "osv-packagist" => SourceEcosystem::Packagist,
        "osv-npm" => SourceEcosystem::Npm,
        "kev" => return Some(Registered::Enrichment(Box::new(KevSource))),
        "epss" => return Some(Registered::Enrichment(Box::new(EpssSource))),
        _ => return None,
    };
    Some(Registered::Vulns(Box::new(OsvSource { ecosystem })))
}

/// Sources de `[vulns] sources`, dans l'ordre de [`KNOWN`], plus `kev` et
/// `epss` d'office dès qu'une source de failles est déclarée (les écrire
/// est admis, sans doublon) ; vide sans section ou sans source de failles.
pub fn declared(config: &Config) -> Vec<&'static str> {
    let Some(vulns) = &config.vulns else {
        return Vec::new();
    };
    let any_vulns = vulns
        .sources
        .iter()
        .any(|s| KNOWN.contains(&s.as_str()) && !ENRICHMENT.contains(&s.as_str()));
    KNOWN
        .iter()
        .copied()
        .filter(|id| {
            if ENRICHMENT.contains(id) {
                any_vulns
            } else {
                vulns.sources.iter().any(|s| s == id)
            }
        })
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
            assert_eq!(
                matches!(source, Registered::Enrichment(_)),
                ENRICHMENT.contains(id)
            );
        }
        assert!(build("osv-pypi").is_none());
        // Enrichissement en dernier.
        assert_eq!(KNOWN[KNOWN.len() - ENRICHMENT.len()..], *ENRICHMENT);
    }
}
