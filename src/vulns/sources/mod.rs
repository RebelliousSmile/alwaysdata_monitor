//! Sources de failles branchées sur le cadre de synchronisation
//! (`vulns/sync`) : chacune lit son format et pousse des failles validées
//! par `Advisory::build`. F2 : exports OSV ; F3 : Wordfence,
//! Friends-Of-Presta. Tables d'enrichissement de F4, poussées en lignes
//! typées : CISA KEV, FIRST EPSS.
//!
//! Les convertisseurs de F3 sont purs : octets de la source → failles du
//! modèle de F1, chaque écart compté par raison. Ni réseau ni base : le
//! cadre de F2 télécharge, les convertisseurs lisent.

pub mod epss;
pub mod friends_of_presta;
pub mod kev;
pub mod osv;
pub mod release;
pub mod tar;
pub mod wordfence;

/// Ce qu'une faille d'une source permet de transmettre à un tiers
/// (`docs/failles.md`, « Redistribution, affichage et fixtures »). L'ordre
/// des variantes va du plus restrictif au plus libre. Sérialisé en
/// `internal`, `facts_only`, `free` (résultats de F7, API).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Redistribution {
    /// Usage interne à l'exploitant : rien ne sort du VPS ni de la console
    /// (Wordfence, tant que ses conditions n'ont pas tranché l'affichage aux
    /// clients).
    Internal,
    /// Un document destiné à un client ne reprend que des faits (CVE,
    /// composant, plage, vecteur CVSS, CWE, date) et le lien vers l'avis,
    /// jamais son texte (Friends-Of-Presta).
    FactsOnly,
    /// Faille transmissible avec sa licence et son attribution (OSV).
    Free,
}

impl Redistribution {
    /// Libellé affiché par `vigie vulns sources`, `show` et `match`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Internal => "interne",
            Self::FactsOnly => "faits seulement",
            Self::Free => "libre",
        }
    }

    /// Niveau d'une faille fusionnée depuis deux sources (F7) : le plus
    /// restrictif des deux.
    pub fn most_restrictive(a: Self, b: Self) -> Self {
        a.min(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_most_restrictive_level_wins() {
        use Redistribution::{FactsOnly, Free, Internal};
        let all = [Internal, FactsOnly, Free];
        for a in all {
            for b in all {
                let expected = if a == Internal || b == Internal {
                    Internal
                } else if a == FactsOnly || b == FactsOnly {
                    FactsOnly
                } else {
                    Free
                };
                assert_eq!(
                    Redistribution::most_restrictive(a, b),
                    expected,
                    "{a:?} {b:?}"
                );
            }
        }
        assert_eq!(wordfence::REDISTRIBUTION, Internal);
    }
}
