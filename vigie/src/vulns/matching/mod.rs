//! Rapprochement inventaire × failles (issue #21, F7) : chaque composant de
//! chaque site, vu par chaque source d'inventaire (agent PHP de F5, CI de
//! F6), est confronté aux failles connues de F1 à F4. Règles écrites dans
//! `docs/failles.md`, section « Rapprochement (F7) ».
//!
//! Partie pure (ni base, ni horloge, ni configuration) :
//!
//! - [`group`] : failles candidates d'un purl sans version fusionnées par
//!   identifiant et alias (union-find), verdict du groupe ;
//! - [`assess`] : gravité d'un groupe par la seule règle de F4, faits
//!   gardés pour la réévaluation sans relire les plages, niveau de
//!   redistribution (F3) ;
//! - [`waiver`] : dérogations par site, source, composant, faille et
//!   version ;
//! - [`finding`] : au plus un constat par (site, purl sans version), et les
//!   constats « inventaire périmé ».
//!
//! Stockage et passage de `tick` :
//!
//! - [`epoch`] : époques comparées (failles, KEV/EPSS, dérogations) ;
//! - [`store`] : état par (site, source), runs, bascule et réconciliation
//!   dans une transaction ;
//! - [`pass`] : l'étape F7 de `tick`, sous un budget qui réserve les envois.

pub mod assess;
pub mod epoch;
pub mod finding;
pub mod group;
pub mod pass;
pub mod store;
pub mod waiver;

use sha2::{Digest, Sha256};

use crate::capability;
use crate::config::SiteKind;
use crate::inventory::{Scope, Source};
use crate::vulns::purl::{Purl, PurlType};
use crate::vulns::version::Scheme;

/// Longueur maximale d'une clé de constat de composant, en caractères.
pub const MAX_KEY_CHARS: usize = 256;

/// Composant vu par une source d'inventaire, à rapprocher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    /// Source d'inventaire qui l'a vu (`agent`, `ci`).
    pub source: Source,
    pub ecosystem: PurlType,
    /// purl sans version : la clé de rapprochement.
    pub base: Purl,
    /// Version brute de l'inventaire ; `None` : inconnue.
    pub version: Option<String>,
    pub scope: Scope,
    /// `vigie:path` : jamais dans une clé, une réponse de l'API ni un e-mail.
    pub path: String,
    /// Absent d'un relevé partiel de sa source, reporté depuis le run actif.
    pub carried: bool,
}

/// Le composant est-il rapproché pour un site de ce CMS ? Mêmes
/// écosystèmes que ceux que l'inventaire admet (`capability`, F5).
pub fn admitted(kind: SiteKind, ecosystem: PurlType) -> bool {
    capability::inventory_ecosystems(kind).contains(&ecosystem)
}

/// La source d'inventaire peut-elle porter cet écosystème ? L'agent PHP
/// relève le CMS, Composer et npm ; `vigie-inventory` (CI) lit les lockfiles
/// Composer, npm et Cargo, jamais une extension WordPress ni un module
/// PrestaShop (F5, F6). Sert à dire quelles sources doivent prouver
/// l'absence d'un composant avant de le dire « rétabli ».
pub fn source_carries(source: Source, ecosystem: PurlType) -> bool {
    match (source, ecosystem) {
        (Source::Agent, PurlType::Wordpress)
        | (Source::Agent, PurlType::Prestashop)
        | (Source::Agent, PurlType::Composer)
        | (Source::Agent, PurlType::Npm) => true,
        (Source::Agent, PurlType::Cargo) => false,
        (Source::Ci, PurlType::Composer)
        | (Source::Ci, PurlType::Npm)
        | (Source::Ci, PurlType::Cargo) => true,
        (Source::Ci, PurlType::Wordpress) | (Source::Ci, PurlType::Prestashop) => false,
    }
}

/// Comparateur des versions d'un écosystème d'inventaire.
pub fn scheme_of(ecosystem: PurlType) -> Scheme {
    match ecosystem {
        PurlType::Composer => Scheme::Composer,
        PurlType::Npm | PurlType::Cargo => Scheme::Semver,
        PurlType::Wordpress | PurlType::Prestashop => Scheme::Php,
    }
}

/// Clé du constat d'un purl sans version : sa forme canonique, telle
/// qu'indexée dans `vuln_affected`, jamais la version, le chemin, la
/// source ni le nom propre au site. La grammaire des purl la borne déjà
/// (227 caractères au plus) ; au-delà de [`MAX_KEY_CHARS`], par défense,
/// `purl-sha256-<hex>` : une clé bornée sans collision.
pub fn key(base: &Purl) -> String {
    bounded(base.without_version().canonical())
}

fn bounded(canonical: String) -> String {
    if canonical.chars().count() <= MAX_KEY_CHARS {
        return canonical;
    }
    let digest = Sha256::digest(canonical.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("purl-sha256-{hex}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_the_canonical_purl_without_version() {
        let purl = Purl::parse("pkg:composer/exemple/paquet@2.0.0-RC1").unwrap();
        assert_eq!(key(&purl), "pkg:composer/exemple/paquet");
        let long = format!("pkg:composer/{}", "a".repeat(300));
        let k = bounded(long);
        assert!(k.starts_with("purl-sha256-"), "{k}");
        assert_eq!(k.len(), "purl-sha256-".len() + 64);
    }

    #[test]
    fn ci_never_carries_a_cms_component() {
        for ty in [
            PurlType::Composer,
            PurlType::Npm,
            PurlType::Cargo,
            PurlType::Wordpress,
            PurlType::Prestashop,
        ] {
            let cms = matches!(ty, PurlType::Wordpress | PurlType::Prestashop);
            assert_eq!(source_carries(Source::Ci, ty), !cms, "{ty:?}");
        }
        assert!(source_carries(Source::Agent, PurlType::Wordpress));
        assert!(!source_carries(Source::Agent, PurlType::Cargo));
    }
}
