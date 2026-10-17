//! Inventaire des composants d'un site (issue #19, F5) : document
//! CycloneDX relevé par l'agent PHP et poussé à `POST /r/v1/inventory`.
//!
//! - [`bom`] : liste blanche CycloneDX 1.6/1.7, validation bornée, liste
//!   canonique et digest ;
//! - [`receive`] : porte avant le corps, vérifications hors du writer, puis
//!   écriture par `Store::accept_inventory`.
//!
//! Le corps reçu n'est jamais stocké : seuls des [`Component`] validés vont en
//! base, et aucun nom, version ou purl reçu ne va au journal. Un inventaire
//! n'est pas une preuve de vie : il ne touche ni aux rapports, ni au
//! silence, ni aux incidents. Seul un inventaire `complete` vaut absence d'un
//! composant (règle de F7, #21).

pub mod bom;
pub mod receive;

use crate::vulns::purl::{Purl, PurlType};

/// Composants au plus dans un inventaire.
pub const MAX_COMPONENTS: usize = 2000;
/// Taille maximale du corps d'un inventaire, en octets (sans gzip).
pub const MAX_INVENTORY_BYTES: usize = 512 * 1024;
/// Composants et sources écartés que l'agent peut déclarer, au plus.
pub const MAX_SKIPPED: i64 = 100_000;
/// Conservation des inventaires précédents (et du dernier d'un site qui n'en
/// déclare plus), à compter de leur `seen_at`.
pub const RETENTION: i64 = 30 * 86_400;
/// Au plus un inventaire accepté (nouveau ou inchangé) par site pendant cette
/// durée, en secondes.
pub const MIN_INTERVAL: i64 = 240;
/// Inventaires nouveaux (contenu différent) par site et par jour UTC, au plus.
pub const MAX_NEW_PER_DAY: i64 = 24;
/// Longueur maximale de `vigie:path`.
pub const MAX_PATH_CHARS: usize = 200;
/// Longueur maximale du `name` CycloneDX d'un composant.
pub const MAX_NAME_CHARS: usize = 214;

/// Scope Vigie d'un composant (propriété `vigie:scope`), distinct du `scope`
/// CycloneDX (`required` ou `excluded`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Scope {
    /// Exécuté par le site.
    Required,
    /// Dépendance de développement (`packages-dev`, `dev: true`).
    Dev,
    /// Extension WordPress « must-use » (`wp-content/mu-plugins`).
    Mu,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Dev => "dev",
            Self::Mu => "mu",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "required" => Some(Self::Required),
            "dev" => Some(Self::Dev),
            "mu" => Some(Self::Mu),
            _ => None,
        }
    }
}

/// `type` CycloneDX d'un composant : `application` pour un noyau
/// (`pkg:wordpress/core/core`, `pkg:prestashop/core/prestashop`), `library`
/// pour le reste.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ComponentType {
    Application,
    Library,
}

impl ComponentType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Application => "application",
            Self::Library => "library",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "application" => Some(Self::Application),
            "library" => Some(Self::Library),
            _ => None,
        }
    }
}

/// Composant validé : purl canonique (version comprise si connue), et ce que
/// la liste blanche admet à côté.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    pub purl: Purl,
    /// `name` CycloneDX, 1 à 214 caractères imprimables.
    pub name: String,
    pub ty: ComponentType,
    pub scope: Scope,
    /// `vigie:path`, relatif à la racine du site.
    pub path: String,
    /// `vigie:parent` : slug du thème parent d'un thème enfant.
    pub parent: Option<String>,
    /// `vigie:config-version` : version de `config.xml` d'un module
    /// PrestaShop quand elle diffère du littéral `$this->version`.
    pub config_version: Option<String>,
}

impl Component {
    pub fn ecosystem(&self) -> PurlType {
        self.purl.ty()
    }

    pub fn version(&self) -> Option<&str> {
        self.purl.version()
    }

    /// Clé de rapprochement : purl canonique sans version.
    pub fn base(&self) -> String {
        self.purl.without_version().canonical()
    }
}

/// Inventaire validé, prêt à écrire : composants gardés dans l'ordre
/// canonique `(purl, path)`, et digest de cette liste.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    pub site: String,
    pub seq: i64,
    pub sent_at: i64,
    pub agent: String,
    pub complete: bool,
    /// Composants et sources écartés par l'agent.
    pub skipped: i64,
    pub spec_version: String,
    pub serial: String,
    /// `metadata.timestamp`, en secondes Unix.
    pub generated_at: i64,
    pub components: Vec<Component>,
    /// Composants écartés à la réception, par raison fixe (jamais une valeur
    /// reçue).
    pub dropped: std::collections::BTreeMap<&'static str, usize>,
    /// SHA-256 de la liste canonique ([`bom::digest`]).
    pub digest: [u8; 32],
}

impl Inventory {
    /// Composants écartés à la réception, toutes raisons confondues.
    pub fn dropped_total(&self) -> usize {
        self.dropped.values().sum()
    }
}
