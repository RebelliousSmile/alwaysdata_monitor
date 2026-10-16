//! Contrôles externes : ce que n'importe qui voit du site depuis Internet.
//!
//! Un `enum` plutôt qu'un trait : cinq contrôles connus à la compilation, une
//! même signature, et un registre qui se lit d'un coup d'œil.

mod content;
mod exposed;
mod headers;
pub mod heartbeat;
mod installer;
mod tls;

use std::time::{Duration, Instant};

use crate::config::{Site, SiteKind};
use crate::finding::Finding;
use crate::http::{Http, HttpError, Page, Trust};

/// Les contrôles TLS et des en-têtes changent rarement : une fois par heure
/// au plus souvent.
const SLOW_INTERVAL: u64 = 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckKind {
    Content,
    Installer,
    Exposed,
    Tls,
    Headers,
}

impl CheckKind {
    /// Ordre d'exécution : `content` d'abord, car un site injoignable fait
    /// sauter les autres contrôles.
    pub const ALL: [Self; 5] = [
        Self::Content,
        Self::Installer,
        Self::Exposed,
        Self::Tls,
        Self::Headers,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Content => "content",
            Self::Installer => "installer",
            Self::Exposed => "exposed",
            Self::Tls => "tls",
            Self::Headers => "headers",
        }
    }

    /// CMS auxquels le contrôle s'applique (registre des capacités, issue
    /// #2). `match` sans joker : un contrôle nouveau oblige à décider.
    pub fn cms(self) -> &'static [SiteKind] {
        const ALL_CMS: &[SiteKind] =
            &[SiteKind::Generic, SiteKind::Wordpress, SiteKind::Prestashop];
        match self {
            Self::Installer => &[SiteKind::Wordpress, SiteKind::Prestashop],
            Self::Content | Self::Exposed | Self::Tls | Self::Headers => ALL_CMS,
        }
    }

    pub fn applies(self, site: &Site) -> bool {
        self.cms().contains(&site.kind)
    }

    /// Secondes entre deux passages de ce contrôle sur ce site.
    pub fn interval(self, site: &Site) -> u64 {
        match self {
            Self::Tls | Self::Headers => site.interval.max(SLOW_INTERVAL),
            _ => site.interval,
        }
    }

    pub fn run(self, site: &Site, ctx: &Ctx) -> Result<Vec<Finding>, CheckError> {
        self.observe(site, ctx).map(|outcome| outcome.findings)
    }

    /// Comme `run`, avec les valeurs observées en chemin.
    pub fn observe(self, site: &Site, ctx: &Ctx) -> Result<Outcome, CheckError> {
        let plain = |findings| Outcome {
            findings,
            observed: Observed::default(),
        };
        match self {
            Self::Content => content::run(site, ctx),
            Self::Installer => installer::run(site, ctx).map(plain),
            Self::Exposed => exposed::run(site, ctx).map(plain),
            Self::Tls => tls::run(site, ctx),
            Self::Headers => headers::run(site, ctx).map(plain),
        }
    }
}

/// Valeurs relevées par un passage concluant, montrées par la console.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Observed {
    /// Statut HTTP de la page de `content`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    /// Expiration du certificat lu par `tls`, en secondes Unix.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_not_after: Option<i64>,
}

impl Observed {
    /// JSON, ou `None` s'il n'y a rien à montrer.
    pub fn to_json(&self) -> Option<String> {
        (*self != Self::default()).then(|| serde_json::to_string(self).unwrap_or_default())
    }
}

/// Constats d'un passage concluant, et ce qui a été observé en chemin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub findings: Vec<Finding>,
    pub observed: Observed,
}

/// Ce dont un contrôle a besoin, partagé par tout le passage.
pub struct Ctx<'a> {
    pub http: &'a Http,
    pub trust: &'a Trust,
    pub request_timeout: Duration,
    /// Aucune requête ne commence après cette échéance.
    pub deadline: Instant,
    /// Heure du passage, en secondes Unix : celle des décisions (jours
    /// avant l'expiration d'un certificat).
    pub now: i64,
}

/// Contrôle non concluant : aucun constat, ni dans un sens ni dans l'autre.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct CheckError {
    pub message: String,
    /// Arrêté par l'échéance du passage : à rejouer au passage suivant.
    pub cut_short: bool,
}

impl CheckError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            cut_short: false,
        }
    }
}

impl From<HttpError> for CheckError {
    fn from(err: HttpError) -> Self {
        Self {
            message: err.message,
            cut_short: err.cut_short,
        }
    }
}

/// Clé du constat `content` qui signale un site injoignable.
pub const UNREACHABLE: &str = "unreachable";

/// Vrai si ces constats de `content` disent le site injoignable : les autres
/// contrôles du site sont alors sautés, faute de pouvoir conclure.
pub fn is_unreachable(findings: &[Finding]) -> bool {
    findings
        .iter()
        .any(|f| f.check == CheckKind::Content.name() && f.key == UNREACHABLE)
}

/// Chemin aléatoire, pour savoir à quoi ressemble la réponse du site à une
/// URL qui n'existe pas (beaucoup d'hébergements répondent 200 partout).
fn witness_path(prefix: &str) -> String {
    let mut bytes = [0u8; 8];
    // Sans aléa, un suffixe fixe : le témoin reste une URL improbable.
    let _ = getrandom::fill(&mut bytes);
    format!("{prefix}vigie-temoin-{:016x}", u64::from_le_bytes(bytes))
}

/// La sonde ressemble-t-elle à la réponse du témoin ? Un même corps (aux
/// blancs près), c'est la page générique du site, pas le fichier demandé.
fn same_as_witness(page: &Page, witness: &Page) -> bool {
    witness.status == page.status && witness.body.trim() == page.body.trim()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_installer_check_applies_to_a_cms_only() {
        assert_eq!(
            CheckKind::Installer.cms(),
            [SiteKind::Wordpress, SiteKind::Prestashop]
        );
        for kind in CheckKind::ALL {
            if kind != CheckKind::Installer {
                assert_eq!(kind.cms().len(), 3, "{}", kind.name());
            }
        }
    }
}
