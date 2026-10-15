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

    pub fn applies(self, site: &Site) -> bool {
        match self {
            Self::Installer => site.kind != SiteKind::Generic,
            _ => true,
        }
    }

    /// Secondes entre deux passages de ce contrôle sur ce site.
    pub fn interval(self, site: &Site) -> u64 {
        match self {
            Self::Tls | Self::Headers => site.interval.max(SLOW_INTERVAL),
            _ => site.interval,
        }
    }

    pub fn run(self, site: &Site, ctx: &Ctx) -> Result<Vec<Finding>, CheckError> {
        match self {
            Self::Content => content::run(site, ctx),
            Self::Installer => installer::run(site, ctx),
            Self::Exposed => exposed::run(site, ctx),
            Self::Tls => tls::run(site, ctx),
            Self::Headers => headers::run(site, ctx),
        }
    }
}

/// Ce dont un contrôle a besoin, partagé par tout le passage.
pub struct Ctx<'a> {
    pub http: &'a Http,
    pub trust: &'a Trust,
    pub request_timeout: Duration,
    /// Aucune requête ne commence après cette échéance.
    pub deadline: Instant,
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
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mixed = (nanos as u64) ^ (u64::from(std::process::id()) << 32);
    format!("{prefix}vigie-temoin-{mixed:016x}")
}

/// La sonde ressemble-t-elle à la réponse du témoin ? Un même corps (aux
/// blancs près), c'est la page générique du site, pas le fichier demandé.
fn same_as_witness(page: &Page, witness: &Page) -> bool {
    witness.status == page.status && witness.body.trim() == page.body.trim()
}
