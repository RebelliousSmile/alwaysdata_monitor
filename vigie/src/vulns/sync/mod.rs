//! Synchronisation des bases de failles (issue #16, F2) : téléchargement
//! borné vers des origines codées en dur, dossier de travail privé, lecture
//! stricte d'un zip sans rien extraire sur le disque. Règles, plafonds et
//! mesures : `docs/failles.md`, « Synchronisation (F2) ».
//!
//! Les briques de ce module ([`download::Download`], [`workdir::WorkDir`],
//! [`zip::ZipReader`]) ne touchent pas la base : le moteur les assemble
//! source par source, sous le bail de `vulns/store.rs`. F3 (Wordfence,
//! Friends-Of-Presta) et F4 (KEV, EPSS) les réutilisent telles quelles.

use std::time::Duration;

use crate::vulns::advisory::MAX_ENTRY_BYTES;
use crate::vulns::version::SourceEcosystem;

pub mod download;
pub mod origin;
pub mod workdir;
pub mod zip;

const MIB: u64 = 1024 * 1024;

/// Plafonds d'une source, contrôlés avant décompression (tailles annoncées
/// et déclarées) puis pendant (octets reçus, octets réellement produits,
/// échéance).
#[derive(Debug, Clone, PartialEq)]
pub struct Limits {
    /// Dump compressé, en octets (`Content-Length`, puis octets reçus).
    pub compressed: u64,
    /// Somme des tailles décompressées, déclarées puis réelles.
    pub unpacked: u64,
    /// Entrées de l'archive.
    pub entries: u64,
    /// Taille déclarée d'une entrée ; au-delà, entrée sautée et comptée
    /// `too_large` (borne F1).
    pub entry: u64,
    /// Répertoire central du zip, lu en mémoire.
    pub central_directory: u64,
    /// Durée de la synchronisation de la source, téléchargement compris.
    pub duration: Duration,
    /// Part maximale de failles perdues (`Reason::is_drop`) parmi les
    /// entrées lues ; au-delà, le dump est refusé.
    pub max_dropped_ratio: f64,
}

impl Limits {
    /// Plafonds d'un export OSV : facteur ≈ 3 sur la mesure du 2026-10-17
    /// (`docs/failles.md`), confirmés par le relevé du VPS.
    pub fn osv(ecosystem: SourceEcosystem) -> Self {
        let (compressed, unpacked, entries, minutes) = match ecosystem {
            SourceEcosystem::CratesIo => (32 * MIB, 64 * MIB, 20_000, 15),
            SourceEcosystem::Packagist => (64 * MIB, 256 * MIB, 50_000, 15),
            SourceEcosystem::Npm => (640 * MIB, 1536 * MIB, 700_000, 90),
            // Pas d'export OSV : plafonds du plus petit, jamais employés.
            SourceEcosystem::Wordfence | SourceEcosystem::FriendsOfPresta => {
                (32 * MIB, 64 * MIB, 20_000, 15)
            }
        };
        Self {
            compressed,
            unpacked,
            entries,
            entry: MAX_ENTRY_BYTES as u64,
            central_directory: 64 * MIB,
            duration: Duration::from_secs(minutes * 60),
            max_dropped_ratio: 0.01,
        }
    }
}

/// Échec d'une synchronisation, par cause. Le message ne reprend aucune
/// donnée de la source (ni URL reçue, ni en-tête, ni texte d'entrée) : il
/// finit dans `last_error` et dans le journal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SyncError {
    /// Statut HTTP autre que 200 et 304 ; `retry_after` en secondes, borné
    /// à 24 h.
    #[error("statut HTTP {code}{}", retry_after.map(|s| format!(" (réessayer dans {s} s)")).unwrap_or_default())]
    Status { code: u16, retry_after: Option<u64> },
    #[error("statut HTTP 401 : authentification refusée")]
    Unauthorized,
    #[error("statut HTTP 403 : accès interdit")]
    Forbidden,
    #[error("réseau : {0}")]
    Network(String),
    #[error("plafond dépassé : {what}")]
    TooLarge { what: &'static str },
    #[error("corps tronqué : moins d'octets que Content-Length")]
    Truncated,
    #[error("encodage de contenu inattendu : {0}")]
    ContentEncoding(String),
    #[error("délai de la source dépassé")]
    Deadline,
    #[error("zip refusé : {0}")]
    Zip(&'static str),
    #[error("espace disque insuffisant : {needed} o nécessaires, {available} o libres")]
    Disk { needed: u64, available: u64 },
    #[error("fichier : {0}")]
    Io(String),
    #[error("origine non admise pour cette source")]
    OriginRefused,
    #[error("redirection refusée : {0}")]
    Redirect(&'static str),
}

impl SyncError {
    pub(crate) fn io(context: &str, err: &std::io::Error) -> Self {
        Self::Io(format!("{context} : {}", err.kind()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn osv_limits_follow_the_plan() {
        let npm = Limits::osv(SourceEcosystem::Npm);
        assert_eq!(npm.compressed, 640 * MIB);
        assert_eq!(npm.unpacked, 1536 * MIB);
        assert_eq!(npm.entries, 700_000);
        assert_eq!(npm.duration, Duration::from_secs(90 * 60));
        let crates = Limits::osv(SourceEcosystem::CratesIo);
        assert_eq!(crates.entry, 4 * MIB);
        assert_eq!(crates.central_directory, 64 * MIB);
        assert_eq!(crates.max_dropped_ratio, 0.01);
        assert_eq!(Limits::osv(SourceEcosystem::Packagist).unpacked, 256 * MIB);
    }

    #[test]
    fn messages_carry_no_source_data() {
        let err = SyncError::Status {
            code: 429,
            retry_after: Some(3600),
        };
        assert_eq!(err.to_string(), "statut HTTP 429 (réessayer dans 3600 s)");
        assert_eq!(
            SyncError::ContentEncoding("gzip".into()).to_string(),
            "encodage de contenu inattendu : gzip"
        );
    }
}
