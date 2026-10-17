//! Synchronisation des bases de failles (issue #16, F2) : téléchargement
//! borné vers des origines codées en dur, dossier de travail privé, lecture
//! stricte d'un zip sans rien extraire sur le disque. Règles, plafonds et
//! mesures : `docs/failles.md`, « Synchronisation (F2) ».
//!
//! Les briques ([`download::Download`], [`workdir::WorkDir`],
//! [`zip::ZipReader`]) ne touchent pas la base : le moteur
//! ([`engine::sync_source`]) les assemble source par source, sous le bail
//! de `vulns/store.rs`. Une source implémente [`VulnSource`] : elle décrit
//! ses origines, plafonds et licence ([`SourceMeta`]) et pousse ses failles
//! **en flux** dans un [`Sink`], jamais en une liste en mémoire. F3
//! (Wordfence, Friends-Of-Presta) s'y branche : identifiant dans
//! [`registry::KNOWN`], champs ajoutés à [`SourceMeta`]. Les tables
//! d'enrichissement de F4 (KEV, EPSS) ne sont pas des failles : elles
//! implémentent [`enrichment::EnrichmentSource`], voisin de
//! [`VulnSource`], et passent par le même moteur, le même bail, le même
//! débit et le même état.
//!
//! Seul `vigie vulns sync` écrit les tables de failles ; `tick` lit l'état
//! des sources (constat `vulns-sync`), `serve` lit les failles.

use std::time::Duration;

use url::Url;

use crate::clock::Clock;
use crate::config::Config;
use crate::http::Trust;
use crate::store::Store;
use crate::vulns::UsageError;
use crate::vulns::advisory::{Advisory, MAX_ENTRY_BYTES, Tally};
use crate::vulns::store::{Outcome, SyncState};
use crate::vulns::version::SourceEcosystem;

pub mod download;
pub mod engine;
pub mod enrichment;
pub mod freshness;
pub mod origin;
pub mod registry;
pub mod workdir;
pub mod zip;

use download::{Download, Received};

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
    /// Bail repris par une autre synchronisation, ou expiré.
    #[error("bail du chargement perdu")]
    LeaseLost,
    #[error("base : {0}")]
    Store(String),
    /// Jeu illisible ou refusé par ses contrôles (F4 : JSON KEV, CSV EPSS,
    /// gzip, taux d'écart) ; le message ne cite aucun texte de la source.
    #[error("format refusé : {0}")]
    Format(String),
}

impl From<crate::vulns::store::LoadError> for SyncError {
    fn from(err: crate::vulns::store::LoadError) -> Self {
        use crate::vulns::store::LoadError;
        match err {
            LoadError::Supplanted | LoadError::LeaseExpired | LoadError::Busy { .. } => {
                Self::LeaseLost
            }
            LoadError::UnknownSource(_) => Self::Store("source inconnue".into()),
            LoadError::Db(e) => Self::Store(format!("{e:#}")),
        }
    }
}

/// Description d'une source, codée en dur. Structure ouverte : F3 y ajoute
/// le niveau de redistribution, F4 les encodages admis sans décodage.
#[derive(Debug, Clone, PartialEq)]
pub struct SourceMeta {
    /// URL du dump.
    pub url: &'static str,
    /// Origines admises (`hôte`, port), redirections comprises.
    pub origins: &'static [(&'static str, u16)],
    /// Licence quand elle est unique à la source ; vide si elle vaut par
    /// enregistrement (OSV).
    pub license: &'static str,
    pub attribution: &'static str,
    pub limits: Limits,
    /// Intervalle minimal entre deux requêtes (0 pour OSV ; 30 min pour
    /// Wordfence, F3).
    pub min_interval: Duration,
    /// Version du lecteur, à incrémenter à chaque changement de lecture ou
    /// de conversion qui change ce qui est stocké : différente de celle de
    /// la génération active, le dump est rechargé sans requête
    /// conditionnelle.
    pub loader_version: u32,
    /// `Content-Encoding` admis **sans décodage** (F4, EPSS : `gzip`) : les
    /// octets reçus sont gardés tels quels, empreinte comprise ; tout autre
    /// encodage est refusé. Vide pour les autres sources.
    pub raw_content_encodings: &'static [&'static str],
}

/// Ce que la source sait au moment de décider si elle peut être demandée.
#[derive(Debug, Clone)]
pub struct SyncContext {
    pub now: i64,
    pub state: Option<SyncState>,
}

/// Source pas prête (F3 : conditions Wordfence non relues) : aucune
/// requête, issue `failed` avec la raison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotReady(pub String);

/// Reçoit les failles d'une source, en flux.
pub trait Sink {
    fn push(&mut self, advisory: Advisory) -> Result<(), SyncError>;
}

/// Dump lu et poussé.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dumped {
    pub sha256: String,
    pub validators: Received,
    /// Octets du dump compressé.
    pub bytes: u64,
    /// Somme des tailles décompressées.
    pub unpacked_bytes: u64,
    /// Entrées lues du dump (dénominateur du taux d'écart).
    pub entries: u64,
    /// URL demandée qui a servi le dump, gardée avec ses validateurs.
    pub served: Option<String>,
}

/// Issue d'une source qui n'a pas échoué.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchOutcome {
    /// 304 (`not_modified`) ou même empreinte que l'active ; `validators`
    /// à écrire avec l'URL qui les a servis (`served`), `None` : gardés.
    /// `stale` (F4, KEV) : jeu reçu plus ancien que l'actif, refusé ;
    /// validateurs de l'actif gardés, `stale_count` + 1.
    Unchanged {
        not_modified: bool,
        validators: Option<Received>,
        stale: bool,
        served: Option<String>,
    },
    Loaded(Dumped),
    /// Garde contre le rétrécissement appliquée par la source elle-même
    /// (F4, KEV : avant d'essayer son second hôte) : enregistré tel quel,
    /// sans réévaluer la garde.
    RefusedShrink(String),
}

/// Une source de failles.
pub trait VulnSource {
    /// Identifiant stable, clé de `vuln_sources` (`osv-npm`).
    fn id(&self) -> &'static str;
    fn meta(&self) -> SourceMeta;
    /// Refus avant toute requête ; jamais compté comme une requête.
    fn ready(&self, _ctx: &SyncContext) -> Result<(), NotReady> {
        Ok(())
    }
    /// Télécharge par `dl` (validateurs, origines et dossier de travail de
    /// la source) et pousse chaque faille dans `sink`, chaque écart dans
    /// `tally`.
    fn fetch(
        &self,
        dl: &mut Download,
        sink: &mut dyn Sink,
        tally: &mut Tally,
    ) -> Result<FetchOutcome, SyncError>;
}

/// Points d'injection des tests, construits par le code seulement : la CLI
/// prend [`SyncOptions::default`] (production) et n'a aucune option d'URL.
#[derive(Debug, Clone, Default)]
pub struct SyncOptions {
    pub trust: Trust,
    /// Origine complète (schéma, hôte, port) qui remplace celle de chaque
    /// source et devient la seule admise ; le chemin de l'URL de la source
    /// est gardé.
    pub endpoint_override: Option<Url>,
    pub limits_override: Option<Limits>,
    /// Espace libre imposé, à la place de `statvfs`.
    pub free_space_override: Option<u64>,
    /// Tests des sources de failles seules : KEV et EPSS, déclarés d'office,
    /// ne sont pas synchronisés.
    pub skip_enrichment: bool,
}

/// Bilan d'une source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceReport {
    pub id: &'static str,
    pub outcome: Outcome,
    /// Ligne de journal : issue, entrées lues, retenues, écartées par
    /// raison, Mo téléchargés, durée, génération.
    pub line: String,
}

/// Bilan d'un `vigie vulns sync`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub sources: Vec<SourceReport>,
}

impl SyncReport {
    /// Au moins une source chargée, enrichissement compris : le
    /// rapprochement de F7 (#21) doit être refait.
    pub fn loaded(&self) -> bool {
        self.sources.iter().any(|s| s.outcome == Outcome::Loaded)
    }

    /// Sources en échec (`failed`, `refused_shrink`) : code de sortie 1.
    pub fn failures(&self) -> usize {
        self.sources
            .iter()
            .filter(|s| matches!(s.outcome, Outcome::Failed | Outcome::RefusedShrink))
            .count()
    }
}

/// Synchronise les sources déclarées (`only` : une seule), dans l'ordre de
/// [`registry::KNOWN`], une à une ; une source en échec n'arrête pas les
/// suivantes. `only` hors de `[vulns] sources` : [`UsageError`].
pub fn run(
    config: &Config,
    options: &SyncOptions,
    clock: &dyn Clock,
    only: Option<&str>,
    accept_shrink: bool,
) -> anyhow::Result<SyncReport> {
    let declared = registry::declared(config);
    if let Some(id) = only
        && !declared.contains(&id)
    {
        return Err(UsageError(format!(
            "source {id:?} absente de [vulns] sources (déclarées : {})",
            declared.join(", ")
        ))
        .into());
    }
    let mut store = Store::open(&config.database)?;
    let base_dir = config
        .database
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_default();
    let mut report = SyncReport::default();
    for id in declared {
        if only.is_some_and(|o| o != id) {
            continue;
        }
        let accept = accept_shrink && only == Some(id);
        let one = match registry::build(id) {
            None => continue,
            Some(registry::Registered::Vulns(source)) => engine::sync_source(
                &mut store,
                &base_dir,
                source.as_ref(),
                options,
                clock,
                accept,
            ),
            Some(registry::Registered::Enrichment(_)) if options.skip_enrichment => continue,
            Some(registry::Registered::Enrichment(source)) => engine::sync_enrichment(
                &mut store,
                &base_dir,
                source.as_ref(),
                options,
                clock,
                accept,
            ),
        };
        report.sources.push(one);
    }
    Ok(report)
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
