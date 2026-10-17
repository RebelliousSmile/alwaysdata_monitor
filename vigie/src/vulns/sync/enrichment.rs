//! Tables d'enrichissement (F4, issue #18) : CISA KEV et FIRST EPSS ne
//! sont pas des failles mais des tables jointes par CVE. Elles se branchent
//! sur le moteur de F2 par [`EnrichmentSource`], voisin de
//! [`super::VulnSource`] : même bail, même débit, même `Download`, même
//! seuil d'écart (`Limits::max_dropped_ratio`, raisons `bad_cve`,
//! `bad_date`, `bad_value`, `missing_field`, `duplicate`), même garde
//! contre le rétrécissement, même état et même constat `vulns-sync`. Les
//! lignes typées sont poussées dans un [`EnrichSink`] (vers `EnrichLoad`).

use super::download::Download;
use super::{FetchOutcome, NotReady, SourceMeta, SyncContext, SyncError};
use crate::vulns::advisory::Tally;
use crate::vulns::enrich_store::{ActiveDataset, DatasetHeader, EpssRow, KevRow};
use crate::vulns::exploit::Cve;

/// Reçoit les lignes d'une table, en flux, et dit ce qu'il faut savoir
/// avant d'écrire.
pub trait EnrichSink {
    fn push_kev(&mut self, row: KevRow) -> Result<(), SyncError>;
    fn push_epss(&mut self, cve: Cve, row: EpssRow) -> Result<(), SyncError>;
    /// En-tête du jeu poussé (version, date de publication) ; exigé avant
    /// [`FetchOutcome::Loaded`].
    fn set_header(&mut self, header: DatasetHeader);
    /// Jeu actif de la source.
    fn active(&self) -> Option<&ActiveDataset>;
    /// Lignes retenues des derniers chargements réussis (garde contre le
    /// rétrécissement).
    fn recent_entries(&self) -> &[u64];
    /// `--accept-shrink` donné pour cette source.
    fn accept_shrink(&self) -> bool;
}

/// Une table d'enrichissement.
pub trait EnrichmentSource {
    /// Identifiant stable, clé de `vuln_sources` (`kev`, `epss`).
    fn id(&self) -> &'static str;
    fn meta(&self) -> SourceMeta;
    /// Refus avant toute requête ; jamais compté comme une requête.
    fn ready(&self, _ctx: &SyncContext) -> Result<(), NotReady> {
        Ok(())
    }
    /// Télécharge par `dl`, contrôle, pousse les lignes dans `sink` et
    /// chaque écart dans `tally`.
    fn fetch(
        &self,
        dl: &mut Download,
        sink: &mut dyn EnrichSink,
        tally: &mut Tally,
    ) -> Result<FetchOutcome, SyncError>;
}
