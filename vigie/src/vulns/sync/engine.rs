//! Synchronisation d'une source, dans cet ordre :
//!
//! 1. `upsert_source` (licence, attribution, URL) ;
//! 2. `ready` : un refus note `failed`, aucune requête ;
//! 3. bail ([`Load::begin`], [`EnrichLoad::begin`] pour KEV et EPSS,
//!    plafond de durée + 30 min) **avant** toute requête : détenu ailleurs
//!    → `busy`, aucune requête, pas un échec ;
//! 4. débit (`claim_request`) : fenêtre fermée ou `Retry-After` qui court →
//!    bail rendu, `rate_limited`, aucune requête ;
//! 5. téléchargement et lecture par la source, poussée par lots dans la
//!    génération réservée ; validateurs envoyés seulement si
//!    `LOADER_VERSION` concorde et vers l'URL qui les a servis ;
//! 6. inchangé (304, même empreinte, jeu périmé de KEV) →
//!    `finish_unchanged` ; refus de rétrécissement décidé par la source
//!    (KEV) → enregistré tel quel ; chargé → seuil d'écart, puis garde
//!    contre le rétrécissement ([`shrink_refused`]), puis bascule ;
//! 7. toute erreur → bail rendu (génération orpheline, purgée ensuite),
//!    `failed` ou `rate_limited`, base précédente intacte.
//!
//! Le dossier de travail est préparé sous le bail et vidé à la fin. Les
//! deux sortes de sources ([`sync_source`], [`sync_enrichment`]) suivent ce
//! même parcours ([`drive`]).

use std::path::Path;
use std::time::{Duration, Instant};

use url::Url;

use super::download::{Download, Validators as Conditions};
use super::enrichment::{EnrichSink, EnrichmentSource};
use super::origin::Origins;
use super::workdir::WorkDir;
use super::{
    FetchOutcome, NotReady, Sink, SourceMeta, SourceReport, SyncContext, SyncError, SyncOptions,
    VulnSource,
};
use crate::clock::Clock;
use crate::store::Store;
use crate::vulns::advisory::{Advisory, Tally};
use crate::vulns::enrich_store::{
    ActiveDataset, DatasetHeader, ENRICH_BATCH, EnrichLoad, EnrichSource, EpssRow, KevRow,
};
use crate::vulns::exploit::Cve;
use crate::vulns::store::{
    self as vstore, Committed, Load, LoadError, Outcome, SyncMeta, SyncState, VULN_BATCH,
    Validators,
};

/// Marge du bail sur le plafond de durée de la source.
pub const LEASE_MARGIN: Duration = Duration::from_secs(30 * 60);
/// Part minimale du maximum des derniers chargements en deçà de laquelle un
/// dump est refusé.
pub const SHRINK_FLOOR: f64 = 0.8;
/// La garde ne s'applique qu'à partir de ce nombre de failles retenues.
pub const SHRINK_MIN: u64 = 100;
/// Délai de connexion d'une requête de dump.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Garde contre le rétrécissement : `retained` sous 80 % du maximum des
/// derniers chargements réussis (dès [`SHRINK_MIN`]), sauf
/// `--accept-shrink`. Seule règle, appelée par le moteur et par KEV avant
/// d'essayer son second hôte.
pub fn shrink_refused(retained: u64, recent_entries: &[u64], accept_shrink: bool) -> bool {
    let reference = recent_entries.iter().copied().max().unwrap_or(0);
    !accept_shrink && reference >= SHRINK_MIN && (retained as f64) < SHRINK_FLOOR * reference as f64
}

/// Message d'un refus de rétrécissement.
pub fn shrink_message(id: &str, retained: u64, recent_entries: &[u64]) -> String {
    let reference = recent_entries.iter().copied().max().unwrap_or(0);
    format!(
        "rétrécissement refusé : {retained} entrées retenues, moins de 80 % du maximum récent ({reference}) ; `vigie vulns sync --source {id} --accept-shrink` pour l'accepter"
    )
}

/// Pousse les failles par lots de [`VULN_BATCH`] dans la génération
/// réservée.
struct LoadSink<'l, 'a> {
    load: &'l mut Load<'a>,
    batch: Vec<Advisory>,
}

impl LoadSink<'_, '_> {
    fn flush(&mut self) -> Result<(), SyncError> {
        if !self.batch.is_empty() {
            self.load.push(&self.batch)?;
            self.batch.clear();
        }
        Ok(())
    }
}

impl Sink for LoadSink<'_, '_> {
    fn push(&mut self, advisory: Advisory) -> Result<(), SyncError> {
        self.batch.push(advisory);
        if self.batch.len() >= VULN_BATCH {
            self.flush()?;
        }
        Ok(())
    }
}

/// Chargement sous bail, de failles ou d'une table d'enrichissement.
trait Target {
    fn claim_request(&mut self, min_interval: i64) -> anyhow::Result<bool>;
    /// Lignes retenues jusqu'ici.
    fn entries(&self) -> u64;
    fn tally(&self) -> &Tally;
    fn release(self) -> Result<(), LoadError>;
    fn finish(
        self,
        validators: &Validators,
        outcome: Outcome,
        stale: bool,
    ) -> Result<bool, LoadError>;
    fn commit(self, tally: &Tally, meta: &SyncMeta) -> Result<Committed, SyncError>;
}

impl Target for Load<'_> {
    fn claim_request(&mut self, min_interval: i64) -> anyhow::Result<bool> {
        Load::claim_request(self, min_interval)
    }
    fn entries(&self) -> u64 {
        Load::entries(self)
    }
    fn tally(&self) -> &Tally {
        Load::tally(self)
    }
    fn release(self) -> Result<(), LoadError> {
        Load::release(self)
    }
    fn finish(
        self,
        validators: &Validators,
        outcome: Outcome,
        stale: bool,
    ) -> Result<bool, LoadError> {
        Load::finish(self, validators, outcome, stale)
    }
    fn commit(self, tally: &Tally, meta: &SyncMeta) -> Result<Committed, SyncError> {
        Ok(Load::commit(self, tally, meta)?)
    }
}

/// Chargement KEV ou EPSS : lignes tamponnées par lots de
/// [`ENRICH_BATCH`], en-tête du jeu, et ce que la source doit savoir avant
/// d'écrire.
struct EnrichTarget<'a> {
    load: EnrichLoad<'a>,
    kev: Vec<KevRow>,
    epss: Vec<(Cve, EpssRow)>,
    header: Option<DatasetHeader>,
    active: Option<ActiveDataset>,
    recent: Vec<u64>,
    accept_shrink: bool,
}

impl EnrichTarget<'_> {
    fn flush(&mut self) -> Result<(), SyncError> {
        if !self.kev.is_empty() {
            self.load.push_kev(&self.kev)?;
            self.kev.clear();
        }
        if !self.epss.is_empty() {
            self.load.push_epss(&self.epss)?;
            self.epss.clear();
        }
        Ok(())
    }
}

impl EnrichSink for EnrichTarget<'_> {
    fn push_kev(&mut self, row: KevRow) -> Result<(), SyncError> {
        self.kev.push(row);
        if self.kev.len() >= ENRICH_BATCH {
            self.flush()?;
        }
        Ok(())
    }
    fn push_epss(&mut self, cve: Cve, row: EpssRow) -> Result<(), SyncError> {
        self.epss.push((cve, row));
        if self.epss.len() >= ENRICH_BATCH {
            self.flush()?;
        }
        Ok(())
    }
    fn set_header(&mut self, header: DatasetHeader) {
        self.header = Some(header);
    }
    fn active(&self) -> Option<&ActiveDataset> {
        self.active.as_ref()
    }
    fn recent_entries(&self) -> &[u64] {
        &self.recent
    }
    fn accept_shrink(&self) -> bool {
        self.accept_shrink
    }
}

impl Target for EnrichTarget<'_> {
    fn claim_request(&mut self, min_interval: i64) -> anyhow::Result<bool> {
        self.load.claim_request(min_interval)
    }
    fn entries(&self) -> u64 {
        self.load.entries()
    }
    fn tally(&self) -> &Tally {
        self.load.tally()
    }
    fn release(self) -> Result<(), LoadError> {
        self.load.release()
    }
    fn finish(
        self,
        validators: &Validators,
        outcome: Outcome,
        stale: bool,
    ) -> Result<bool, LoadError> {
        self.load.finish_unchanged(validators, outcome, stale)
    }
    fn commit(self, tally: &Tally, meta: &SyncMeta) -> Result<Committed, SyncError> {
        let header = self
            .header
            .ok_or_else(|| SyncError::Format("en-tête du jeu absent".into()))?;
        Ok(self.load.commit(&header, tally, meta)?)
    }
}

/// Chargement d'une source de l'une ou l'autre sorte.
enum AnyTarget<'a> {
    Vulns(Load<'a>),
    Enrichment(Box<EnrichTarget<'a>>),
}

impl Target for AnyTarget<'_> {
    fn claim_request(&mut self, min_interval: i64) -> anyhow::Result<bool> {
        match self {
            Self::Vulns(t) => Target::claim_request(t, min_interval),
            Self::Enrichment(t) => Target::claim_request(t.as_mut(), min_interval),
        }
    }
    fn entries(&self) -> u64 {
        match self {
            Self::Vulns(t) => Target::entries(t),
            Self::Enrichment(t) => Target::entries(t.as_ref()),
        }
    }
    fn tally(&self) -> &Tally {
        match self {
            Self::Vulns(t) => Target::tally(t),
            Self::Enrichment(t) => Target::tally(t.as_ref()),
        }
    }
    fn release(self) -> Result<(), LoadError> {
        match self {
            Self::Vulns(t) => Target::release(t),
            Self::Enrichment(t) => Target::release(*t),
        }
    }
    fn finish(
        self,
        validators: &Validators,
        outcome: Outcome,
        stale: bool,
    ) -> Result<bool, LoadError> {
        match self {
            Self::Vulns(t) => Target::finish(t, validators, outcome, stale),
            Self::Enrichment(t) => Target::finish(*t, validators, outcome, stale),
        }
    }
    fn commit(self, tally: &Tally, meta: &SyncMeta) -> Result<Committed, SyncError> {
        match self {
            Self::Vulns(t) => Target::commit(t, tally, meta),
            Self::Enrichment(t) => Target::commit(*t, tally, meta),
        }
    }
}

/// Une sorte de source : comment prendre son bail et lire son dump.
trait Kind {
    fn id(&self) -> &'static str;
    fn meta(&self) -> SourceMeta;
    fn ready(&self, ctx: &SyncContext) -> Result<(), NotReady>;
    fn begin<'a>(
        &self,
        store: &'a mut Store,
        clock: &'a dyn Clock,
        lease: i64,
        state: &SyncState,
        accept_shrink: bool,
    ) -> Result<AnyTarget<'a>, LoadError>;
    fn fetch(
        &self,
        dl: &mut Download,
        target: &mut AnyTarget<'_>,
        tally: &mut Tally,
    ) -> Result<FetchOutcome, SyncError>;
}

/// Chargement d'une autre sorte que la source : erreur de programmation.
fn wrong_kind() -> SyncError {
    SyncError::Store("chargement d'une autre sorte de source".into())
}

struct Vulns<'s>(&'s dyn VulnSource);

impl Kind for Vulns<'_> {
    fn id(&self) -> &'static str {
        self.0.id()
    }
    fn meta(&self) -> SourceMeta {
        self.0.meta()
    }
    fn ready(&self, ctx: &SyncContext) -> Result<(), NotReady> {
        self.0.ready(ctx)
    }
    fn begin<'a>(
        &self,
        store: &'a mut Store,
        clock: &'a dyn Clock,
        lease: i64,
        _state: &SyncState,
        _accept_shrink: bool,
    ) -> Result<AnyTarget<'a>, LoadError> {
        Load::begin(store, self.0.id(), clock, lease).map(AnyTarget::Vulns)
    }
    fn fetch(
        &self,
        dl: &mut Download,
        target: &mut AnyTarget<'_>,
        tally: &mut Tally,
    ) -> Result<FetchOutcome, SyncError> {
        let AnyTarget::Vulns(target) = target else {
            return Err(wrong_kind());
        };
        let mut sink = LoadSink {
            load: target,
            batch: Vec::new(),
        };
        let outcome = self.0.fetch(dl, &mut sink, tally)?;
        sink.flush()?;
        Ok(outcome)
    }
}

struct Enrichment<'s>(&'s dyn EnrichmentSource, EnrichSource);

impl Kind for Enrichment<'_> {
    fn id(&self) -> &'static str {
        self.0.id()
    }
    fn meta(&self) -> SourceMeta {
        self.0.meta()
    }
    fn ready(&self, ctx: &SyncContext) -> Result<(), NotReady> {
        self.0.ready(ctx)
    }
    fn begin<'a>(
        &self,
        store: &'a mut Store,
        clock: &'a dyn Clock,
        lease: i64,
        state: &SyncState,
        accept_shrink: bool,
    ) -> Result<AnyTarget<'a>, LoadError> {
        let load = EnrichLoad::begin(store, self.1, clock, lease)?;
        let active = load.active()?;
        Ok(AnyTarget::Enrichment(Box::new(EnrichTarget {
            load,
            kev: Vec::new(),
            epss: Vec::new(),
            header: None,
            active,
            recent: state.recent_entries.clone(),
            accept_shrink,
        })))
    }
    fn fetch(
        &self,
        dl: &mut Download,
        target: &mut AnyTarget<'_>,
        tally: &mut Tally,
    ) -> Result<FetchOutcome, SyncError> {
        let AnyTarget::Enrichment(target) = target else {
            return Err(wrong_kind());
        };
        let outcome = self.0.fetch(dl, target.as_mut(), tally)?;
        target.flush()?;
        Ok(outcome)
    }
}

/// URL de la source, origine remplacée par `endpoint_override` (chemin
/// gardé).
pub(crate) fn source_url(url: &str, endpoint: Option<&Url>) -> Result<Url, SyncError> {
    let mut url = Url::parse(url).map_err(|_| SyncError::OriginRefused)?;
    if let Some(e) = endpoint {
        url.set_host(e.host_str())
            .map_err(|_| SyncError::OriginRefused)?;
        url.set_port(e.port_or_known_default())
            .map_err(|_| SyncError::OriginRefused)?;
    }
    Ok(url)
}

fn mib(bytes: u64) -> String {
    format!("{:.1}", bytes as f64 / (1024.0 * 1024.0))
}

/// Compteurs par raison, pour le journal et `last_error`.
fn reasons(tally: &Tally) -> String {
    let parts: Vec<String> = tally
        .iter()
        .map(|(r, n)| format!("{} {n}", r.as_str()))
        .collect();
    if parts.is_empty() {
        "aucun écart".into()
    } else {
        parts.join(", ")
    }
}

/// Synchronise une source de failles ; ne rend jamais d'erreur : l'issue
/// est notée en base et dans le bilan.
pub fn sync_source(
    store: &mut Store,
    base_dir: &Path,
    source: &dyn VulnSource,
    options: &SyncOptions,
    clock: &dyn Clock,
    accept_shrink: bool,
) -> SourceReport {
    drive(
        store,
        base_dir,
        &Vulns(source),
        options,
        clock,
        accept_shrink,
    )
}

/// Synchronise une table d'enrichissement (KEV, EPSS) par le même
/// parcours ; identifiant hors de `kev` et `epss` : `failed`.
pub fn sync_enrichment(
    store: &mut Store,
    base_dir: &Path,
    source: &dyn EnrichmentSource,
    options: &SyncOptions,
    clock: &dyn Clock,
    accept_shrink: bool,
) -> SourceReport {
    let id = source.id();
    let Some(table) = EnrichSource::from_id(id) else {
        let line = format!("{id} : failed (table d'enrichissement inconnue)");
        log::error!("{line}");
        return SourceReport {
            id,
            outcome: Outcome::Failed,
            line,
        };
    };
    drive(
        store,
        base_dir,
        &Enrichment(source, table),
        options,
        clock,
        accept_shrink,
    )
}

fn drive(
    store: &mut Store,
    base_dir: &Path,
    source: &dyn Kind,
    options: &SyncOptions,
    clock: &dyn Clock,
    accept_shrink: bool,
) -> SourceReport {
    let id = source.id();
    let started = Instant::now();
    let report = |outcome: Outcome, line: String| {
        let line = format!("{id} : {line}");
        match outcome {
            Outcome::Failed | Outcome::RefusedShrink => log::error!("{line}"),
            _ => log::info!("{line}"),
        }
        SourceReport { id, outcome, line }
    };
    let fail = |store: &mut Store, err: &str, retry: Option<i64>| {
        let now = clock.unix();
        if let Err(e) = vstore::record_outcome(store, id, Outcome::Failed, Some(err), retry, now) {
            log::error!("{id} : issue non enregistrée : {e:#}");
        }
        report(Outcome::Failed, format!("failed ({err})"))
    };
    let meta = source.meta();
    let limits = options
        .limits_override
        .clone()
        .unwrap_or_else(|| meta.limits.clone());
    let row = vstore::SourceMeta {
        id: id.to_owned(),
        url: meta.url.to_owned(),
        license: meta.license.to_owned(),
        attribution: meta.attribution.to_owned(),
    };
    if let Err(e) = vstore::upsert_source(store, &row) {
        return report(Outcome::Failed, format!("failed (base : {e:#})"));
    }
    let state = match vstore::sync_state(store, id) {
        Ok(state) => state,
        Err(e) => return fail(store, &format!("base : {e:#}"), None),
    };
    if let Err(not_ready) = source.ready(&SyncContext {
        now: clock.unix(),
        state: state.clone(),
    }) {
        return fail(store, &format!("source pas prête : {}", not_ready.0), None);
    }
    let state = state.unwrap_or_default();
    let lease = i64::try_from((limits.duration + LEASE_MARGIN).as_secs()).unwrap_or(i64::MAX);
    let mut load = match source.begin(store, clock, lease, &state, accept_shrink) {
        Ok(load) => load,
        Err(LoadError::Busy { since }) => {
            let now = clock.unix();
            let _ = vstore::record_outcome(store, id, Outcome::Busy, None, None, now);
            return report(
                Outcome::Busy,
                format!(
                    "déjà en cours depuis {} (bail détenu ailleurs)",
                    crate::human_age(now - since)
                ),
            );
        }
        Err(e) => return fail(store, &SyncError::from(e).to_string(), None),
    };
    let min_interval = i64::try_from(meta.min_interval.as_secs()).unwrap_or(i64::MAX);
    match load.claim_request(min_interval) {
        Ok(true) => {}
        Ok(false) => {
            let _ = load.release();
            let _ =
                vstore::record_outcome(store, id, Outcome::RateLimited, None, None, clock.unix());
            return report(
                Outcome::RateLimited,
                "rate_limited (fenêtre de débit fermée ou Retry-After en cours)".into(),
            );
        }
        Err(e) => {
            let _ = load.release();
            return fail(store, &format!("base : {e:#}"), None);
        }
    }
    let conditional =
        state.active_generation > 0 && state.loader_version == Some(meta.loader_version);
    // Un validateur sans l'URL qui l'a servi n'est jamais envoyé.
    let known = state.validator_url.is_some();
    let conditions = Conditions {
        etag: state.etag.clone().filter(|_| known),
        last_modified: state.http_last_modified.clone().filter(|_| known),
        active_sha256: state.dump_sha256.clone(),
        conditional,
    };
    let mut tally = Tally::default();
    let fetched = (|| {
        let url = source_url(meta.url, options.endpoint_override.as_ref())?;
        let origins = match &options.endpoint_override {
            Some(e) => Origins::pinned(&[e])?,
            None => Origins::fixed(meta.origins),
        };
        let workdir = WorkDir::prepare(base_dir, id)?.with_free_space(options.free_space_override);
        let mut dl = Download::new(
            crate::http::agent(&options.trust, CONNECT_TIMEOUT),
            origins,
            conditions,
            limits.clone(),
            Instant::now() + limits.duration,
            workdir,
        )
        .with_url(url)
        .with_endpoint(options.endpoint_override.clone())
        .with_validator_url(state.validator_url.clone())
        .with_raw_encodings(meta.raw_content_encodings);
        source.fetch(&mut dl, &mut load, &mut tally)
    })();
    match fetched {
        Err(err) => {
            let _ = load.release();
            let retry = match &err {
                SyncError::Status {
                    retry_after: Some(s),
                    ..
                } => Some(clock.unix().saturating_add(i64::try_from(*s).unwrap_or(0))),
                _ => None,
            };
            if let SyncError::Status {
                code: 429 | 503,
                retry_after: Some(_),
            } = err
            {
                let _ = vstore::record_outcome(
                    store,
                    id,
                    Outcome::RateLimited,
                    Some(&err.to_string()),
                    retry,
                    clock.unix(),
                );
                return report(Outcome::RateLimited, format!("rate_limited ({err})"));
            }
            fail(store, &err.to_string(), retry)
        }
        Ok(FetchOutcome::RefusedShrink(err)) => {
            // Décidé par la source avec `shrink_refused` : pas réévalué.
            let _ = load.release();
            let _ = vstore::record_outcome(
                store,
                id,
                Outcome::RefusedShrink,
                Some(&err),
                None,
                clock.unix(),
            );
            report(Outcome::RefusedShrink, format!("refused_shrink ({err})"))
        }
        Ok(FetchOutcome::Unchanged {
            not_modified,
            validators,
            stale,
            served,
        }) => {
            let outcome = if not_modified {
                Outcome::NotModified
            } else {
                Outcome::Unchanged
            };
            let validators = match validators {
                None => Validators::Keep,
                Some(v) => Validators::Set {
                    etag: v.etag,
                    last_modified: v.last_modified,
                    url: served,
                },
            };
            match load.finish(&validators, outcome, stale) {
                Ok(true) => report(
                    outcome,
                    format!(
                        "{}{} en {} ms, génération {} gardée",
                        outcome.as_str(),
                        if stale {
                            " (jeu reçu plus ancien que l'actif, refusé)"
                        } else {
                            ""
                        },
                        started.elapsed().as_millis(),
                        state.active_generation
                    ),
                ),
                // Bail repris ou bascule concurrente : rien n'est écrit.
                Ok(false) => report(
                    Outcome::Busy,
                    "busy (bail repris ou génération basculée ailleurs, rien écrit)".into(),
                ),
                Err(e) => fail(store, &SyncError::from(e).to_string(), None),
            }
        }
        Ok(FetchOutcome::Loaded(dump)) => {
            let mut all = tally.clone();
            all.merge(load.tally());
            let dropped = all.dropped();
            let ratio = if dump.entries == 0 {
                0.0
            } else {
                dropped as f64 / dump.entries as f64
            };
            if ratio > limits.max_dropped_ratio {
                let _ = load.release();
                return fail(
                    store,
                    &format!(
                        "taux d'écart {:.2} % au-delà de {:.2} % ({dropped} sur {} entrées : {})",
                        ratio * 100.0,
                        limits.max_dropped_ratio * 100.0,
                        dump.entries,
                        reasons(&all)
                    ),
                    None,
                );
            }
            let retained = load.entries();
            if shrink_refused(retained, &state.recent_entries, accept_shrink) {
                let _ = load.release();
                let err = shrink_message(id, retained, &state.recent_entries);
                let _ = vstore::record_outcome(
                    store,
                    id,
                    Outcome::RefusedShrink,
                    Some(&err),
                    None,
                    clock.unix(),
                );
                return report(Outcome::RefusedShrink, format!("refused_shrink ({err})"));
            }
            let reference = state.recent_entries.iter().copied().max().unwrap_or(0);
            if accept_shrink && reference >= SHRINK_MIN {
                log::warn!(
                    "{id} : --accept-shrink : {retained} entrées retenues acceptées (maximum récent {reference}), nouvelle référence"
                );
            }
            let meta = SyncMeta {
                sha256: Some(dump.sha256.clone()),
                etag: dump.validators.etag.clone(),
                http_last_modified: dump.validators.last_modified.clone(),
                dump_bytes: dump.bytes,
                unpacked_bytes: dump.unpacked_bytes,
                duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                loader_version: meta.loader_version,
                accept_shrink,
                revision: dump.revision.clone(),
                validator_url: dump.served.clone(),
            };
            match load.commit(&tally, &meta) {
                Ok(done) => report(
                    Outcome::Loaded,
                    format!(
                        "loaded : {} entrées lues, {} retenues, écarts : {} ; {} Mio en {} ms, génération {}",
                        dump.entries,
                        done.entries,
                        reasons(&done.tally),
                        mib(dump.bytes),
                        meta.duration_ms,
                        done.generation
                    ),
                ),
                Err(e) => fail(store, &e.to_string(), None),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_override_keeps_the_path() {
        let e = Url::parse("https://127.0.0.1:8443/").unwrap();
        assert_eq!(
            source_url(
                "https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip",
                Some(&e)
            )
            .unwrap()
            .as_str(),
            "https://127.0.0.1:8443/crates.io/all.zip"
        );
        assert_eq!(
            source_url("https://dumps.example.org/a/all.zip", None)
                .unwrap()
                .as_str(),
            "https://dumps.example.org/a/all.zip"
        );
    }

    #[test]
    fn shrink_guard_is_the_f2_rule() {
        assert!(!shrink_refused(79, &[99], false), "sous le minimum");
        assert!(shrink_refused(79, &[100], false));
        assert!(!shrink_refused(80, &[100], false));
        assert!(shrink_refused(700, &[1_000, 400], false), "maximum récent");
        assert!(!shrink_refused(1, &[1_000], true));
        assert!(!shrink_refused(5, &[], false));
    }
}
