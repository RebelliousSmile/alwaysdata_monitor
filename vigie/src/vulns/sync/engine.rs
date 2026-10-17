//! Synchronisation d'une source, dans cet ordre :
//!
//! 1. `upsert_source` (licence, attribution, URL) ;
//! 2. `ready` : un refus note `failed`, aucune requête ;
//! 3. bail ([`Load::begin`], plafond de durée + 30 min) **avant** toute
//!    requête : détenu ailleurs → `busy`, aucune requête, pas un échec ;
//! 4. débit ([`Load::claim_request`]) : fenêtre fermée ou `Retry-After` qui
//!    court → bail rendu, `rate_limited`, aucune requête ;
//! 5. téléchargement et lecture par la source, poussée par lots dans la
//!    génération réservée ;
//! 6. inchangé (304, même empreinte) → `finish_unchanged` ; chargé → seuil
//!    d'écart, puis garde contre le rétrécissement, puis bascule ;
//! 7. toute erreur → bail rendu (génération orpheline, purgée par F1),
//!    `failed` ou `rate_limited`, base précédente intacte.
//!
//! Le dossier de travail est préparé sous le bail et vidé à la fin.

use std::path::Path;
use std::time::{Duration, Instant};

use url::Url;

use super::download::{Download, Validators as Conditions};
use super::origin::Origins;
use super::workdir::WorkDir;
use super::{FetchOutcome, Sink, SourceReport, SyncContext, SyncError, SyncOptions, VulnSource};
use crate::clock::Clock;
use crate::store::Store;
use crate::vulns::advisory::{Advisory, Tally};
use crate::vulns::store::{
    self as vstore, Load, LoadError, Outcome, SyncMeta, VULN_BATCH, Validators,
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

/// URL de la source, origine remplacée par `endpoint_override` (chemin
/// gardé).
fn source_url(url: &str, endpoint: Option<&Url>) -> Result<Url, SyncError> {
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

/// Synchronise une source ; ne rend jamais d'erreur : l'issue est notée en
/// base et dans le bilan.
pub fn sync_source(
    store: &mut Store,
    base_dir: &Path,
    source: &dyn VulnSource,
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
    let lease = i64::try_from((limits.duration + LEASE_MARGIN).as_secs()).unwrap_or(i64::MAX);
    let mut load = match Load::begin(store, id, clock, lease) {
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
    let state = state.unwrap_or_default();
    let conditional =
        state.active_generation > 0 && state.loader_version == Some(meta.loader_version);
    let conditions = Conditions {
        etag: state.etag.clone(),
        last_modified: state.http_last_modified.clone(),
        active_sha256: state.dump_sha256.clone(),
        conditional,
    };
    // URL demandée, gardée avec les validateurs qu'elle sert.
    let requested = source_url(meta.url, options.endpoint_override.as_ref())
        .ok()
        .map(|u| u.to_string());
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
        .with_url(url);
        let mut sink = LoadSink {
            load: &mut load,
            batch: Vec::new(),
        };
        let outcome = source.fetch(&mut dl, &mut sink, &mut tally)?;
        sink.flush()?;
        Ok::<_, SyncError>(outcome)
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
        Ok(FetchOutcome::Unchanged {
            not_modified,
            validators,
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
                    url: requested.clone(),
                },
            };
            match load.finish_unchanged(&validators, outcome) {
                Ok(true) => report(
                    outcome,
                    format!(
                        "{} en {} ms, génération {} gardée",
                        outcome.as_str(),
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
            let reference = state.recent_entries.iter().copied().max().unwrap_or(0);
            if !accept_shrink
                && reference >= SHRINK_MIN
                && (retained as f64) < SHRINK_FLOOR * reference as f64
            {
                let _ = load.release();
                let err = format!(
                    "rétrécissement refusé : {retained} failles retenues, moins de 80 % du maximum récent ({reference}) ; `vigie vulns sync --source {id} --accept-shrink` pour l'accepter"
                );
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
            if accept_shrink && reference >= SHRINK_MIN {
                log::warn!(
                    "{id} : --accept-shrink : {retained} failles retenues acceptées (maximum récent {reference}), nouvelle référence"
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
                validator_url: requested.clone(),
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
                Err(e) => fail(store, &SyncError::from(e).to_string(), None),
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
}
