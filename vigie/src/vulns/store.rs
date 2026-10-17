//! Stockage des failles connues (migration 15) : sources, générations sous
//! bail, lectures du rapprochement.
//!
//! **Écrivain** : la synchronisation seule (F2, processus lancé par un
//! timer), par [`Store::open`] ; `serve` ne fait que lire (F7).
//!
//! **Remplacement atomique sans tenir le verrou.** Un dump npm compte près
//! de 230 000 failles : il n'est pas écrit dans une seule transaction.
//!
//! 1. [`Load::begin`] (IMMEDIATE) réserve `g = next_generation`, jamais
//!    réutilisée, et prend le bail (`loading_generation = g`,
//!    `loading_since`) pour la durée donnée (F2 : plafond de durée de la
//!    source + 30 min, [`LEASE`] au plus). Un second chargement est refusé
//!    tant que le bail court ; il le reprend après expiration.
//! 2. [`Load::push`] écrit par lots de [`VULN_BATCH`] failles, une
//!    transaction IMMEDIATE chacun, qui **revérifie le bail** : expiré ou
//!    supplanté, le chargement s'arrête aussitôt.
//! 3. [`Load::commit`] bascule `active_generation` en compare-and-swap
//!    (génération active attendue et bail toujours détenu, sinon
//!    [`LoadError::Supplanted`] et la génération reste orpheline), avec,
//!    dans la même instruction, les validateurs HTTP et l'état de
//!    synchronisation ([`SyncMeta`]), puis purge et
//!    `PRAGMA wal_checkpoint(PASSIVE)`. Dump inchangé (304, même
//!    empreinte) : [`finish_unchanged`] rend le bail et date le succès en
//!    une instruction, sans écrire de génération ; échec :
//!    [`Load::release`] rend le bail, la génération réservée reste vide et
//!    orpheline.
//!
//! La purge ([`purge`]) retire par lots tout sauf la génération active et
//! celle sous bail en cours, enfants d'abord. Les tables KEV et EPSS de F4
//! (`vulns/enrich_store.rs`) reprennent ces primitives : [`reserve`],
//! [`switch`], [`check_lease`], [`finish_unchanged`] et [`purge_batches`]
//! selon la forme de leur clé ([`KeyShape`]). Les lecteurs ne lisent que la
//! génération active, dans une transaction de lecture : ils voient l'ancien
//! jeu complet ou le nouveau, jamais un mélange.

use std::collections::BTreeMap;

use anyhow::Context;
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::clock::Clock;
use crate::store::{SCHEMA_ENRICHMENT, SCHEMA_VULNS, SCHEMA_VULNS_SYNC, Store};
use crate::vulns::advisory::{
    Advisory, Affected, LastKnown, Range, Reason, Reference, Score, ScoreOrigin, Seen, Severity,
    Tally, normalize_alias,
};
use crate::vulns::purl::{Purl, PurlType};
use crate::vulns::range::{Verdict, match_advisory};
use crate::vulns::version::Scheme;

/// Durée maximale du bail d'un chargement (F1) : celui de F2 est le
/// plafond de durée de la source + 30 min. La purge épargne une génération
/// sous bail tant qu'il n'a pas dépassé cette durée.
pub const LEASE: i64 = 6 * 3600;
/// Failles retenues gardées par source pour la garde contre le
/// rétrécissement : celles des 7 derniers chargements réussis.
pub const RECENT_LOADS: usize = 7;
/// Failles écrites par transaction. Mesure du test de contention
/// (`tests/store_concurrency.rs`, 2026-10-17, build debug, 20 000 failles
/// face aux écritures de `serve` et `tick`) : le lot le plus lent tient
/// ≈ 100 ms, loin des 5 s de `busy_timeout` des autres écrivains.
pub const VULN_BATCH: usize = 500;
/// Lignes supprimées par transaction de purge.
pub const PURGE_BATCH: usize = 5_000;

/// Échec d'un chargement.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("source de failles inconnue : {0}")]
    UnknownSource(String),
    #[error("chargement déjà en cours depuis {since}")]
    Busy { since: i64 },
    #[error("chargement supplanté par un autre")]
    Supplanted,
    #[error("bail du chargement expiré")]
    LeaseExpired,
    #[error(transparent)]
    Db(#[from] anyhow::Error),
}

impl From<rusqlite::Error> for LoadError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Db(err.into())
    }
}

/// Description d'une source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceMeta {
    /// `osv-packagist`, `osv-npm`, `osv-crates-io`, `wordfence`…
    pub id: String,
    pub url: String,
    /// Licence de la source quand elle est unique (Wordfence,
    /// Friends-Of-Presta) ; vide pour OSV (licence par enregistrement).
    pub license: String,
    pub attribution: String,
}

/// Crée ou met à jour une source, sans toucher à ses générations.
pub fn upsert_source(store: &mut Store, meta: &SourceMeta) -> anyhow::Result<()> {
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "INSERT INTO vuln_sources (id, url, license, attribution) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (id) DO UPDATE SET url = excluded.url, license = excluded.license,
             attribution = excluded.attribution",
        params![meta.id, meta.url, meta.license, meta.attribution],
    )
    .context("source de failles")?;
    tx.commit()?;
    Ok(())
}

/// Enregistre l'échec d'une synchronisation (téléchargement, archive) sans
/// toucher à la génération active.
pub fn record_error(store: &mut Store, source: &str, error: &str, now: i64) -> anyhow::Result<()> {
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "UPDATE vuln_sources SET last_error = ?2, last_attempt_at = ?3 WHERE id = ?1",
        params![
            source,
            crate::api::log_text::LogText::detail(error).as_str(),
            now
        ],
    )?;
    tx.commit()?;
    Ok(())
}

/// Issue de la dernière tentative de synchronisation (`last_outcome`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Nouvelle génération chargée.
    Loaded,
    /// Empreinte du dump identique à celle de l'active.
    Unchanged,
    /// 304 sur la requête conditionnelle.
    NotModified,
    Failed,
    /// Bail détenu par une autre synchronisation, ou repris en route.
    Busy,
    /// Dump refusé par la garde contre le rétrécissement.
    RefusedShrink,
    /// Fenêtre de débit fermée ou `Retry-After` de la source.
    RateLimited,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Loaded => "loaded",
            Self::Unchanged => "unchanged",
            Self::NotModified => "not_modified",
            Self::Failed => "failed",
            Self::Busy => "busy",
            Self::RefusedShrink => "refused_shrink",
            Self::RateLimited => "rate_limited",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        [
            Self::Loaded,
            Self::Unchanged,
            Self::NotModified,
            Self::Failed,
            Self::Busy,
            Self::RefusedShrink,
            Self::RateLimited,
        ]
        .into_iter()
        .find(|o| o.as_str() == name)
    }

    /// Synchronisation réussie : la base est à jour.
    pub fn is_success(self) -> bool {
        matches!(self, Self::Loaded | Self::Unchanged | Self::NotModified)
    }
}

/// Validateurs HTTP écrits par [`finish_unchanged`] : gardés tels quels
/// (304, jeu périmé) ou remplacés par ceux de la réponse (même empreinte),
/// avec l'URL demandée qui les a servis (`validator_url`, F4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Validators {
    Keep,
    Set {
        etag: Option<String>,
        last_modified: Option<String>,
        /// URL demandée ; `None` efface `validator_url`.
        url: Option<String>,
    },
}

/// État de synchronisation joint à la bascule de génération
/// ([`Load::commit`]), écrit dans la même instruction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncMeta {
    /// SHA-256 du dump, en hexadécimal.
    pub sha256: Option<String>,
    pub etag: Option<String>,
    pub http_last_modified: Option<String>,
    pub dump_bytes: u64,
    pub unpacked_bytes: u64,
    pub duration_ms: u64,
    /// `LOADER_VERSION` de la source qui a lu ce dump.
    pub loader_version: u32,
    /// `--accept-shrink` : la référence de la garde repart de ce chargement
    /// (`recent_entries` = `[retenues]`).
    pub accept_shrink: bool,
    /// Révision du dump (commit de l'archive Friends-Of-Presta, F3).
    pub revision: Option<String>,
    /// URL demandée qui a servi `etag` et `http_last_modified` (F4).
    pub validator_url: Option<String>,
}

/// Rend le bail d'un dump inchangé et date le succès, en **une seule
/// instruction** compare-and-swap : bail détenu par `generation` et
/// génération active toujours `expected_active`, sinon rien n'est écrit et
/// la fonction rend `false`. Validateurs et `validator_url` écrits
/// seulement avec [`Validators::Set`] ; `stale` (jeu reçu plus ancien que
/// l'actif, KEV) ajoute 1 à `stale_count` dans la même instruction.
/// Primitive générique de bail : [`Load`] (F1, F2, F3) et l'enrichissement
/// de F4 s'en servent ; `outcome` vaut [`Outcome::NotModified`] ou
/// [`Outcome::Unchanged`].
#[allow(clippy::too_many_arguments)]
pub fn finish_unchanged(
    conn: &rusqlite::Connection,
    source: &str,
    generation: i64,
    expected_active: i64,
    validators: &Validators,
    outcome: Outcome,
    stale: bool,
    now: i64,
) -> anyhow::Result<bool> {
    anyhow::ensure!(
        matches!(outcome, Outcome::NotModified | Outcome::Unchanged),
        "issue {} hors de finish_unchanged",
        outcome.as_str()
    );
    let mut sql = String::from(
        "UPDATE vuln_sources SET loading_generation = NULL, loading_since = NULL,
             last_success_at = ?4, last_attempt_at = ?4, last_outcome = ?5, last_error = NULL",
    );
    let (etag, last_modified, url) = match validators {
        Validators::Keep => (None, None, None),
        Validators::Set {
            etag,
            last_modified,
            url,
        } => {
            sql.push_str(", etag = ?6, http_last_modified = ?7, validator_url = ?8");
            (
                clean_etag(etag.as_deref()),
                clean_date(last_modified.as_deref()),
                clean_url(url.as_deref()),
            )
        }
    };
    if stale {
        sql.push_str(", stale_count = stale_count + 1");
    }
    sql.push_str(" WHERE id = ?1 AND loading_generation = ?2 AND active_generation = ?3");
    let mut stmt = conn.prepare(&sql)?;
    let name = outcome.as_str();
    let mut values: Vec<&dyn rusqlite::ToSql> =
        vec![&source, &generation, &expected_active, &now, &name];
    if matches!(validators, Validators::Set { .. }) {
        values.push(&etag);
        values.push(&last_modified);
        values.push(&url);
    }
    Ok(stmt.execute(values.as_slice())? == 1)
}

/// ETag gardé en base : ASCII imprimable, 1 à 256 caractères.
fn clean_etag(etag: Option<&str>) -> Option<String> {
    etag.filter(|e| (1..=256).contains(&e.len()) && e.bytes().all(|b| (0x20..0x7f).contains(&b)))
        .map(str::to_owned)
}

/// Date HTTP gardée en base : ASCII imprimable, 64 caractères au plus.
fn clean_date(date: Option<&str>) -> Option<String> {
    date.filter(|d| (1..=64).contains(&d.len()) && d.bytes().all(|b| (0x20..0x7f).contains(&b)))
        .map(str::to_owned)
}

/// URL d'un validateur gardée en base : ASCII imprimable sans espace,
/// 2 048 caractères au plus.
fn clean_url(url: Option<&str>) -> Option<String> {
    url.filter(|u| (1..=2048).contains(&u.len()) && u.bytes().all(|b| (0x21..0x7f).contains(&b)))
        .map(str::to_owned)
}

/// Réserve une requête vers la source, en compare-and-swap : la dernière
/// requête date d'au moins `min_interval` secondes et aucun `Retry-After`
/// ne court. `false` : rien n'est écrit, aucune requête ne doit partir.
pub fn claim_request(
    store: &mut Store,
    source: &str,
    now: i64,
    min_interval: i64,
) -> anyhow::Result<bool> {
    let changed = store.conn.execute(
        "UPDATE vuln_sources SET last_request_at = ?2, last_attempt_at = ?2
         WHERE id = ?1
           AND (last_request_at IS NULL OR last_request_at <= ?2 - ?3)
           AND (retry_after_until IS NULL OR retry_after_until <= ?2)",
        params![source, now, min_interval],
    )?;
    Ok(changed == 1)
}

/// Note l'issue d'une tentative qui n'a rien chargé (`failed`, `busy`,
/// `refused_shrink`, `rate_limited`) : dernière tentative, issue, erreur
/// assainie (500 caractères) si donnée, `retry_after_until` si donné. Ni
/// la génération active, ni `last_success_at`, ni les validateurs, ni
/// `last_request_at` ne bougent.
pub fn record_outcome(
    store: &mut Store,
    source: &str,
    outcome: Outcome,
    error: Option<&str>,
    retry_after_until: Option<i64>,
    now: i64,
) -> anyhow::Result<()> {
    let error = error.map(|e| crate::api::log_text::LogText::new(e, 500));
    store.conn.execute(
        "UPDATE vuln_sources SET last_attempt_at = ?2, last_outcome = ?3,
             last_error = coalesce(?4, last_error),
             retry_after_until = coalesce(?5, retry_after_until)
         WHERE id = ?1",
        params![
            source,
            now,
            outcome.as_str(),
            error.as_ref().map(|e| e.as_str()),
            retry_after_until
        ],
    )?;
    Ok(())
}

/// État de synchronisation d'une source (`vulns/sync`, `vigie vulns
/// sources`, constat de fraîcheur).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncState {
    pub active_generation: i64,
    /// SHA-256 du dump de la génération active.
    pub dump_sha256: Option<String>,
    /// Failles de la génération active.
    pub entries: i64,
    pub etag: Option<String>,
    pub http_last_modified: Option<String>,
    pub loader_version: Option<u32>,
    /// Failles retenues des derniers chargements réussis, du plus ancien au
    /// plus récent.
    pub recent_entries: Vec<u64>,
    pub last_success_at: Option<i64>,
    pub last_attempt_at: Option<i64>,
    pub last_request_at: Option<i64>,
    pub retry_after_until: Option<i64>,
    /// Début du bail en cours.
    pub loading_since: Option<i64>,
    pub last_outcome: Option<Outcome>,
    pub last_error: Option<String>,
    pub dump_bytes: Option<i64>,
    pub unpacked_bytes: Option<i64>,
    pub last_duration_ms: Option<i64>,
    /// Révision du dump actif (Friends-Of-Presta).
    pub revision: Option<String>,
    /// URL demandée qui a servi `etag` et `http_last_modified` (F4) : une
    /// requête n'est conditionnelle que vers cette URL.
    pub validator_url: Option<String>,
    /// Synchronisations réussies sur un jeu reçu plus ancien que l'actif.
    pub stale_count: i64,
}

/// Colonnes de [`SyncState`] (`revision` existe depuis `0017.sql`) ;
/// celles de F4 valent `NULL` et 0 sur une base pas encore migrée (lecteur
/// de la CLI).
fn state_columns(store: &Store) -> anyhow::Result<&'static str> {
    Ok(if store.schema_version()? >= SCHEMA_ENRICHMENT {
        "active_generation, dump_sha256, entries, etag, http_last_modified,
         loader_version, recent_entries, last_success_at, last_attempt_at, last_request_at,
         retry_after_until, loading_since, last_outcome, last_error, dump_bytes, unpacked_bytes,
         last_duration_ms, revision, validator_url, stale_count"
    } else {
        "active_generation, dump_sha256, entries, etag, http_last_modified,
         loader_version, recent_entries, last_success_at, last_attempt_at, last_request_at,
         retry_after_until, loading_since, last_outcome, last_error, dump_bytes, unpacked_bytes,
         last_duration_ms, revision, NULL, 0"
    })
}

fn state_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<SyncState> {
    let recent: String = r.get(6)?;
    let outcome: Option<String> = r.get(12)?;
    let loader: Option<i64> = r.get(5)?;
    Ok(SyncState {
        active_generation: r.get(0)?,
        dump_sha256: r.get(1)?,
        entries: r.get(2)?,
        etag: r.get(3)?,
        http_last_modified: r.get(4)?,
        loader_version: loader.and_then(|v| u32::try_from(v).ok()),
        recent_entries: serde_json::from_str(&recent).unwrap_or_default(),
        last_success_at: r.get(7)?,
        last_attempt_at: r.get(8)?,
        last_request_at: r.get(9)?,
        retry_after_until: r.get(10)?,
        loading_since: r.get(11)?,
        last_outcome: outcome.as_deref().and_then(Outcome::from_name),
        last_error: r.get(13)?,
        dump_bytes: r.get(14)?,
        unpacked_bytes: r.get(15)?,
        last_duration_ms: r.get(16)?,
        revision: r.get(17)?,
        validator_url: r.get(18)?,
        stale_count: r.get(19)?,
    })
}

/// État d'une source ; `None` si elle n'a jamais été vue.
pub fn sync_state(store: &Store, source: &str) -> anyhow::Result<Option<SyncState>> {
    Ok(store
        .conn
        .query_row(
            &format!(
                "SELECT {} FROM vuln_sources WHERE id = ?1",
                state_columns(store)?
            ),
            [source],
            state_row,
        )
        .optional()?)
}

/// État de chaque source, par identifiant.
pub fn sync_states(store: &Store) -> anyhow::Result<Vec<(String, SyncState)>> {
    let mut stmt = store.conn.prepare(&format!(
        "SELECT {}, id FROM vuln_sources ORDER BY id",
        state_columns(store)?
    ))?;
    Ok(stmt
        .query_map([], |r| Ok((r.get(20)?, state_row(r)?)))?
        .collect::<rusqlite::Result<_>>()?)
}

/// `true` si la base porte l'état de synchronisation (migration 0017).
pub fn sync_available(store: &Store) -> anyhow::Result<bool> {
    Ok(store.schema_version()? >= SCHEMA_VULNS_SYNC)
}

/// Bilan d'un chargement validé.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Committed {
    pub generation: i64,
    pub entries: u64,
    pub tally: Tally,
}

/// Chargement d'une génération sous bail.
pub struct Load<'a> {
    store: &'a mut Store,
    clock: &'a dyn Clock,
    source: String,
    generation: i64,
    expected_active: i64,
    since: i64,
    /// Durée du bail, en secondes.
    lease: i64,
    seen: Seen,
    tally: Tally,
    entries: u64,
}

impl<'a> Load<'a> {
    /// Réserve une génération et prend le bail pour `lease` secondes
    /// ([`LEASE`] au plus), puis purge les générations orphelines.
    pub fn begin(
        store: &'a mut Store,
        source: &str,
        clock: &'a dyn Clock,
        lease: i64,
    ) -> Result<Load<'a>, LoadError> {
        let lease = lease.clamp(1, LEASE);
        let now = clock.unix();
        let (generation, expected_active) = reserve(store, source, now, lease)?;
        purge(store, source, now)?;
        Ok(Load {
            store,
            clock,
            source: source.to_owned(),
            generation,
            expected_active,
            since: now,
            lease,
            seen: Seen::default(),
            tally: Tally::default(),
            entries: 0,
        })
    }

    /// Génération réservée.
    pub fn generation(&self) -> i64 {
        self.generation
    }

    /// Compteurs du chargement : l'appelant (F2, F3) y ajoute les écarts de
    /// `from_osv`.
    pub fn tally_mut(&mut self) -> &mut Tally {
        &mut self.tally
    }

    /// Compteurs du chargement (`duplicate_id` compris).
    pub fn tally(&self) -> &Tally {
        &self.tally
    }

    /// Failles écrites jusqu'ici (retenues).
    pub fn entries(&self) -> u64 {
        self.entries
    }

    /// Génération active attendue à la bascule.
    pub fn expected_active(&self) -> i64 {
        self.expected_active
    }

    /// Réserve une requête vers la source ([`claim_request`]), sous ce bail.
    pub fn claim_request(&mut self, min_interval: i64) -> anyhow::Result<bool> {
        claim_request(self.store, &self.source, self.clock.unix(), min_interval)
    }

    /// Écrit des failles, par lots de [`VULN_BATCH`] ; un id déjà écrit dans
    /// ce chargement est écarté et compté `duplicate_id`.
    pub fn push(&mut self, advisories: &[Advisory]) -> Result<(), LoadError> {
        let fresh: Vec<&Advisory> = advisories
            .iter()
            .filter(|a| self.seen.first(a, &mut self.tally))
            .collect();
        for chunk in fresh.chunks(VULN_BATCH) {
            let now = self.clock.unix();
            let tx = self
                .store
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            check_lease(
                &tx,
                &self.source,
                self.generation,
                self.expected_active,
                now,
                self.lease,
            )?;
            for a in chunk {
                insert_advisory(&tx, &self.source, self.generation, a)?;
            }
            tx.commit()?;
            self.entries += chunk.len() as u64;
        }
        Ok(())
    }

    /// Bascule en compare-and-swap, avec dans la même instruction les
    /// compteurs (`tally`, ajouté à ceux du chargement) et l'état de
    /// synchronisation (`meta`) : un ETag n'est jamais écrit sans la
    /// génération qui lui correspond. Puis purge et point de contrôle du WAL.
    pub fn commit(mut self, tally: &Tally, meta: &SyncMeta) -> Result<Committed, LoadError> {
        self.tally.merge(tally);
        let now = self.clock.unix();
        let tx = self
            .store
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        switch(
            &tx,
            &Switch {
                source: &self.source,
                generation: self.generation,
                expected_active: self.expected_active,
                since: self.since,
                lease: self.lease,
                now,
                entries: self.entries,
                tally: &self.tally,
            },
            meta,
        )?;
        tx.commit()?;
        purge(self.store, &self.source, now)?;
        // PASSIVE : n'attend aucun lecteur ; le WAL est réutilisé ensuite.
        self.store
            .conn
            .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |_| Ok(()))?;
        Ok(Committed {
            generation: self.generation,
            entries: self.entries,
            tally: self.tally,
        })
    }

    /// Dump inchangé (304 ou même empreinte) : [`finish_unchanged`] sous
    /// ce bail. `false` : bail repris ou bascule concurrente, rien écrit.
    pub fn finish_unchanged(
        self,
        validators: &Validators,
        outcome: Outcome,
    ) -> Result<bool, LoadError> {
        self.finish(validators, outcome, false)
    }

    /// [`Load::finish_unchanged`], jeu reçu périmé compris (`stale`).
    pub fn finish(
        self,
        validators: &Validators,
        outcome: Outcome,
        stale: bool,
    ) -> Result<bool, LoadError> {
        Ok(finish_unchanged(
            &self.store.conn,
            &self.source,
            self.generation,
            self.expected_active,
            validators,
            outcome,
            stale,
            self.clock.unix(),
        )?)
    }

    /// Rend le bail s'il est encore détenu, sans rien noter ; la génération
    /// réservée reste vide et orpheline (purgée au chargement suivant).
    pub fn release(self) -> Result<(), LoadError> {
        self.store.conn.execute(
            "UPDATE vuln_sources SET loading_generation = NULL, loading_since = NULL
             WHERE id = ?1 AND loading_generation = ?2",
            params![self.source, self.generation],
        )?;
        Ok(())
    }

    /// Abandonne le chargement : rend le bail s'il est encore détenu et
    /// note l'erreur ; la génération réservée reste orpheline (purgée au
    /// chargement suivant).
    pub fn abandon(self, error: &str) -> Result<(), LoadError> {
        let now = self.clock.unix();
        let tx = self
            .store
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "UPDATE vuln_sources SET loading_generation = NULL, loading_since = NULL
             WHERE id = ?1 AND loading_generation = ?2",
            params![self.source, self.generation],
        )?;
        tx.execute(
            "UPDATE vuln_sources SET last_error = ?2, last_attempt_at = ?3 WHERE id = ?1",
            params![
                self.source,
                crate::api::log_text::LogText::detail(error).as_str(),
                now
            ],
        )?;
        tx.commit()?;
        Ok(())
    }
}

/// Réserve `g = next_generation`, jamais réutilisée, et prend le bail
/// (IMMEDIATE) ; rend `g` et la génération active attendue à la bascule.
/// Primitive partagée par [`Load`] et l'enrichissement de F4.
pub(crate) fn reserve(
    store: &mut Store,
    source: &str,
    now: i64,
    lease: i64,
) -> Result<(i64, i64), LoadError> {
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let row: Option<(i64, i64, Option<i64>, Option<i64>)> = tx
        .query_row(
            "SELECT active_generation, next_generation, loading_generation, loading_since
             FROM vuln_sources WHERE id = ?1",
            [source],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some((active, next, loading, since)) = row else {
        return Err(LoadError::UnknownSource(source.to_owned()));
    };
    if let (Some(_), Some(since)) = (loading, since)
        && now - since < lease
    {
        return Err(LoadError::Busy { since });
    }
    tx.execute(
        "UPDATE vuln_sources SET next_generation = ?2, loading_generation = ?3,
             loading_since = ?4, last_attempt_at = ?4
         WHERE id = ?1",
        params![source, next + 1, next, now],
    )?;
    tx.commit()?;
    Ok((next, active))
}

/// Chargement à basculer ([`switch`]).
pub(crate) struct Switch<'s> {
    pub source: &'s str,
    pub generation: i64,
    pub expected_active: i64,
    pub since: i64,
    pub lease: i64,
    pub now: i64,
    /// Lignes retenues.
    pub entries: u64,
    pub tally: &'s Tally,
}

/// Bascule en compare-and-swap dans `tx`, bail revérifié, avec dans la même
/// instruction les compteurs, les validateurs, leur URL et l'état de
/// synchronisation ; zéro ligne touchée : [`LoadError::Supplanted`].
/// Primitive partagée par [`Load::commit`] et l'enrichissement de F4.
pub(crate) fn switch(
    tx: &rusqlite::Transaction<'_>,
    load: &Switch<'_>,
    meta: &SyncMeta,
) -> Result<(), LoadError> {
    check_lease(
        tx,
        load.source,
        load.generation,
        load.expected_active,
        load.now,
        load.lease,
    )?;
    let recent: String = tx.query_row(
        "SELECT recent_entries FROM vuln_sources WHERE id = ?1",
        [load.source],
        |r| r.get(0),
    )?;
    let mut recent: Vec<u64> = if meta.accept_shrink {
        Vec::new()
    } else {
        serde_json::from_str(&recent).unwrap_or_default()
    };
    recent.push(load.entries);
    let skip = recent.len().saturating_sub(RECENT_LOADS);
    let recent = json(&recent[skip..].to_vec())?;
    let detail = serde_json::to_string(load.tally).context("compteurs")?;
    let sha256 = meta
        .sha256
        .as_deref()
        .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()));
    let changed = tx.execute(
        "UPDATE vuln_sources SET active_generation = ?2, loading_generation = NULL,
             loading_since = NULL, last_success_at = ?3, dump_sha256 = ?4, entries = ?5,
             dropped = ?6, dropped_detail = ?7, out_of_scope = ?8, last_error = NULL,
             etag = ?11, http_last_modified = ?12, dump_bytes = ?13, unpacked_bytes = ?14,
             last_duration_ms = ?15, loader_version = ?16, recent_entries = ?17,
             validator_url = ?18, revision = ?19, last_outcome = 'loaded', last_attempt_at = ?3
         WHERE id = ?1 AND active_generation = ?9 AND loading_generation = ?2
             AND loading_since = ?10",
        params![
            load.source,
            load.generation,
            load.now,
            sha256,
            load.entries as i64,
            load.tally.dropped() as i64,
            detail,
            load.tally.get(Reason::OutOfScope) as i64,
            load.expected_active,
            load.since,
            clean_etag(meta.etag.as_deref()),
            clean_date(meta.http_last_modified.as_deref()),
            i64::try_from(meta.dump_bytes).unwrap_or(i64::MAX),
            i64::try_from(meta.unpacked_bytes).unwrap_or(i64::MAX),
            i64::try_from(meta.duration_ms).unwrap_or(i64::MAX),
            meta.loader_version,
            recent,
            clean_url(meta.validator_url.as_deref()),
            meta.revision
                .as_deref()
                .filter(|r| (1..=128).contains(&r.len())
                    && r.bytes().all(|b| b.is_ascii_alphanumeric())),
        ],
    )?;
    if changed != 1 {
        return Err(LoadError::Supplanted);
    }
    Ok(())
}

pub(crate) fn check_lease(
    tx: &rusqlite::Transaction<'_>,
    source: &str,
    generation: i64,
    expected_active: i64,
    now: i64,
    lease: i64,
) -> Result<(), LoadError> {
    let (active, loading, since): (i64, Option<i64>, Option<i64>) = tx.query_row(
        "SELECT active_generation, loading_generation, loading_since
         FROM vuln_sources WHERE id = ?1",
        [source],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    if loading != Some(generation) || active != expected_active {
        return Err(LoadError::Supplanted);
    }
    if since.is_none_or(|since| now - since >= lease) {
        return Err(LoadError::LeaseExpired);
    }
    Ok(())
}

fn json<T: serde::Serialize>(value: &T) -> anyhow::Result<String> {
    serde_json::to_string(value).context("JSON")
}

fn insert_advisory(
    tx: &rusqlite::Transaction<'_>,
    source: &str,
    generation: i64,
    a: &Advisory,
) -> anyhow::Result<()> {
    tx.execute(
        "INSERT INTO vuln_advisories (source, generation, id, aliases, summary, severity, score,
             score_origin, informational, malicious, license, attribution, cwe, published,
             modified, refs, source_url)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
        params![
            source,
            generation,
            a.id,
            json(&a.aliases)?,
            a.summary,
            json(&a.severity)?,
            a.score.map(|s| s.tenths),
            a.score.map(|s| s.origin.as_str()),
            a.informational,
            a.malicious,
            a.license,
            a.attribution,
            json(&a.cwe)?,
            a.published,
            a.modified,
            json(&a.references)?,
            a.source_url,
        ],
    )
    .with_context(|| format!("faille {}", a.id))?;
    let mut alias = tx.prepare_cached(
        "INSERT INTO vuln_aliases (source, generation, advisory_id, alias) VALUES (?1, ?2, ?3, ?4)",
    )?;
    for al in &a.aliases {
        alias.execute(params![source, generation, a.id, al])?;
    }
    let mut line = tx.prepare_cached(
        "INSERT INTO vuln_affected (source, generation, advisory_id, purl_type, purl_namespace,
             purl_name, scheme, ranges, versions, last_known, unevaluable)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
    )?;
    for l in &a.affected {
        line.execute(params![
            source,
            generation,
            a.id,
            l.purl.ty().as_str(),
            l.purl.namespace().unwrap_or(""),
            l.purl.name(),
            l.scheme.as_str(),
            json(&l.ranges)?,
            json(&l.versions)?,
            l.last_known.as_ref().map(json).transpose()?,
            l.unevaluable,
        ])?;
    }
    Ok(())
}

/// Forme de la clé d'une table par génération, pour la purge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyShape {
    /// Tables de F1 (colonne `source`, rowid) : `DELETE … WHERE rowid IN
    /// (SELECT rowid … LIMIT n)`.
    RowidBySource,
    /// Tables `WITHOUT ROWID` de F4, propres à une source, clé
    /// `(generation, cve)` : génération orpheline par génération orpheline
    /// (trouvée par la clé, sans parcourir l'active), `DELETE … WHERE
    /// generation = g AND cve IN (SELECT cve … WHERE generation = g LIMIT
    /// n)` rejoué jusqu'à zéro ligne.
    GenerationCve,
}

/// Générations à épargner : l'active et celle sous bail en cours (l'active
/// deux fois si aucun bail ne court : jamais `NULL`, qui viderait
/// `NOT IN`). `None` si la source n'existe pas.
fn kept(
    tx: &rusqlite::Transaction<'_>,
    source: &str,
    now: i64,
) -> anyhow::Result<Option<[i64; 2]>> {
    let keep: Option<(i64, Option<i64>, Option<i64>)> = tx
        .query_row(
            "SELECT active_generation, loading_generation, loading_since
             FROM vuln_sources WHERE id = ?1",
            [source],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    Ok(keep.map(|(active, loading, since)| {
        // Une génération sous bail expiré n'est plus épargnée.
        let leased = match (loading, since) {
            (Some(g), Some(since)) if now - since < LEASE => g,
            _ => active,
        };
        [active, leased]
    }))
}

/// Première génération orpheline d'une table `(generation, cve)`, par
/// recherches successives sur la clé.
fn first_orphan(
    tx: &rusqlite::Transaction<'_>,
    table: &str,
    keep: [i64; 2],
) -> anyhow::Result<Option<i64>> {
    let mut stmt = tx.prepare_cached(&format!(
        "SELECT generation FROM {table} WHERE generation > ?1 ORDER BY generation LIMIT 1"
    ))?;
    let mut after = i64::MIN;
    loop {
        let next: Option<i64> = stmt.query_row([after], |r| r.get(0)).optional()?;
        match next {
            Some(g) if keep.contains(&g) => after = g,
            other => return Ok(other),
        }
    }
}

/// Purge par lots tout sauf la génération active et celle sous bail en
/// cours ; rend le nombre de lignes retirées. Une transaction par lot.
pub fn purge(store: &mut Store, source: &str, now: i64) -> anyhow::Result<u64> {
    purge_batches(
        store,
        source,
        now,
        &[
            ("vuln_aliases", KeyShape::RowidBySource),
            ("vuln_affected", KeyShape::RowidBySource),
            ("vuln_advisories", KeyShape::RowidBySource),
        ],
    )
}

/// Purge de `tables`, dans l'ordre, selon la forme de leur clé : jamais
/// plus de [`PURGE_BATCH`] lignes par transaction, générations à épargner
/// relues dans chacune.
pub fn purge_batches(
    store: &mut Store,
    source: &str,
    now: i64,
    tables: &[(&str, KeyShape)],
) -> anyhow::Result<u64> {
    let mut removed = 0;
    for &(table, shape) in tables {
        loop {
            let tx = store
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let Some(keep) = kept(&tx, source, now)? else {
                return Ok(removed);
            };
            let n = match shape {
                KeyShape::RowidBySource => tx.execute(
                    &format!(
                        "DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table}
                             WHERE source = ?1 AND generation NOT IN (?2, ?3) LIMIT ?4)"
                    ),
                    params![source, keep[0], keep[1], PURGE_BATCH as i64],
                )?,
                KeyShape::GenerationCve => match first_orphan(&tx, table, keep)? {
                    None => 0,
                    Some(g) => tx.execute(
                        &format!(
                            "DELETE FROM {table} WHERE generation = ?1 AND cve IN
                                 (SELECT cve FROM {table} WHERE generation = ?1 LIMIT ?2)"
                        ),
                        params![g, PURGE_BATCH as i64],
                    )?,
                },
            };
            tx.commit()?;
            removed += n as u64;
            let done = match shape {
                KeyShape::RowidBySource => n < PURGE_BATCH,
                // Plus aucune génération orpheline.
                KeyShape::GenerationCve => n == 0,
            };
            if done {
                break;
            }
        }
    }
    Ok(removed)
}

/// Une source, pour `vigie vulns sources`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRow {
    pub id: String,
    pub url: String,
    pub license: String,
    pub attribution: String,
    pub active_generation: i64,
    pub loading_since: Option<i64>,
    pub last_success_at: Option<i64>,
    pub last_attempt_at: Option<i64>,
    pub entries: i64,
    pub dropped: i64,
    pub dropped_detail: BTreeMap<String, u64>,
    pub out_of_scope: i64,
    pub last_error: Option<String>,
}

/// `true` si la base porte les tables des failles.
pub fn available(store: &Store) -> anyhow::Result<bool> {
    Ok(store.schema_version()? >= SCHEMA_VULNS)
}

/// Sources, par identifiant.
pub fn sources(store: &Store) -> anyhow::Result<Vec<SourceRow>> {
    let mut stmt = store.conn.prepare(
        "SELECT id, url, license, attribution, active_generation, loading_since,
             last_success_at, last_attempt_at, entries, dropped, dropped_detail, out_of_scope,
             last_error
         FROM vuln_sources ORDER BY id",
    )?;
    let rows = stmt
        .query_map([], |r| {
            let detail: String = r.get(10)?;
            Ok(SourceRow {
                id: r.get(0)?,
                url: r.get(1)?,
                license: r.get(2)?,
                attribution: r.get(3)?,
                active_generation: r.get(4)?,
                loading_since: r.get(5)?,
                last_success_at: r.get(6)?,
                last_attempt_at: r.get(7)?,
                entries: r.get(8)?,
                dropped: r.get(9)?,
                dropped_detail: serde_json::from_str(&detail).unwrap_or_default(),
                out_of_scope: r.get(11)?,
                last_error: r.get(12)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(rows)
}

/// Faille relue, avec sa source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    pub source: String,
    pub advisory: Advisory,
}

const ADVISORY_COLUMNS: &str = "a.source, a.id, a.aliases, a.summary, a.severity, a.score,
    a.score_origin, a.informational, a.malicious, a.license, a.attribution, a.cwe, a.published,
    a.modified, a.refs, a.source_url, a.generation";

fn decode<T: serde::de::DeserializeOwned>(raw: &str) -> rusqlite::Result<T> {
    serde_json::from_str(raw).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })
}

/// Faille sans ses lignes, et sa génération.
fn advisory_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<(String, i64, Advisory)> {
    let score: Option<u8> = r.get(5)?;
    let origin: Option<String> = r.get(6)?;
    let score = match (score, origin.as_deref().and_then(ScoreOrigin::from_name)) {
        (Some(tenths), Some(origin)) => Some(Score { tenths, origin }),
        _ => None,
    };
    let advisory = Advisory {
        id: r.get(1)?,
        aliases: decode(&r.get::<_, String>(2)?)?,
        summary: r.get(3)?,
        severity: decode::<Vec<Severity>>(&r.get::<_, String>(4)?)?,
        score,
        informational: r.get(7)?,
        malicious: r.get(8)?,
        license: r.get(9)?,
        attribution: r.get(10)?,
        cwe: decode(&r.get::<_, String>(11)?)?,
        published: r.get(12)?,
        modified: r.get(13)?,
        references: decode::<Vec<Reference>>(&r.get::<_, String>(14)?)?,
        source_url: r.get(15)?,
        affected: Vec::new(),
    };
    Ok((r.get(0)?, r.get(16)?, advisory))
}

const LINE_COLUMNS: &str = "purl_type, purl_namespace, purl_name, scheme, ranges, versions,
    last_known, unevaluable";

fn line_row(r: &rusqlite::Row<'_>, offset: usize) -> rusqlite::Result<Option<Affected>> {
    let ty: String = r.get(offset)?;
    let ns: String = r.get(offset + 1)?;
    let name: String = r.get(offset + 2)?;
    let scheme: String = r.get(offset + 3)?;
    let (Some(ty), Some(scheme)) = (PurlType::from_name(&ty), Scheme::from_name(&scheme)) else {
        return Ok(None);
    };
    let Ok(purl) = Purl::new(ty, (!ns.is_empty()).then_some(ns.as_str()), &name, None) else {
        return Ok(None);
    };
    let last_known: Option<String> = r.get(offset + 6)?;
    Ok(Some(Affected {
        purl,
        scheme,
        ranges: decode::<Vec<Range>>(&r.get::<_, String>(offset + 4)?)?,
        versions: decode(&r.get::<_, String>(offset + 5)?)?,
        last_known: last_known.as_deref().map(decode::<LastKnown>).transpose()?,
        unevaluable: r.get(offset + 7)?,
    }))
}

/// Failles actives dont l'identifiant ou un alias vaut `id_or_alias`
/// (alias normalisé : `cve-…` trouve `CVE-…`), avec toutes leurs lignes.
pub fn advisory(store: &Store, id_or_alias: &str) -> anyhow::Result<Vec<Stored>> {
    let Some(key) = normalize_alias(id_or_alias) else {
        return Ok(Vec::new());
    };
    let tx = store.conn.unchecked_transaction()?;
    let mut out = Vec::new();
    {
        let mut stmt = tx.prepare(&format!(
            "SELECT {ADVISORY_COLUMNS} FROM vuln_advisories a
             JOIN vuln_sources s ON s.id = a.source AND s.active_generation = a.generation
             WHERE a.id = ?1 OR a.id = ?2
                OR a.id IN (SELECT advisory_id FROM vuln_aliases al
                            WHERE al.alias = ?2 AND al.source = a.source
                              AND al.generation = a.generation)
             ORDER BY a.source, a.id"
        ))?;
        let rows: Vec<(String, i64, Advisory)> = stmt
            .query_map(params![id_or_alias, key], advisory_row)?
            .collect::<rusqlite::Result<_>>()?;
        let mut lines = tx.prepare(&format!(
            "SELECT {LINE_COLUMNS} FROM vuln_affected
             WHERE source = ?1 AND generation = ?2 AND advisory_id = ?3 ORDER BY rowid"
        ))?;
        for (source, generation, mut advisory) in rows {
            advisory.affected = lines
                .query_map(params![source, generation, advisory.id], |r| line_row(r, 0))?
                .filter_map(|l| l.transpose())
                .collect::<rusqlite::Result<_>>()?;
            out.push(Stored { source, advisory });
        }
    }
    tx.finish()?;
    Ok(out)
}

/// Faille candidate au rapprochement d'un purl : la faille (sans ses
/// lignes) et les lignes de ce purl.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub source: String,
    /// Génération active lue.
    pub generation: i64,
    /// Faille complète (alias, score, drapeaux, références, licence,
    /// attribution), sans ses lignes.
    pub advisory: Advisory,
    /// Lignes `affected` de ce purl.
    pub lines: Vec<Affected>,
    /// Une ligne de `lines` vient d'une correction de plage active (F3,
    /// `vulns/corrections.rs`) : affichée « plage corrigée ».
    pub corrected: bool,
}

/// Failles actives qui visent le purl (sans version), en une requête jointe
/// sur la génération active, dans une seule lecture. Une ligne
/// `unevaluable` de Friends-Of-Presta prend la plage de sa correction active
/// (F3), lue dans la même lecture ; une correction illisible la laisse en
/// « plage inconnue ».
pub fn candidates(store: &Store, purl: &Purl) -> anyhow::Result<Vec<Candidate>> {
    let tx = store.conn.unchecked_transaction()?;
    let mut out: Vec<Candidate> = Vec::new();
    {
        let mut stmt = tx.prepare_cached(&format!(
            "SELECT {ADVISORY_COLUMNS}, f.purl_type, f.purl_namespace, f.purl_name, f.scheme,
                 f.ranges, f.versions, f.last_known, f.unevaluable
             FROM vuln_affected f
             JOIN vuln_sources s ON s.id = f.source AND s.active_generation = f.generation
             JOIN vuln_advisories a ON a.source = f.source AND a.generation = f.generation
                 AND a.id = f.advisory_id
             WHERE f.purl_type = ?1 AND f.purl_namespace = ?2 AND f.purl_name = ?3
             ORDER BY a.source, a.id, f.rowid"
        ))?;
        let mut rows = stmt.query(params![
            purl.ty().as_str(),
            purl.namespace().unwrap_or(""),
            purl.name()
        ])?;
        while let Some(r) = rows.next()? {
            let (source, generation, advisory) = advisory_row(r)?;
            let Some(line) = line_row(r, 17)? else {
                continue;
            };
            match out.last_mut() {
                Some(c) if c.source == source && c.advisory.id == advisory.id => c.lines.push(line),
                _ => out.push(Candidate {
                    source,
                    generation,
                    advisory,
                    lines: vec![line],
                    corrected: false,
                }),
            }
        }
        for c in &mut out {
            if c.source != crate::vulns::sources::friends_of_presta::SOURCE_ID {
                continue;
            }
            for line in c.lines.iter_mut().filter(|l| l.unevaluable) {
                let correction = crate::vulns::corrections::active(
                    &tx,
                    &c.source,
                    &c.advisory.id,
                    &line.purl.canonical(),
                )?;
                if let Some(crate::vulns::corrections::Active::Ranges { ranges, .. }) = correction {
                    line.ranges = ranges;
                    line.unevaluable = false;
                    c.corrected = true;
                }
            }
        }
    }
    tx.finish()?;
    Ok(out)
}

/// Verdict de chaque faille candidate pour le purl et sa version (`None` :
/// version inconnue, chaque faille en « version inconnue »).
pub fn match_purl(store: &Store, purl: &Purl) -> anyhow::Result<Vec<(Candidate, Verdict)>> {
    Ok(candidates(store, &purl.without_version())?
        .into_iter()
        .map(|c| {
            let lines: Vec<&Affected> = c.lines.iter().collect();
            let verdict = match_advisory(&lines, purl.version());
            (c, verdict)
        })
        .collect())
}

/// Génération active de chaque source, sans compteur : lecture légère pour
/// l'« époque » des constats de F7.
pub fn active_generations(store: &Store) -> anyhow::Result<Vec<(String, i64)>> {
    let mut stmt = store
        .conn
        .prepare_cached("SELECT id, active_generation FROM vuln_sources ORDER BY id")?;
    Ok(stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?)
}

/// Failles de la génération active d'une source (lecture cohérente).
pub fn active_count(store: &Store, source: &str) -> anyhow::Result<i64> {
    Ok(store.conn.query_row(
        "SELECT count(*) FROM vuln_advisories a
         JOIN vuln_sources s ON s.id = a.source AND s.active_generation = a.generation
         WHERE a.source = ?1",
        [source],
        |r| r.get(0),
    )?)
}

/// Générations présentes en base pour une source (tests de purge).
pub fn generations(store: &Store, source: &str) -> anyhow::Result<Vec<i64>> {
    let mut stmt = store.conn.prepare(
        "SELECT DISTINCT generation FROM vuln_advisories WHERE source = ?1
         UNION SELECT DISTINCT generation FROM vuln_affected WHERE source = ?1
         UNION SELECT DISTINCT generation FROM vuln_aliases WHERE source = ?1
         ORDER BY 1",
    )?;
    Ok(stmt
        .query_map([source], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?)
}
