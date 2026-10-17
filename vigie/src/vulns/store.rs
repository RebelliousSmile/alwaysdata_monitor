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
//!    `loading_since`). Un second chargement est refusé tant que le bail
//!    court ([`LEASE`]) ; il le reprend après expiration.
//! 2. [`Load::push`] écrit par lots de [`VULN_BATCH`] failles, une
//!    transaction IMMEDIATE chacun, qui **revérifie le bail** : expiré ou
//!    supplanté, le chargement s'arrête aussitôt.
//! 3. [`Load::commit`] bascule `active_generation` en compare-and-swap
//!    (génération active attendue et bail toujours détenu, sinon
//!    [`LoadError::Supplanted`] et la génération reste orpheline), puis purge
//!    et `PRAGMA wal_checkpoint(PASSIVE)`.
//!
//! La purge ([`purge`]) retire par lots tout sauf la génération active et
//! celle sous bail en cours, enfants d'abord. Les lecteurs ne lisent que la
//! génération active, dans une transaction de lecture : ils voient l'ancien
//! jeu complet ou le nouveau, jamais un mélange.

use std::collections::BTreeMap;

use anyhow::Context;
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::clock::Clock;
use crate::store::{SCHEMA_VULNS, Store};
use crate::vulns::advisory::{
    Advisory, Affected, LastKnown, Range, Reason, Reference, Score, ScoreOrigin, Seen, Severity,
    Tally, normalize_alias,
};
use crate::vulns::purl::{Purl, PurlType};
use crate::vulns::range::{Verdict, match_advisory};
use crate::vulns::version::Scheme;

/// Durée du bail d'un chargement.
pub const LEASE: i64 = 6 * 3600;
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
    #[error("chargement déjà en cours depuis {since} (bail de 6 h)")]
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
    seen: Seen,
    tally: Tally,
    entries: u64,
}

impl<'a> Load<'a> {
    /// Réserve une génération et prend le bail, puis purge les générations
    /// orphelines.
    pub fn begin(
        store: &'a mut Store,
        source: &str,
        clock: &'a dyn Clock,
    ) -> Result<Load<'a>, LoadError> {
        let now = clock.unix();
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
            && now - since < LEASE
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
        purge(store, source, now)?;
        Ok(Load {
            store,
            clock,
            source: source.to_owned(),
            generation: next,
            expected_active: active,
            since: now,
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
            )?;
            for a in chunk {
                insert_advisory(&tx, &self.source, self.generation, a)?;
            }
            tx.commit()?;
            self.entries += chunk.len() as u64;
        }
        Ok(())
    }

    /// Bascule en compare-and-swap, puis purge et point de contrôle du WAL.
    pub fn commit(self, dump_sha256: Option<&str>) -> Result<Committed, LoadError> {
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
        )?;
        let detail = serde_json::to_string(&self.tally).context("compteurs")?;
        let changed = tx.execute(
            "UPDATE vuln_sources SET active_generation = ?2, loading_generation = NULL,
                 loading_since = NULL, last_success_at = ?3, dump_sha256 = ?4, entries = ?5,
                 dropped = ?6, dropped_detail = ?7, out_of_scope = ?8, last_error = NULL
             WHERE id = ?1 AND active_generation = ?9 AND loading_generation = ?2
                 AND loading_since = ?10",
            params![
                self.source,
                self.generation,
                now,
                dump_sha256,
                self.entries as i64,
                self.tally.dropped() as i64,
                detail,
                self.tally.get(Reason::OutOfScope) as i64,
                self.expected_active,
                self.since,
            ],
        )?;
        if changed != 1 {
            return Err(LoadError::Supplanted);
        }
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

fn check_lease(
    tx: &rusqlite::Transaction<'_>,
    source: &str,
    generation: i64,
    expected_active: i64,
    now: i64,
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
    if since.is_none_or(|since| now - since >= LEASE) {
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

/// Purge par lots tout sauf la génération active et celle sous bail en
/// cours ; rend le nombre de lignes retirées. Une transaction par lot.
pub fn purge(store: &mut Store, source: &str, now: i64) -> anyhow::Result<u64> {
    let mut removed = 0;
    for table in ["vuln_aliases", "vuln_affected", "vuln_advisories"] {
        loop {
            let tx = store
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let keep: Option<(i64, Option<i64>, Option<i64>)> = tx
                .query_row(
                    "SELECT active_generation, loading_generation, loading_since
                     FROM vuln_sources WHERE id = ?1",
                    [source],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let Some((active, loading, since)) = keep else {
                return Ok(removed);
            };
            // Une génération sous bail expiré n'est plus épargnée.
            let leased = match (loading, since) {
                (Some(g), Some(since)) if now - since < LEASE => g,
                _ => active,
            };
            let n = tx.execute(
                &format!(
                    "DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table}
                         WHERE source = ?1 AND generation NOT IN (?2, ?3) LIMIT ?4)"
                ),
                params![source, active, leased, PURGE_BATCH as i64],
            )?;
            tx.commit()?;
            removed += n as u64;
            if n < PURGE_BATCH {
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
    /// Une correction de plage auditée s'applique (F3) ; toujours `false`
    /// en F1.
    pub corrected: bool,
}

/// Failles actives qui visent le purl (sans version), en une requête jointe
/// sur la génération active, dans une seule lecture.
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
