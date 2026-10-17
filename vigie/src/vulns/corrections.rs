//! Corrections de plage auditées (#17, migration `0018.sql`) : pour une ligne
//! `unevaluable` de Friends-Of-Presta (« Impacted release » hors grammaire),
//! la plage machine saisie sur le VPS par l'exploitant, valable pour tous les
//! sites. Distincte d'une dérogation : elle ne masque rien, elle remplace
//! « plage inconnue » par une plage évaluée (`docs/failles.md`,
//! « Dérogations »).
//!
//! - **En ajout seul** (`vuln_range_corrections`, déclencheurs) : la ligne la
//!   plus récente d'une clé `(source, advisory_id, purl)` fait foi ; `ranges`
//!   NULL vaut retrait. Hors des générations : une resynchronisation ne
//!   l'efface pas.
//! - **Auditée** : chaque saisie et chaque retrait sont inscrits, dans la
//!   même transaction, dans la chaîne signée du pseudo-site réservé
//!   `_veilleur` (`command/audit.rs`) ; [`verify`] contrôle la chaîne et la
//!   correspondance dans les deux sens.
//! - **Appliquée à la lecture** (`vulns/store.rs`, `candidates`) : seule une
//!   ligne `unevaluable` de `friends-of-presta` prend la plage corrigée ; si
//!   la source devient lisible, sa plage prime (correction « sans objet ») ;
//!   une correction illisible laisse la ligne en « plage inconnue ».

use std::collections::HashMap;

use anyhow::Context;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use crate::api::log_text::LogText;
use crate::capability::WATCHER_SITE;
use crate::command::audit::{self, Entry};
use crate::store::{SCHEMA_RANGE_CORRECTIONS, Store};
use crate::vulns::UsageError;
use crate::vulns::advisory::{Event, Range};
use crate::vulns::purl::Purl;
use crate::vulns::sources::friends_of_presta::SOURCE_ID;
use crate::vulns::sources::release::parse_release;
use crate::vulns::version::{Scheme, parse, parse_bound};

/// Motif : 1 à 500 caractères.
pub const MAX_REASON_CHARS: usize = 500;
/// Évènement d'audit d'une saisie.
pub const EVENT_SET: &str = "range-corrected";
/// Évènement d'audit d'un retrait.
pub const EVENT_CLEAR: &str = "range-correction-cleared";

/// Une ligne de `vuln_range_corrections`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub id: i64,
    pub source: String,
    pub advisory_id: String,
    /// purl canonique, sans version.
    pub purl: String,
    /// Plages en JSON ; `None` : retrait.
    pub ranges: Option<String>,
    pub reason: String,
    pub operator: String,
    pub at: i64,
    pub audit_hash: String,
}

/// Détail de l'entrée d'audit : ce que la ligne porte.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Detail {
    source: String,
    advisory_id: String,
    purl: String,
    ranges: Option<String>,
    reason: String,
    operator: String,
}

/// Correction relue pour une ligne.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Active {
    /// Plages évaluables, et le motif.
    Ranges { ranges: Vec<Range>, reason: String },
    /// `ranges` illisible en base : la ligne reste « plage inconnue ».
    Unreadable,
}

/// État d'une correction, pour `vigie vulns corrections`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Appliquée à une ligne `unevaluable`.
    Active,
    /// La ligne de la source est devenue évaluable : sa plage prime.
    Moot,
    /// Faille ou purl absent de la génération active.
    Orphan,
    /// `ranges` illisible.
    Unreadable,
    /// Retirée (`--clear`).
    Cleared,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Moot => "sans objet",
            Self::Orphan => "orpheline",
            Self::Unreadable => "illisible",
            Self::Cleared => "retirée",
        }
    }
}

/// Nom du compte qui saisit : `getpwuid(geteuid())`, jamais `$USER` (que
/// l'appelant choisit) ; l'uid seul sans entrée passwd ; hors Unix,
/// « inconnu ».
#[cfg(unix)]
pub fn operator() -> String {
    // SAFETY: geteuid n'a ni argument ni effet de bord, et ne peut échouer.
    let uid = unsafe { libc::geteuid() };
    // SAFETY: `passwd` est une structure C sans invariant ; remplie par
    // getpwuid_r, ses pointeurs visent `buf`, gardé vivant jusqu'à la copie.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: tous les pointeurs sont valides pour la durée de l'appel et
    // `buf.len()` est la taille réelle du tampon.
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc == 0 && !result.is_null() && !pwd.pw_name.is_null() {
        // SAFETY: pw_name pointe dans `buf`, terminé par un octet nul.
        let name = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) }.to_string_lossy();
        if !name.is_empty() {
            return String::from(LogText::new(&name, 64));
        }
    }
    format!("uid {uid}")
}

/// Hors Unix (tests et reprise locale sous Windows) : aucun compte lisible.
#[cfg(not(unix))]
pub fn operator() -> String {
    "inconnu (hors Unix)".to_owned()
}

/// Plus grand `id` de la table (`None` si elle est vide ou absente), en
/// lecture seule : toute saisie et tout retrait le font croître. Sert
/// d'« époque » au rapprochement de F7 (#21).
pub fn latest_range_correction_id(store: &Store) -> anyhow::Result<Option<i64>> {
    if store.schema_version()? < SCHEMA_RANGE_CORRECTIONS {
        return Ok(None);
    }
    Ok(store
        .conn
        .query_row("SELECT max(id) FROM vuln_range_corrections", [], |r| {
            r.get(0)
        })?)
}

/// Plages d'une correction relues : non vides, PHP, bornes analysables.
fn decode_ranges(raw: &str) -> Option<Vec<Range>> {
    let ranges: Vec<Range> = serde_json::from_str(raw).ok()?;
    let ok = !ranges.is_empty()
        && ranges.iter().all(|r| {
            r.scheme == Scheme::Php
                && !r.events.is_empty()
                && r.events.iter().all(|e| match e {
                    Event::Introduced(v) => parse_bound(Scheme::Php, v).is_ok(),
                    Event::Fixed(v) | Event::LastAffected(v) | Event::Limit(v) => {
                        parse(Scheme::Php, v).is_ok()
                    }
                })
        });
    ok.then_some(ranges)
}

/// Correction en vigueur pour une ligne : la plus récente de la clé, si
/// elle n'est pas un retrait. Table absente (base antérieure) : aucune.
pub fn active(
    conn: &rusqlite::Connection,
    source: &str,
    advisory_id: &str,
    purl: &str,
) -> anyhow::Result<Option<Active>> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version < SCHEMA_RANGE_CORRECTIONS as i64 {
        return Ok(None);
    }
    let row: Option<(Option<String>, String)> = conn
        .prepare_cached(
            "SELECT ranges, reason FROM vuln_range_corrections
             WHERE source = ?1 AND advisory_id = ?2 AND purl = ?3 ORDER BY id DESC LIMIT 1",
        )?
        .query_row(params![source, advisory_id, purl], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .optional()?;
    Ok(match row {
        None | Some((None, _)) => None,
        Some((Some(raw), reason)) => Some(match decode_ranges(&raw) {
            Some(ranges) => Active::Ranges { ranges, reason },
            None => Active::Unreadable,
        }),
    })
}

/// Motif de la correction en vigueur d'une ligne (affichage « plage
/// corrigée »).
pub fn reason_for(
    store: &Store,
    source: &str,
    advisory_id: &str,
    purl: &Purl,
) -> anyhow::Result<Option<String>> {
    Ok(
        match active(
            &store.conn,
            source,
            advisory_id,
            &purl.without_version().canonical(),
        )? {
            Some(Active::Ranges { reason, .. }) => Some(reason),
            _ => None,
        },
    )
}

/// Ligne de la faille dans la génération active de Friends-Of-Presta :
/// `None` absente, `Some(unevaluable)` sinon.
fn source_line(
    conn: &rusqlite::Connection,
    advisory_id: &str,
    purl: &Purl,
) -> rusqlite::Result<Option<bool>> {
    conn.query_row(
        "SELECT max(f.unevaluable) FROM vuln_affected f
         JOIN vuln_sources s ON s.id = f.source AND s.active_generation = f.generation
         WHERE f.source = ?1 AND f.advisory_id = ?2 AND f.purl_type = ?3
           AND f.purl_namespace = ?4 AND f.purl_name = ?5",
        params![
            SOURCE_ID,
            advisory_id,
            purl.ty().as_str(),
            purl.namespace().unwrap_or(""),
            purl.name()
        ],
        |r| r.get::<_, Option<bool>>(0),
    )
}

/// Motif saisi : 1 à 500 caractères, assaini.
fn clean_reason(reason: &str) -> Result<String, UsageError> {
    let reason = reason.trim();
    let n = reason.chars().count();
    if n == 0 || n > MAX_REASON_CHARS {
        return Err(UsageError(format!(
            "motif obligatoire, {MAX_REASON_CHARS} caractères au plus (reçu : {n})"
        )));
    }
    Ok(LogText::new(reason, MAX_REASON_CHARS).into())
}

/// La faille doit être de Friends-Of-Presta et avoir une ligne pour ce purl ;
/// rend `true` si cette ligne est `unevaluable`.
fn check_target(store: &Store, advisory_id: &str, purl: &Purl) -> anyhow::Result<bool> {
    let sources: Vec<String> = store
        .conn
        .prepare(
            "SELECT a.source FROM vuln_advisories a
             JOIN vuln_sources s ON s.id = a.source AND s.active_generation = a.generation
             WHERE a.id = ?1 ORDER BY a.source",
        )?
        .query_map([advisory_id], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    if sources.is_empty() {
        return Err(UsageError(format!("aucune faille {advisory_id} dans la base")).into());
    }
    if !sources.iter().any(|s| s == SOURCE_ID) {
        return Err(UsageError(format!(
            "faille {advisory_id} de la source {} : seules les failles {SOURCE_ID} se corrigent",
            sources.join(", ")
        ))
        .into());
    }
    match source_line(&store.conn, advisory_id, purl)? {
        None => Err(UsageError(format!("{purl} absent de la faille {advisory_id}")).into()),
        Some(unevaluable) => Ok(unevaluable),
    }
}

/// Écrit une ligne et son entrée d'audit dans une seule transaction.
fn write(
    store: &mut Store,
    signer: &SigningKey,
    advisory_id: &str,
    purl: &Purl,
    ranges: Option<String>,
    reason: String,
    now: i64,
) -> anyhow::Result<i64> {
    let detail = Detail {
        source: SOURCE_ID.to_owned(),
        advisory_id: advisory_id.to_owned(),
        purl: purl.canonical(),
        ranges,
        reason,
        operator: operator(),
    };
    let entry = Entry {
        site: WATCHER_SITE.to_owned(),
        at: now,
        event: if detail.ranges.is_some() {
            EVENT_SET
        } else {
            EVENT_CLEAR
        }
        .to_owned(),
        command_id: None,
        detail: serde_json::to_string(&detail)?,
        typology: None,
    };
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let hash = audit::append(&tx, signer, &entry)?;
    tx.execute(
        "INSERT INTO vuln_range_corrections
             (source, advisory_id, purl, ranges, reason, operator, at, audit_hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            detail.source,
            detail.advisory_id,
            detail.purl,
            detail.ranges,
            detail.reason,
            detail.operator,
            now,
            hash
        ],
    )
    .context("correction de plage")?;
    let id = tx.last_insert_rowid();
    tx.commit()?;
    Ok(id)
}

/// Saisit une correction : `expression` suit la grammaire fermée de
/// « Impacted release », sans remarque. Rend l'`id` de la ligne.
pub fn add(
    store: &mut Store,
    signer: &SigningKey,
    advisory_id: &str,
    purl: &Purl,
    expression: &str,
    reason: &str,
    now: i64,
) -> anyhow::Result<i64> {
    let purl = purl.without_version();
    let reason = clean_reason(reason)?;
    let events = parse_release(expression, false).ok_or_else(|| {
        UsageError(
            "plage hors grammaire (« <= V », « < V », « >= A, < B », « A - B »…, sans remarque entre parenthèses)".into(),
        )
    })?;
    if !check_target(store, advisory_id, &purl)? {
        return Err(UsageError(format!(
            "la plage de la source est lisible pour {purl} : rien à corriger"
        ))
        .into());
    }
    let ranges = serde_json::to_string(&vec![Range {
        scheme: Scheme::Php,
        events,
    }])?;
    write(store, signer, advisory_id, &purl, Some(ranges), reason, now)
}

/// Retire la correction en vigueur d'une clé (la faille peut avoir
/// disparu : une correction orpheline se retire aussi).
pub fn clear(
    store: &mut Store,
    signer: &SigningKey,
    advisory_id: &str,
    purl: &Purl,
    reason: &str,
    now: i64,
) -> anyhow::Result<i64> {
    let purl = purl.without_version();
    let reason = clean_reason(reason)?;
    let current: Option<Option<String>> = store
        .conn
        .query_row(
            "SELECT ranges FROM vuln_range_corrections
             WHERE source = ?1 AND advisory_id = ?2 AND purl = ?3 ORDER BY id DESC LIMIT 1",
            params![SOURCE_ID, advisory_id, purl.canonical()],
            |r| r.get(0),
        )
        .optional()?;
    if !matches!(current, Some(Some(_))) {
        return Err(UsageError(format!(
            "aucune correction en vigueur pour {advisory_id} {purl}"
        ))
        .into());
    }
    write(store, signer, advisory_id, &purl, None, reason, now)
}

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    Ok(Row {
        id: r.get(0)?,
        source: r.get(1)?,
        advisory_id: r.get(2)?,
        purl: r.get(3)?,
        ranges: r.get(4)?,
        reason: r.get(5)?,
        operator: r.get(6)?,
        at: r.get(7)?,
        audit_hash: r.get(8)?,
    })
}

const ROW_COLUMNS: &str = "id, source, advisory_id, purl, ranges, reason, operator, at, audit_hash";

/// Toutes les lignes, dans l'ordre.
pub fn rows(store: &Store) -> anyhow::Result<Vec<Row>> {
    if store.schema_version()? < SCHEMA_RANGE_CORRECTIONS {
        return Ok(Vec::new());
    }
    Ok(store
        .conn
        .prepare(&format!(
            "SELECT {ROW_COLUMNS} FROM vuln_range_corrections ORDER BY id"
        ))?
        .query_map([], row)?
        .collect::<rusqlite::Result<_>>()?)
}

/// Dernière ligne de chaque clé et son état.
pub fn list(store: &Store) -> anyhow::Result<Vec<(Row, State)>> {
    let mut latest: Vec<Row> = Vec::new();
    let mut at: HashMap<(String, String, String), usize> = HashMap::new();
    for r in rows(store)? {
        let key = (r.source.clone(), r.advisory_id.clone(), r.purl.clone());
        match at.get(&key) {
            Some(&i) => latest[i] = r,
            None => {
                at.insert(key, latest.len());
                latest.push(r);
            }
        }
    }
    let mut out = Vec::with_capacity(latest.len());
    for r in latest {
        let state = match &r.ranges {
            None => State::Cleared,
            Some(raw) if decode_ranges(raw).is_none() => State::Unreadable,
            Some(_) => match Purl::parse(&r.purl)
                .ok()
                .map(|p| source_line(&store.conn, &r.advisory_id, &p))
                .transpose()?
                .flatten()
            {
                None => State::Orphan,
                Some(true) => State::Active,
                Some(false) => State::Moot,
            },
        };
        out.push((r, state));
    }
    Ok(out)
}

/// Plages d'une ligne, en texte court (`introduced 0, last_affected 3.1.0`).
pub fn describe(raw: &str) -> String {
    match decode_ranges(raw) {
        None => "illisible".to_owned(),
        Some(ranges) => ranges
            .iter()
            .map(|r| {
                r.events
                    .iter()
                    .map(|e| {
                        let name = match e {
                            Event::Introduced(_) => "introduced",
                            Event::Fixed(_) => "fixed",
                            Event::LastAffected(_) => "last_affected",
                            Event::Limit(_) => "limit",
                        };
                        format!("{name} {}", e.value())
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .collect::<Vec<_>>()
            .join(" ; "),
    }
}

/// Vérifie la chaîne `_veilleur` (liens, hash, signatures) puis la
/// correspondance dans les deux sens : chaque ligne a son entrée d'audit au
/// contenu égal, chaque entrée `range-*` a sa ligne. Rend le nombre de
/// lignes et d'entrées.
pub fn verify(
    store: &Store,
    public: &VerifyingKey,
) -> anyhow::Result<Result<(usize, usize), String>> {
    let records = audit::records(&store.conn, WATCHER_SITE)?;
    if let Err(broken) = audit::verify(WATCHER_SITE, &records, public, None) {
        return Ok(Err(format!("chaîne {WATCHER_SITE} altérée : {broken}")));
    }
    let rows = rows(store)?;
    let mut entries: HashMap<&str, Entry> = HashMap::new();
    for record in &records {
        let entry: Entry = serde_json::from_str(&record.entry).context("entrée d'audit")?;
        entries.insert(record.hash.as_str(), entry);
    }
    for r in &rows {
        let Some(entry) = entries.get(r.audit_hash.as_str()) else {
            return Ok(Err(format!("correction {} sans entrée d'audit", r.id)));
        };
        let expected = Detail {
            source: r.source.clone(),
            advisory_id: r.advisory_id.clone(),
            purl: r.purl.clone(),
            ranges: r.ranges.clone(),
            reason: r.reason.clone(),
            operator: r.operator.clone(),
        };
        let event = if r.ranges.is_some() {
            EVENT_SET
        } else {
            EVENT_CLEAR
        };
        let same = entry.at == r.at
            && entry.event == event
            && serde_json::from_str::<Detail>(&entry.detail).is_ok_and(|d| d == expected);
        if !same {
            return Ok(Err(format!(
                "correction {} différente de son entrée d'audit",
                r.id
            )));
        }
    }
    let mut range_entries = 0;
    for (hash, entry) in &entries {
        if !entry.event.starts_with("range-") {
            continue;
        }
        range_entries += 1;
        if !rows.iter().any(|r| r.audit_hash == *hash) {
            return Ok(Err(format!("entrée d'audit {hash} sans correction")));
        }
    }
    Ok(Ok((rows.len(), range_entries)))
}
