//! Résultats du rapprochement (migration `0021.sql`) : état comparé par
//! (site, source), runs écrits par lots puis basculés, constats du site
//! reconstruits en entier et réconciliés dans la transaction de bascule.
//!
//! **Écrivain** : `tick` seul (`pass.rs`) ; la CLI n'écrit que les
//! dérogations (`waiver_store.rs`) ; `serve` lit.
//!
//! 1. [`begin_run`] (IMMEDIATE) réserve un id dans la séquence **globale**
//!    `vuln_match_runs` et le pose en `pending_run`, curseur à 0 ;
//! 2. [`push`] écrit un lot de composants par transaction IMMEDIATE, avec
//!    compare-and-swap du curseur (`WHERE pending_run = run AND
//!    cursor_rowid = attendu`) : deux `tick` concurrents n'écrivent jamais
//!    deux fois la même position ;
//! 3. [`build_findings`] lit **hors transaction** les runs de toutes les
//!    sources du site, les dérogations, les incidents `vulns` ouverts et la
//!    provenance, et construit tous les constats du site ;
//! 4. [`commit_and_reconcile`], dans **une** transaction IMMEDIATE, revérifie
//!    ce qui a été lu (runs actifs et en cours, époques, incidents ouverts) —
//!    tout écart : rien n'est écrit, le site reste dû —, bascule les runs en
//!    compare-and-swap, clôt « plus surveillé » ce qui ne tenait qu'à une
//!    source retirée ou à un report échu, puis appelle `reconcile_in` ;
//! 5. [`purge_runs`] retire ensuite, par lots, les runs qui ne sont plus ni
//!    actifs ni en cours.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::Context;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::config::Site;
use crate::finding::{Finding, Severity};
use crate::inventory::{Scope, Source, stale_after};
use crate::store::{
    InventoryHead, RunRecord, SCHEMA_VULNS_MATCH, Store, reconcile_in, record_result_in,
};
use crate::vulns::purl::{Purl, PurlType};

use super::assess::{GroupResult, MemberFacts, State};
use super::epoch;
use super::finding::{self as vfinding, CHECK, View, base_finding, stale_finding, stale_key};
use super::waiver::Waiver;
use super::{Component, key, source_carries};

/// Composants écrits par transaction.
pub const BATCH: usize = 500;
/// Lignes supprimées par transaction de purge.
pub const PURGE_BATCH: usize = 5_000;
/// Préfixe de la méta de déclaration d'une source d'inventaire :
/// `vulns.inventory.declared.<site>.<source>` = date de première vue.
pub const META_DECLARED: &str = "vulns.inventory.declared.";
/// Préfixe de la méta d'un retrait de site : `vulns.removed.<site>`.
pub const META_REMOVED: &str = "vulns.removed.";
/// Détail d'un incident `vulns` clos depuis plus de 30 jours.
pub const MASKED: &str = crate::analysis::findings::MASKED;
/// Conservation du détail et de la clé d'un incident `vulns` clos.
pub const MASK_AFTER: i64 = 30 * 86_400;

/// `true` si la base porte les tables du rapprochement.
pub fn available(store: &Store) -> anyhow::Result<bool> {
    Ok(store.schema_version()? >= SCHEMA_VULNS_MATCH)
}

/// Rang d'une gravité : 0 sans faille, puis 1 à 3.
pub fn rank(severity: Option<Severity>) -> i64 {
    match severity {
        None => 0,
        Some(Severity::Info) => 1,
        Some(Severity::Warning) => 2,
        Some(Severity::Critical) => 3,
    }
}

fn source_name(raw: &str) -> rusqlite::Result<Source> {
    Source::from_name(raw).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            format!("source inconnue : {raw}").into(),
        )
    })
}

/// État comparé d'un (site, source).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StateRow {
    pub site: String,
    pub source: Option<Source>,
    pub inventory_id: Option<i64>,
    pub seen_at: Option<i64>,
    pub declared_sources: String,
    pub match_epoch: Option<String>,
    pub enrich_epoch: Option<String>,
    pub waiver_epoch: Option<String>,
    pub next_stale_check: Option<i64>,
    pub next_waiver_check: Option<i64>,
    pub active_run: Option<i64>,
    pub pending_run: Option<i64>,
    pub pending_inventory_id: Option<i64>,
    pub pending_match_epoch: Option<String>,
    pub pending_enrich_epoch: Option<String>,
    pub cursor_rowid: i64,
    pub due_since: Option<i64>,
    pub error_count: i64,
}

const STATE_COLUMNS: &str = "site, source, inventory_id, seen_at, declared_sources, match_epoch,
    enrich_epoch, waiver_epoch, next_stale_check, next_waiver_check, active_run, pending_run,
    pending_inventory_id, pending_match_epoch, pending_enrich_epoch, cursor_rowid, due_since,
    error_count";

fn state_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<StateRow> {
    Ok(StateRow {
        site: r.get(0)?,
        source: Some(source_name(&r.get::<_, String>(1)?)?),
        inventory_id: r.get(2)?,
        seen_at: r.get(3)?,
        declared_sources: r.get(4)?,
        match_epoch: r.get(5)?,
        enrich_epoch: r.get(6)?,
        waiver_epoch: r.get(7)?,
        next_stale_check: r.get(8)?,
        next_waiver_check: r.get(9)?,
        active_run: r.get(10)?,
        pending_run: r.get(11)?,
        pending_inventory_id: r.get(12)?,
        pending_match_epoch: r.get(13)?,
        pending_enrich_epoch: r.get(14)?,
        cursor_rowid: r.get(15)?,
        due_since: r.get(16)?,
        error_count: r.get(17)?,
    })
}

/// États de tous les (site, source).
pub fn states(conn: &Connection) -> anyhow::Result<Vec<StateRow>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {STATE_COLUMNS} FROM vuln_match_state ORDER BY site, source"
    ))?;
    let rows = stmt.query_map([], state_row)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// États d'un site.
pub fn site_states(conn: &Connection, site: &str) -> anyhow::Result<Vec<StateRow>> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {STATE_COLUMNS} FROM vuln_match_state WHERE site = ?1 ORDER BY source"
    ))?;
    let rows = stmt.query_map([site], state_row)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Passages en échec d'affilée du rapprochement d'un site (`vigie status`).
pub fn site_errors(store: &Store, site: &str) -> anyhow::Result<i64> {
    Ok(site_states(&store.conn, site)?
        .iter()
        .map(|r| r.error_count)
        .max()
        .unwrap_or(0))
}

/// Réserve un run pour (site, source) et le pose en cours, curseur à 0.
pub fn begin_run(
    store: &mut Store,
    site: &str,
    source: Source,
    inventory_id: i64,
    match_epoch: &str,
    enrich_epoch: &str,
    now: i64,
) -> anyhow::Result<i64> {
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "INSERT INTO vuln_match_runs (site, source, started_at) VALUES (?1, ?2, ?3)",
        params![site, source.as_str(), now],
    )?;
    let run = tx.last_insert_rowid();
    tx.execute(
        "INSERT INTO vuln_match_state (site, source, pending_run, pending_inventory_id,
             pending_match_epoch, pending_enrich_epoch, cursor_rowid, due_since)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7)
         ON CONFLICT (site, source) DO UPDATE SET pending_run = excluded.pending_run,
             pending_inventory_id = excluded.pending_inventory_id,
             pending_match_epoch = excluded.pending_match_epoch,
             pending_enrich_epoch = excluded.pending_enrich_epoch, cursor_rowid = 0,
             due_since = coalesce(vuln_match_state.due_since, excluded.due_since)",
        params![
            site,
            source.as_str(),
            run,
            inventory_id,
            match_epoch,
            enrich_epoch,
            now
        ],
    )?;
    tx.commit()?;
    Ok(run)
}

/// Abandonne le run en cours d'un (site, source) s'il vaut toujours `run` :
/// il sera purgé, et le rapprochement reprendra au début.
pub fn abandon_run(store: &mut Store, site: &str, source: Source, run: i64) -> anyhow::Result<()> {
    store.conn.execute(
        "UPDATE vuln_match_state SET pending_run = NULL, pending_inventory_id = NULL,
             pending_match_epoch = NULL, pending_enrich_epoch = NULL, cursor_rowid = 0
         WHERE site = ?1 AND source = ?2 AND pending_run = ?3",
        params![site, source.as_str(), run],
    )?;
    Ok(())
}

/// Composant rapproché, prêt à écrire dans un run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentResult {
    pub component: Component,
    pub groups: Vec<GroupResult>,
    /// Au moins une faille candidate (provenance).
    pub candidates: bool,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
}

impl ComponentResult {
    pub fn severity(&self) -> Option<Severity> {
        self.groups.iter().map(|g| g.severity).max()
    }
}

/// Lignes d'un composant dans `tx`.
fn insert_result(
    tx: &Transaction<'_>,
    site: &str,
    source: Source,
    run: i64,
    r: &ComponentResult,
) -> anyhow::Result<()> {
    let c = &r.component;
    let base = c.base.canonical();
    let severity = r.severity();
    tx.prepare_cached(
        "INSERT OR REPLACE INTO vuln_match_components (site, source, run, base, path, version,
             ecosystem, scope, carried, candidates, first_seen_at, last_seen_at, severity, rank,
             groups)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
    )?
    .execute(params![
        site,
        source.as_str(),
        run,
        base,
        c.path,
        c.version,
        c.ecosystem.as_str(),
        c.scope.as_str(),
        c.carried,
        r.candidates,
        r.first_seen_at,
        r.last_seen_at,
        severity.map(Severity::as_str),
        rank(severity),
        r.groups.len() as i64,
    ])?;
    let mut item = tx.prepare_cached(
        "INSERT OR REPLACE INTO vuln_match_items (site, source, run, base, path, group_key,
             verdict, reason, severity, rank, rule, fixed, members, facts, covered_ids, kev,
             epss_ppm, score_tenths, redistribution)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18,
             ?19)",
    )?;
    for g in &r.groups {
        let (verdict, reason) = match g.state {
            State::Affected => ("affected", None),
            State::VersionUnknown | State::RangeUnknown => ("unknown", Some(g.state.as_str())),
        };
        let members: Vec<serde_json::Value> = g
            .members
            .iter()
            .map(
                |m| serde_json::json!({ "id": m.id, "source": m.source, "corrected": m.corrected }),
            )
            .collect();
        let redistribution = serde_json::to_value(g.redistribution)?;
        item.execute(params![
            site,
            source.as_str(),
            run,
            base,
            c.path,
            g.key,
            verdict,
            reason,
            g.severity.as_str(),
            rank(Some(g.severity)),
            g.rule,
            (!g.fixed.is_empty()).then(|| g.fixed.join(", ")),
            serde_json::to_string(&members)?,
            serde_json::to_string(g)?,
            serde_json::to_string(&g.ids)?,
            g.kev.is_some(),
            g.epss.map(|e| e.epss_ppm),
            g.score,
            redistribution.as_str().unwrap_or("internal"),
        ])?;
    }
    Ok(())
}

/// Écrit un lot de composants dans le run en cours, en compare-and-swap du
/// curseur : `false` si un autre passage a déjà écrit cette position, ou
/// si le run n'est plus en cours (rien n'est écrit).
pub fn push(
    store: &mut Store,
    site: &str,
    source: Source,
    run: i64,
    expected_cursor: i64,
    results: &[ComponentResult],
    new_cursor: i64,
) -> anyhow::Result<bool> {
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let moved = tx.execute(
        "UPDATE vuln_match_state SET cursor_rowid = ?5
         WHERE site = ?1 AND source = ?2 AND pending_run = ?3 AND cursor_rowid = ?4",
        params![site, source.as_str(), run, expected_cursor, new_cursor],
    )?;
    if moved != 1 {
        return Ok(false);
    }
    for r in results {
        insert_result(&tx, site, source, run, r)?;
    }
    tx.commit()?;
    Ok(true)
}

/// Composant lu d'un run, avec ses groupes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredComponent {
    pub result: ComponentResult,
}

/// Composants et groupes d'un run (lecture cohérente dans une transaction
/// de lecture). Une ligne illisible est une erreur : le site est en échec,
/// jamais rapproché à moitié.
pub fn run_results(
    conn: &Connection,
    site: &str,
    source: Source,
    run: i64,
) -> anyhow::Result<Vec<ComponentResult>> {
    let mut groups: HashMap<(String, String), Vec<GroupResult>> = HashMap::new();
    {
        let mut stmt = conn.prepare_cached(
            "SELECT base, path, facts FROM vuln_match_items
             WHERE site = ?1 AND source = ?2 AND run = ?3",
        )?;
        let mut rows = stmt.query(params![site, source.as_str(), run])?;
        while let Some(r) = rows.next()? {
            let facts: String = r.get(2)?;
            let g: GroupResult =
                serde_json::from_str(&facts).context("groupe illisible dans vuln_match_items")?;
            groups.entry((r.get(0)?, r.get(1)?)).or_default().push(g);
        }
    }
    let mut stmt = conn.prepare_cached(
        "SELECT base, path, version, ecosystem, scope, carried, candidates, first_seen_at,
             last_seen_at
         FROM vuln_match_components WHERE site = ?1 AND source = ?2 AND run = ?3
         ORDER BY base, path",
    )?;
    let mut rows = stmt.query(params![site, source.as_str(), run])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        let base: String = r.get(0)?;
        let path: String = r.get(1)?;
        let ecosystem: String = r.get(3)?;
        let scope: String = r.get(4)?;
        let purl = Purl::parse(&base).context("purl illisible dans vuln_match_components")?;
        let mut g = groups.remove(&(base, path.clone())).unwrap_or_default();
        g.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.key.cmp(&b.key)));
        out.push(ComponentResult {
            component: Component {
                source,
                ecosystem: PurlType::from_name(&ecosystem).context("écosystème illisible")?,
                base: purl,
                version: r.get(2)?,
                scope: Scope::from_name(&scope).context("portée illisible")?,
                path,
                carried: r.get(5)?,
            },
            groups: g,
            candidates: r.get(6)?,
            first_seen_at: r.get(7)?,
            last_seen_at: r.get(8)?,
        });
    }
    Ok(out)
}

/// Composants d'un run sans leurs groupes : premières vues et report d'un
/// rapprochement neuf. Ne lit aucun JSON : un run aux groupes illisibles se
/// remplace par un run neuf.
pub fn run_components(
    conn: &Connection,
    site: &str,
    source: Source,
    run: i64,
) -> anyhow::Result<Vec<ComponentResult>> {
    let mut stmt = conn.prepare_cached(
        "SELECT base, path, version, ecosystem, scope, carried, candidates, first_seen_at,
             last_seen_at
         FROM vuln_match_components WHERE site = ?1 AND source = ?2 AND run = ?3
         ORDER BY base, path",
    )?;
    let mut rows = stmt.query(params![site, source.as_str(), run])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        let base: String = r.get(0)?;
        let ecosystem: String = r.get(3)?;
        let scope: String = r.get(4)?;
        let (Ok(purl), Some(ecosystem), Some(scope)) = (
            Purl::parse(&base),
            PurlType::from_name(&ecosystem),
            Scope::from_name(&scope),
        ) else {
            continue;
        };
        out.push(ComponentResult {
            component: Component {
                source,
                ecosystem,
                base: purl,
                version: r.get(2)?,
                scope,
                path: r.get(1)?,
                carried: r.get(5)?,
            },
            groups: Vec::new(),
            candidates: r.get(6)?,
            first_seen_at: r.get(7)?,
            last_seen_at: r.get(8)?,
        });
    }
    Ok(out)
}

/// Dérogations non retirées d'un site.
pub fn waivers(conn: &Connection, site: &str) -> anyhow::Result<Vec<Waiver>> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, source, base, advisory_ref, version, covered_ids, until, reason
         FROM vuln_waivers WHERE site = ?1 AND revoked_at IS NULL ORDER BY id",
    )?;
    let mut rows = stmt.query([site])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        let covered: String = r.get(5)?;
        out.push(Waiver {
            id: r.get(0)?,
            source: source_name(&r.get::<_, String>(1)?)?,
            base: r.get(2)?,
            advisory_ref: r.get(3)?,
            version: r.get(4)?,
            covered_ids: serde_json::from_str(&covered).context("covered_ids illisible")?,
            until: r.get(6)?,
            reason: r.get(7)?,
        });
    }
    Ok(out)
}

/// Incident `vulns` ouvert d'un site.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OpenIncident {
    id: i64,
    severity: Severity,
    detail: String,
}

/// Incidents `vulns` ouverts d'un site, par clé de constat.
fn open_incidents(conn: &Connection, site: &str) -> anyhow::Result<BTreeMap<String, OpenIncident>> {
    let prefix = format!("{site}/{CHECK}/");
    let mut stmt = conn.prepare_cached(
        "SELECT id, key, severity, detail FROM incidents
         WHERE site = ?1 AND check_name = ?2 AND closed_at IS NULL ORDER BY id",
    )?;
    let mut rows = stmt.query(params![site, CHECK])?;
    let mut out = BTreeMap::new();
    while let Some(r) = rows.next()? {
        let full: String = r.get(1)?;
        let Some(key) = full.strip_prefix(&prefix) else {
            continue;
        };
        let severity: String = r.get(2)?;
        out.insert(
            key.to_owned(),
            OpenIncident {
                id: r.get(0)?,
                severity: Severity::parse(&severity).unwrap_or(Severity::Critical),
                detail: r.get(3)?,
            },
        );
    }
    Ok(out)
}

/// Provenance d'une clé : dernière vue par source.
fn seen_rows(
    conn: &Connection,
    site: &str,
) -> anyhow::Result<BTreeMap<String, Vec<(Source, i64)>>> {
    let mut stmt = conn
        .prepare_cached("SELECT key, source, last_seen_at FROM vuln_match_seen WHERE site = ?1")?;
    let mut rows = stmt.query([site])?;
    let mut out: BTreeMap<String, Vec<(Source, i64)>> = BTreeMap::new();
    while let Some(r) = rows.next()? {
        out.entry(r.get(0)?)
            .or_default()
            .push((source_name(&r.get::<_, String>(1)?)?, r.get(2)?));
    }
    Ok(out)
}

fn lost_views(conn: &Connection, site: &str) -> anyhow::Result<BTreeMap<String, Option<i64>>> {
    let mut stmt =
        conn.prepare_cached("SELECT key, lost_view_at FROM vuln_match_keys WHERE site = ?1")?;
    let rows = stmt.query_map([site], |r| Ok((r.get(0)?, r.get(1)?)))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Attribution d'une faille (sinon de sa source), relue pour l'affichage :
/// jamais copiée dans les résultats.
pub fn attribution(conn: &Connection, source: &str, id: &str) -> anyhow::Result<Option<String>> {
    let own: Option<String> = conn
        .prepare_cached(
            "SELECT a.attribution FROM vuln_advisories a
             JOIN vuln_sources s ON s.id = a.source AND s.active_generation = a.generation
             WHERE a.source = ?1 AND a.id = ?2",
        )?
        .query_row(params![source, id], |r| r.get(0))
        .optional()?;
    if let Some(a) = own.filter(|a| !a.is_empty()) {
        return Ok(Some(a));
    }
    Ok(conn
        .prepare_cached("SELECT attribution FROM vuln_sources WHERE id = ?1")?
        .query_row([source], |r| r.get::<_, String>(0))
        .optional()?
        .filter(|a| !a.is_empty()))
}

/// Ce que le passage sait d'un site, pour en construire les constats.
#[derive(Debug, Clone)]
pub struct SiteInput<'a> {
    pub site: &'a Site,
    /// Sources d'inventaire déclarées, triées.
    pub declared: Vec<Source>,
    /// Sources de failles déclarées (sans KEV ni EPSS).
    pub declared_vulns: Vec<&'static str>,
    /// Dernier inventaire de chaque source déclarée.
    pub heads: BTreeMap<Source, InventoryHead>,
    /// Date de déclaration de chaque source (méta).
    pub declared_at: BTreeMap<Source, i64>,
    pub match_epoch: String,
    pub enrich_epoch: String,
}

/// Bascule d'une source dans la transaction de [`commit_and_reconcile`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Switch {
    pub source: Source,
    /// Run à rendre actif ; `None` : plus aucun (source sans inventaire).
    pub run: Option<i64>,
    pub inventory_id: Option<i64>,
    pub match_epoch: String,
    pub enrich_epoch: String,
}

/// Ce qui a été lu, revérifié dans la transaction de bascule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    /// (source, run actif, run en cours) de chaque source déclarée.
    pub runs: Vec<(Source, Option<i64>, Option<i64>)>,
    pub waiver_epoch: String,
    /// Incidents `vulns` ouverts du site.
    pub open: Vec<i64>,
}

/// Provenance à écrire : (clé, source, première vue, dernière vue).
pub type SeenRow = (String, Source, i64, i64);

/// Constats du site et écritures qui les accompagnent.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub findings: Vec<Finding>,
    /// Clés à clore « plus surveillé » avant la réconciliation.
    pub unwatched: Vec<String>,
    /// Clés closes par ce passage (rétablies ou plus surveillées).
    pub closed: Vec<String>,
    pub seen: Vec<SeenRow>,
    /// Clés d'incidents ouverts sans vue.
    pub lost: Vec<String>,
    /// Clés vues par un run.
    pub viewed: Vec<String>,
    /// (source, run, dernière vue) des composants non reportés à avancer.
    pub touched: Vec<(Source, i64, i64)>,
    pub next_check: Option<i64>,
    pub next_waiver_check: Option<i64>,
    pub fingerprint: Fingerprint,
    /// Composants lus (relevé).
    pub components: usize,
}

fn earliest(slot: &mut Option<i64>, at: i64) {
    *slot = Some(slot.map_or(at, |t| t.min(at)));
}

fn secs(d: std::time::Duration) -> i64 {
    i64::try_from(d.as_secs()).unwrap_or(i64::MAX)
}

/// Sources de failles des membres d'une clé dans un run remplacé.
fn replaced_sources(
    conn: &Connection,
    site: &str,
    source: Source,
    run: i64,
    base: &str,
) -> anyhow::Result<Option<BTreeSet<String>>> {
    let mut stmt = conn.prepare_cached(
        "SELECT facts FROM vuln_match_items WHERE site = ?1 AND source = ?2 AND run = ?3
             AND base = ?4",
    )?;
    let mut rows = stmt.query(params![site, source.as_str(), run, base])?;
    let mut sources = BTreeSet::new();
    let mut any = false;
    while let Some(r) = rows.next()? {
        any = true;
        let g: GroupResult = serde_json::from_str(&r.get::<_, String>(0)?)
            .context("groupe illisible dans vuln_match_items")?;
        sources.extend(g.members.iter().map(|m| m.source.clone()));
    }
    Ok(any.then_some(sources))
}

/// Constats complets du site, lus **hors transaction** : runs de chaque
/// source déclarée (le run à basculer à la place de l'actif), dérogations,
/// incidents ouverts, provenance ; plus les constats de péremption.
pub fn build_findings(
    store: &Store,
    input: &SiteInput<'_>,
    switches: &[Switch],
    now: i64,
) -> anyhow::Result<Snapshot> {
    let conn = &store.conn;
    let site = input.site.id.as_str();
    let states = site_states(conn, site)?;
    let state_of = |s: Source| states.iter().find(|r| r.source == Some(s));
    let mut fingerprint = Fingerprint {
        runs: Vec::new(),
        waiver_epoch: epoch::waiver_epoch(conn, site)?,
        open: Vec::new(),
    };
    let open = open_incidents(conn, site)?;
    fingerprint.open = open.values().map(|i| i.id).collect();
    fingerprint.open.sort_unstable();
    let waivers = waivers(conn, site)?;
    let seen = seen_rows(conn, site)?;
    let lost_at = lost_views(conn, site)?;
    let mut next_check: Option<i64> = None;

    // Runs lus, et runs remplacés par une bascule.
    let mut views: BTreeMap<String, Vec<View>> = BTreeMap::new();
    let mut seen_out: BTreeMap<(String, Source), (i64, i64)> = BTreeMap::new();
    let mut replaced: Vec<(Source, i64)> = Vec::new();
    let mut touched = Vec::new();
    let mut components = 0;
    for &source in &input.declared {
        let state = state_of(source);
        fingerprint.runs.push((
            source,
            state.and_then(|s| s.active_run),
            state.and_then(|s| s.pending_run),
        ));
        let switch = switches.iter().find(|s| s.source == source);
        let (run, inventory) = match switch {
            Some(sw) => {
                if let Some(old) = state.and_then(|s| s.active_run) {
                    replaced.push((source, old));
                }
                (sw.run, sw.inventory_id)
            }
            None => (
                state.and_then(|s| s.active_run),
                state.and_then(|s| s.inventory_id),
            ),
        };
        let Some(run) = run else {
            continue;
        };
        let head = input.heads.get(&source);
        // Composants non reportés de l'inventaire de tête : vus à son
        // dernier renvoi.
        let fresh = head.filter(|h| Some(h.id) == inventory).map(|h| h.seen_at);
        if let Some(at) = fresh {
            touched.push((source, run, at));
        }
        let threshold = secs(stale_after(source));
        for mut r in run_results(conn, site, source, run)? {
            components += 1;
            if r.component.carried {
                let expires = r.last_seen_at.saturating_add(threshold);
                if expires <= now {
                    continue;
                }
                earliest(&mut next_check, expires);
            } else if let Some(at) = fresh {
                r.last_seen_at = r.last_seen_at.max(at);
            }
            let k = key(&r.component.base);
            if r.candidates {
                let slot = seen_out
                    .entry((k.clone(), source))
                    .or_insert((r.first_seen_at, r.last_seen_at));
                slot.0 = slot.0.min(r.first_seen_at);
                slot.1 = slot.1.max(r.last_seen_at);
            }
            views.entry(k).or_default().push(View {
                component: r.component,
                groups: r.groups,
            });
        }
    }

    // Attributions des membres, relues une fois.
    let mut attributions: HashMap<(String, String), Option<String>> = HashMap::new();
    for m in views
        .values()
        .flatten()
        .flat_map(|v| &v.groups)
        .flat_map(|g| &g.members)
    {
        if let std::collections::hash_map::Entry::Vacant(slot) =
            attributions.entry((m.source.clone(), m.id.clone()))
        {
            slot.insert(attribution(conn, &m.source, &m.id)?);
        }
    }
    let attribution_of = |m: &MemberFacts| -> Option<String> {
        attributions
            .get(&(m.source.clone(), m.id.clone()))
            .cloned()
            .flatten()
    };

    let mut findings = Vec::new();
    let mut unwatched = Vec::new();
    let mut closed = Vec::new();
    let mut lost = Vec::new();
    let mut viewed = Vec::new();
    // Une clé dont tous les groupes ne tenaient qu'à des sources de failles
    // retirées de `[vulns]` : plus surveillée, jamais rétablie.
    let retired_only = |k: &str| -> anyhow::Result<bool> {
        let mut any = false;
        for &(source, run) in &replaced {
            if let Some(sources) = replaced_sources(conn, site, source, run, k)? {
                any = true;
                if sources
                    .iter()
                    .any(|s| input.declared_vulns.contains(&s.as_str()))
                {
                    return Ok(false);
                }
            }
        }
        Ok(any)
    };
    for (k, list) in &views {
        viewed.push(k.clone());
        let is_open = open.contains_key(k);
        if list.iter().all(|v| v.groups.is_empty()) {
            if is_open {
                if retired_only(k)? {
                    unwatched.push(k.clone());
                }
                closed.push(k.clone());
            }
            continue;
        }
        for w in waivers.iter().filter(|w| w.base == *k && w.until > now) {
            earliest(&mut next_check, w.until);
        }
        match base_finding(site, k, list, &waivers, &attribution_of, is_open, now) {
            Some(f) => findings.push(f),
            None if is_open => closed.push(k.clone()),
            None => {}
        }
    }

    // Constats de péremption, par source déclarée.
    let mut stale_keys = BTreeSet::new();
    for &source in &input.declared {
        stale_keys.insert(stale_key(source));
        let declared_at = input.declared_at.get(&source).copied().unwrap_or(now);
        let last = input.heads.get(&source).map(|h| h.seen_at);
        let threshold = stale_after(source);
        match stale_finding(site, source, last, declared_at, threshold, now) {
            Some(f) => findings.push(f),
            None => {
                let since = last.map_or(declared_at, |l| l.max(declared_at));
                earliest(&mut next_check, since.saturating_add(secs(threshold)) + 1);
            }
        }
    }

    // Incidents sans vue : identiques tant qu'une source requise n'a pas
    // prouvé l'absence ; « plus surveillé » à son échéance.
    for (k, incident) in &open {
        if views.contains_key(k) {
            continue;
        }
        if k == vfinding::KEY_STALE_AGENT || k == vfinding::KEY_STALE_CI {
            if !stale_keys.contains(k.as_str()) {
                // Péremption d'une source qui n'est plus déclarée.
                unwatched.push(k.clone());
                closed.push(k.clone());
            }
            continue;
        }
        lost.push(k.clone());
        let ecosystem = Purl::parse(k).ok().map(|p| p.ty());
        let carries = |s: Source| ecosystem.is_none_or(|e| source_carries(s, e));
        let provenance = seen.get(k).filter(|rows| !rows.is_empty());
        let required: Vec<(Source, i64)> = match provenance {
            Some(rows) => rows
                .iter()
                .filter(|(s, _)| input.declared.contains(s) && carries(*s))
                .copied()
                .collect(),
            None => {
                let since = lost_at.get(k).copied().flatten().unwrap_or(now);
                input
                    .declared
                    .iter()
                    .filter(|s| carries(**s))
                    .map(|s| (*s, since))
                    .collect()
            }
        };
        if required.is_empty() {
            unwatched.push(k.clone());
            closed.push(k.clone());
            continue;
        }
        let missing: Vec<(Source, i64)> = required
            .iter()
            .filter(|(s, since)| {
                !input
                    .heads
                    .get(s)
                    .is_some_and(|h| h.complete && h.received_at > *since)
            })
            .copied()
            .collect();
        if missing.is_empty() {
            // Absent d'un inventaire complet de chaque source requise.
            closed.push(k.clone());
            continue;
        }
        let deadline = missing
            .iter()
            .map(|(s, since)| since.saturating_add(secs(stale_after(*s))))
            .min()
            .unwrap_or(now);
        if now >= deadline {
            unwatched.push(k.clone());
            closed.push(k.clone());
            continue;
        }
        earliest(&mut next_check, deadline);
        findings.push(Finding::new(
            site,
            CHECK,
            incident.severity,
            k.clone(),
            incident.detail.clone(),
        ));
    }

    let next_waiver_check = waivers.iter().map(|w| w.until).filter(|u| *u > now).min();
    Ok(Snapshot {
        findings,
        unwatched,
        closed,
        seen: seen_out
            .into_iter()
            .map(|((k, s), (first, last))| (k, s, first, last))
            .collect(),
        lost,
        viewed,
        touched,
        next_check,
        next_waiver_check,
        fingerprint,
        components,
    })
}

fn open_ids(conn: &Connection, site: &str) -> anyhow::Result<Vec<i64>> {
    let mut stmt = conn.prepare_cached(
        "SELECT id FROM incidents WHERE site = ?1 AND check_name = ?2 AND closed_at IS NULL
         ORDER BY id",
    )?;
    let rows = stmt.query_map(params![site, CHECK], |r| r.get(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Bascule les runs prêts et réconcilie les constats du site, dans **une**
/// transaction IMMEDIATE. `false` : ce qui a été lu a changé (autre
/// passage, synchronisation, dérogation, incident) ; rien n'est écrit et
/// le site reste dû.
pub fn commit_and_reconcile(
    store: &mut Store,
    input: &SiteInput<'_>,
    switches: &[Switch],
    snapshot: &Snapshot,
    now: i64,
) -> anyhow::Result<bool> {
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    if !unchanged(&tx, input, snapshot)? {
        return Ok(false);
    }
    commit_in(&tx, input, switches, snapshot, now)?;
    #[cfg(test)]
    hooks::before_commit(&input.site.id);
    tx.commit()?;
    Ok(true)
}

/// Revérifie dans la transaction ce qui a été lu hors d'elle.
fn unchanged(tx: &Connection, input: &SiteInput<'_>, snapshot: &Snapshot) -> anyhow::Result<bool> {
    let site = input.site.id.as_str();
    let states = site_states(tx, site)?;
    for (source, active, pending) in &snapshot.fingerprint.runs {
        let now_state = states.iter().find(|r| r.source == Some(*source));
        if (
            now_state.and_then(|s| s.active_run),
            now_state.and_then(|s| s.pending_run),
        ) != (*active, *pending)
        {
            return Ok(false);
        }
    }
    Ok(
        epoch::waiver_epoch(tx, site)? == snapshot.fingerprint.waiver_epoch
            && epoch::match_epoch(tx, &input.declared_vulns)? == input.match_epoch
            && open_ids(tx, site)? == snapshot.fingerprint.open,
    )
}

fn commit_in(
    tx: &Transaction<'_>,
    input: &SiteInput<'_>,
    switches: &[Switch],
    snapshot: &Snapshot,
    now: i64,
) -> anyhow::Result<()> {
    let site = input.site.id.as_str();
    for sw in switches {
        let changed = match sw.run {
            Some(run) => tx.execute(
                "UPDATE vuln_match_state SET active_run = ?3, inventory_id = ?4,
                     match_epoch = ?5, enrich_epoch = ?6, pending_run = NULL,
                     pending_inventory_id = NULL, pending_match_epoch = NULL,
                     pending_enrich_epoch = NULL, cursor_rowid = 0
                 WHERE site = ?1 AND source = ?2 AND pending_run = ?3",
                params![
                    site,
                    sw.source.as_str(),
                    run,
                    sw.inventory_id,
                    sw.match_epoch,
                    sw.enrich_epoch
                ],
            )?,
            None => tx.execute(
                "INSERT INTO vuln_match_state (site, source, match_epoch, enrich_epoch)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (site, source) DO UPDATE SET active_run = NULL,
                     inventory_id = NULL, match_epoch = excluded.match_epoch,
                     enrich_epoch = excluded.enrich_epoch, pending_run = NULL,
                     pending_inventory_id = NULL, pending_match_epoch = NULL,
                     pending_enrich_epoch = NULL, cursor_rowid = 0",
                params![site, sw.source.as_str(), sw.match_epoch, sw.enrich_epoch],
            )?,
        };
        anyhow::ensure!(changed == 1, "bascule refusée : run supplanté");
    }
    let declared = epoch::declared_text(&input.declared);
    let next_stale = snapshot.next_check;
    for &source in &input.declared {
        let seen_at = input.heads.get(&source).map(|h| h.seen_at);
        tx.execute(
            "INSERT INTO vuln_match_state (site, source, seen_at, declared_sources,
                 waiver_epoch, next_stale_check, next_waiver_check, match_epoch, enrich_epoch)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT (site, source) DO UPDATE SET seen_at = excluded.seen_at,
                 declared_sources = excluded.declared_sources,
                 waiver_epoch = excluded.waiver_epoch,
                 next_stale_check = excluded.next_stale_check,
                 next_waiver_check = excluded.next_waiver_check, due_since = NULL,
                 error_count = 0,
                 match_epoch = CASE WHEN vuln_match_state.active_run IS NULL
                     AND vuln_match_state.pending_run IS NULL AND ?3 IS NULL
                     THEN excluded.match_epoch ELSE vuln_match_state.match_epoch END,
                 enrich_epoch = CASE WHEN vuln_match_state.active_run IS NULL
                     THEN excluded.enrich_epoch ELSE vuln_match_state.enrich_epoch END",
            params![
                site,
                source.as_str(),
                seen_at,
                declared,
                snapshot.fingerprint.waiver_epoch,
                next_stale,
                snapshot.next_waiver_check,
                input.match_epoch,
                input.enrich_epoch,
            ],
        )?;
    }
    // Source d'inventaire retirée : état supprimé, run purgé ensuite.
    {
        let mut stmt =
            tx.prepare_cached("DELETE FROM vuln_match_state WHERE site = ?1 AND source = ?2")?;
        for source in Source::ALL {
            if !input.declared.contains(&source) {
                stmt.execute(params![site, source.as_str()])?;
            }
        }
    }
    // D'abord « plus surveillé », puis la réconciliation.
    {
        let mut stmt = tx.prepare_cached(
            "UPDATE incidents SET closed_at = ?3, close_reason = 'unwatched'
             WHERE key = ?1 AND check_name = ?2 AND closed_at IS NULL",
        )?;
        for k in &snapshot.unwatched {
            stmt.execute(params![format!("{site}/{CHECK}/{k}"), CHECK, now])?;
        }
    }
    reconcile_in(tx, site, CHECK, &snapshot.findings, now)?;
    record_result_in(
        tx,
        site,
        CHECK,
        now,
        &RunRecord::concluded(&snapshot.findings),
    )?;
    for (source, run, at) in &snapshot.touched {
        tx.prepare_cached(
            "UPDATE vuln_match_components SET last_seen_at = ?4
             WHERE site = ?1 AND source = ?2 AND run = ?3 AND carried = 0 AND last_seen_at < ?4",
        )?
        .execute(params![site, source.as_str(), run, at])?;
    }
    // Provenance : seulement les clés qui ont une faille candidate.
    {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO vuln_match_seen (site, key, source, first_seen_at, last_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (site, key, source) DO UPDATE SET
                 first_seen_at = min(vuln_match_seen.first_seen_at, excluded.first_seen_at),
                 last_seen_at = max(vuln_match_seen.last_seen_at, excluded.last_seen_at)",
        )?;
        for (k, source, first, last) in &snapshot.seen {
            stmt.execute(params![site, k, source.as_str(), first, last])?;
        }
    }
    {
        let mut forget_seen =
            tx.prepare_cached("DELETE FROM vuln_match_seen WHERE site = ?1 AND key = ?2")?;
        let mut forget_key =
            tx.prepare_cached("DELETE FROM vuln_match_keys WHERE site = ?1 AND key = ?2")?;
        for k in &snapshot.closed {
            forget_seen.execute(params![site, k])?;
            forget_key.execute(params![site, k])?;
        }
        for k in &snapshot.viewed {
            forget_key.execute(params![site, k])?;
        }
        let mut lose = tx.prepare_cached(
            "INSERT INTO vuln_match_keys (site, key, lost_view_at) VALUES (?1, ?2, ?3)
             ON CONFLICT (site, key) DO UPDATE SET
                 lost_view_at = coalesce(vuln_match_keys.lost_view_at, excluded.lost_view_at)",
        )?;
        for k in snapshot
            .lost
            .iter()
            .filter(|k| !snapshot.closed.contains(k))
        {
            lose.execute(params![site, k, now])?;
        }
    }
    // Provenance périmée d'une clé sans incident ouvert ni vue.
    for source in Source::ALL {
        tx.prepare_cached(
            "DELETE FROM vuln_match_seen WHERE site = ?1 AND source = ?2 AND last_seen_at < ?3
               AND NOT EXISTS (SELECT 1 FROM incidents i WHERE i.check_name = ?4
                   AND i.closed_at IS NULL AND i.key = ?1 || '/' || ?4 || '/' || vuln_match_seen.key)",
        )?
        .execute(params![
            site,
            source.as_str(),
            now.saturating_sub(secs(stale_after(source))),
            CHECK
        ])?;
    }
    let remaining: i64 = tx.query_row(
        "SELECT count(*) FROM vuln_match_keys WHERE site = ?1",
        [site],
        |r| r.get(0),
    )?;
    if remaining == 0 {
        tx.execute(
            "DELETE FROM meta WHERE key = ?1",
            [format!("{META_REMOVED}{site}")],
        )?;
    }
    Ok(())
}

/// Note un échec du site : compté, daté, et l'époque des failles oubliée
/// pour que le passage suivant reprenne le rapprochement au début (une
/// ligne illisible d'un run se remplace par un run neuf).
pub fn record_error(
    store: &mut Store,
    site: &str,
    sources: &[Source],
    now: i64,
) -> anyhow::Result<()> {
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    for source in sources {
        tx.execute(
            "INSERT INTO vuln_match_state (site, source, due_since, error_count)
             VALUES (?1, ?2, ?3, 1)
             ON CONFLICT (site, source) DO UPDATE SET error_count = error_count + 1,
                 due_since = coalesce(vuln_match_state.due_since, excluded.due_since),
                 match_epoch = NULL, pending_run = NULL, pending_inventory_id = NULL,
                 pending_match_epoch = NULL, pending_enrich_epoch = NULL, cursor_rowid = 0",
            params![site, source.as_str(), now],
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// Marque un site dû sans le traiter (budget épuisé).
pub fn mark_due(store: &mut Store, site: &str, sources: &[Source], now: i64) -> anyhow::Result<()> {
    for source in sources {
        store.conn.execute(
            "INSERT INTO vuln_match_state (site, source, due_since) VALUES (?1, ?2, ?3)
             ON CONFLICT (site, source) DO UPDATE SET
                 due_since = coalesce(vuln_match_state.due_since, excluded.due_since)",
            params![site, source.as_str(), now],
        )?;
    }
    Ok(())
}

/// Runs qui ne sont plus ni actifs ni en cours, retirés par lots (une
/// transaction par lot). Rend le nombre de lignes retirées.
pub fn purge_runs(store: &mut Store) -> anyhow::Result<u64> {
    let orphans: Vec<(i64, String, String)> = {
        let mut stmt = store.conn.prepare(
            "SELECT id, site, source FROM vuln_match_runs r WHERE NOT EXISTS (
                 SELECT 1 FROM vuln_match_state s WHERE s.site = r.site AND s.source = r.source
                   AND (s.active_run = r.id OR s.pending_run = r.id))
             ORDER BY id",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    let mut removed = 0u64;
    for (run, site, source) in orphans {
        // Tables `WITHOUT ROWID` : lot par clé primaire.
        for (table, key) in [
            (
                "vuln_match_items",
                "site, source, run, base, path, group_key",
            ),
            ("vuln_match_components", "site, source, run, base, path"),
        ] {
            loop {
                let tx = store
                    .conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;
                let n = tx.execute(
                    &format!(
                        "DELETE FROM {table} WHERE ({key}) IN (SELECT {key} FROM {table}
                             WHERE site = ?1 AND source = ?2 AND run = ?3 LIMIT ?4)"
                    ),
                    params![site, source, run, PURGE_BATCH as i64],
                )?;
                tx.commit()?;
                removed += n as u64;
                if n < PURGE_BATCH {
                    break;
                }
            }
        }
        store.conn.execute(
            "DELETE FROM vuln_match_runs WHERE id = ?1 AND NOT EXISTS (
                 SELECT 1 FROM vuln_match_state s WHERE s.active_run = ?1 OR s.pending_run = ?1)",
            [run],
        )?;
    }
    Ok(removed)
}

/// Sites absents de la configuration ou sans source d'inventaire : état,
/// runs, provenance et dates de perte de vue retirés (leurs incidents sont
/// clos « plus surveillé » par `tick`). Méta de déclaration retirée pour
/// chaque (site, source) qui n'est plus déclaré.
pub fn purge_unwatched(store: &mut Store, watched: &[(String, Vec<Source>)]) -> anyhow::Result<()> {
    let sites: Vec<String> = {
        let mut stmt = store.conn.prepare(
            "SELECT site FROM vuln_match_state UNION SELECT site FROM vuln_match_seen
             UNION SELECT site FROM vuln_match_keys",
        )?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    for site in sites {
        if watched.iter().any(|(s, _)| *s == site) {
            continue;
        }
        for table in [
            "vuln_match_state",
            "vuln_match_seen",
            "vuln_match_keys",
            "vuln_match_runs",
        ] {
            tx.execute(&format!("DELETE FROM {table} WHERE site = ?1"), [&site])?;
        }
        tx.execute("DELETE FROM vuln_match_components WHERE site = ?1", [&site])?;
        tx.execute("DELETE FROM vuln_match_items WHERE site = ?1", [&site])?;
    }
    let metas: Vec<String> = {
        let mut stmt =
            tx.prepare("SELECT key FROM meta WHERE key LIKE 'vulns.inventory.declared.%'")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    for meta in metas {
        let kept = watched.iter().any(|(site, sources)| {
            sources
                .iter()
                .any(|s| meta == format!("{META_DECLARED}{site}.{}", s.as_str()))
        });
        if !kept {
            tx.execute("DELETE FROM meta WHERE key = ?1", [&meta])?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// Minimisation : détail **et clé** des incidents `vulns` clos depuis plus
/// de 30 jours masqués (`<site>/vulns/masque-<id>`) ; détail du dernier
/// passage `vulns` d'un site plus vieux que 30 jours masqué de même.
pub fn mask_closed(store: &mut Store, now: i64) -> anyhow::Result<usize> {
    let limit = now.saturating_sub(MASK_AFTER);
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let n = tx.execute(
        "UPDATE incidents SET detail = ?1, key = site || '/' || ?2 || '/masque-' || id
         WHERE check_name = ?2 AND closed_at IS NOT NULL AND closed_at < ?3
           AND key <> site || '/' || ?2 || '/masque-' || id",
        params![MASKED, CHECK, limit],
    )?;
    tx.execute(
        "UPDATE check_runs SET detail = ?1
         WHERE check_name = ?2 AND last_run < ?3 AND detail IS NOT NULL AND detail <> ?1",
        params![MASKED, CHECK, limit],
    )?;
    tx.commit()?;
    Ok(n)
}

/// `site remove` (dans la transaction de `Store::remove_key`) : runs, état,
/// provenance, dérogations et passages `vulns` du site supprimés ; chaque
/// incident `vulns` ouvert perd sa vue à `now` (date de départ toujours
/// présente) ; méta `vulns.removed.<site>`.
pub(crate) fn forget_site(tx: &Transaction<'_>, site: &str, now: i64) -> anyhow::Result<()> {
    for table in [
        "vuln_match_state",
        "vuln_match_components",
        "vuln_match_items",
        "vuln_match_runs",
        "vuln_match_seen",
        "vuln_waivers",
    ] {
        tx.execute(&format!("DELETE FROM {table} WHERE site = ?1"), [site])?;
    }
    tx.execute(
        "DELETE FROM check_runs WHERE site = ?1 AND check_name = ?2",
        params![site, CHECK],
    )?;
    let prefix = format!("{site}/{CHECK}/");
    let keys: Vec<String> = {
        let mut stmt = tx.prepare(
            "SELECT key FROM incidents WHERE site = ?1 AND check_name = ?2 AND closed_at IS NULL",
        )?;
        let rows = stmt.query_map(params![site, CHECK], |r| r.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    let mut any = false;
    for full in keys {
        let Some(k) = full.strip_prefix(&prefix) else {
            continue;
        };
        if k == vfinding::KEY_STALE_AGENT || k == vfinding::KEY_STALE_CI {
            continue;
        }
        any = true;
        tx.execute(
            "INSERT INTO vuln_match_keys (site, key, lost_view_at) VALUES (?1, ?2, ?3)
             ON CONFLICT (site, key) DO UPDATE SET
                 lost_view_at = coalesce(vuln_match_keys.lost_view_at, excluded.lost_view_at)",
            params![site, k, now],
        )?;
    }
    if any {
        tx.execute(
            "INSERT INTO meta (key, value, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value,
                 updated_at = excluded.updated_at",
            params![format!("{META_REMOVED}{site}"), now.to_string(), now],
        )?;
    }
    Ok(())
}

/// Injection de pannes des tests : panique dans la transaction de bascule.
#[cfg(test)]
pub mod hooks {
    use std::sync::Mutex;

    static PANIC_ON: Mutex<Option<String>> = Mutex::new(None);

    pub fn panic_before_commit(site: Option<&str>) {
        *PANIC_ON.lock().unwrap_or_else(|e| e.into_inner()) = site.map(str::to_owned);
    }

    pub(super) fn before_commit(site: &str) {
        let armed = PANIC_ON.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if armed.as_deref() == Some(site) {
            panic!("panique injectée dans la transaction de bascule");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Alerts, Config, InventorySource, SiteInventory, SiteKind};
    use crate::inventory::{Component as InvComponent, ComponentType, Inventory};
    use crate::store::InventoryDoc;
    use crate::vulns::exploit::MemoryTables;
    use crate::vulns::matching::pass::{self, Budget};

    const T0: i64 = 4_070_908_800;

    fn config(dir: &std::path::Path, site: &str) -> Config {
        Config {
            alerts: Alerts {
                to: "alertes@example.org".into(),
                from: "vigie@example.org".into(),
                smtp_host: "smtp.example.org".into(),
                smtp_port: 587,
                smtp_user: None,
                password_file: dir.join("smtp-password"),
            },
            database: dir.join("vigie.db"),
            api: None,
            commands: None,
            logs: Default::default(),
            vulns: None,
            sites: vec![Site {
                id: site.into(),
                url: format!("https://{site}.example.org/"),
                kind: SiteKind::Generic,
                runtime: None,
                keyword_url: None,
                keyword: None,
                interval: 300,
                agent_silence: 900,
                logs: None,
                inventory: Some(SiteInventory::new(&[InventorySource::Ci])),
            }],
        }
    }

    /// Inventaire `ci` fictif d'un composant.
    fn inventory(store: &mut Store, site: &str) {
        let key = [9u8; 32];
        let public = ed25519_dalek::SigningKey::from_bytes(&key)
            .verifying_key()
            .to_bytes();
        store.add_inventory_key(site, &public, T0).unwrap();
        let components = vec![InvComponent {
            purl: Purl::parse("pkg:npm/exemple@1.0.0").unwrap(),
            name: "exemple".into(),
            ty: ComponentType::Library,
            scope: Scope::Required,
            path: "package-lock.json".into(),
            parent: None,
            config_version: None,
        }];
        let inventory = Inventory {
            site: site.into(),
            source: Source::Ci,
            seq: 1,
            sent_at: T0,
            agent: "vigie-inventory/0.1.0".into(),
            complete: true,
            skipped: 0,
            spec_version: "1.7".into(),
            serial: "urn:uuid:00000000-0000-4000-8000-000000000001".into(),
            generated_at: T0,
            digest: crate::inventory::bom::digest(&components),
            components,
            dropped: Default::default(),
        };
        store
            .accept_inventory(
                &InventoryDoc {
                    site,
                    source: Source::Ci,
                    pubkey: &public,
                    inventory: &inventory,
                },
                T0,
            )
            .unwrap();
    }

    fn budget() -> Budget {
        let far = std::time::Instant::now() + std::time::Duration::from_secs(3_600);
        Budget {
            deadline: far,
            hard_stop: far,
            max_batches: usize::MAX,
        }
    }

    #[test]
    fn a_cursor_position_is_written_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = Store::open(&dir.path().join("vigie.db")).unwrap();
        let mut b = Store::open(&dir.path().join("vigie.db")).unwrap();
        let run = begin_run(&mut a, "site-a", Source::Agent, 1, "m", "e", T0).unwrap();
        let other = begin_run(&mut a, "site-b", Source::Agent, 1, "m", "e", T0).unwrap();
        assert!(other > run, "séquence globale");
        assert!(push(&mut a, "site-a", Source::Agent, run, 0, &[], 10).unwrap());
        assert!(
            !push(&mut b, "site-a", Source::Agent, run, 0, &[], 10).unwrap(),
            "second passage sur la même position"
        );
        assert!(push(&mut b, "site-a", Source::Agent, run, 10, &[], 20).unwrap());
    }

    #[test]
    fn a_panic_in_the_switch_transaction_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let config = config(dir.path(), "site-panique");
        let mut store = Store::open(&config.database).unwrap();
        inventory(&mut store, "site-panique");
        let reader = Store::open_read(&config.database).unwrap().unwrap();
        let tables = MemoryTables::default();
        hooks::panic_before_commit(Some("site-panique"));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pass::run(&mut store, &reader, &config, &tables, T0 + 60, &budget())
        }));
        hooks::panic_before_commit(None);
        assert!(outcome.is_err(), "panique injectée");
        drop(store);
        let mut store = Store::open(&config.database).unwrap();
        let active: Option<i64> = store
            .conn
            .query_row(
                "SELECT active_run FROM vuln_match_state WHERE site = 'site-panique'",
                [],
                |r| r.get(0),
            )
            .optional()
            .unwrap()
            .flatten();
        assert_eq!(active, None, "ni bascule");
        let runs: i64 = store
            .conn
            .query_row(
                "SELECT count(*) FROM check_runs WHERE check_name = 'vulns'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(runs, 0, "ni réconciliation");
        let report = pass::run(&mut store, &reader, &config, &tables, T0 + 120, &budget());
        assert_eq!(report.commits, 1, "{report:?}");
    }

    #[test]
    fn site_remove_empties_the_match_tables_and_keeps_incidents() {
        let dir = tempfile::tempdir().unwrap();
        let config = config(dir.path(), "site-a");
        let mut store = Store::open(&config.database).unwrap();
        inventory(&mut store, "site-a");
        let reader = Store::open_read(&config.database).unwrap().unwrap();
        pass::run(
            &mut store,
            &reader,
            &config,
            &MemoryTables::default(),
            T0 + 60,
            &budget(),
        );
        store
            .conn
            .execute(
                "INSERT INTO incidents (key, site, check_name, severity, detail, opened_at)
                 VALUES ('site-a/vulns/pkg:npm/exemple', 'site-a', 'vulns', 'warning', 'x', 1)",
                [],
            )
            .unwrap();
        store.remove_key("site-a", T0 + 120).unwrap();
        for table in [
            "vuln_match_state",
            "vuln_match_components",
            "vuln_match_items",
            "vuln_match_seen",
            "vuln_waivers",
        ] {
            let n: i64 = store
                .conn
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                .unwrap();
            assert_eq!(n, 0, "{table}");
        }
        let lost: i64 = store
            .conn
            .query_row(
                "SELECT lost_view_at FROM vuln_match_keys WHERE key = 'pkg:npm/exemple'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(lost, T0 + 120);
        assert!(store.meta("vulns.removed.site-a").unwrap().is_some());
        assert_eq!(store.open_incidents().unwrap().len(), 1, "incident gardé");
    }
}
