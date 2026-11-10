//! Étape F7 de `tick` : le rapprochement de ce qui a changé, sous un budget
//! borné qui réserve le temps des envois.
//!
//! **Dû** : un site l'est quand l'état comparé d'une de ses sources
//! d'inventaire diffère de l'état gardé (`vuln_match_state`) : nouvel
//! inventaire, renvoi inchangé (`seen_at`), époque des failles, époque KEV et
//! EPSS, époque des dérogations, sources déclarées ; ou quand `now` atteint
//! une échéance gardée (péremption, report, dérogation, perte de vue).
//!
//! **Ce qui est refait** : inventaire ou époque des failles → rapprochement
//! de la source, par lots de 500 composants dans un run neuf, curseur
//! reprenable ; époque KEV/EPSS seule → réévaluation sur les faits gardés,
//! dans un run neuf, sans relire une plage ; le reste → constats seuls.
//! Dans tous les cas les constats du site sont reconstruits en entier et
//! passés à **une** réconciliation (`store::commit_and_reconcile`).
//!
//! **Budget** : un lot obligatoire par passage, sauf après `hard_stop`
//! (`start + send_budget − send_reserve / 2`) ; ensuite l'échéance et le
//! nombre de lots sont vérifiés entre deux lots. Les sites passent à tour
//! de rôle, le plus anciennement dû d'abord, ceux en erreur en dernier.
//!
//! **Erreurs** : chaque site est traité dans son propre `Result` ; une
//! erreur est journalisée (sans texte de la base), comptée dans
//! `error_count`, et le passage continue. Rien ne remonte à `tick`.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::rc::Rc;
use std::time::{Duration, Instant};

use anyhow::Context;

use crate::config::{Config, Site};
use crate::inventory::{Source, stale_after};
use crate::store::{InventoryHead, Store};
use crate::vulns::exploit::Exploitation;
use crate::vulns::purl::Purl;
use crate::vulns::store::{Candidate, candidates};

use super::assess::{assess, reassess};
use super::epoch;
use super::group::groups;
use super::store::{
    self as mstore, BATCH, ComponentResult, META_DECLARED, SiteInput, StateRow, Switch,
};
use super::{Component, admitted};

/// Poids du cache des candidates d'un passage : lignes `affected` et
/// entrées `versions[]` cumulées.
pub const CACHE_WEIGHT: usize = 50_000;

/// Échéances du passage.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    /// Aucun lot ne commence au-delà, sauf le premier.
    pub deadline: Instant,
    /// Aucun lot ne commence au-delà, pas même le premier.
    pub hard_stop: Instant,
    /// Lots au plus (tests) ; illimité en production.
    pub max_batches: usize,
}

/// Bilan d'un passage.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PassReport {
    /// Composants d'inventaire rapprochés (plages lues).
    pub components: usize,
    /// Sites en erreur.
    pub errors: usize,
    /// Lots (rapprochement, réévaluation, constats seuls).
    pub batches: usize,
    /// Purl sans version dont les candidates ont été lues en base.
    pub candidate_reads: usize,
    /// Sites dont les constats ont été réconciliés.
    pub commits: usize,
    /// Sites dus restés pour le passage suivant.
    pub deferred: usize,
    /// Plus long lot.
    pub max_batch: Duration,
    /// Plus longue transaction de bascule et réconciliation.
    pub max_commit: Duration,
}

/// Candidates des purl sans version, gardées le temps d'un passage, bornées
/// en poids ; la plus ancienne entrée sort d'abord.
struct Cache {
    map: HashMap<String, (Rc<Vec<Candidate>>, usize)>,
    order: VecDeque<String>,
    weight: usize,
    reads: usize,
}

impl Cache {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            weight: 0,
            reads: 0,
        }
    }

    fn get(
        &mut self,
        reader: &Store,
        base: &Purl,
        declared: &[&str],
    ) -> anyhow::Result<Rc<Vec<Candidate>>> {
        let k = base.canonical();
        if let Some((hit, _)) = self.map.get(&k) {
            return Ok(Rc::clone(hit));
        }
        self.reads += 1;
        let found: Vec<Candidate> = candidates(reader, base)?
            .into_iter()
            .filter(|c| declared.contains(&c.source.as_str()))
            .collect();
        let weight = found
            .iter()
            .flat_map(|c| &c.lines)
            .map(|l| 1 + l.versions.len())
            .sum::<usize>()
            .max(1);
        let found = Rc::new(found);
        while self.weight + weight > CACHE_WEIGHT {
            let Some(old) = self.order.pop_front() else {
                break;
            };
            if let Some((_, w)) = self.map.remove(&old) {
                self.weight -= w;
            }
        }
        if weight <= CACHE_WEIGHT {
            self.map.insert(k.clone(), (Rc::clone(&found), weight));
            self.order.push_back(k);
            self.weight += weight;
        }
        Ok(found)
    }
}

/// Travail d'une source d'un site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Work {
    Nothing,
    Rematch,
    Reassess,
}

#[derive(Debug, Clone)]
struct SourcePlan {
    source: Source,
    head: Option<InventoryHead>,
    state: Option<StateRow>,
    work: Work,
}

struct SitePlan<'a> {
    site: &'a Site,
    sources: Vec<SourcePlan>,
    due: bool,
    order: (bool, i64),
}

/// Le passage du rapprochement. `store` écrit, `reader` (connexion de
/// lecture) sert les candidates, l'inventaire et les tables KEV/EPSS.
pub fn run(
    store: &mut Store,
    reader: &Store,
    config: &Config,
    tables: &impl Exploitation,
    now: i64,
    budget: &Budget,
) -> PassReport {
    let mut report = PassReport::default();
    match mstore::available(store) {
        Ok(true) => {}
        Ok(false) => return report,
        Err(err) => {
            log::error!("rapprochement des failles : schéma illisible : {err:#}");
            return report;
        }
    }
    if let Err(err) = pass(store, reader, config, tables, now, budget, &mut report) {
        log::error!("rapprochement des failles : {err:#}");
    }
    report
}

/// Sources d'inventaire déclarées de chaque site surveillé.
pub fn watched_sites(config: &Config) -> Vec<(String, Vec<Source>)> {
    config
        .sites
        .iter()
        .map(|s| (s.id.clone(), epoch::declared_sources(s)))
        .filter(|(_, sources)| !sources.is_empty())
        .collect()
}

/// Date de déclaration de chaque source (méta écrite au premier passage
/// qui la voit déclarée).
fn declared_at(
    store: &mut Store,
    site: &str,
    sources: &[Source],
    now: i64,
) -> anyhow::Result<BTreeMap<Source, i64>> {
    let mut out = BTreeMap::new();
    for &source in sources {
        let key = format!("{META_DECLARED}{site}.{}", source.as_str());
        let at = match store.meta(&key)? {
            Some((value, _)) => value.parse().unwrap_or(now),
            None => {
                store.set_meta(&key, &now.to_string(), now)?;
                now
            }
        };
        out.insert(source, at);
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn pass(
    store: &mut Store,
    reader: &Store,
    config: &Config,
    tables: &impl Exploitation,
    now: i64,
    budget: &Budget,
    report: &mut PassReport,
) -> anyhow::Result<()> {
    let watched = watched_sites(config);
    mstore::purge_unwatched(store, &watched)?;
    let declared_vulns = epoch::declared_vulns(config);
    let match_epoch = epoch::match_epoch(&store.conn, &declared_vulns)?;
    let enrich_epoch = epoch::enrich_epoch(&store.conn)?;
    let states = mstore::states(&store.conn)?;
    let heads = store.inventory_heads()?;

    let mut plans = Vec::new();
    for site in &config.sites {
        let declared = epoch::declared_sources(site);
        if declared.is_empty() {
            continue;
        }
        let rows: Vec<&StateRow> = states.iter().filter(|r| r.site == site.id).collect();
        let waiver_epoch = epoch::waiver_epoch(&store.conn, &site.id)?;
        let declared_text = epoch::declared_text(&declared);
        let mut due = rows.iter().any(|r| {
            r.source.is_none_or(|s| !declared.contains(&s))
                || r.declared_sources != declared_text
                || r.waiver_epoch.as_deref() != Some(waiver_epoch.as_str())
                || r.next_stale_check.is_some_and(|t| now >= t)
                || r.next_waiver_check.is_some_and(|t| now >= t)
        });
        let mut sources = Vec::new();
        for &source in &declared {
            let head = heads
                .iter()
                .find(|h| h.site == site.id && h.source == source)
                .cloned();
            let state = rows
                .iter()
                .find(|r| r.source == Some(source))
                .map(|r| (*r).clone());
            let work = match (&head, &state) {
                (_, None) => {
                    due = true;
                    if head.is_some() {
                        Work::Rematch
                    } else {
                        Work::Nothing
                    }
                }
                (None, Some(st)) => {
                    if st.active_run.is_some() || st.pending_run.is_some() {
                        Work::Rematch
                    } else {
                        Work::Nothing
                    }
                }
                (Some(h), Some(st)) => {
                    if st.seen_at != Some(h.seen_at) {
                        due = true;
                    }
                    if st.inventory_id != Some(h.id)
                        || st.match_epoch.as_deref() != Some(match_epoch.as_str())
                        || st.pending_run.is_some()
                    {
                        Work::Rematch
                    } else if st.enrich_epoch.as_deref() != Some(enrich_epoch.as_str()) {
                        Work::Reassess
                    } else {
                        Work::Nothing
                    }
                }
            };
            if work != Work::Nothing {
                due = true;
            }
            sources.push(SourcePlan {
                source,
                head,
                state,
                work,
            });
        }
        let errored = rows.iter().any(|r| r.error_count > 0);
        let since = rows.iter().filter_map(|r| r.due_since).min().unwrap_or(now);
        plans.push(SitePlan {
            site,
            sources,
            due,
            order: (errored, since),
        });
    }
    plans.retain(|p| p.due);
    plans.sort_by(|a, b| a.order.cmp(&b.order).then(a.site.id.cmp(&b.site.id)));

    let mut cache = Cache::new();
    let ctx = Ctx {
        reader,
        tables,
        now,
        budget,
        declared_vulns: &declared_vulns,
        match_epoch: &match_epoch,
        enrich_epoch: &enrich_epoch,
    };
    for plan in &plans {
        let declared: Vec<Source> = plan.sources.iter().map(|s| s.source).collect();
        if ctx.stop(report.batches) {
            report.deferred += 1;
            if let Err(err) = mstore::mark_due(store, &plan.site.id, &declared, now) {
                log::error!("{} : rapprochement des failles : {err:#}", plan.site.id);
            }
            continue;
        }
        match site_pass(store, &ctx, &mut cache, plan, report) {
            Ok(()) => {}
            Err(err) => {
                report.errors += 1;
                log::error!(
                    "{} : rapprochement des failles en échec, retenté au passage suivant : {err:#}",
                    plan.site.id
                );
                if let Err(err) = mstore::record_error(store, &plan.site.id, &declared, now) {
                    log::error!("{} : échec non noté : {err:#}", plan.site.id);
                }
            }
        }
    }
    report.candidate_reads = cache.reads;
    match mstore::purge_runs(store) {
        Ok(0) => {}
        Ok(n) => log::info!("rapprochement des failles : {n} ligne(s) d'anciens runs purgée(s)"),
        Err(err) => log::error!("purge des runs de rapprochement : {err:#}"),
    }
    Ok(())
}

struct Ctx<'a, T: Exploitation> {
    reader: &'a Store,
    tables: &'a T,
    now: i64,
    budget: &'a Budget,
    declared_vulns: &'a [&'static str],
    match_epoch: &'a str,
    enrich_epoch: &'a str,
}

impl<T: Exploitation> Ctx<'_, T> {
    /// Aucun lot ne commence : après `hard_stop`, ou après l'échéance ou le
    /// plafond de lots quand un lot a déjà été fait.
    fn stop(&self, batches: usize) -> bool {
        let now = Instant::now();
        now >= self.budget.hard_stop
            || (batches > 0 && (now >= self.budget.deadline || batches >= self.budget.max_batches))
    }
}

/// Un site : rapprochement ou réévaluation de chaque source qui en a
/// besoin, puis constats complets du site et bascule.
fn site_pass<T: Exploitation>(
    store: &mut Store,
    ctx: &Ctx<'_, T>,
    cache: &mut Cache,
    plan: &SitePlan<'_>,
    report: &mut PassReport,
) -> anyhow::Result<()> {
    let site = plan.site;
    let declared: Vec<Source> = plan.sources.iter().map(|s| s.source).collect();
    let mut switches = Vec::new();
    let mut pending = false;
    for sp in &plan.sources {
        match sp.work {
            Work::Nothing => {}
            Work::Rematch => match &sp.head {
                None => switches.push(Switch {
                    source: sp.source,
                    run: None,
                    inventory_id: None,
                    match_epoch: ctx.match_epoch.to_owned(),
                    enrich_epoch: ctx.enrich_epoch.to_owned(),
                }),
                Some(head) => match rematch(store, ctx, cache, site, sp, head, report)? {
                    Some(sw) => switches.push(sw),
                    None => pending = true,
                },
            },
            Work::Reassess => {
                if ctx.stop(report.batches) {
                    pending = true;
                    continue;
                }
                let started = Instant::now();
                report.batches += 1;
                if let Some(sw) = reassess_source(store, ctx, site, sp)? {
                    switches.push(sw);
                }
                report.max_batch = report.max_batch.max(started.elapsed());
            }
        }
    }
    if pending && switches.is_empty() {
        mstore::mark_due(store, &site.id, &declared, ctx.now)?;
        report.deferred += 1;
        return Ok(());
    }
    // Constats seuls : un lot.
    if switches.is_empty() {
        if ctx.stop(report.batches) {
            mstore::mark_due(store, &site.id, &declared, ctx.now)?;
            report.deferred += 1;
            return Ok(());
        }
        report.batches += 1;
    }
    let input = SiteInput {
        site,
        declared: declared.clone(),
        declared_vulns: ctx.declared_vulns.to_vec(),
        heads: plan
            .sources
            .iter()
            .filter_map(|s| s.head.clone().map(|h| (s.source, h)))
            .collect(),
        declared_at: declared_at(store, &site.id, &declared, ctx.now)?,
        match_epoch: ctx.match_epoch.to_owned(),
        enrich_epoch: ctx.enrich_epoch.to_owned(),
    };
    let snapshot = mstore::build_findings(store, &input, &switches, ctx.now)?;
    let started = Instant::now();
    let committed = mstore::commit_and_reconcile(store, &input, &switches, &snapshot, ctx.now)?;
    report.max_commit = report.max_commit.max(started.elapsed());
    if committed {
        report.commits += 1;
        if pending {
            mstore::mark_due(store, &site.id, &declared, ctx.now)?;
        }
        return Ok(());
    }
    // Lu puis changé : les runs neufs sont abandonnés (repris au début au
    // passage suivant, époques relues) ; le site reste dû.
    for sw in &switches {
        if let Some(run) = sw.run {
            mstore::abandon_run(store, &site.id, sw.source, run)?;
        }
    }
    log::info!(
        "{} : constats de failles relus puis changés, repris au passage suivant",
        site.id
    );
    mstore::mark_due(store, &site.id, &declared, ctx.now)?;
    report.deferred += 1;
    Ok(())
}

/// Composants d'un lot rapprochés.
#[allow(clippy::too_many_arguments)]
fn match_rows<T: Exploitation>(
    ctx: &Ctx<'_, T>,
    cache: &mut Cache,
    site: &Site,
    source: Source,
    head: &InventoryHead,
    rows: &[crate::store::InventoryComponentRow],
    first_seen: &HashMap<(String, String), i64>,
) -> anyhow::Result<Vec<ComponentResult>> {
    let mut out = Vec::new();
    for row in rows {
        if !admitted(site.kind, row.ecosystem) {
            continue;
        }
        let base = Purl::parse(&row.base).context("purl d'inventaire illisible")?;
        let component = Component {
            source,
            ecosystem: row.ecosystem,
            base: base.clone(),
            version: row.version.clone(),
            scope: row.scope,
            path: row.path.clone(),
            carried: false,
        };
        out.push(evaluate(
            ctx,
            cache,
            component,
            first_seen
                .get(&(row.base.clone(), row.path.clone()))
                .copied()
                .unwrap_or(head.received_at),
            head.seen_at,
        )?);
    }
    Ok(out)
}

fn evaluate<T: Exploitation>(
    ctx: &Ctx<'_, T>,
    cache: &mut Cache,
    component: Component,
    first_seen_at: i64,
    last_seen_at: i64,
) -> anyhow::Result<ComponentResult> {
    let cands = cache.get(ctx.reader, &component.base, ctx.declared_vulns)?;
    let groups = groups(&cands, component.version.as_deref())
        .iter()
        .filter_map(|g| assess(g, ctx.tables))
        .collect();
    Ok(ComponentResult {
        component,
        groups,
        candidates: !cands.is_empty(),
        first_seen_at,
        last_seen_at,
    })
}

/// Rapprochement d'une source : reprend le run en cours s'il vise le même
/// inventaire et la même époque, sinon en réserve un neuf ; lots de 500
/// tant que le budget le permet. `Some` quand le run est complet, prêt à
/// basculer.
fn rematch<T: Exploitation>(
    store: &mut Store,
    ctx: &Ctx<'_, T>,
    cache: &mut Cache,
    site: &Site,
    sp: &SourcePlan,
    head: &InventoryHead,
    report: &mut PassReport,
) -> anyhow::Result<Option<Switch>> {
    let source = sp.source;
    let resume = sp.state.as_ref().and_then(|st| {
        (st.pending_inventory_id == Some(head.id)
            && st.pending_match_epoch.as_deref() == Some(ctx.match_epoch)
            && st.pending_enrich_epoch.as_deref() == Some(ctx.enrich_epoch))
        .then_some(())
        .and(st.pending_run.map(|run| (run, st.cursor_rowid)))
    });
    let active = sp.state.as_ref().and_then(|st| st.active_run);
    let previous: Vec<ComponentResult> = match active {
        Some(run) => mstore::run_components(&store.conn, &site.id, source, run)?,
        None => Vec::new(),
    };
    let first_seen: HashMap<(String, String), i64> = previous
        .iter()
        .map(|r| {
            (
                (r.component.base.canonical(), r.component.path.clone()),
                r.first_seen_at,
            )
        })
        .collect();
    let (run, mut cursor) = match resume {
        Some(found) => found,
        None => {
            if ctx.stop(report.batches) {
                return Ok(None);
            }
            let run = mstore::begin_run(
                store,
                &site.id,
                source,
                head.id,
                ctx.match_epoch,
                ctx.enrich_epoch,
                ctx.now,
            )?;
            (run, 0)
        }
    };
    loop {
        if ctx.stop(report.batches) {
            return Ok(None);
        }
        let started = Instant::now();
        report.batches += 1;
        let rows = ctx.reader.inventory_components(head.id, cursor, BATCH)?;
        let done = rows.len() < BATCH;
        let next = rows.last().map_or(cursor, |r| r.rowid);
        let results = match_rows(ctx, cache, site, source, head, &rows, &first_seen)?;
        report.components += rows.len();
        if !mstore::push(store, &site.id, source, run, cursor, &results, next)? {
            // Un autre passage a écrit cette position, ou le run a changé.
            log::info!(
                "{} / {} : lot déjà écrit par un autre passage",
                site.id,
                source.as_str()
            );
            return Ok(None);
        }
        report.max_batch = report.max_batch.max(started.elapsed());
        cursor = next;
        if done {
            break;
        }
    }
    if !head.complete {
        carry(store, ctx, cache, site, source, run, cursor, &previous)?;
    }
    Ok(Some(Switch {
        source,
        run: Some(run),
        inventory_id: Some(head.id),
        match_epoch: ctx.match_epoch.to_owned(),
        enrich_epoch: ctx.enrich_epoch.to_owned(),
    }))
}

/// Relevé partiel : les composants du run actif absents du run neuf y sont
/// reportés, rapprochés sur leur dernière version connue, tant que leur
/// dernière vue a moins de `inventory::stale_after(source)`.
#[allow(clippy::too_many_arguments)]
fn carry<T: Exploitation>(
    store: &mut Store,
    ctx: &Ctx<'_, T>,
    cache: &mut Cache,
    site: &Site,
    source: Source,
    run: i64,
    cursor: i64,
    previous: &[ComponentResult],
) -> anyhow::Result<()> {
    let present: HashSet<(String, String)> =
        mstore::run_components(&store.conn, &site.id, source, run)?
            .into_iter()
            .map(|r| (r.component.base.canonical(), r.component.path))
            .collect();
    let threshold = i64::try_from(stale_after(source).as_secs()).unwrap_or(i64::MAX);
    let mut carried = Vec::new();
    for p in previous {
        let k = (p.component.base.canonical(), p.component.path.clone());
        if present.contains(&k) || p.last_seen_at.saturating_add(threshold) <= ctx.now {
            continue;
        }
        let mut component = p.component.clone();
        component.carried = true;
        carried.push(evaluate(
            ctx,
            cache,
            component,
            p.first_seen_at,
            p.last_seen_at,
        )?);
    }
    for chunk in carried.chunks(BATCH) {
        anyhow::ensure!(
            mstore::push(store, &site.id, source, run, cursor, chunk, cursor)?,
            "run supplanté pendant le report"
        );
    }
    Ok(())
}

/// Réévaluation sur les faits gardés : run neuf copié de l'actif, gravités
/// recalculées par F4, aucune plage relue.
fn reassess_source<T: Exploitation>(
    store: &mut Store,
    ctx: &Ctx<'_, T>,
    site: &Site,
    sp: &SourcePlan,
) -> anyhow::Result<Option<Switch>> {
    let Some(state) = &sp.state else {
        return Ok(None);
    };
    let (Some(active), Some(inventory)) = (state.active_run, state.inventory_id) else {
        return Ok(None);
    };
    let match_epoch = state.match_epoch.clone().unwrap_or_default();
    let results: Vec<ComponentResult> =
        mstore::run_results(&store.conn, &site.id, sp.source, active)?
            .into_iter()
            .map(|mut r| {
                r.groups = r.groups.iter().map(|g| reassess(g, ctx.tables)).collect();
                r
            })
            .collect();
    let run = mstore::begin_run(
        store,
        &site.id,
        sp.source,
        inventory,
        &match_epoch,
        ctx.enrich_epoch,
        ctx.now,
    )?;
    // Curseur : rang du lot copié.
    for (cursor, chunk) in (0i64..).zip(results.chunks(BATCH)) {
        if !mstore::push(store, &site.id, sp.source, run, cursor, chunk, cursor + 1)? {
            return Ok(None);
        }
    }
    Ok(Some(Switch {
        source: sp.source,
        run: Some(run),
        inventory_id: Some(inventory),
        match_epoch,
        enrich_epoch: ctx.enrich_epoch.to_owned(),
    }))
}
