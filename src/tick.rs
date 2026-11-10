//! `vigie tick` : passage lancé chaque minute par `vigie-tick.timer`.
//!
//! 1. enregistre le passage, que `/health` surveille, et purge les logs
//!    reçus de plus de 30 jours (`docs/logs.md`) ;
//! 2. lance les contrôles dus, les sites les plus en retard d'abord, sans
//!    commencer de requête après 40 s ;
//! 3. ouvre ou clôt le silence de chaque agent déclaré, et l'avertissement
//!    `typology` d'une clé d'agent sur un site sans runtime `php` ;
//! 4. replie les logs nouveaux des sites qui ont une source, à tour de rôle,
//!    par lots de 500, sous un budget global de 10 s vérifié entre deux lots
//!    (`analysis/`, issue #8), puis réconcilie les constats `logs` de chacun
//!    sur ses agrégats ;
//! 5. rapproche les inventaires des sites des failles connues (#21,
//!    `vulns/matching/pass.rs`) : ce qui a changé seulement, par lots de 500,
//!    sous un budget de 10 s qui réserve le temps des envois (aucun lot après
//!    `start + send_budget − send_reserve`, sauf le premier, et pas même lui
//!    après `start + send_budget − send_reserve / 2`) ; une erreur d'un site
//!    n'arrête jamais le passage ;
//! 6. clôt « plus surveillé » les incidents des contrôles que le registre des
//!    capacités ne surveille plus pour leur site (`capability::watched`), puis
//!    envoie les e-mails en attente (ouvertures, clôtures, rappels) jusqu'à
//!    50 s, y compris ceux des rapports d'agent acceptés par `serve`, groupés
//!    par site au-delà de cinq pour le contrôle `vulns`. Ce qui n'a pas pu
//!    partir reste en attente pour le passage suivant.

use std::time::{Duration, Instant};

use anyhow::{Result, bail};

use crate::alert::{self, Email, Notifier, SmtpNotifier};
use crate::analysis::findings::{self as log_findings, CHECK as LOGS_CHECK};
use crate::analysis::fold::{BATCH_SIZE, SiteState, secs_to_ms};
use crate::analysis::rules::{self as log_rules, RuleSet};
use crate::analysis::{shared, store as agg};
use crate::capability::{self, Control, TYPOLOGY};
use crate::checks::{self, CheckError, CheckKind, Ctx, heartbeat};
use crate::config::{Config, LogSourceKind, Site, TypologyRecord};
use crate::finding::Finding;
use crate::http::{Http, REQUEST_TIMEOUT, Trust};
use crate::logs::alwaysdata::AlwaysdataSource;
use crate::logs::source::{Cursor, LogSource, SourceError};
use crate::store::{Agent, Incident, META_TYPOLOGY_TICK, Notified, RunRecord, Store};
use crate::vulns::enrich_store::StoreTables;
use crate::vulns::matching::pass::{self as matching_pass, Budget, PassReport};
use crate::vulns::matching::store as matching_store;
use crate::vulns::store as vulns_store;
use crate::vulns::sync::{freshness, registry};

#[derive(Debug, Clone)]
pub struct Options {
    pub trust: Trust,
    pub request_timeout: Duration,
    /// Aucune requête de contrôle ne commence au-delà.
    pub check_budget: Duration,
    /// Aucun envoi ne commence au-delà, depuis le début du passage.
    pub send_budget: Duration,
    /// Budget global du repli des logs, pris sur celui du passage : aucun lot
    /// ne commence au-delà.
    pub analysis_budget: Duration,
    /// Lots de logs repliés au plus par passage, tous sites confondus :
    /// illimité en production, borné par les tests pour épuiser le budget à
    /// un lot près.
    pub analysis_max_batches: usize,
    /// Budget du rapprochement des failles (#21), pris sur celui du
    /// passage : aucun lot ne commence au-delà, sauf le premier.
    pub vulns_budget: Duration,
    /// Temps réservé aux envois : l'analyse de logs et le rapprochement
    /// s'arrêtent à `send_budget − send_reserve` ; aucun lot de rapprochement
    /// ne commence après `send_budget − send_reserve / 2`.
    pub send_reserve: Duration,
    /// Lots de rapprochement au plus par passage (tests).
    pub vulns_max_batches: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            trust: Trust::WebPki,
            request_timeout: REQUEST_TIMEOUT,
            check_budget: Duration::from_secs(40),
            send_budget: Duration::from_secs(50),
            analysis_budget: Duration::from_secs(10),
            analysis_max_batches: usize::MAX,
            vulns_budget: Duration::from_secs(10),
            send_reserve: Duration::from_secs(10),
            vulns_max_batches: usize::MAX,
        }
    }
}

/// Bilan d'un passage, pour le journal et les tests.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Summary {
    pub checks_run: usize,
    pub inconclusive: usize,
    /// Entrées de logs repliées, tous sites confondus.
    pub logs_folded: usize,
    /// Composants d'inventaire rapprochés des failles (plages lues).
    pub vulns_components: usize,
    /// Sites dont le rapprochement a échoué ce passage.
    pub vulns_errors: usize,
    pub emails_sent: usize,
    pub emails_pending: usize,
}

/// Source des logs d'un site, ou `None` s'il n'en a pas. Injectée par les
/// tests (`MemorySource`).
pub type Sources<'a> = dyn Fn(&Site) -> Option<Box<dyn LogSource>> + 'a;

/// Source déclarée par `[sites.logs] source`.
pub fn default_source(config: &Config, site: &Site) -> Option<Box<dyn LogSource>> {
    match site.logs.as_ref()?.source? {
        LogSourceKind::Alwaysdata => Some(Box::new(AlwaysdataSource::new(
            site.id.clone(),
            config.database.clone(),
        ))),
    }
}

/// Verdict « surveillé » de `close_unwatched` : celui du registre
/// (`capability::watched`) pour le site de la configuration, avec ses clé
/// d'agent et référence d'empreintes en base ; pour le pseudo-site du
/// veilleur, celui de `capability::watched_by_watcher` (source de failles
/// toujours déclarée). Un site absent de la configuration n'a plus rien de
/// surveillé.
pub fn watched_by_tick<'a>(
    config: &'a Config,
    agents: &'a [Agent],
    baselines: &'a [String],
) -> impl Fn(&Incident) -> bool + 'a {
    move |incident| {
        if incident.site == capability::WATCHER_SITE {
            return capability::watched_by_watcher(
                config,
                &incident.check_name,
                incident.finding_key(),
            );
        }
        config
            .sites
            .iter()
            .find(|s| s.id == incident.site)
            .is_some_and(|site| {
                capability::watched(
                    site,
                    &incident.check_name,
                    &context(site, agents, baselines),
                )
            })
    }
}

/// Contexte du registre d'un site : clé d'agent et référence en base.
fn context(site: &Site, agents: &[Agent], baselines: &[String]) -> capability::Ctx {
    capability::Ctx {
        agent: agents.iter().any(|a| a.site == site.id),
        baseline: baselines.contains(&site.id),
    }
}

pub fn run(config: &Config, now: i64) -> Result<()> {
    let notifier = SmtpNotifier::new(config.alerts.clone());
    let summary = run_with(config, now, &Options::default(), &notifier)?;
    log::info!(
        "tick : {} contrôle(s), {} non concluant(s), {} entrée(s) de logs repliée(s), {} composant(s) rapproché(s), {} site(s) en échec de rapprochement, {} e-mail(s) envoyé(s), {} en attente",
        summary.checks_run,
        summary.inconclusive,
        summary.logs_folded,
        summary.vulns_components,
        summary.vulns_errors,
        summary.emails_sent,
        summary.emails_pending
    );
    Ok(())
}

/// Écrit la typologie vue par ce passage quand elle a changé, et journalise
/// les sites concernés : le journal garde quelle typologie valait quand.
fn record_typology(store: &mut Store, config: &Config, now: i64) -> Result<()> {
    let current = TypologyRecord::of(config);
    let previous = store
        .meta(META_TYPOLOGY_TICK)?
        .and_then(|(value, _)| serde_json::from_str::<TypologyRecord>(&value).ok());
    if previous.as_ref() == Some(&current) {
        return Ok(());
    }
    match &previous {
        Some(previous) => log::info!(
            "typologie changée, empreinte {} : {}",
            current.fingerprint,
            previous.changes(&current).join(" ; ")
        ),
        None => log::info!("typologie relevée, empreinte {}", current.fingerprint),
    }
    store.set_meta(META_TYPOLOGY_TICK, &serde_json::to_string(&current)?, now)
}

/// Canal de commandes : expiration des commandes (`expired`, `unknown`) et
/// envoi de la tête de chaque journal d'audit modifié, ancre hors de la base
/// (`command/audit.rs`). Sans `[commands]` ou sans clé d'audit lisible, rien
/// n'expire (`serve` vérifie lui-même l'échéance) et le passage continue.
/// Rend le nombre d'e-mails envoyés.
fn commands_housekeeping(
    store: &mut Store,
    config: &Config,
    now: i64,
    notifier: &dyn Notifier,
    deadline: Instant,
) -> usize {
    let Some(commands) = &config.commands else {
        return 0;
    };
    if store.schema_version().unwrap_or(0) < crate::store::SCHEMA_COMMANDS {
        return 0;
    }
    let audit_key = match crate::command::key::load(&commands.audit_key_file) {
        Ok(key) => key,
        Err(err) => {
            log::error!("canal de commandes : clé d'audit illisible, aucune expiration : {err}");
            return 0;
        }
    };
    match store.expire_commands(now, &audit_key) {
        Ok(0) => {}
        Ok(n) => log::info!("{n} commande(s) expirée(s) ou d'issue inconnue"),
        Err(err) => log::error!("expiration des commandes : {err:#}"),
    }
    let heads = match store.audit_heads_to_notify() {
        Ok(heads) => heads,
        Err(err) => {
            log::error!("têtes d'audit : {err:#}");
            return 0;
        }
    };
    let mut sent = 0;
    for (site, head) in heads {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let email = Email {
            subject: format!("[vigie] {site} : journal des commandes"),
            body: format!(
                "Le journal d'audit des commandes de {site} a changé.\n\nTête de la chaîne : {head}\nRelevée le {}\n\nGarder cet e-mail : il prouve l'état du journal à cette date.\nVérifier : vigie site audit {site} --verify --head {head}\n",
                crate::iso_utc(now)
            ),
        };
        match notifier.send(&email, remaining) {
            Ok(()) => {
                if let Err(err) = store.mark_audit_notified(&site, &head, now) {
                    log::error!("{site} : tête d'audit envoyée mais non notée : {err:#}");
                }
                sent += 1;
            }
            Err(err) => log::warn!("{site} : envoi de la tête d'audit échoué : {err}"),
        }
    }
    sent
}

pub fn run_with(
    config: &Config,
    now: i64,
    options: &Options,
    notifier: &dyn Notifier,
) -> Result<Summary> {
    run_with_sources(config, now, options, notifier, &|site| {
        default_source(config, site)
    })
}

/// [`run_with`], avec les sources de logs données.
pub fn run_with_sources(
    config: &Config,
    now: i64,
    options: &Options,
    notifier: &dyn Notifier,
    sources: &Sources<'_>,
) -> Result<Summary> {
    let start = Instant::now();
    let mut store = Store::open(&config.database)?;
    store.record_tick(now)?;
    record_typology(&mut store, config, now)?;
    // RGPD : conservation de 30 jours. Un échec n'arrête pas le passage.
    match store.purge_logs(now) {
        Ok((0, 0)) => {}
        Ok((entries, batches)) => {
            log::info!("logs : {entries} entrée(s) et {batches} lot(s) de plus de 30 jours purgés")
        }
        Err(err) => log::error!("purge des logs : {err:#}"),
    }
    // Erreurs des sites (#52) : 14 jours. Même règle.
    match store.purge_errors(now) {
        Ok(0) => {}
        Ok(groups) => {
            log::info!("erreurs : {groups} groupe(s) de plus de 14 jours purgés")
        }
        Err(err) => log::error!("purge des erreurs : {err:#}"),
    }
    purge_analysis(&mut store, now);
    // Inventaires : dernier et 30 jours d'historique par (site, source) ; le
    // dernier d'une source que le site ne déclare plus part aussi après 30
    // jours.
    let declared: Vec<(String, crate::inventory::Source)> = config
        .sites
        .iter()
        .flat_map(|site| {
            crate::capability::inventory_sources(site)
                .into_iter()
                .map(|source| (site.id.clone(), source.into()))
        })
        .collect();
    match store.purge_inventory(now, &declared) {
        Ok(0) => {}
        Ok(purged) => log::info!("inventaires : {purged} inventaire(s) de plus de 30 jours purgés"),
        Err(err) => log::error!("purge des inventaires : {err:#}"),
    }
    let http = Http::new(&options.trust, options.request_timeout);
    let ctx = Ctx {
        http: &http,
        trust: &options.trust,
        request_timeout: options.request_timeout,
        deadline: start + options.check_budget,
        now,
    };
    let mut summary = Summary::default();

    for (site, due) in due_checks(&store, &config.sites, now)? {
        if Instant::now() >= ctx.deadline {
            log::warn!("échéance des contrôles atteinte, la suite au passage suivant");
            break;
        }
        for kind in due {
            let started = Instant::now();
            match kind.observe(site, &ctx) {
                Ok(checks::Outcome { findings, observed }) => {
                    summary.checks_run += 1;
                    let record = RunRecord::concluded(&findings)
                        .with_duration(started.elapsed())
                        .with_observed(observed.to_json());
                    store.record_result(&site.id, kind.name(), now, &record)?;
                    store.reconcile(&site.id, kind.name(), &findings, now)?;
                    if kind == CheckKind::Content && checks::is_unreachable(&findings) {
                        // Les autres contrôles ne concluraient rien.
                        break;
                    }
                }
                Err(CheckError { message, cut_short }) => {
                    summary.inconclusive += 1;
                    log::warn!("{} / {} : non concluant : {message}", site.id, kind.name());
                    if cut_short {
                        // Rejoué au passage suivant.
                        break;
                    }
                    let record = RunRecord::failed(&message).with_duration(started.elapsed());
                    store.record_result(&site.id, kind.name(), now, &record)?;
                }
            }
        }
    }

    // Silence des agents et typologie : seuls les sites de la configuration
    // qui ont une clé. Sans runtime `php`, l'agent n'est pas surveillé :
    // l'avertissement `typology` le dit, au lieu de clore en silence. Avec
    // `php`, `typology` est réconcilié vide (clos « rétabli ») ; sans clé, il
    // est laissé à `close_unwatched` (clos « plus surveillé »).
    let agents = store.agents()?;
    let baselines = store.baseline_sites()?;
    for site in &config.sites {
        let Some(agent) = agents.iter().find(|a| a.site == site.id) else {
            continue;
        };
        let ctx = context(site, &agents, &baselines);
        if Control::Heartbeat.watched(site, &ctx) {
            let findings = heartbeat::evaluate(site, agent, now);
            store.record_result(
                &site.id,
                heartbeat::NAME,
                now,
                &RunRecord::concluded(&findings),
            )?;
            store.reconcile(&site.id, heartbeat::NAME, &findings, now)?;
        }
        let findings = capability::typology_findings(site, &ctx);
        if Control::Typology.watched(site, &ctx) {
            store.record_result(&site.id, TYPOLOGY, now, &RunRecord::concluded(&findings))?;
        }
        store.reconcile(&site.id, TYPOLOGY, &findings, now)?;
    }

    // Le temps des envois est réservé : l'analyse de logs et le
    // rapprochement s'arrêtent avant.
    let sends_reserved = start + options.send_budget.saturating_sub(options.send_reserve);
    let analysis_deadline = (Instant::now() + options.analysis_budget).min(sends_reserved);
    summary.logs_folded = analyse_logs(
        &mut store,
        config,
        now,
        sources,
        analysis_deadline,
        options.analysis_max_batches,
    );

    let budget = Budget {
        deadline: (Instant::now() + options.vulns_budget).min(sends_reserved),
        hard_stop: start + options.send_budget.saturating_sub(options.send_reserve / 2),
        max_batches: options.vulns_max_batches,
    };
    let report = match_vulns(&mut store, config, now, &budget);
    summary.vulns_components = report.components;
    summary.vulns_errors = report.errors;

    // La référence a pu naître d'un rapport pendant le passage : relue.
    let baselines = store.baseline_sites()?;
    // Seul appel de `close_unwatched`, en fin de passage : un appel plus tôt
    // pourrait clore un incident `integrity` ouvert pendant le passage. Une
    // source de failles retirée est close « plus surveillé » ici, avant que
    // `vulns_freshness` ne réconcilie les autres.
    let closed = store.close_unwatched(watched_by_tick(config, &agents, &baselines), now)?;
    if closed > 0 {
        log::info!(
            "{closed} incident(s) clos « plus surveillé » : contrôle hors du registre des capacités pour son site"
        );
    }
    vulns_freshness(&mut store, config, now);

    summary.emails_sent = notify(
        &mut store,
        config,
        now,
        notifier,
        start + options.send_budget,
    )?;
    summary.emails_sent += commands_housekeeping(
        &mut store,
        config,
        now,
        notifier,
        start + options.send_budget,
    );
    summary.emails_pending = store.pending_notifications(now)?;
    Ok(summary)
}

/// Rapprochement inventaire × failles (#21) : l'étape entière est
/// enveloppée, toute erreur (base de lecture, tables KEV et EPSS) est
/// journalisée et le passage continue vers `close_unwatched` et `notify`.
/// Puis minimisation des incidents `vulns` clos depuis 30 jours.
fn match_vulns(store: &mut Store, config: &Config, now: i64, budget: &Budget) -> PassReport {
    let report = match Store::open_read(&config.database) {
        Ok(Some(reader)) => match StoreTables::open(&reader) {
            Ok(tables) => matching_pass::run(store, &reader, config, &tables, now, budget),
            Err(err) => {
                log::error!("rapprochement des failles : tables KEV et EPSS illisibles : {err:#}");
                PassReport::default()
            }
        },
        Ok(None) => PassReport::default(),
        Err(err) => {
            log::error!("rapprochement des failles : base de lecture : {err:#}");
            PassReport::default()
        }
    };
    if store
        .schema_version()
        .is_ok_and(|v| v >= crate::store::SCHEMA_VULNS_MATCH)
    {
        match matching_store::mask_closed(store, now) {
            Ok(0) => {}
            Ok(n) => log::info!("{n} incident(s) de failles clos depuis 30 jours masqué(s)"),
            Err(err) => log::error!("minimisation des incidents de failles : {err:#}"),
        }
    }
    report
}

/// Fraîcheur des bases de failles (#16), avant `notify` pour que l'e-mail
/// parte dans le même passage : date de première vue de chaque source
/// déclarée (`meta vulns.declared.<source>`, supprimée quand elle ne l'est
/// plus), puis constat `vulns-sync` réconcilié sur le pseudo-site du
/// veilleur. Une lecture de l'état en échec ne vaut pas « aucun constat » :
/// rien n'est réconcilié, le passage continue. `tick` ne fait que lire
/// `vuln_sources`.
fn vulns_freshness(store: &mut Store, config: &Config, now: i64) {
    if store.schema_version().unwrap_or(0) < crate::store::SCHEMA_VULNS_SYNC {
        return;
    }
    let declared = registry::declared(config);
    let mut since = std::collections::HashMap::new();
    for id in registry::KNOWN {
        let key = format!("{}{id}", freshness::META_DECLARED);
        let result = if declared.contains(id) {
            match store.meta(&key) {
                Ok(Some((value, _))) => {
                    since.insert(*id, value.parse::<i64>().unwrap_or(now));
                    Ok(())
                }
                Ok(None) => {
                    since.insert(*id, now);
                    store.set_meta(&key, &now.to_string(), now)
                }
                Err(err) => Err(err),
            }
        } else {
            store.delete_meta(&key)
        };
        if let Err(err) = result {
            log::error!("failles : date de déclaration de {id} : {err:#}");
        }
    }
    if declared.is_empty() {
        return;
    }
    let states = match vulns_store::sync_states(store) {
        Ok(states) => states,
        Err(err) => {
            log::error!(
                "failles : état des sources illisible, constat vulns-sync non évalué : {err:#}"
            );
            return;
        }
    };
    let findings = freshness::findings(&declared, &states, |id| since.get(id).copied(), now);
    let result = store
        .record_result(
            capability::WATCHER_SITE,
            capability::VULNS_SYNC,
            now,
            &RunRecord::concluded(&findings),
        )
        .and_then(|()| {
            store.reconcile(
                capability::WATCHER_SITE,
                capability::VULNS_SYNC,
                &findings,
                now,
            )
        });
    if let Err(err) = result {
        log::error!("failles : constat vulns-sync non réconcilié : {err:#}");
    }
}

/// Purges de l'analyse de logs, pour tous les sites, y compris ceux qui
/// n'ont plus de source : profils et verdicts à 48 h, seaux, robots et
/// charge à 24 h, signatures et résumés à 30 jours, détails des incidents
/// `logs` clos masqués à 30 jours. Un échec n'arrête pas le passage.
fn purge_analysis(store: &mut Store, now: i64) {
    if let Err(err) = agg::purge(store, now.saturating_mul(1000)) {
        log::error!("purge des agrégats de logs : {err:#}");
    }
    if let Err(err) = log_findings::purge(store, now) {
        log::error!("purge des analyses de logs : {err:#}");
    }
    match shared::purge(store, now) {
        Ok(0) => {}
        Ok(n) => log::info!("{n} signature(s) d'UA expirée(s)"),
        Err(err) => log::error!("purge des signatures d'UA : {err:#}"),
    }
}

/// Repli en cours d'un site qui a une source.
struct LogRun<'a> {
    site: &'a Site,
    rules: RuleSet,
    source: Box<dyn LogSource>,
    /// Curseur enregistré au début du passage ; ensuite celui de `state`.
    cursor: Cursor,
    /// Ouvert au premier lot non vide.
    state: Option<SiteState>,
    more: bool,
    folded: usize,
    /// Une reprise au début (curseur invalide) au plus par passage.
    restarted: bool,
    failed: bool,
}

/// Replie les logs nouveaux des sites qui ont une source, un lot par site à
/// tour de rôle, sans commencer de lot après `deadline` ni au-delà de
/// `max_batches` ; puis réconcilie les constats `logs` de chacun, complets
/// par construction sur les agrégats. Rend le nombre d'entrées repliées.
fn analyse_logs(
    store: &mut Store,
    config: &Config,
    now: i64,
    sources: &Sources<'_>,
    deadline: Instant,
    max_batches: usize,
) -> usize {
    let now_ms = now.saturating_mul(1000);
    let mut runs = Vec::new();
    for site in &config.sites {
        let Some(source) = sources(site) else {
            continue;
        };
        let rules = match log_rules::for_site(config, site) {
            Ok(rules) => rules,
            Err(err) => {
                log::error!("{} : règles de logs : {err}", site.id);
                continue;
            }
        };
        let cursor = match agg::cursor(store, &site.id) {
            Ok(cursor) => cursor.map(|(cursor, _)| cursor).unwrap_or_default(),
            Err(err) => {
                log::error!("{} : curseur de logs illisible : {err:#}", site.id);
                continue;
            }
        };
        runs.push(LogRun {
            site,
            rules,
            source,
            cursor,
            state: None,
            more: true,
            folded: 0,
            restarted: false,
            failed: false,
        });
    }
    if runs.is_empty() {
        return 0;
    }
    // `tick` est synchrone ; appelé depuis un runtime (tests asynchrones), il
    // attend chaque lot sur un fil à part (`block_on`).
    let runtime = if tokio::runtime::Handle::try_current().is_ok() {
        None
    } else {
        match tokio::runtime::Builder::new_current_thread().build() {
            Ok(runtime) => Some(runtime),
            Err(err) => {
                log::error!("analyse des logs : runtime indisponible : {err}");
                return 0;
            }
        }
    };

    let mut batches = 0usize;
    'rounds: loop {
        let mut progressed = false;
        for run in runs.iter_mut().filter(|r| r.more && !r.failed) {
            // Budget vérifié entre deux lots, jamais au milieu.
            if batches >= max_batches || Instant::now() >= deadline {
                log::warn!("analyse des logs : budget atteint, la suite au passage suivant");
                break 'rounds;
            }
            batches += 1;
            progressed = true;
            if let Err(err) = fold_next(store, run, runtime.as_ref(), now_ms) {
                log::error!("{} : repli des logs : {err:#}", run.site.id);
                run.failed = true;
                // Le repli a pu avancer l'état avant l'échec de l'écriture.
                run.state = None;
            }
        }
        if !progressed {
            break;
        }
    }

    let mut folded = 0;
    for run in &runs {
        folded += run.folded;
        if let Err(err) = reconcile_logs(store, run, now) {
            log::error!("{} : constats de logs : {err:#}", run.site.id);
        }
    }
    folded
}

/// Attend `future` sur `runtime`, ou, sans lui (appel depuis un runtime, qui
/// ne peut en bloquer un autre ni en détruire un), sur un runtime créé et
/// détruit sur un fil à part.
fn block_on<F>(runtime: Option<&tokio::runtime::Runtime>, future: F) -> Result<F::Output>
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    if let Some(runtime) = runtime {
        return Ok(runtime.block_on(future));
    }
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread().build()?;
                Ok(runtime.block_on(future))
            })
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}

/// Lit et replie le lot suivant d'un site.
fn fold_next(
    store: &mut Store,
    run: &mut LogRun<'_>,
    runtime: Option<&tokio::runtime::Runtime>,
    now_ms: i64,
) -> Result<()> {
    let from = run
        .state
        .as_ref()
        .map_or_else(|| run.cursor.clone(), |s| s.cursor.clone());
    match block_on(runtime, run.source.fetch(&from, BATCH_SIZE))? {
        Ok(fetched) => {
            if fetched.entries.is_empty() && fetched.next == from {
                run.more = false;
                return Ok(());
            }
            run.more = fetched.more;
            let state = match &mut run.state {
                Some(state) => state,
                state @ None => state.insert(agg::open_site(
                    store,
                    &run.site.id,
                    run.site.agent_silence,
                    now_ms,
                )?),
            };
            let delta = agg::fold_batch(store, state, &run.rules, &fetched, now_ms)?;
            run.folded += delta.folded;
            Ok(())
        }
        Err(SourceError::CursorInvalid { restart }) if !run.restarted => {
            // Reprendre au début sur des agrégats vidés : rien n'est compté
            // deux fois.
            log::warn!(
                "{} : curseur de logs invalide, reprise de {} depuis « {} »",
                run.site.id,
                run.source.id(),
                restart.0
            );
            agg::reset_site(store, &run.site.id)?;
            run.restarted = true;
            run.state = None;
            run.cursor = restart;
            run.more = true;
            Ok(())
        }
        Err(err) => Err(err.into()),
    }
}

/// Analyse d'un site et réconciliation de ses constats `logs`. Les verdicts
/// ne sont recalculés, et l'instantané écrit, que si le passage a replié
/// des entrées.
fn reconcile_logs(store: &mut Store, run: &LogRun<'_>, now: i64) -> Result<()> {
    let site = run.site.id.as_str();
    let now_ms = now.saturating_mul(1000);
    let reference = agg::cursor(store, site)?
        .and_then(|(_, reference)| reference)
        .map(|r| r.min(now_ms));
    let findings = match reference {
        None => Vec::new(),
        Some(reference) => {
            let analysis = if run.folded > 0 {
                let elsewhere = shared::elsewhere(store, site, now)?;
                let (analysis, to_note) =
                    log_findings::analyse(store, site, &run.rules, reference, now, &elsewhere)?;
                shared::note(store, site, &to_note, now)?;
                log_findings::persist(store, &analysis)?;
                analysis
            } else {
                log_findings::refresh(store, site, &run.rules, reference, now)?
            };
            log_findings::findings(&analysis, now_ms, secs_to_ms(run.site.agent_silence))
        }
    };
    store.record_result(site, LOGS_CHECK, now, &RunRecord::concluded(&findings))?;
    store.reconcile(site, LOGS_CHECK, &findings, now)?;
    Ok(())
}

/// Contrôles dus de chaque site, les sites les plus en retard d'abord. Un
/// contrôle est dû quand son intervalle est entièrement écoulé.
fn due_checks<'a>(
    store: &Store,
    sites: &'a [Site],
    now: i64,
) -> Result<Vec<(&'a Site, Vec<CheckKind>)>> {
    let mut plan = Vec::new();
    for site in sites {
        let mut due = Vec::new();
        let mut lateness = i64::MIN;
        for kind in CheckKind::ALL.into_iter().filter(|k| k.applies(site)) {
            let interval = i64::try_from(kind.interval(site)).unwrap_or(i64::MAX);
            let late = match store.last_run(&site.id, kind.name())? {
                None => i64::MAX,
                Some(last) => (now - last).saturating_sub(interval),
            };
            if late >= 0 {
                due.push(kind);
                lateness = lateness.max(late);
            }
        }
        if !due.is_empty() {
            plan.push((site, due, lateness));
        }
    }
    plan.sort_by(|a, b| b.2.cmp(&a.2));
    Ok(plan.into_iter().map(|(site, due, _)| (site, due)).collect())
}

enum Kind {
    Open,
    Close,
    Reminder,
}

/// Au-delà de ce nombre d'e-mails `vulns` en attente pour un site, un seul
/// e-mail groupé part (#21).
pub const VULNS_GROUP_OVER: usize = 5;

/// Envoie dans l'ordre ouvertures, clôtures, rappels. S'arrête au premier
/// échec : le relais est sans doute en panne, inutile d'insister.
///
/// Contrôle `vulns` : ce qui est **en attente pour un site** (ouvertures
/// nouvelles et gravités montées, rappels, clôtures) au-delà de cinq part en
/// un seul e-mail, puis tous sont marqués dans une transaction. Envoi raté :
/// rien n'est marqué, l'e-mail groupé est retenté. Marquage raté après
/// l'envoi : l'e-mail groupé peut repartir (doublon accepté).
fn notify(
    store: &mut Store,
    config: &Config,
    now: i64,
    notifier: &dyn Notifier,
    deadline: Instant,
) -> Result<usize> {
    let mut sent = 0;
    // Chaque phase relit la base : un incident ouvert puis clos avant d'avoir
    // été annoncé reçoit son ouverture, puis sa clôture, dans le même passage.
    for kind in [Kind::Open, Kind::Close, Kind::Reminder] {
        let incidents = match kind {
            Kind::Open => store.pending_opens()?,
            Kind::Close => store.pending_closes()?,
            Kind::Reminder => store.due_reminders(now)?,
        };
        let mut vulns: std::collections::BTreeMap<String, Vec<Incident>> = Default::default();
        for incident in incidents.iter().filter(|i| alert::is_vulns(i)) {
            vulns
                .entry(incident.site.clone())
                .or_default()
                .push(incident.clone());
        }
        vulns.retain(|_, list| list.len() > VULNS_GROUP_OVER);
        for (site, list) in &vulns {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                log::warn!("échéance des envois atteinte, la suite au passage suivant");
                return Ok(sent);
            }
            let url = site_url(config, site);
            let (email, marked) = match kind {
                Kind::Open => (alert::vulns_grouped_open(site, url, list), Notified::Open),
                Kind::Close => (alert::vulns_grouped_close(site, url, list), Notified::Close),
                Kind::Reminder => (
                    alert::vulns_grouped_reminder(site, url, list),
                    Notified::Reminder,
                ),
            };
            if let Err(err) = notifier.send(&email, remaining) {
                log::warn!("e-mail groupé des failles de {site} non envoyé : {err}");
                return Ok(sent);
            }
            sent += 1;
            let ids: Vec<i64> = list.iter().map(|i| i.id).collect();
            if let Err(err) = store.mark_all_notified(marked, &ids, now) {
                log::error!(
                    "{site} : e-mail groupé des failles envoyé mais non noté, il pourra repartir : {err:#}"
                );
                return Ok(sent);
            }
        }
        for incident in incidents
            .into_iter()
            .filter(|i| !(alert::is_vulns(i) && vulns.contains_key(&i.site)))
        {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                log::warn!("échéance des envois atteinte, la suite au passage suivant");
                return Ok(sent);
            }
            let url = site_url(config, &incident.site);
            let email: Email = match kind {
                Kind::Open => alert::open_email(&incident, url),
                Kind::Close => alert::close_email(&incident, url),
                Kind::Reminder => alert::reminder_email(&incident, url),
            };
            if let Err(err) = notifier.send(&email, remaining) {
                log::warn!("e-mail de l'incident {} non envoyé : {err}", incident.id);
                return Ok(sent);
            }
            sent += 1;
            match kind {
                Kind::Open => store.mark_open_notified(incident.id, now)?,
                Kind::Close => store.mark_close_notified(incident.id, now)?,
                Kind::Reminder => store.mark_reminded(incident.id, now)?,
            }
        }
    }
    Ok(sent)
}

pub(crate) fn site_url<'a>(config: &'a Config, site: &str) -> &'a str {
    config
        .sites
        .iter()
        .find(|s| s.id == site)
        .map(|s| s.url.as_str())
        .unwrap_or("site retiré de la configuration")
}

/// Résultat de `vigie check <site> --once`, contrôle par contrôle.
pub type Report = Vec<(CheckKind, Result<Vec<Finding>, CheckError>)>;

/// Tous les contrôles d'un site, sans base ni e-mail.
pub fn check_once(config: &Config, site_id: &str, options: &Options, now: i64) -> Result<Report> {
    let Some(site) = config.sites.iter().find(|s| s.id == site_id) else {
        bail!("aucun site « {site_id} » dans la configuration");
    };
    let http = Http::new(&options.trust, options.request_timeout);
    let ctx = Ctx {
        http: &http,
        trust: &options.trust,
        request_timeout: options.request_timeout,
        deadline: Instant::now() + options.check_budget,
        now,
    };
    let mut report = Vec::new();
    for kind in CheckKind::ALL.into_iter().filter(|k| k.applies(site)) {
        let result = kind.run(site, &ctx);
        let unreachable =
            matches!(&result, Ok(f) if kind == CheckKind::Content && checks::is_unreachable(f));
        report.push((kind, result));
        if unreachable {
            break;
        }
    }
    Ok(report)
}

#[cfg(test)]
mod typology_tests {
    use super::*;

    fn config(database: std::path::PathBuf, runtime: &str) -> Config {
        crate::config::parse(
            std::path::Path::new("config.toml"),
            &format!(
                "database = '{}'\n[alerts]\nto = \"a@example.org\"\nfrom = \"v@example.org\"\nsmtp_host = \"smtp.example.org\"\npassword_file = \"/x\"\n[[sites]]\nid = \"site-a\"\nurl = \"https://site-a.example.org/\"\n{runtime}",
                database.display()
            ),
        )
        .expect("configuration")
    }

    #[test]
    fn the_typology_is_written_once_per_change() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("vigie.db");
        let mut store = Store::open(&db).expect("base");
        let php = config(db.clone(), "runtime = \"php\"\n");
        record_typology(&mut store, &php, 100).expect("relevé");
        record_typology(&mut store, &php, 200).expect("inchangé");
        let (_, at) = store.meta(META_TYPOLOGY_TICK).unwrap().expect("écrite");
        assert_eq!(at, 100, "une seule écriture pour une typologie inchangée");

        let generic = config(db, "");
        record_typology(&mut store, &generic, 300).expect("changée");
        let (value, at) = store.meta(META_TYPOLOGY_TICK).unwrap().expect("écrite");
        assert_eq!(at, 300);
        let record: TypologyRecord = serde_json::from_str(&value).unwrap();
        assert_eq!(record.sites, ["site-a generic -"]);
    }
}
