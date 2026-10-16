//! `vigie tick` : passage lancé chaque minute par `vigie-tick.timer`.
//!
//! 1. enregistre le passage, que `/health` surveille, et purge les logs
//!    reçus de plus de 30 jours (`docs/logs.md`) ;
//! 2. lance les contrôles dus, les sites les plus en retard d'abord, sans
//!    commencer de requête après 40 s ;
//! 3. ouvre ou clôt le silence de chaque agent déclaré ;
//! 4. réconcilie les incidents, puis envoie les e-mails en attente (ouvertures,
//!    clôtures, rappels) jusqu'à 50 s, y compris ceux des rapports d'agent
//!    acceptés par `serve`. Ce qui n'a pas pu partir reste en attente pour le
//!    passage suivant.

use std::time::{Duration, Instant};

use anyhow::{Result, bail};

use crate::alert::{self, Email, Notifier, SmtpNotifier};
use crate::checks::{self, CheckError, CheckKind, Ctx, heartbeat};
use crate::config::{Config, Site, TypologyRecord};
use crate::finding::Finding;
use crate::http::{Http, REQUEST_TIMEOUT, Trust};
use crate::store::{AGENT_PREFIX, META_TYPOLOGY_TICK, RunRecord, Store};

#[derive(Debug, Clone)]
pub struct Options {
    pub trust: Trust,
    pub request_timeout: Duration,
    /// Aucune requête de contrôle ne commence au-delà.
    pub check_budget: Duration,
    /// Aucun envoi ne commence au-delà, depuis le début du passage.
    pub send_budget: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            trust: Trust::WebPki,
            request_timeout: REQUEST_TIMEOUT,
            check_budget: Duration::from_secs(40),
            send_budget: Duration::from_secs(50),
        }
    }
}

/// Bilan d'un passage, pour le journal et les tests.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Summary {
    pub checks_run: usize,
    pub inconclusive: usize,
    pub emails_sent: usize,
    pub emails_pending: usize,
}

pub fn run(config: &Config, now: i64) -> Result<()> {
    let notifier = SmtpNotifier::new(config.alerts.clone());
    let summary = run_with(config, now, &Options::default(), &notifier)?;
    log::info!(
        "tick : {} contrôle(s), {} non concluant(s), {} e-mail(s) envoyé(s), {} en attente",
        summary.checks_run,
        summary.inconclusive,
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

    // Silence des agents : seuls les sites de la configuration qui ont une clé.
    let agents = store.agents()?;
    for site in &config.sites {
        if let Some(agent) = agents.iter().find(|a| a.site == site.id) {
            let findings = heartbeat::evaluate(site, agent, now);
            store.record_result(
                &site.id,
                heartbeat::NAME,
                now,
                &RunRecord::concluded(&findings),
            )?;
            store.reconcile(&site.id, heartbeat::NAME, &findings, now)?;
        }
    }

    let closed = store.close_unwatched(
        |site_id, check| {
            let Some(site) = config.sites.iter().find(|s| s.id == site_id) else {
                return false;
            };
            if check == heartbeat::NAME || check.starts_with(AGENT_PREFIX) {
                return agents.iter().any(|a| a.site == site_id);
            }
            CheckKind::ALL
                .into_iter()
                .any(|kind| kind.applies(site) && kind.name() == check)
        },
        now,
    )?;
    if closed > 0 {
        log::info!("{closed} incident(s) clos : contrôle ou agent retiré de la configuration");
    }

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

/// Envoie dans l'ordre ouvertures, clôtures, rappels. S'arrête au premier
/// échec : le relais est sans doute en panne, inutile d'insister.
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
        for incident in incidents {
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

fn site_url<'a>(config: &'a Config, site: &str) -> &'a str {
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
