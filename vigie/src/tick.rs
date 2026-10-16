//! `vigie tick` : passage lancé chaque minute par `vigie-tick.timer`.
//!
//! 1. enregistre le passage, que `/health` surveille ;
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
use crate::config::{Config, Site};
use crate::finding::Finding;
use crate::http::{Http, REQUEST_TIMEOUT, Trust};
use crate::store::{AGENT_PREFIX, RunRecord, Store};

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

pub fn run_with(
    config: &Config,
    now: i64,
    options: &Options,
    notifier: &dyn Notifier,
) -> Result<Summary> {
    let start = Instant::now();
    let mut store = Store::open(&config.database)?;
    store.record_tick(now)?;
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
