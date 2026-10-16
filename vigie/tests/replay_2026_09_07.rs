//! Reprise de l'incident du 2026-09-07 sur le site A : `wp-config.php` absent,
//! installeur `setup-config.php` servi avec son formulaire, page surveillée
//! sans son mot-clé.
//!
//! Le veilleur voit l'incident par deux canaux : l'agent (constat
//! `critical-file`) et les contrôles externes (`content` et `installer`). Pour
//! chaque décalage d'une minute entre l'injection et le prochain passage de
//! chaque canal, le test simule 15 min de passages `tick` chaque minute et
//! relève le premier e-mail. L'heure est logique : `tick::run_with` et
//! `ingest::ingest` la reçoivent en argument, rien n'attend vraiment.
//!
//! Le site servi est celui de `support/incident_site.rs`, que la reprise
//! locale réelle (`examples/replay_local.rs`) sert aussi.

#[path = "support/incident_site.rs"]
mod incident_site;

use std::path::Path;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};

use incident_site::{IncidentSite, Mode};
use vigie::alert::{Email, MemoryNotifier};
use vigie::config::{Alerts, Config, Site, SiteKind};
use vigie::http::Trust;
use vigie::ingest;
use vigie::store::Store;
use vigie::tick::{self, Options};

/// Instant arbitraire : seuls les écarts comptent.
const T0: i64 = 1_800_000_000;
const MINUTE: i64 = 60;
/// Période de l'agent et `interval` du site, comme en production.
const PERIOD: i64 = 300;
/// Durée simulée après l'injection.
const HORIZON: i64 = 15 * MINUTE;
/// Promesse de réception : une alerte moins de 10 min après l'incident.
const PROMISE: i64 = 10 * MINUTE;
/// Le rapport arrive juste après le passage `tick` (et après l'injection) :
/// il attend le suivant, c'est le pire cas.
const AFTER_TICK: i64 = 1;

const CRITICAL: [&str; 5] = [
    "wp-config.php",
    ".htaccess",
    ".user.ini",
    "wordfence-waf.php",
    "index.php",
];

const AGENT_KEY: &str = "site-a/agent:critical-file/wp-config.php";
const EXTERNAL_KEYS: [&str; 2] = [
    "site-a/content/keyword",
    "site-a/installer/wp-admin/setup-config.php",
];

fn options(site: &IncidentSite) -> Options {
    Options {
        trust: Trust::Custom(vec![site.ca.clone()]),
        request_timeout: Duration::from_secs(5),
        ..Options::default()
    }
}

fn config(dir: &Path, base: &str) -> Config {
    Config {
        database: dir.join("vigie.db"),
        api: None,
        alerts: Alerts {
            to: "alertes@example.org".into(),
            from: "vigie@example.org".into(),
            smtp_host: "smtp.example.org".into(),
            smtp_port: 587,
            smtp_user: None,
            password_file: dir.join("smtp-password"),
        },
        sites: vec![Site {
            id: "site-a".into(),
            url: format!("{base}/"),
            kind: SiteKind::Wordpress,
            runtime: None,
            keyword_url: Some(format!("{base}/kb/")),
            keyword: Some("/problemes/".into()),
            interval: PERIOD.unsigned_abs(),
            agent_silence: 900,
        }],
    }
}

/// Rapport de l'agent PHP, dans la forme de `vigie-agent.php`.
fn report(seq: i64, sent_at: i64, incident: bool) -> Value {
    let findings = if incident {
        json!([{
            "check": "critical-file",
            "severity": "critical",
            "key": "wp-config.php",
            "detail": "Fichier critique absent : wp-config.php"
        }])
    } else {
        json!([])
    };
    let files: serde_json::Map<_, _> = CRITICAL
        .iter()
        .map(|path| {
            let hash = if incident && *path == "wp-config.php" {
                Value::Null
            } else {
                json!(format!("{:0>64}", path.len()))
            };
            ((*path).to_owned(), hash)
        })
        .collect();
    json!({
        "v": 1,
        "site": "site-a",
        "seq": seq,
        "sent_at": sent_at,
        "agent": "agent-php/0.1.0",
        "findings": findings,
        "facts": {"php_version": "8.3.12", "wp_version": "6.8.3"},
        "files": files
    })
}

/// Canal d'un e-mail d'ouverture, d'après la ligne « Contrôle : » du corps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Channel {
    Agent,
    External,
}

fn channel(email: &Email) -> Channel {
    if email.body.contains("Contrôle : agent:") {
        Channel::Agent
    } else {
        Channel::External
    }
}

/// Premier e-mail, en secondes après l'injection, au total et par canal.
#[derive(Debug, Clone, Copy)]
struct Delays {
    first: i64,
    agent: i64,
    external: i64,
}

/// Rejoue l'incident, injecté juste après le passage `tick` de l'instant
/// `grid`. Le premier rapport de l'agent qui le porte part `agent_phase`
/// minutes plus tard, juste après un passage ; le premier contrôle externe
/// qui le voit tombe au passage `external_phase + 1` minutes après `grid`.
///
/// `tick` tourne chaque minute du début à la fin, comme sous systemd : seul
/// le premier passage fixe l'échéancier des contrôles externes.
fn replay(site: &IncidentSite, agent_phase: i64, external_phase: i64) -> Delays {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = config(dir.path(), &site.base());
    let options = options(site);
    let mail = MemoryNotifier::new();
    let key = SigningKey::from_bytes(&[7; 32]);
    let grid = T0 + 2 * 86_400;
    let injected = grid + 1;
    let first_external = grid + (external_phase + 1) * MINUTE;
    let first_report = injected + AFTER_TICK + agent_phase * MINUTE;
    // Deux périodes saines avant : la référence des empreintes est posée et
    // tls et headers sont faits pour la journée.
    let first_tick = first_external - 2 * PERIOD;
    let mut next_report = first_report - 2 * PERIOD;

    site.set(Mode::Healthy);
    let mut store = Store::open(&config.database).expect("base");
    store
        .add_key(
            "site-a",
            &key.verifying_key().to_bytes(),
            first_tick.min(next_report) - MINUTE,
        )
        .expect("add_key");
    let mut seq = 0;
    let mut send = |at: i64| {
        seq += 1;
        let body = serde_json::to_vec(&report(seq, at, at > injected)).expect("json");
        let signature = STANDARD.encode(key.sign(&body).to_bytes());
        ingest::ingest(
            &mut store,
            &["site-a".into()],
            Some("site-a"),
            Some(&signature),
            &body,
            at,
        )
        .expect("rapport accepté");
    };

    let (mut agent, mut external) = (None, None);
    let mut opened: Vec<String> = Vec::new();
    let mut now = first_tick;
    while now <= grid + HORIZON {
        while next_report < now {
            send(next_report);
            next_report += PERIOD;
        }
        if now > injected {
            site.set(Mode::Incident);
        }
        tick::run_with(&config, now, &options, &mail).expect("tick");
        for email in mail.take() {
            assert!(
                now > injected,
                "aucun e-mail avant l'injection (phases {agent_phase}/{external_phase}) : {email:?}"
            );
            assert!(
                !email.subject.contains("rétabli") && !email.subject.contains("toujours"),
                "seules des ouvertures pendant l'incident : {email:?}"
            );
            let delay = now - injected;
            match channel(&email) {
                Channel::Agent => agent = agent.or(Some(delay)),
                Channel::External => external = external.or(Some(delay)),
            }
            opened.push(email.subject);
        }
        now += MINUTE;
    }

    let store = Store::open(&config.database).expect("base");
    let open: Vec<_> = store
        .open_incidents()
        .expect("incidents")
        .into_iter()
        .map(|i| i.key)
        .collect();
    for key in EXTERNAL_KEYS.iter().chain([&AGENT_KEY]) {
        assert!(open.iter().any(|k| k == key), "{key} absent de {open:?}");
    }
    // Un e-mail par incident ouvert, aucun doublon.
    assert_eq!(opened.len(), open.len(), "{opened:#?} pour {open:?}");

    let agent = agent.expect("e-mail de l'agent");
    let external = external.expect("e-mail des contrôles externes");
    Delays {
        first: agent.min(external),
        agent,
        external,
    }
}

#[test]
fn every_phase_alerts_within_ten_minutes_on_each_channel() {
    let site = IncidentSite::start(0);
    let phases = 0..PERIOD / MINUTE;
    let mut cases = Vec::new();
    for agent_phase in phases.clone() {
        for external_phase in phases.clone() {
            cases.push((
                agent_phase,
                external_phase,
                replay(&site, agent_phase, external_phase),
            ));
        }
    }
    let worst = |delay: fn(&Delays) -> i64| {
        cases
            .iter()
            .max_by_key(|(_, _, d)| delay(d))
            .map(|&(a, e, d)| (a, e, delay(&d)))
            .expect("au moins un cas")
    };
    for (name, delay) in [
        ("premier e-mail", (|d| d.first) as fn(&Delays) -> i64),
        ("canal agent seul", |d| d.agent),
        ("canal externe seul", |d| d.external),
    ] {
        let (a, e, seconds) = worst(delay);
        println!(
            "{} cas, pire {name} : {seconds} s (agent à +{a} min, externe à +{} min)",
            cases.len(),
            e + 1
        );
    }
    let failures: Vec<_> = cases
        .iter()
        .filter(|(_, _, d)| d.agent >= PROMISE || d.external >= PROMISE)
        .collect();
    assert!(
        failures.is_empty(),
        "promesse de {PROMISE} s non tenue : {failures:#?}"
    );
}
