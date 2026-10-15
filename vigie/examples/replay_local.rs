//! Moitié « veilleur » de la reprise locale réelle, lancée par
//! `scripts/replay-incident.mjs` : sert le site A en HTTPS local et passe
//! `tick` chaque minute.
//!
//! Ce n'est pas le binaire `vigie` : un exemple Cargo, absent du build de
//! production. `vigie tick` fait confiance aux seules autorités publiques et
//! envoie par SMTP STARTTLS ; ici le passage est le même `tick::run_with`, mais
//! avec l'autorité de test du site local et des e-mails écrits sur la sortie
//! standard, une ligne `MAIL {json}` chacun.
//!
//! Le site passe en état d'incident dès que le fichier `--incident-flag`
//! existe, vérifié avant chaque passage : seuls les passages l'interrogent.
//!
//! cargo run --example replay_local -- --config <config.toml> --port <port> --incident-flag <fichier>

#[path = "../tests/support/incident_site.rs"]
mod incident_site;

use std::io::Write;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use serde_json::json;

use incident_site::{IncidentSite, Mode};
use vigie::alert::{Email, Notifier};
use vigie::http::Trust;
use vigie::tick::{self, Options};
use vigie::{config, now};

/// Période du timer systemd.
const TICK: Duration = Duration::from_secs(60);

struct StdoutNotifier;

impl Notifier for StdoutNotifier {
    fn send(&self, email: &Email, _timeout: Duration) -> Result<(), String> {
        let line = json!({"at": now(), "subject": email.subject, "body": email.body});
        let mut out = std::io::stdout().lock();
        writeln!(out, "MAIL {line}")
            .and_then(|()| out.flush())
            .map_err(|err| format!("sortie standard : {err}"))
    }
}

struct Args {
    config: PathBuf,
    port: u16,
    incident_flag: PathBuf,
}

fn args() -> anyhow::Result<Args> {
    let mut config = None;
    let mut port = None;
    let mut flag = None;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let value = it
            .next()
            .with_context(|| format!("{arg} : valeur attendue"))?;
        match arg.as_str() {
            "--config" => config = Some(PathBuf::from(value)),
            "--port" => port = Some(value.parse().context("--port")?),
            "--incident-flag" => flag = Some(PathBuf::from(value)),
            _ => bail!("option inconnue : {arg}"),
        }
    }
    Ok(Args {
        config: config.context("--config manquant")?,
        port: port.context("--port manquant")?,
        incident_flag: flag.context("--incident-flag manquant")?,
    })
}

fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = args()?;
    let config = config::load(&args.config)?;
    let site = IncidentSite::start(args.port);
    let options = Options {
        trust: Trust::Custom(vec![site.ca.clone()]),
        ..Options::default()
    };
    println!("READY {}", json!({"base": site.base()}));
    std::io::stdout().flush()?;
    loop {
        let start = Instant::now();
        let mode = if args.incident_flag.exists() {
            Mode::Incident
        } else {
            Mode::Healthy
        };
        site.set(mode);
        let at = now();
        match tick::run_with(&config, at, &options, &StdoutNotifier) {
            Ok(summary) => println!(
                "TICK {}",
                json!({
                    "at": at,
                    "incident": mode == Mode::Incident,
                    "checks": summary.checks_run,
                    "inconclusive": summary.inconclusive,
                    "sent": summary.emails_sent,
                    "pending": summary.emails_pending,
                })
            ),
            Err(err) => println!("TICK {}", json!({"at": at, "error": format!("{err:#}")})),
        }
        std::io::stdout().flush()?;
        thread::sleep(TICK.saturating_sub(start.elapsed()));
    }
}
