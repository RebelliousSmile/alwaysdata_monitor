//! Contention entre processus simulée par des threads : `serve`, `tick` et la
//! CLI ouvrent chacun leur connexion (`Store::open`) et écrivent en même temps.
//! Toutes les transactions d'écriture sont IMMEDIATE : elles attendent le
//! verrou (`busy_timeout`) au lieu d'échouer en SQLITE_BUSY.

use std::time::{Duration, Instant};

use anyhow::{Result, ensure};

use vigie::finding::{Finding, Severity};
use vigie::store::{AcceptedReport, REPORT_MIN_GAP, ReportOutcome, RunRecord, Store};

/// Durée pendant laquelle chaque thread écrit en boucle.
const DURATION: Duration = Duration::from_secs(3);

const KEY: [u8; 32] = [7; 32];

/// Boucle sur `step` jusqu'à l'échéance ; rend le nombre de tours.
fn spin(deadline: Instant, mut step: impl FnMut(i64) -> Result<()>) -> Result<i64> {
    let mut round = 0;
    while Instant::now() < deadline {
        round += 1;
        step(round)?;
    }
    Ok(round)
}

#[test]
fn four_connections_write_in_parallel_without_sqlite_busy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("vigie.db");
    Store::open(&path)
        .expect("open")
        .add_key("site-a", &KEY, 0)
        .expect("add_key");
    let deadline = Instant::now() + DURATION;

    // Passages de `tick`, comme le timer systemd.
    let ticks = {
        let path = path.clone();
        std::thread::spawn(move || -> Result<i64> {
            let mut store = Store::open(&path)?;
            spin(deadline, |round| store.record_tick(1_000 + round))
        })
    };
    // Résultats des contrôles et incidents ouverts, mis à jour, clos.
    let results = {
        let path = path.clone();
        std::thread::spawn(move || -> Result<i64> {
            let mut store = Store::open(&path)?;
            spin(deadline, |round| {
                let finding = Finding::new(
                    "site-a",
                    "content",
                    Severity::Warning,
                    "mot-clé",
                    "mot-clé absent",
                );
                let findings = if round % 2 == 0 {
                    vec![finding]
                } else {
                    vec![]
                };
                let record = RunRecord::concluded(&findings);
                store.record_result("site-a", "content", round, &record)?;
                store.reconcile("site-a", "content", &findings, round)
            })
        })
    };
    // La CLI ou la console acquittent un incident ouvert, puis il se clôt.
    let acks = {
        let path = path.clone();
        std::thread::spawn(move || -> Result<i64> {
            let mut store = Store::open(&path)?;
            spin(deadline, |round| {
                let finding = Finding::new(
                    "site-b",
                    "exposed",
                    Severity::Critical,
                    ".env",
                    ".env servi",
                );
                store.reconcile("site-b", "exposed", &[finding], round)?;
                let open = store.open_incidents()?;
                if let Some(incident) = open.iter().find(|i| i.site == "site-b") {
                    store.ack(incident.id, round)?;
                    store.mark_open_notified(incident.id, round)?;
                }
                store.reconcile("site-b", "exposed", &[], round)
            })
        })
    };
    // Rapports d'agent : chacun espacé du précédent de `REPORT_MIN_GAP`.
    let reports = {
        let path = path.clone();
        std::thread::spawn(move || -> Result<i64> {
            let mut store = Store::open(&path)?;
            spin(deadline, |round| {
                let findings = [Finding::new(
                    "site-a",
                    "agent:php",
                    Severity::Critical,
                    "display_errors",
                    "display_errors activé",
                )];
                let outcome = store.accept_report(
                    &AcceptedReport {
                        site: "site-a",
                        pubkey: &KEY,
                        seq: round,
                        agent: "agent-php/0.1.0",
                        facts: "{}",
                        files: "{}",
                        findings: if round % 2 == 0 { &findings } else { &[] },
                    },
                    round * (REPORT_MIN_GAP + 1),
                )?;
                ensure!(outcome == ReportOutcome::Accepted, "rapport {outcome:?}");
                Ok(())
            })
        })
    };

    for (name, handle) in [
        ("ticks", ticks),
        ("résultats", results),
        ("acquittements", acks),
        ("rapports", reports),
    ] {
        let rounds = handle
            .join()
            .expect("thread")
            .unwrap_or_else(|err| panic!("{name} : {err:#}"));
        assert!(rounds > 0, "{name} : aucun tour");
    }
}
