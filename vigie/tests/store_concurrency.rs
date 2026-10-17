//! Contention entre processus simulée par des threads : `serve`, `tick` et la
//! CLI ouvrent chacun leur connexion (`Store::open`) et écrivent en même temps.
//! Toutes les transactions d'écriture sont IMMEDIATE : elles attendent le
//! verrou (`busy_timeout`) au lieu d'échouer en SQLITE_BUSY.
//!
//! Écrivains (issue #4, audit du chemin critique) : passages de `tick`,
//! résultats et incidents, acquittements, rapports d'agent, retraits de
//! commande et lots de logs. Aucun `SQLITE_BUSY` ne remonte (chaque écriture
//! rend `Ok`), et aucune écriture n'est perdue (chaque table relue à la fin
//! porte le dernier tour de son écrivain).

use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use anyhow::{Result, ensure};
use ed25519_dalek::SigningKey;

use vigie::capability::CommandKind;
use vigie::command::key::{self as command_key, DOMAIN_PULL};
use vigie::command::pull::{self, Keys, PULL_MIN_GAP};
use vigie::config::{self, Config, Runtime};
use vigie::finding::{Finding, Severity};
use vigie::ingest::Reason;
use vigie::logs::Entry;
use vigie::store::{
    AcceptedReport, LogBatch, LogsOutcome, REPORT_MIN_GAP, ReportOutcome, RunRecord, Store,
};

/// Durée pendant laquelle chaque thread écrit en boucle.
const DURATION: Duration = Duration::from_secs(3);

/// Écrivains en parallèle.
const WRITERS: usize = 6;

/// Clé de l'agent du site A : signe les retraits ; sa clé publique vérifie
/// aussi rapports et lots.
fn agent() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

/// Entrées par lot de logs.
const ENTRIES: usize = 5;
/// Octets couverts par un lot de logs.
const SPAN: i64 = 100;

fn config(path: &std::path::Path) -> Config {
    let raw = format!(
        "database = '{}'\n[alerts]\nto = \"alertes@example.org\"\nfrom = \"vigie@example.org\"\nsmtp_host = \"smtp.example.org\"\npassword_file = '{}'\n[[sites]]\nid = \"site-a\"\nurl = \"https://site-a.example.org/\"\nruntime = \"php\"\n",
        path.display(),
        path.with_file_name("smtp-password").display()
    );
    config::parse(std::path::Path::new("config.toml"), &raw).expect("configuration")
}

/// Retrait signé de l'agent du site A, `seq` à l'instant `now`.
fn pull_request(seq: i64, now: i64) -> (Vec<u8>, String) {
    let body = serde_json::to_vec(&serde_json::json!({
        "v": 1,
        "type": "pull",
        "site": "site-a",
        "seq": seq,
        "sent_at": now,
        "nonce": pull::new_nonce(),
        "agent": "vigie-agent-php/0.4.0",
    }))
    .expect("json");
    let signature = command_key::sign(&agent(), DOMAIN_PULL, &[&body]);
    (body, signature)
}

/// Instant du retrait `round` : espacés de `PULL_MIN_GAP`.
fn pull_at(round: i64) -> i64 {
    10_000 + round * (PULL_MIN_GAP + 1)
}

/// Lot de logs `round` : plage `[(round-1)·SPAN, round·SPAN)`, `ENTRIES`
/// entrées, `seq` égal au tour.
fn accept_batch(store: &mut Store, seq: i64, round: i64, key: &[u8; 32]) -> Result<LogsOutcome> {
    let entries: Vec<Entry> = (0..ENTRIES)
        .map(|i| Entry::new(round * 1_000 + i as i64, format!("/p/{round}/{i}"), 200))
        .collect();
    store.accept_logs(
        &LogBatch {
            site: "site-a",
            pubkey: key,
            seq,
            file: "http-2026-10-17.log",
            generation: 1,
            start: (round - 1) * SPAN,
            end: round * SPAN,
            bytes: SPAN,
            skipped_files: 0,
            entries: &entries,
            rejected: "{}",
        },
        // Le plafond quotidien compte par jour : un jour par lot.
        round * 86_400,
    )
}

/// Attend que toutes les connexions soient ouvertes, puis boucle sur `step`
/// pendant `DURATION` ; rend le nombre de tours. La fenêtre ne part qu'une
/// fois toutes les connexions ouvertes : sous contention, une ouverture peut
/// attendre le verrou plusieurs secondes (`OPEN_PATIENCE`), et ce test mesure
/// les écritures, pas l'ouverture.
fn spin(start: &Barrier, mut step: impl FnMut(i64) -> Result<()>) -> Result<i64> {
    start.wait();
    let deadline = Instant::now() + DURATION;
    let mut round = 0;
    while Instant::now() < deadline {
        round += 1;
        step(round)?;
    }
    Ok(round)
}

#[test]
fn six_writers_in_parallel_raise_no_sqlite_busy_and_lose_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("vigie.db");
    let config = config(&path);
    let key = agent().verifying_key().to_bytes();
    let commands_key = SigningKey::from_bytes(&[8; 32]);
    let audit_key = SigningKey::from_bytes(&[9; 32]);
    {
        let mut store = Store::open(&path).expect("open");
        store.add_key("site-a", &key, 0).expect("add_key");
        // Une commande en file : le premier retrait la sert, et l'audit écrit.
        store
            .set_commands_enabled("site-a", true, 10_000, &audit_key)
            .expect("activation");
        let id = vigie::command::uuid_v7(10_000_000).expect("id");
        store
            .enqueue_command(
                "site-a",
                CommandKind::Ping,
                Runtime::Php,
                "{}",
                &config::typology_fingerprint(&config),
                &id,
                10_000,
                false,
                &audit_key,
            )
            .expect("file")
            .expect("en file");
    }
    let start = Arc::new(Barrier::new(WRITERS));

    // Passages de `tick`, comme le timer systemd.
    let ticks = {
        let path = path.clone();
        let start = Arc::clone(&start);
        std::thread::spawn(move || -> Result<i64> {
            let mut store = Store::open(&path)?;
            spin(&start, |round| store.record_tick(1_000 + round))
        })
    };
    // Résultats des contrôles et incidents ouverts, mis à jour, clos.
    let results = {
        let path = path.clone();
        let start = Arc::clone(&start);
        std::thread::spawn(move || -> Result<i64> {
            let mut store = Store::open(&path)?;
            spin(&start, |round| {
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
        let start = Arc::clone(&start);
        std::thread::spawn(move || -> Result<i64> {
            let mut store = Store::open(&path)?;
            spin(&start, |round| {
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
        let start = Arc::clone(&start);
        std::thread::spawn(move || -> Result<i64> {
            let mut store = Store::open(&path)?;
            spin(&start, |round| {
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
                        pubkey: &key,
                        seq: round,
                        agent: "agent-php/0.1.0",
                        facts: "{}",
                        files: "{}",
                        findings: if round % 2 == 0 { &findings } else { &[] },
                        dropped: 0,
                    },
                    round * (REPORT_MIN_GAP + 1),
                    &|_, _| true,
                )?;
                ensure!(outcome == ReportOutcome::Accepted, "rapport {outcome:?}");
                Ok(())
            })
        })
    };

    // `serve` : retraits de commande signés, un par `PULL_MIN_GAP`.
    let pulls = {
        let path = path.clone();
        let start = Arc::clone(&start);
        let config = config.clone();
        let (commands_key, audit_key) = (commands_key.clone(), audit_key.clone());
        std::thread::spawn(move || -> Result<i64> {
            let mut store = Store::open(&path)?;
            let keys = Keys {
                commands: &commands_key,
                audit: &audit_key,
            };
            spin(&start, |round| {
                let now = pull_at(round);
                let (body, signature) = pull_request(round, now);
                pull::pull(
                    &mut store,
                    &config,
                    &keys,
                    Some("site-a"),
                    Some(&signature),
                    &body,
                    Some("192.0.2.10".parse().expect("ip")),
                    now,
                )
                .map_err(|refusal| anyhow::anyhow!("{refusal}"))?;
                Ok(())
            })
        })
    };
    // `serve` : lots de logs, un renvoi à l'identique tous les trois tours.
    let batches = {
        let path = path.clone();
        let start = Arc::clone(&start);
        std::thread::spawn(move || -> Result<i64> {
            let mut store = Store::open(&path)?;
            let mut seq = 0;
            spin(&start, |round| {
                seq += 1;
                let outcome = accept_batch(&mut store, seq, round, &key)?;
                ensure!(
                    outcome == LogsOutcome::Accepted { gap: 0 },
                    "lot {outcome:?}"
                );
                if round % 3 == 0 {
                    seq += 1;
                    let outcome = accept_batch(&mut store, seq, round, &key)?;
                    ensure!(outcome == LogsOutcome::Duplicate, "renvoi {outcome:?}");
                }
                Ok(())
            })
        })
    };

    let mut rounds = std::collections::HashMap::new();
    for (name, handle) in [
        ("ticks", ticks),
        ("résultats", results),
        ("acquittements", acks),
        ("rapports", reports),
        ("retraits", pulls),
        ("lots", batches),
    ] {
        let n = handle
            .join()
            .expect("thread")
            .unwrap_or_else(|err| panic!("{name} : {err:#}"));
        assert!(n > 0, "{name} : aucun tour");
        rounds.insert(name, n);
    }

    // Aucune écriture perdue : chaque écrivain a laissé son dernier tour.
    let mut store = Store::open(&path).expect("open");
    assert_eq!(
        store.last_tick().expect("tick"),
        Some(1_000 + rounds["ticks"])
    );
    assert_eq!(
        store.last_run("site-a", "content").expect("passage"),
        Some(rounds["résultats"])
    );
    let agent_state = store.agent("site-a").expect("agent").expect("clé");
    assert_eq!(agent_state.last_seq, rounds["rapports"]);
    let entries = store
        .log_entries_after("site-a", 0, 1_000_000)
        .expect("entrées");
    assert_eq!(entries.len() as i64, rounds["lots"] * ENTRIES as i64);
    // Le dernier `seq` de retrait est en base : son rejeu est refusé, le
    // suivant passe.
    let keys = Keys {
        commands: &commands_key,
        audit: &audit_key,
    };
    let last = rounds["retraits"];
    let now = pull_at(last + 1);
    let (body, signature) = pull_request(last, now);
    let refusal = pull::pull(
        &mut store,
        &config,
        &keys,
        Some("site-a"),
        Some(&signature),
        &body,
        None,
        now,
    )
    .expect_err("rejeu");
    assert_eq!(
        refusal.reason,
        Reason::Replay {
            seq: last,
            last_seq: last
        }
    );
    let (body, signature) = pull_request(last + 1, now);
    pull::pull(
        &mut store,
        &config,
        &keys,
        Some("site-a"),
        Some(&signature),
        &body,
        None,
        now,
    )
    .expect("retrait suivant");
    let commands = store.commands("site-a").expect("commandes");
    assert!(
        commands
            .iter()
            .all(|c| c.state != vigie::command::State::Pending),
        "{commands:?}"
    );
}
