//! Contrat de l'analyse de logs (`docs/logs.md`) : fixtures communes,
//! registre de sources dyn-compatible, lots bornés.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;

use jiff::tz::TimeZone;
use serde::Deserialize;

use vigie::logs::source::{Cursor, LogSource, MemorySource, SourceError};
use vigie::logs::{self, Entry, MAX_USER_AGENT, Rejection, combined};

#[derive(Deserialize)]
struct Expected {
    reference_now_ms: i64,
    files: BTreeMap<String, FileExpectation>,
}

#[derive(Deserialize)]
struct FileExpectation {
    tz: Option<String>,
    lines: usize,
    accepted: usize,
    rejected: BTreeMap<String, u64>,
}

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/logs")
}

fn read(name: &str) -> Vec<u8> {
    let raw = std::fs::read(fixtures().join(name)).expect("fixture");
    if name.ends_with(".gz") {
        let mut plain = Vec::new();
        flate2::read::GzDecoder::new(raw.as_slice())
            .read_to_end(&mut plain)
            .expect("gzip");
        plain
    } else {
        raw
    }
}

/// Ce que fera un adaptateur : découper chaque ligne, normaliser, compter.
fn parse(
    bytes: &[u8],
    tz: Option<&TimeZone>,
    now_ms: i64,
) -> (Vec<Entry>, BTreeMap<String, u64>, usize) {
    let mut entries = Vec::new();
    let mut rejected = BTreeMap::new();
    let mut lines = 0;
    for line in bytes.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
        lines += 1;
        match combined::split(line).and_then(|raw| logs::normalize(&raw, tz, now_ms)) {
            Ok(entry) => entries.push(entry),
            Err(reason) => *rejected.entry(reason.to_string()).or_insert(0) += 1,
        }
    }
    (entries, rejected, lines)
}

#[test]
fn every_fixture_gives_its_expected_counts() {
    let expected: Expected =
        serde_json::from_slice(&std::fs::read(fixtures().join("expected.json")).unwrap()).unwrap();
    let on_disk: Vec<String> = std::fs::read_dir(fixtures())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.ends_with(".log") || n.ends_with(".gz"))
        .collect();
    for name in &on_disk {
        assert!(
            expected.files.contains_key(name),
            "{name} absent de expected.json"
        );
    }
    for (name, want) in &expected.files {
        let tz = want
            .tz
            .as_deref()
            .map(|z| TimeZone::get(z).expect("fuseau"));
        let (entries, rejected, lines) = parse(&read(name), tz.as_ref(), expected.reference_now_ms);
        assert_eq!(lines, want.lines, "{name} : lignes");
        assert_eq!(entries.len(), want.accepted, "{name} : acceptées");
        assert_eq!(rejected, want.rejected, "{name} : rejets");
        for e in &entries {
            assert!(e.user_agent.len() <= MAX_USER_AGENT, "{name}");
        }
    }
}

#[test]
fn fixtures_use_documentation_addresses_only() {
    let expected: Expected =
        serde_json::from_slice(&std::fs::read(fixtures().join("expected.json")).unwrap()).unwrap();
    for (name, want) in &expected.files {
        let tz = want.tz.as_deref().map(|z| TimeZone::get(z).unwrap());
        let (entries, _, _) = parse(&read(name), tz.as_ref(), expected.reference_now_ms);
        for e in entries {
            if let Some(ip) = e.ip {
                let text = ip.to_string();
                let documentation = ["192.0.2.", "198.51.100.", "203.0.113.", "2001:db8:"]
                    .iter()
                    .any(|p| text.starts_with(p));
                assert!(documentation, "{name} : {text}");
            }
            if let Some(host) = &e.host {
                assert!(host.ends_with(".example.org"), "{name} : {host}");
            }
        }
    }
}

#[test]
fn the_cut_line_and_the_odd_user_are_read() {
    let (entries, _, _) = parse(&read("alwaysdata-advanced.log"), None, 1_792_108_800_000);
    let cut = entries.last().expect("ligne coupée");
    assert_eq!(cut.path, "/recherche");
    assert_eq!(cut.query_keys, ["q"]);
    assert_eq!(cut.user_agent.len(), MAX_USER_AGENT);
    assert_eq!(cut.duration_us, None, "la queue a été coupée");
    assert_eq!(entries[0].duration_us, Some(10_000));

    let paris = TimeZone::get("Europe/Paris").unwrap();
    let (entries, _, _) = parse(
        &read("apache-combined.log"),
        Some(&paris),
        1_792_108_800_000,
    );
    assert_eq!(entries[1].status, 401);
    assert_eq!(entries[1].ip, Some("192.0.2.41".parse().unwrap()));
    // 12:00:02 à Paris en octobre (+02:00) = 10:00:02 UTC.
    assert_eq!(entries[2].timestamp_ms, 1_792_058_402_000);
}

#[test]
fn a_one_megabyte_user_agent_still_gives_an_entry() {
    let line = format!(
        r#"site-a.example.org 192.0.2.10 - - [15/Oct/2026:14:32:10 +0200] "GET / HTTP/1.1" 200 1 "-" "{}""#,
        "x".repeat(1024 * 1024)
    );
    let (entries, rejected, _) = parse(line.as_bytes(), None, 1_792_108_800_000);
    assert!(rejected.is_empty(), "{rejected:?}");
    assert_eq!(entries[0].user_agent.len(), MAX_USER_AGENT);
    // Au-delà de MAX_LINE seulement, la ligne est rejetée.
    let huge = vec![b'x'; logs::MAX_LINE + 1];
    assert_eq!(combined::split(&huge).map(|_| ()), Err(Rejection::TooLong));
}

#[tokio::test]
async fn sources_live_in_a_dyn_registry_and_serve_bounded_batches() {
    let entries: Vec<Entry> = (0..5)
        .map(|i| Entry::new(i, format!("/{i}"), 200))
        .collect();
    let registry: Vec<Box<dyn LogSource>> = vec![
        Box::new(MemorySource::new("a", entries.clone())),
        Box::new(MemorySource::new("b", Vec::new())),
    ];
    let a = &registry[0];
    assert_eq!(a.id(), "a");
    let mut cursor = Cursor::start();
    let mut sizes = Vec::new();
    let mut seen = Vec::new();
    loop {
        let batch = a.fetch(&cursor, 2).await.expect("lot");
        sizes.push(batch.entries.len());
        seen.extend(batch.entries);
        cursor = batch.next;
        if !batch.more {
            break;
        }
    }
    assert_eq!(sizes, [2, 2, 1]);
    assert_eq!(seen, entries);

    let empty = registry[1].fetch(&Cursor::start(), 10).await.unwrap();
    assert!(empty.entries.is_empty() && !empty.more);

    let invalid = a.fetch(&Cursor("99".into()), 1).await;
    assert_eq!(
        invalid,
        Err(SourceError::CursorInvalid {
            restart: Cursor::start()
        })
    );
}

#[path = "support/veilleur.rs"]
mod veilleur;

// --- Chemin complet (#1) : lot signé → `/r/v1/logs` → base → AlwaysdataSource

mod full_path {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use tower::ServiceExt;

    use vigie::alert::MemoryNotifier;
    use vigie::checks::CheckKind;
    use vigie::clock::{Clock, FakeClock};
    use vigie::command::key::{self, DOMAIN_LOGS};
    use vigie::config::{Config, LogSourceKind, SiteLogs};
    use vigie::ingest::{HEADER_SIGNATURE, HEADER_SITE};
    use vigie::logs::alwaysdata::AlwaysdataSource;
    use vigie::logs::source::{Cursor, LogSource, SourceError};
    use vigie::serve;
    use vigie::store::Store;
    use vigie::tick::{self, Options};

    use super::{Expected, fixtures, read, veilleur};

    struct Veilleur {
        config: Config,
        clock: Arc<FakeClock>,
        key: SigningKey,
        seq: std::cell::Cell<i64>,
        _dir: tempfile::TempDir,
    }

    impl Veilleur {
        fn new(now: i64) -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let mut config = veilleur::config(dir.path().join("vigie.db"));
            config.sites[0].interval = 86_400;
            config.sites[0].logs = Some(SiteLogs {
                source: Some(LogSourceKind::Alwaysdata),
                tz: Some("Europe/Paris".into()),
                hosts: vec!["site-a.example.org".into(), "site-b.example.org".into()],
                ..SiteLogs::default()
            });
            let key = SigningKey::from_bytes(&[21; 32]);
            let mut store = Store::open(&config.database).expect("base");
            store
                .add_key("site-a", &key.verifying_key().to_bytes(), now)
                .expect("clé");
            for kind in CheckKind::ALL {
                store.record_run("site-a", kind.name(), now).expect("run");
            }
            Self {
                config,
                clock: Arc::new(FakeClock::new(now)),
                key,
                seq: std::cell::Cell::new(0),
                _dir: dir,
            }
        }

        /// Lot signé de `chunk`, comme l'agent l'enverrait.
        async fn send(&self, file: &str, start: i64, chunk: &[u8]) -> StatusCode {
            self.seq.set(self.seq.get() + 1);
            let body = serde_json::to_vec(&json!({
                "v": 1, "type": "logs", "site": "site-a", "seq": self.seq.get(),
                "sent_at": self.clock.unix(), "agent": "vigie-agent-php/0.3.0",
                "file": file, "gen": 1, "start": start, "end": start + chunk.len() as i64 + 1,
                "skipped_files": 0, "chunk": STANDARD.encode(chunk),
            }))
            .unwrap();
            let signature = key::sign(&self.key, DOMAIN_LOGS, &[&body]);
            let router = serve::router_with_clock(
                self.config.clone(),
                Arc::clone(&self.clock) as Arc<dyn Clock>,
            );
            let request = Request::post("/r/v1/logs")
                .header(HEADER_SITE, "site-a")
                .header(HEADER_SIGNATURE, signature)
                .body(Body::from(body))
                .unwrap();
            router.oneshot(request).await.unwrap().status()
        }

        fn source(&self) -> AlwaysdataSource {
            AlwaysdataSource::new("site-a", &self.config.database)
        }

        fn rejected(&self, file: &str) -> BTreeMap<String, u64> {
            let raw: String = rusqlite::Connection::open(&self.config.database)
                .unwrap()
                .query_row(
                    "SELECT rejected FROM log_batches WHERE file = ?1",
                    [file],
                    |row| row.get(0),
                )
                .unwrap();
            serde_json::from_str(&raw).unwrap()
        }
    }

    async fn drain(
        source: &dyn LogSource,
        from: &Cursor,
        max: usize,
    ) -> (Vec<vigie::logs::Entry>, Cursor) {
        let mut cursor = from.clone();
        let mut all = Vec::new();
        loop {
            let batch = source.fetch(&cursor, max).await.expect("lot");
            assert!(batch.entries.len() <= max);
            assert!(batch.rejected.is_empty());
            all.extend(batch.entries);
            cursor = batch.next;
            if !batch.more {
                return (all, cursor);
            }
        }
    }

    #[tokio::test]
    async fn every_fixture_keeps_its_counts_through_the_full_path() {
        let expected: Expected =
            serde_json::from_slice(&std::fs::read(fixtures().join("expected.json")).unwrap())
                .unwrap();
        let v = Veilleur::new(expected.reference_now_ms / 1000);
        let source = v.source();
        let mut cursor = Cursor::start();
        for (day, (name, want)) in expected.files.iter().enumerate() {
            let file = format!("http-2026-10-{:02}.log", day + 1);
            assert_eq!(
                v.send(&file, 0, &read(name)).await,
                StatusCode::NO_CONTENT,
                "{name}"
            );
            let (entries, next) = drain(&source, &cursor, 2).await;
            cursor = next;
            let rejected = v.rejected(&file);
            if name == "apache-combined.log" {
                // Sans hôte en tête : écarté à la réception (fail-closed),
                // comme l'agent l'écarte déjà.
                assert!(entries.is_empty(), "{name}");
                let host: BTreeMap<String, u64> =
                    [("host".to_owned(), want.accepted as u64)].into();
                assert_eq!(rejected, host, "{name}");
                continue;
            }
            assert_eq!(entries.len(), want.accepted, "{name} : acceptées");
            assert_eq!(rejected, want.rejected, "{name} : rejets");
        }
    }

    #[tokio::test]
    async fn the_cursor_never_serves_an_entry_twice_even_after_a_full_purge() {
        let now = 1_792_152_000; // 2026-10-16T12:00:00Z
        let v = Veilleur::new(now);
        let line = |path: &str| {
            format!(
                "site-a.example.org 192.0.2.10 - - [16/Oct/2026:11:00:00 +0000] \"GET {path} HTTP/1.1\" 200 1 \"-\" \"ua\"\n"
            )
        };
        let chunk: String = (0..5).map(|i| line(&format!("/{i}"))).collect();
        assert_eq!(
            v.send(FILE_A, 0, chunk.as_bytes()).await,
            StatusCode::NO_CONTENT
        );
        let source = v.source();
        let first = source.fetch(&Cursor::start(), 3).await.unwrap();
        assert!(first.more);
        let second = source.fetch(&first.next, 3).await.unwrap();
        assert!(!second.more);
        let paths: Vec<String> = first
            .entries
            .iter()
            .chain(&second.entries)
            .map(|e| e.path.clone())
            .collect();
        assert_eq!(paths, ["/0", "/1", "/2", "/3", "/4"]);
        let end = source.fetch(&second.next, 3).await.unwrap();
        assert!(end.entries.is_empty() && !end.more);
        assert_eq!(end.next, second.next, "curseur stable sans entrée nouvelle");

        // Purge totale (31 jours plus tard), puis un nouveau lot : l'ancien
        // curseur rend les nouvelles entrées.
        let later = now + 31 * 86_400;
        let (entries, batches) = Store::open(&v.config.database)
            .unwrap()
            .purge_logs(later)
            .unwrap();
        assert_eq!((entries, batches), (5, 1));
        v.clock.set(later);
        let fresh = "site-a.example.org 192.0.2.10 - - [16/Nov/2026:11:00:00 +0000] \"GET /neuf HTTP/1.1\" 200 1 \"-\" \"ua\"\n";
        assert_eq!(
            v.send(FILE_A, 0, fresh.as_bytes()).await,
            StatusCode::NO_CONTENT
        );
        let after = source.fetch(&second.next, 10).await.unwrap();
        assert_eq!(after.entries.len(), 1);
        assert_eq!(after.entries[0].path, "/neuf");

        let bad = source.fetch(&Cursor("pas-un-id".into()), 1).await;
        assert_eq!(
            bad,
            Err(SourceError::CursorInvalid {
                restart: Cursor::start()
            })
        );
        assert_eq!(source.id(), "alwaysdata:site-a");
    }

    const FILE_A: &str = "http-2026-10-16.log";

    #[tokio::test]
    async fn tick_at_day_31_purges_the_entries_of_day_0() {
        let now = 1_792_152_000; // jour J, 2026-10-16T12:00:00Z
        let v = Veilleur::new(now);
        let chunk = "site-a.example.org 192.0.2.10 - - [16/Oct/2026:11:00:00 +0000] \"GET / HTTP/1.1\" 200 1 \"-\" \"ua\"\n";
        assert_eq!(
            v.send(FILE_A, 0, chunk.as_bytes()).await,
            StatusCode::NO_CONTENT
        );
        let mail = MemoryNotifier::new();
        // J+30 : encore là.
        v.clock.set(now + 30 * 86_400 - 7200);
        tick::run_with(&v.config, v.clock.unix(), &Options::default(), &mail).unwrap();
        assert_eq!(drain(&v.source(), &Cursor::start(), 10).await.0.len(), 1);
        // J+31 : plus aucune entrée du jour J, ni lot, ni limite haute.
        v.clock.set(now + 31 * 86_400);
        tick::run_with(&v.config, v.clock.unix(), &Options::default(), &mail).unwrap();
        assert!(drain(&v.source(), &Cursor::start(), 10).await.0.is_empty());
        let conn = rusqlite::Connection::open(&v.config.database).unwrap();
        for table in ["log_batches", "log_marks"] {
            let n: i64 = conn
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(n, 0, "{table}");
        }
    }
}
