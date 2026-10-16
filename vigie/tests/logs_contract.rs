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
