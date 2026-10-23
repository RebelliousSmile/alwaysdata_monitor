//! Lots de logs de bout en bout : `POST /r/v1/logs` par le routeur de `serve`,
//! jusqu'à `log_entries` (`docs/logs.md`, issue #1).

use std::path::Path;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vigie::clock::{Clock, FakeClock};
use vigie::command::key::{self, DOMAIN_LOGS};
use vigie::config::{Alerts, Config, LogSourceKind, Site, SiteKind, SiteLogs};
use vigie::ingest::{HEADER_SIGNATURE, HEADER_SITE};
use vigie::logs::receive::{MAX_DAILY_BYTES, MAX_RANGE};
use vigie::serve;
use vigie::store::{KeyOutcome, Store};

/// 2026-10-16T12:00:00Z.
const T0: i64 = 1_792_152_000;
const FILE: &str = "http-2026-10-16.log";

fn site(id: &str, logs: Option<SiteLogs>) -> Site {
    Site {
        id: id.into(),
        url: format!("https://{id}.example.org/"),
        kind: SiteKind::Generic,
        runtime: None,
        keyword_url: None,
        keyword: None,
        interval: 300,
        agent_silence: 900,
        logs,
        inventory: None,
        custom_checks: Vec::new(),
    }
}

fn alwaysdata(hosts: &[&str]) -> SiteLogs {
    SiteLogs {
        source: Some(LogSourceKind::Alwaysdata),
        hosts: hosts.iter().map(|h| (*h).to_owned()).collect(),
        ..SiteLogs::default()
    }
}

fn config(dir: &Path) -> Config {
    Config {
        database: dir.join("vigie.db"),
        api: None,
        commands: None,
        logs: Default::default(),
        vulns: None,
        alerts: Alerts {
            to: "alertes@example.org".into(),
            from: "vigie@example.org".into(),
            smtp_host: "smtp.example.org".into(),
            smtp_port: 587,
            smtp_user: None,
            password_file: dir.join("smtp-password"),
        },
        sites: vec![
            site("site-a", Some(alwaysdata(&["site-a.example.org"]))),
            // Section d'analyse sans source : la réception reste fermée.
            site(
                "site-b",
                Some(SiteLogs {
                    behind_proxy: true,
                    ..SiteLogs::default()
                }),
            ),
        ],
    }
}

fn agent_key() -> SigningKey {
    SigningKey::from_bytes(&[11; 32])
}

struct Harness {
    config: Config,
    clock: Arc<FakeClock>,
    key: SigningKey,
    seq: std::cell::Cell<i64>,
    _dir: tempfile::TempDir,
}

impl Harness {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());
        let key = agent_key();
        let mut store = Store::open(&config.database).expect("base");
        for id in ["site-a", "site-b"] {
            store
                .add_key(id, &key.verifying_key().to_bytes(), T0)
                .expect("add_key");
        }
        Self {
            config,
            clock: Arc::new(FakeClock::new(T0)),
            key,
            seq: std::cell::Cell::new(0),
            _dir: dir,
        }
    }

    fn store(&self) -> Store {
        Store::open(&self.config.database).expect("base")
    }

    fn next_seq(&self) -> i64 {
        self.seq.set(self.seq.get() + 1);
        self.seq.get()
    }

    async fn post(&self, uri: &str, site: &str, signature: &str, body: Vec<u8>) -> StatusCode {
        let router = serve::router_with_clock(
            self.config.clone(),
            Arc::clone(&self.clock) as Arc<dyn Clock>,
        );
        let request = Request::post(uri)
            .header(HEADER_SITE, site)
            .header(HEADER_SIGNATURE, signature)
            .body(Body::from(body))
            .expect("requête");
        let response = router.oneshot(request).await.expect("réponse");
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("corps")
            .to_bytes();
        assert!(body.is_empty(), "404 et 204 sans corps");
        status
    }

    /// Lot signé par la clé de l'agent avec le préfixe des logs.
    async fn send(&self, site: &str, batch: &Value) -> StatusCode {
        let body = serde_json::to_vec(batch).expect("json");
        let signature = key::sign(&self.key, DOMAIN_LOGS, &[&body]);
        self.post("/r/v1/logs", site, &signature, body).await
    }

    /// Lot de `site-a` sur `FILE`, `seq` suivant.
    fn batch(&self, generation: i64, start: i64, end: i64, chunk: &[u8]) -> Value {
        json!({
            "v": 1, "type": "logs", "site": "site-a", "seq": self.next_seq(),
            "sent_at": self.clock.unix(), "agent": "vigie-agent-php/0.3.0",
            "file": FILE, "gen": generation, "start": start, "end": end,
            "skipped_files": 0, "chunk": STANDARD.encode(chunk),
        })
    }

    fn entries(&self, site: &str) -> Vec<vigie::logs::Entry> {
        self.store()
            .log_entries_after(site, 0, 10_000)
            .expect("lecture")
            .into_iter()
            .map(|(_, e)| e)
            .collect()
    }

    fn raw(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(&self.config.database).expect("sqlite")
    }
}

fn line(path: &str, minute: u32) -> String {
    format!(
        "site-a.example.org 192.0.2.10 - - [16/Oct/2026:11:{minute:02}:00 +0000] \"GET {path} HTTP/1.1\" 200 512 \"-\" \"Mozilla/5.0\"\n"
    )
}

fn three_lines() -> Vec<u8> {
    [
        line("/", 1),
        line("/compte?token=secret&page=2", 2),
        line("/style.css", 3),
    ]
    .concat()
    .into_bytes()
}

/// Toutes les valeurs de toutes les tables, en texte.
fn dump(conn: &rusqlite::Connection) -> String {
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let mut out = String::new();
    for table in tables {
        let mut stmt = conn.prepare(&format!("SELECT * FROM \"{table}\"")).unwrap();
        let columns = stmt.column_count();
        let mut rows = stmt.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            for i in 0..columns {
                let value: rusqlite::types::Value = row.get(i).unwrap();
                out.push_str(&format!("{value:?}|"));
            }
            out.push('\n');
        }
    }
    out
}

#[tokio::test]
async fn a_signed_batch_of_three_lines_gives_three_entries_without_query_values() {
    let h = Harness::new();
    let chunk = three_lines();
    let status = h
        .send("site-a", &h.batch(1, 0, chunk.len() as i64, &chunk))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let entries = h.entries("site-a");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[1].path, "/compte");
    assert_eq!(entries[1].query_keys, ["token", "page"]);
    assert_eq!(entries[1].host.as_deref(), Some("site-a.example.org"));
    // Ni la valeur, ni la ligne brute, nulle part en base.
    let dump = dump(&h.raw());
    assert!(!dump.contains("secret"), "{dump}");
    assert!(!dump.contains("Oct/2026"), "ligne brute écrite : {dump}");
    // Un lot ne vaut ni rapport ni preuve de vie.
    let agent = h.store().agent("site-a").unwrap().unwrap();
    assert_eq!(agent.last_valid_at, None);
}

#[tokio::test]
async fn a_resent_batch_counts_once_and_the_next_one_follows() {
    let h = Harness::new();
    let chunk = three_lines();
    let end = chunk.len() as i64;
    assert_eq!(
        h.send("site-a", &h.batch(1, 0, end, &chunk)).await,
        StatusCode::NO_CONTENT
    );
    // Réponse perdue : l'agent renvoie la même plage, avec un seq plus grand.
    assert_eq!(
        h.send("site-a", &h.batch(1, 0, end, &chunk)).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(h.entries("site-a").len(), 3);
    // Puis le lot suivant, qui commence à la limite haute.
    let more = [line("/a", 4), line("/b", 5)].concat().into_bytes();
    let next_end = end + more.len() as i64;
    assert_eq!(
        h.send("site-a", &h.batch(1, end, next_end, &more)).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(h.entries("site-a").len(), 5);
    // Le doublon a bien avancé le seq : le rejouer tel quel est refusé.
    let mut replay = h.batch(1, 0, end, &chunk);
    replay["seq"] = json!(1);
    assert_eq!(h.send("site-a", &replay).await, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_overlapping_batch_is_refused_and_writes_nothing() {
    let h = Harness::new();
    let chunk = three_lines();
    let end = chunk.len() as i64;
    h.send("site-a", &h.batch(1, 0, end, &chunk)).await;
    let overlap = h.batch(1, 10, end + 100, &chunk);
    let overlap_seq = overlap["seq"].as_i64().unwrap();
    assert_eq!(h.send("site-a", &overlap).await, StatusCode::NOT_FOUND);
    assert_eq!(h.entries("site-a").len(), 3);
    // Rien d'écrit, seq compris : le même seq passe encore.
    let mut next = h.batch(1, end, end + 50, b"");
    next["seq"] = json!(overlap_seq);
    assert_eq!(h.send("site-a", &next).await, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn a_new_generation_starts_at_zero_and_a_gap_is_admitted() {
    let h = Harness::new();
    let chunk = three_lines();
    let end = chunk.len() as i64;
    h.send("site-a", &h.batch(1, 0, end, &chunk)).await;
    // Fichier remplacé : génération suivante, depuis 0.
    assert_eq!(
        h.send("site-a", &h.batch(2, 0, end, &chunk)).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(h.entries("site-a").len(), 6);
    // Un trou est admis et compté.
    assert_eq!(
        h.send("site-a", &h.batch(2, end + 1000, end + 2000, b""))
            .await,
        StatusCode::NO_CONTENT
    );
    let gap: i64 = h
        .raw()
        .query_row(
            "SELECT gap FROM log_batches ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(gap, 1000);
}

#[tokio::test]
async fn an_empty_chunk_moves_the_high_mark() {
    let h = Harness::new();
    assert_eq!(
        h.send("site-a", &h.batch(1, 0, 4096, b"")).await,
        StatusCode::NO_CONTENT
    );
    assert!(h.entries("site-a").is_empty());
    // La plage est couverte : un renvoi est un doublon, un lot à cheval est refusé.
    assert_eq!(
        h.send("site-a", &h.batch(1, 0, 4096, b"")).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        h.send("site-a", &h.batch(1, 100, 5000, b"")).await,
        StatusCode::NOT_FOUND
    );
    let batches: i64 = h
        .raw()
        .query_row("SELECT count(*) FROM log_batches", [], |row| row.get(0))
        .unwrap();
    assert_eq!(batches, 1);
}

#[tokio::test]
async fn hostile_bytes_are_counted_without_panic() {
    let h = Harness::new();
    let mut state: u64 = 0x5eed_0001;
    let mut chunk = Vec::new();
    for _ in 0..8000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        chunk.push((state & 0xff) as u8);
    }
    chunk.extend_from_slice(b"\nsite-a.example.org 192.0.2.10 - - [16/Oct/2026:11:00:00 +0000] \"GET /\xff\xfe HTTP/1.1\" 200 1 \"-\" \"\xc3(\"\n");
    chunk.extend_from_slice(&line("/", 9).into_bytes());
    chunk.extend_from_slice(b"site-b.example.org 192.0.2.11 - - [16/Oct/2026:11:00:00 +0000] \"GET / HTTP/1.1\" 200 1 \"-\" \"ua\"\n");
    let end = chunk.len() as i64;
    assert_eq!(
        h.send("site-a", &h.batch(1, 0, end, &chunk)).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(h.entries("site-a").len(), 2);
    let (accepted, rejected): (i64, String) = h
        .raw()
        .query_row("SELECT accepted, rejected FROM log_batches", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    assert_eq!(accepted, 2);
    let rejected: std::collections::BTreeMap<String, u64> =
        serde_json::from_str(&rejected).unwrap();
    assert_eq!(rejected.get("host"), Some(&1), "{rejected:?}");
    assert!(
        rejected.get("malformed").is_some_and(|&n| n > 0),
        "{rejected:?}"
    );
}

#[tokio::test]
async fn a_site_without_a_log_source_is_refused() {
    let h = Harness::new();
    let chunk = three_lines();
    let mut batch = h.batch(1, 0, chunk.len() as i64, &chunk);
    batch["site"] = json!("site-b");
    assert_eq!(h.send("site-b", &batch).await, StatusCode::NOT_FOUND);
    // Site absent de la configuration.
    batch["site"] = json!("site-c");
    assert_eq!(h.send("site-c", &batch).await, StatusCode::NOT_FOUND);
    assert!(h.entries("site-b").is_empty());
}

#[tokio::test]
async fn a_signature_only_holds_for_its_own_endpoint() {
    let h = Harness::new();
    // Rapport signé (sans préfixe) envoyé sur /r/v1/logs.
    let report = serde_json::to_vec(&json!({
        "v": 1, "site": "site-a", "seq": 1, "sent_at": T0,
        "agent": "vigie-agent-php/0.3.0", "findings": [], "facts": {},
    }))
    .unwrap();
    let raw = STANDARD.encode(h.key.sign(&report).to_bytes());
    assert_eq!(
        h.post("/r/v1/logs", "site-a", &raw, report.clone()).await,
        StatusCode::NOT_FOUND
    );
    // Le même rapport passe sur son propre point d'entrée.
    assert_eq!(
        h.post("/r/v1/report", "site-a", &raw, report).await,
        StatusCode::NO_CONTENT
    );
    // Lot de logs signé avec son préfixe, envoyé sur /r/v1/report.
    let chunk = three_lines();
    let batch = serde_json::to_vec(&h.batch(1, 0, chunk.len() as i64, &chunk)).unwrap();
    let prefixed = key::sign(&h.key, DOMAIN_LOGS, &[&batch]);
    h.clock.advance(61);
    assert_eq!(
        h.post("/r/v1/report", "site-a", &prefixed, batch.clone())
            .await,
        StatusCode::NOT_FOUND
    );
    // Et le lot signé sans préfixe est refusé sur /r/v1/logs.
    let unprefixed = STANDARD.encode(h.key.sign(&batch).to_bytes());
    assert_eq!(
        h.post("/r/v1/logs", "site-a", &unprefixed, batch).await,
        StatusCode::NOT_FOUND
    );
    assert!(h.entries("site-a").is_empty());
}

#[tokio::test]
async fn a_44_kib_batch_stays_under_64_kb_and_is_accepted() {
    let h = Harness::new();
    let mut chunk = Vec::new();
    let mut minute = 0;
    while chunk.len() + 200 <= 44 * 1024 {
        chunk.extend_from_slice(line(&format!("/page-{minute}"), minute % 60).as_bytes());
        minute += 1;
    }
    let pad = 44 * 1024 - chunk.len();
    chunk.extend_from_slice(&vec![b'#'; pad - 1]);
    chunk.push(b'\n');
    assert_eq!(chunk.len(), 44 * 1024);
    let batch = h.batch(1, 0, chunk.len() as i64 + 10, &chunk);
    let body = serde_json::to_vec(&batch).unwrap();
    assert!(body.len() < serve::MAX_REPORT_BYTES, "{}", body.len());
    assert_eq!(h.send("site-a", &batch).await, StatusCode::NO_CONTENT);
    assert_eq!(h.entries("site-a").len(), minute as usize);
}

#[tokio::test]
async fn the_daily_cap_refuses_further_batches() {
    let h = Harness::new();
    h.raw()
        .execute(
            "INSERT INTO log_batches (site, file, gen, range_start, range_end, bytes, gap,
               skipped_files, received_at, accepted, rejected)
             VALUES ('site-a', 'http-2026-10-15.log', 1, 0, 1, ?1, 0, 0, ?2, 0, '{}')",
            rusqlite::params![MAX_DAILY_BYTES - 10, T0 - 60],
        )
        .unwrap();
    let chunk = three_lines();
    let end = chunk.len() as i64;
    assert_eq!(
        h.send("site-a", &h.batch(1, 0, end, &chunk)).await,
        StatusCode::NOT_FOUND
    );
    assert!(h.entries("site-a").is_empty());
    // Le lendemain (UTC), le plafond repart.
    h.clock.set(T0 + 43_200);
    assert_eq!(
        h.send("site-a", &h.batch(1, 0, end, &chunk)).await,
        StatusCode::NO_CONTENT
    );
}

/// Modification d'un lot valide qui doit le faire refuser.
type Alteration = Box<dyn Fn(&mut Value)>;

#[tokio::test]
async fn malformed_batches_are_refused() {
    let h = Harness::new();
    let chunk = three_lines();
    let end = chunk.len() as i64;
    let cases: Vec<(&str, Alteration)> = vec![
        ("champ inconnu", Box::new(|b| b["extra"] = json!(1))),
        ("type", Box::new(|b| b["type"] = json!("report"))),
        (
            "chemin",
            Box::new(|b| b["file"] = json!("../http-2026-10-16.log")),
        ),
        (
            "gz",
            Box::new(|b| b["file"] = json!("http-2026-10-16.log.gz")),
        ),
        ("plage vide", Box::new(move |b| b["start"] = json!(end))),
        ("chunk trop long", Box::new(|b| b["end"] = json!(10))),
        (
            "plage de plus de 4 Mio",
            Box::new(|b| b["end"] = json!(MAX_RANGE + 1)),
        ),
        (
            "base64",
            Box::new(|b| b["chunk"] = json!("pas du base64 !")),
        ),
        ("horloge", Box::new(|b| b["sent_at"] = json!(T0 - 301))),
        ("site", Box::new(|b| b["site"] = json!("site-b"))),
    ];
    for (name, alter) in cases {
        let mut batch = h.batch(1, 0, end, &chunk);
        alter(&mut batch);
        assert_eq!(
            h.send("site-a", &batch).await,
            StatusCode::NOT_FOUND,
            "{name}"
        );
    }
    assert!(h.entries("site-a").is_empty());
    // Une plage de 4 Mio pile est admise.
    assert_eq!(
        h.send("site-a", &h.batch(1, 0, MAX_RANGE, &chunk)).await,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn rotate_key_resets_the_logs_seq_and_remove_purges_the_logs() {
    let h = Harness::new();
    let chunk = three_lines();
    let end = chunk.len() as i64;
    let mut batch = h.batch(1, 0, end, &chunk);
    batch["seq"] = json!(1_000);
    assert_eq!(h.send("site-a", &batch).await, StatusCode::NO_CONTENT);

    // Nouvelle clé : la séquence des lots repart de zéro.
    let new_key = SigningKey::from_bytes(&[12; 32]);
    assert_eq!(
        h.store()
            .rotate_key("site-a", &new_key.verifying_key().to_bytes(), T0)
            .unwrap(),
        KeyOutcome::Done
    );
    let mut h = h;
    h.key = new_key;
    let mut next = h.batch(1, end, end + 10, b"");
    next["seq"] = json!(1);
    assert_eq!(h.send("site-a", &next).await, StatusCode::NO_CONTENT);

    assert!(h.store().remove_key("site-a", 0).unwrap());
    let raw = h.raw();
    for table in ["log_entries", "log_batches", "log_marks"] {
        let n: i64 = raw
            .query_row(
                &format!("SELECT count(*) FROM {table} WHERE site = 'site-a'"),
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(n, 0, "{table}");
    }
}
