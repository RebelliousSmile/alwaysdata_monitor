//! Lots d'erreurs de bout en bout : `POST /r/v1/errors` par le routeur de
//! `serve`, jusqu'à `error_groups` (`docs/protocole-agent.md`, issue #52).
//!
//! IP des plages de documentation (RFC 5737).

use std::path::Path;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vigie::clock::{Clock, FakeClock};
use vigie::command::key::{self, DOMAIN_ERRORS, DOMAIN_INVENTORY, DOMAIN_LOGS};
use vigie::config::{Alerts, Config, Runtime, Site, SiteKind};
use vigie::ingest::{HEADER_SIGNATURE, HEADER_SITE};
use vigie::serve;
use vigie::store::Store;

/// 2026-10-16T12:00:00Z.
const T0: i64 = 1_792_152_000;
const DAY: i64 = 86_400;
const TODAY: &str = "2026-10-16";

fn site(id: &str, runtime: Option<Runtime>) -> Site {
    Site {
        id: id.into(),
        url: format!("https://{id}.example.org/"),
        kind: SiteKind::Generic,
        runtime,
        keyword_url: None,
        keyword: None,
        interval: 300,
        agent_silence: 900,
        logs: None,
        inventory: None,
        custom_checks: Vec::new(),
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
            site("site-a", Some(Runtime::Php)),
            // Pas de runtime php : la réception reste fermée.
            site("site-b", None),
        ],
    }
}

fn agent_key() -> SigningKey {
    SigningKey::from_bytes(&[13; 32])
}

struct Harness {
    config: Config,
    clock: Arc<FakeClock>,
    key: SigningKey,
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
            _dir: dir,
        }
    }

    fn store(&self) -> Store {
        Store::open(&self.config.database).expect("base")
    }

    fn raw(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(&self.config.database).expect("sqlite")
    }

    async fn post(&self, site: &str, signature: Option<&str>, body: Vec<u8>) -> StatusCode {
        let router = serve::router_with_clock(
            self.config.clone(),
            Arc::clone(&self.clock) as Arc<dyn Clock>,
        );
        let mut request = Request::post("/r/v1/errors").header(HEADER_SITE, site);
        if let Some(signature) = signature {
            request = request.header(HEADER_SIGNATURE, signature);
        }
        let response = router
            .oneshot(request.body(Body::from(body)).expect("requête"))
            .await
            .expect("réponse");
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

    /// Lot signé par `key` sous le préfixe `domain`.
    async fn send_as(
        &self,
        key: &SigningKey,
        domain: &[u8],
        site: &str,
        batch: &Value,
    ) -> StatusCode {
        let body = serde_json::to_vec(batch).expect("json");
        let signature = key::sign(key, domain, &[&body]);
        self.post(site, Some(&signature), body).await
    }

    async fn send(&self, site: &str, batch: &Value) -> StatusCode {
        self.send_as(&self.key, DOMAIN_ERRORS, site, batch).await
    }

    /// Groupes (empreinte exclue) de `site`, par jour puis message.
    fn rows(&self, site: &str) -> Vec<(String, String, i64, i64, i64)> {
        let conn = self.raw();
        let mut stmt = conn
            .prepare(
                "SELECT day, message, count, first_seen, last_seen FROM error_groups
                 WHERE site = ?1 ORDER BY day, message",
            )
            .expect("prepare");
        stmt.query_map([site], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .expect("query")
        .collect::<rusqlite::Result<_>>()
        .expect("rows")
    }

    fn last_seq(&self, site: &str) -> i64 {
        self.raw()
            .query_row(
                "SELECT last_errors_seq FROM site_keys WHERE site = ?1",
                [site],
                |row| row.get(0),
            )
            .expect("seq")
    }
}

fn group(message: &str, count: i64) -> Value {
    json!({
        "message": message, "count": count,
        "first_seen": T0 - 3600, "last_seen": T0 - 60,
    })
}

fn batch_for(site: &str, seq: i64, day: &str, groups: Vec<Value>) -> Value {
    json!({
        "v": 1, "type": "errors", "site": site, "seq": seq,
        "sent_at": T0, "agent": "vigie-agent-php/0.4.0",
        "day": day, "groups": groups,
    })
}

fn batch(seq: i64, day: &str, groups: Vec<Value>) -> Value {
    batch_for("site-a", seq, day, groups)
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
async fn a_signed_batch_is_stored_normalized_with_its_fingerprint() {
    let h = Harness::new();
    let status = h
        .send(
            "site-a",
            &batch(
                1,
                TODAY,
                vec![
                    group("Undefined array key 3", 2),
                    group("Undefined array key 42", 5),
                    group("Échec 3f2504e0-4f89-41d3-9a0c-0305e82c3301 sur la page", 1),
                ],
            ),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let rows = h.rows("site-a");
    assert_eq!(rows.len(), 2, "{rows:?}");
    // Les deux premiers groupes se confondent après renormalisation.
    let merged = rows
        .iter()
        .find(|r| r.1 == "Undefined array key #")
        .expect("groupe fusionné");
    assert_eq!(merged.2, 7);
    assert!(rows.iter().any(|r| r.1 == "Échec <uuid> sur la page"));
    let print: String = h
        .raw()
        .query_row(
            "SELECT fingerprint FROM error_groups WHERE message = 'Undefined array key #'",
            [],
            |row| row.get(0),
        )
        .expect("empreinte");
    assert_eq!(print, vigie::errors::fingerprint("Undefined array key #"));
    assert_eq!(h.last_seq("site-a"), 1);
}

#[tokio::test]
async fn an_empty_batch_is_accepted_and_clears_the_day() {
    let h = Harness::new();
    assert_eq!(
        h.send("site-a", &batch(1, TODAY, vec![group("Boom", 1)]))
            .await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(h.rows("site-a").len(), 1);
    assert_eq!(
        h.send("site-a", &batch(2, TODAY, vec![])).await,
        StatusCode::NO_CONTENT
    );
    assert!(h.rows("site-a").is_empty());
}

#[tokio::test]
async fn a_later_batch_replaces_the_day_and_leaves_other_days_alone() {
    let h = Harness::new();
    let yesterday = "2026-10-15";
    for (seq, day, message, count) in [
        (1, yesterday, "Hier", 4),
        (2, TODAY, "Avant", 1),
        (3, TODAY, "Après", 9),
    ] {
        assert_eq!(
            h.send("site-a", &batch(seq, day, vec![group(message, count)]))
                .await,
            StatusCode::NO_CONTENT
        );
    }
    let rows = h.rows("site-a");
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(
        (rows[0].0.as_str(), rows[0].1.as_str()),
        (yesterday, "Hier")
    );
    assert_eq!((rows[1].0.as_str(), rows[1].1.as_str()), (TODAY, "Après"));
    assert_eq!(rows[1].2, 9);
}

#[tokio::test]
async fn a_replayed_or_lower_seq_is_refused_and_changes_nothing() {
    let h = Harness::new();
    assert_eq!(
        h.send("site-a", &batch(5, TODAY, vec![group("Boom", 1)]))
            .await,
        StatusCode::NO_CONTENT
    );
    let before = h.rows("site-a");
    for seq in [5, 4] {
        assert_eq!(
            h.send("site-a", &batch(seq, TODAY, vec![group("Autre", 3)]))
                .await,
            StatusCode::NOT_FOUND,
            "seq {seq}"
        );
    }
    assert_eq!(h.rows("site-a"), before);
    assert_eq!(h.last_seq("site-a"), 5);
    // Le seq des erreurs est propre : celui des logs ou des rapports ne gêne pas.
    assert_eq!(
        h.send("site-a", &batch(6, TODAY, vec![])).await,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn every_failed_check_answers_the_same_silent_404() {
    let h = Harness::new();
    let good = batch(1, TODAY, vec![group("Boom", 1)]);
    let body = serde_json::to_vec(&good).unwrap();
    let signature = key::sign(&h.key, DOMAIN_ERRORS, &[&body]);

    // Site inconnu, site sans runtime php.
    assert_eq!(
        h.post("inconnu", Some(&signature), body.clone()).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        h.send("site-b", &batch_for("site-b", 1, TODAY, vec![]))
            .await,
        StatusCode::NOT_FOUND
    );
    // Sans signature, signature altérée, sans préfixe, mauvais domaine, autre clé.
    assert_eq!(
        h.post("site-a", None, body.clone()).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        h.post("site-a", Some("pas-une-signature"), body.clone())
            .await,
        StatusCode::NOT_FOUND
    );
    let bare = key::sign(&h.key, b"", &[&body]);
    assert_eq!(
        h.post("site-a", Some(&bare), body.clone()).await,
        StatusCode::NOT_FOUND
    );
    for domain in [DOMAIN_INVENTORY, DOMAIN_LOGS] {
        assert_eq!(
            h.send_as(&h.key, domain, "site-a", &good).await,
            StatusCode::NOT_FOUND
        );
    }
    let stranger = SigningKey::from_bytes(&[99; 32]);
    assert_eq!(
        h.send_as(&stranger, DOMAIN_ERRORS, "site-a", &good).await,
        StatusCode::NOT_FOUND
    );
    // Site de l'en-tête différent de celui du corps.
    assert_eq!(
        h.send("site-a", &batch_for("site-b", 1, TODAY, vec![]))
            .await,
        StatusCode::NOT_FOUND
    );
    assert!(h.rows("site-a").is_empty());
    assert_eq!(h.last_seq("site-a"), 0);
    // Le lot valide passe ensuite : aucun des refus n'a consommé le seq.
    assert_eq!(h.send("site-a", &good).await, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn an_address_or_a_control_character_refuses_the_whole_batch() {
    let h = Harness::new();
    let bad_messages = [
        "Connexion de 192.0.2.10 refusée",
        "Hôte [2001:db8::1] injoignable",
        "Hôte 2001:db8::1 injoignable",
        "Ligne un\nligne deux",
        "Tabulation\tdans le message",
        "Octet nul \u{0} dans le message",
    ];
    for (n, bad) in bad_messages.iter().enumerate() {
        let seq = n as i64 + 1;
        assert_eq!(
            h.send(
                "site-a",
                &batch(seq, TODAY, vec![group("Propre", 1), group(bad, 1)])
            )
            .await,
            StatusCode::NOT_FOUND,
            "{bad:?}"
        );
    }
    assert!(h.rows("site-a").is_empty(), "le lot est refusé en entier");
    assert_eq!(h.last_seq("site-a"), 0);
    // Sans adresse : un numéro de version ou une ligne de fichier passent.
    assert_eq!(
        h.send(
            "site-a",
            &batch(1, TODAY, vec![group("PHP 8 : Foo::bar() ligne 12", 1)])
        )
        .await,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn bounds_of_the_schema_are_enforced() {
    let h = Harness::new();
    let too_many: Vec<Value> = (0..51).map(|n| group(&letters(n), 1)).collect();
    let exactly_fifty: Vec<Value> = (0..50).map(|n| group(&letters(n), 1)).collect();
    let long = "é".repeat(201);
    let max = "é".repeat(200);
    let cases: Vec<(&str, Value)> = vec![
        ("51 groupes", batch(1, TODAY, too_many)),
        ("message vide", batch(1, TODAY, vec![group("", 1)])),
        (
            "message de 201 caractères",
            batch(1, TODAY, vec![group(&long, 1)]),
        ),
        ("count nul", batch(1, TODAY, vec![group("Boom", 0)])),
        ("count négatif", batch(1, TODAY, vec![group("Boom", -3)])),
        (
            "count trop grand",
            batch(1, TODAY, vec![group("Boom", 1_000_000_001)]),
        ),
        (
            "first_seen après last_seen",
            batch(
                1,
                TODAY,
                vec![json!({"message": "Boom", "count": 1, "first_seen": 20, "last_seen": 10})],
            ),
        ),
        ("seq nul", batch(0, TODAY, vec![])),
        ("jour mal formé", batch(1, "16/10/2026", vec![])),
        ("jour inexistant", batch(1, "2026-02-30", vec![])),
        ("jour futur", batch(1, "2026-10-17", vec![])),
        ("jour purgé", batch(1, "2026-10-02", vec![])),
        (
            "version",
            json!({"v": 2, "type": "errors", "site": "site-a", "seq": 1,
                   "sent_at": T0, "agent": "a", "day": TODAY, "groups": []}),
        ),
        (
            "type",
            json!({"v": 1, "type": "logs", "site": "site-a", "seq": 1,
                   "sent_at": T0, "agent": "a", "day": TODAY, "groups": []}),
        ),
        (
            "champ inconnu",
            json!({"v": 1, "type": "errors", "site": "site-a", "seq": 1,
                   "sent_at": T0, "agent": "a", "day": TODAY, "groups": [], "extra": 1}),
        ),
        (
            "champ inconnu dans un groupe",
            batch(
                1,
                TODAY,
                vec![json!({"message": "Boom", "count": 1, "first_seen": 1,
                            "last_seen": 2, "file": "/srv/x.php"})],
            ),
        ),
        ("agent vide", {
            let mut b = batch(1, TODAY, vec![]);
            b["agent"] = json!("");
            b
        }),
        ("horloge en avance", {
            let mut b = batch(1, TODAY, vec![]);
            b["sent_at"] = json!(T0 + 301);
            b
        }),
        ("horloge en retard", {
            let mut b = batch(1, TODAY, vec![]);
            b["sent_at"] = json!(T0 - 301);
            b
        }),
    ];
    for (name, case) in &cases {
        assert_eq!(
            h.send("site-a", case).await,
            StatusCode::NOT_FOUND,
            "{name}"
        );
    }
    assert!(h.rows("site-a").is_empty());
    assert_eq!(h.last_seq("site-a"), 0);

    // Les bornes elles-mêmes passent.
    assert_eq!(
        h.send("site-a", &batch(1, TODAY, exactly_fifty)).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(h.rows("site-a").len(), 50);
    assert_eq!(
        h.send(
            "site-a",
            &batch(2, "2026-10-03", vec![group(&max, 1_000_000_000)])
        )
        .await,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn a_body_over_64_kib_is_refused() {
    let h = Harness::new();
    let mut body = serde_json::to_vec(&batch(1, TODAY, vec![])).unwrap();
    body.extend(std::iter::repeat_n(b' ', 64 * 1024));
    let signature = key::sign(&h.key, DOMAIN_ERRORS, &[&body]);
    assert_eq!(
        h.post("site-a", Some(&signature), body).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(h.last_seq("site-a"), 0);
}

#[tokio::test]
async fn days_older_than_fourteen_are_purged_and_the_last_fourteen_kept() {
    let h = Harness::new();
    // 2026-10-03 est le plus ancien jour encore accepté à T0.
    for (seq, day) in [(1, "2026-10-03"), (2, "2026-10-04"), (3, TODAY)] {
        assert_eq!(
            h.send("site-a", &batch(seq, day, vec![group("Boom", 1)]))
                .await,
            StatusCode::NO_CONTENT
        );
    }
    let mut store = h.store();
    assert_eq!(store.purge_errors(T0).expect("purge"), 0);
    assert_eq!(h.rows("site-a").len(), 3);
    // Un jour plus tard, le 2026-10-03 sort des 14 jours.
    assert_eq!(store.purge_errors(T0 + DAY).expect("purge"), 1);
    let days: Vec<String> = h.rows("site-a").into_iter().map(|r| r.0).collect();
    assert_eq!(days, ["2026-10-04", TODAY]);
    assert_eq!(store.purge_errors(T0 + DAY).expect("purge"), 0);
}

#[tokio::test]
async fn rotating_the_key_resets_the_seq_and_drops_the_old_key() {
    let h = Harness::new();
    assert_eq!(
        h.send("site-a", &batch(7, TODAY, vec![group("Boom", 1)]))
            .await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(h.last_seq("site-a"), 7);
    let fresh = SigningKey::from_bytes(&[21; 32]);
    h.store()
        .rotate_key("site-a", &fresh.verifying_key().to_bytes(), T0)
        .expect("rotation");
    assert_eq!(h.last_seq("site-a"), 0);
    // L'ancienne clé ne signe plus rien ; la nouvelle repart de 1.
    let lot = batch(1, TODAY, vec![group("Neuf", 2)]);
    assert_eq!(h.send("site-a", &lot).await, StatusCode::NOT_FOUND);
    assert_eq!(
        h.send_as(&fresh, DOMAIN_ERRORS, "site-a", &lot).await,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn removing_a_key_removes_the_error_groups_of_the_site() {
    let h = Harness::new();
    assert_eq!(
        h.send("site-a", &batch(1, TODAY, vec![group("Boom", 1)]))
            .await,
        StatusCode::NO_CONTENT
    );
    h.store().remove_key("site-a", T0).expect("remove_key");
    assert!(h.rows("site-a").is_empty());
}

#[tokio::test]
async fn nothing_but_normalized_text_reaches_the_database() {
    let h = Harness::new();
    assert_eq!(
        h.send(
            "site-a",
            &batch(
                1,
                TODAY,
                vec![group("Requête 4821 échouée pour l'utilisateur 77", 3)]
            )
        )
        .await,
        StatusCode::NO_CONTENT
    );
    // Un lot refusé pour adresse ne laisse aucune trace de son texte.
    assert_eq!(
        h.send(
            "site-a",
            &batch(
                2,
                TODAY,
                vec![group("Connexion de 198.51.100.7 refusée", 1)]
            )
        )
        .await,
        StatusCode::NOT_FOUND
    );
    let dump = dump(&h.raw());
    assert!(
        dump.contains("Requête # échouée pour l'utilisateur #"),
        "{dump}"
    );
    for secret in ["4821", "198.51.100.7", "192.0.2."] {
        assert!(!dump.contains(secret), "{secret} en base");
    }
}

/// Message distinct par rang, sans chiffre : la normalisation ne les confond pas.
fn letters(n: u8) -> String {
    format!(
        "Message {}{}",
        (b'a' + n / 26) as char,
        (b'a' + n % 26) as char
    )
}
