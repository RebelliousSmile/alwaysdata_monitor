//! Inventaire de bout en bout côté veilleur : `POST /r/v1/inventory` par le
//! routeur de `serve`, jusqu'à `site_inventory` et ses lectures pour F7
//! (issue #19, phase 1). Inventaires signés par une clé Rust, BOM fictifs de
//! `fixtures/inventory/`.

use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vigie::clock::{Clock, FakeClock};
use vigie::command::key::{self, DOMAIN_INVENTORY};
use vigie::config::{Alerts, Config, InventorySource, Runtime, Site, SiteInventory, SiteKind};
use vigie::ingest::{HEADER_SIGNATURE, HEADER_SITE};
use vigie::inventory::{MAX_INVENTORY_BYTES, Scope, Source, bom};
use vigie::serve;
use vigie::store::{InventoryHead, Store};
use vigie::vulns::purl::PurlType;

/// 2026-10-16T12:00:00Z.
const T0: i64 = 1_792_152_000;
const SITE_A: &str = include_str!("fixtures/inventory/site-a-wordpress.json");
const SITE_B: &str = include_str!("fixtures/inventory/site-b-prestashop.json");

// --- Journal capturé -------------------------------------------------------

static LINES: Mutex<Vec<String>> = Mutex::new(Vec::new());

struct Capture;

impl log::Log for Capture {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        LINES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(record.args().to_string());
    }

    fn flush(&self) {}
}

/// Lignes du journal de tous les tests de ce fichier, depuis le début.
fn journal() -> Vec<String> {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        log::set_boxed_logger(Box::new(Capture)).expect("logger");
        log::set_max_level(log::LevelFilter::Info);
    });
    LINES.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

// --- Veilleur de test ------------------------------------------------------

fn site(id: &str, kind: SiteKind, inventory: bool) -> Site {
    Site {
        id: id.into(),
        url: format!("https://{id}.example.org/"),
        kind,
        runtime: (kind == SiteKind::Generic).then_some(Runtime::Php),
        keyword_url: None,
        keyword: None,
        interval: 300,
        agent_silence: 900,
        logs: None,
        inventory: inventory.then(|| SiteInventory::new(&[InventorySource::AgentPhp])),
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
            site("site-a", SiteKind::Wordpress, true),
            site("site-b", SiteKind::Prestashop, true),
            // Clé, mais pas de [sites.inventory] : réception fermée.
            site("site-c", SiteKind::Wordpress, false),
            // [sites.inventory], mais pas de clé.
            site("site-d", SiteKind::Generic, true),
        ],
    }
}

fn agent_key() -> SigningKey {
    SigningKey::from_bytes(&[19; 32])
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
        Self::at(T0)
    }

    fn at(now: i64) -> Self {
        // Journal capturé dès le premier envoi.
        journal();
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());
        let key = agent_key();
        Store::open(&config.database).expect("base");
        // Une même clé pour les trois sites, posée en base comme dans une base
        // d'avant #20 : `add_key` refuse désormais une clé déjà enregistrée.
        let raw = rusqlite::Connection::open(&config.database).expect("sqlite");
        for id in ["site-a", "site-b", "site-c"] {
            raw.execute(
                "INSERT INTO site_keys (site, pubkey, added_at) VALUES (?1, ?2, ?3)",
                rusqlite::params![id, key.verifying_key().to_bytes().as_slice(), now - 600],
            )
            .expect("clé");
        }
        Self {
            config,
            clock: Arc::new(FakeClock::new(now)),
            key,
            seq: std::cell::Cell::new(0),
            _dir: dir,
        }
    }

    fn store(&self) -> Store {
        Store::open(&self.config.database).expect("base")
    }

    fn reader(&self) -> Store {
        Store::open_read(&self.config.database)
            .expect("lecture")
            .expect("base")
    }

    fn raw(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(&self.config.database).expect("sqlite")
    }

    fn count(&self, sql: &str) -> i64 {
        self.raw().query_row(sql, [], |row| row.get(0)).expect(sql)
    }

    fn router(&self) -> axum::Router {
        serve::router_with_clock(
            self.config.clone(),
            Arc::clone(&self.clock) as Arc<dyn Clock>,
        )
    }

    async fn post(&self, uri: &str, site: &str, signature: &str, body: Vec<u8>) -> StatusCode {
        let request = Request::post(uri)
            .header(HEADER_SITE, site)
            .header(HEADER_SIGNATURE, signature)
            .body(Body::from(body))
            .expect("requête");
        let response = self.router().oneshot(request).await.expect("réponse");
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

    /// Inventaire signé par la clé de l'agent sous le domaine des inventaires.
    async fn send(&self, doc: &Value) -> StatusCode {
        let body = serde_json::to_vec(doc).expect("json");
        let signature = key::sign(&self.key, DOMAIN_INVENTORY, &[&body]);
        let site = doc["site"].as_str().unwrap_or("site-a").to_owned();
        self.post("/r/v1/inventory", &site, &signature, body).await
    }

    /// Fixture du site, `seq` suivant et heure courante.
    fn doc(&self, fixture: &str) -> Value {
        let mut doc: Value = serde_json::from_str(fixture).expect("fixture");
        self.seq.set(self.seq.get() + 1);
        doc["seq"] = json!(self.seq.get());
        doc["sent_at"] = json!(self.clock.unix());
        doc["bom"]["metadata"]["timestamp"] = json!(iso(self.clock.unix()));
        doc
    }

    fn site_a(&self) -> Value {
        self.doc(SITE_A)
    }

    fn last(&self, site: &str) -> InventoryHead {
        self.reader()
            .last_inventory(site, Source::Agent)
            .expect("lecture")
            .expect("inventaire")
    }

    /// purl des composants du dernier inventaire du site, dans l'ordre lu.
    fn purls(&self, site: &str) -> Vec<String> {
        let id = self.last(site).id;
        self.reader()
            .inventory_components(id, 0, 10_000)
            .expect("composants")
            .into_iter()
            .map(|c| c.purl)
            .collect()
    }

    fn dropped(&self, site: &str) -> i64 {
        self.raw()
            .query_row(
                "SELECT dropped FROM site_inventory WHERE site = ?1 ORDER BY id DESC LIMIT 1",
                [site],
                |row| row.get(0),
            )
            .expect("dropped")
    }
}

/// Sites dont la source `agent` est déclarée, pour `purge_inventory`.
fn agent_sources(sites: &[&str]) -> Vec<(String, Source)> {
    sites
        .iter()
        .map(|s| ((*s).to_owned(), Source::Agent))
        .collect()
}

fn iso(secs: i64) -> String {
    vigie::iso_utc(secs)
}

fn component(purl: &str, version: &str, path: &str, scope: &str) -> Value {
    let excluded = scope == "dev";
    json!({
        "type": "library", "name": "exemple", "version": version, "purl": purl,
        "scope": if excluded { "excluded" } else { "required" },
        "properties": [
            {"name": "vigie:path", "value": path},
            {"name": "vigie:scope", "value": scope},
        ],
    })
}

fn components(doc: &mut Value) -> &mut Vec<Value> {
    doc["bom"]["components"].as_array_mut().expect("components")
}

// --- Parcours nominal --------------------------------------------------------

#[tokio::test]
async fn an_inventory_is_stored_resent_unchanged_then_replaced() {
    let h = Harness::new();
    assert_eq!(h.send(&h.site_a()).await, StatusCode::NO_CONTENT);
    assert_eq!(h.count("SELECT count(*) FROM site_inventory"), 1);
    let first = h.last("site-a");
    assert_eq!(
        (first.complete, first.seen_at, first.received_at),
        (true, T0, T0)
    );
    assert_eq!(first.agent, "vigie-agent-php/0.5.0");
    let rows = h
        .reader()
        .inventory_components(first.id, 0, 100)
        .expect("composants");
    assert_eq!(rows.len(), 12);
    // Ordre canonique (purl, path), sans doublon.
    let mut sorted: Vec<(String, String)> = rows
        .iter()
        .map(|r| (r.purl.clone(), r.path.clone()))
        .collect();
    sorted.sort();
    assert_eq!(
        rows.iter()
            .map(|r| (r.purl.clone(), r.path.clone()))
            .collect::<Vec<_>>(),
        sorted
    );
    let core = rows
        .iter()
        .find(|r| r.base == "pkg:wordpress/core/core")
        .expect("cœur");
    assert_eq!(core.version.as_deref(), Some("6.6.2"));
    assert_eq!(core.ecosystem, PurlType::Wordpress);
    // Version vide : composant gardé, purl sans @, version None.
    let bare = rows
        .iter()
        .find(|r| r.name == "exemple-sans-version")
        .expect("sans version");
    assert_eq!(bare.purl, "pkg:wordpress/plugin/exemple-sans-version");
    assert_eq!(bare.version, None);
    assert_eq!(bare.path, "wp-content/plugins/exemple-sans-version");
    let mu = rows.iter().find(|r| r.name == "exemple-mu").expect("mu");
    assert_eq!(mu.scope, Scope::Mu);
    let dev = rows
        .iter()
        .find(|r| r.name == "exemple/outil-test")
        .expect("dev");
    assert_eq!(
        (dev.scope, dev.path.as_str()),
        (Scope::Dev, "composer.lock")
    );

    // Même contenu 300 s plus tard, composants permutés, autre serialNumber :
    // une seule ligne, seen_at avancé.
    h.clock.advance(300);
    let mut doc = h.site_a();
    components(&mut doc).reverse();
    doc["bom"]["serialNumber"] = json!("urn:uuid:00000000-0000-4000-8000-000000000001");
    assert_eq!(h.send(&doc).await, StatusCode::NO_CONTENT);
    assert_eq!(h.count("SELECT count(*) FROM site_inventory"), 1);
    let resent = h.last("site-a");
    assert_eq!((resent.id, resent.seen_at), (first.id, T0 + 300));
    assert_eq!(resent.received_at, T0);

    // Une version change : un second inventaire, le dernier est le nouveau.
    h.clock.advance(300);
    let mut doc = h.site_a();
    components(&mut doc)[1]["version"] = json!("5.9.4");
    components(&mut doc)[1]["purl"] = json!("pkg:wordpress/plugin/exemple-formulaire@5.9.4");
    assert_eq!(h.send(&doc).await, StatusCode::NO_CONTENT);
    let history = h
        .reader()
        .inventory_history("site-a", Source::Agent)
        .expect("historique");
    assert_eq!(history.len(), 2);
    assert!(history[0].id > history[1].id, "plus récent d'abord");
    assert_eq!(history[0], h.last("site-a"));
    assert_eq!(
        (history[0].seen_at, history[0].received_at),
        (T0 + 600, T0 + 600)
    );
    assert!(
        h.purls("site-a")
            .contains(&"pkg:wordpress/plugin/exemple-formulaire@5.9.4".to_owned())
    );

    // Pas une preuve de vie : ni rapport, ni incident.
    let agent = h.store().agent("site-a").expect("agent").expect("clé");
    assert_eq!((agent.last_seq, agent.last_valid_at), (0, None));
    assert!(h.store().open_incidents().expect("incidents").is_empty());
    // Le journal d'une acceptation ne contient aucun purl ni nom reçu.
    let lines = journal();
    assert!(
        lines
            .iter()
            .any(|l| l.contains("inventaire accepté (site site-a")
                && l.contains("12 composant(s)")
                && l.contains("nouveau"))
    );
    assert!(lines.iter().any(|l| l.contains("inchangé")));
    for line in &lines {
        assert!(!line.contains("pkg:"), "{line}");
        assert!(!line.contains("exemple-formulaire"), "{line}");
    }
}

#[tokio::test]
async fn heads_list_the_last_inventory_of_each_site_without_reading_components() {
    let h = Harness::new();
    assert_eq!(h.send(&h.site_a()).await, StatusCode::NO_CONTENT);
    assert_eq!(h.send(&h.doc(SITE_B)).await, StatusCode::NO_CONTENT);
    h.clock.advance(300);
    let mut doc = h.site_a();
    components(&mut doc).pop();
    assert_eq!(h.send(&doc).await, StatusCode::NO_CONTENT);

    let heads = h.reader().inventory_heads().expect("têtes");
    assert_eq!(
        heads.iter().map(|h| h.site.as_str()).collect::<Vec<_>>(),
        ["site-a", "site-b"]
    );
    assert_eq!(heads[0], h.last("site-a"));
    assert_eq!(heads[1], h.last("site-b"));
    assert_eq!(
        h.reader()
            .last_inventory("site-c", Source::Agent)
            .expect("lecture"),
        None
    );
    assert!(
        h.reader()
            .inventory_history("site-c", Source::Agent)
            .expect("lecture")
            .is_empty()
    );

    // Une requête sur site_inventory seule.
    let raw = h.raw();
    let mut stmt = raw
        .prepare(
            "EXPLAIN QUERY PLAN SELECT site, id, complete, seen_at, received_at, agent
             FROM site_inventory WHERE id IN (SELECT max(id) FROM site_inventory GROUP BY site)
             ORDER BY site",
        )
        .expect("plan");
    let plan: Vec<String> = stmt
        .query_map([], |row| row.get(3))
        .expect("plan")
        .collect::<rusqlite::Result<_>>()
        .expect("plan");
    let plan = plan.join(" ; ");
    assert!(!plan.contains("site_inventory_components"), "{plan}");

    // PrestaShop : config-version gardée, modules en pkg:prestashop.
    let config_version: String = raw
        .query_row(
            "SELECT config_version FROM site_inventory_components WHERE name = 'exemplemodule'",
            [],
            |row| row.get(0),
        )
        .expect("config_version");
    assert_eq!(config_version, "1.1.0");
}

#[tokio::test]
async fn components_are_read_in_resumable_batches() {
    let h = Harness::new();
    let mut doc = h.site_a();
    let list = components(&mut doc);
    list.clear();
    // Ordre d'envoi mélangé : la lecture rend l'ordre canonique.
    for i in (0..1201).rev() {
        list.push(component(
            &format!("pkg:composer/exemple/paquet-{i:04}@1.0.0"),
            "1.0.0",
            "composer.lock",
            "required",
        ));
    }
    assert_eq!(h.send(&doc).await, StatusCode::NO_CONTENT);
    let id = h.last("site-a").id;
    for store in [h.store(), h.reader()] {
        let mut after = 0;
        let mut sizes = Vec::new();
        let mut all = Vec::new();
        loop {
            let batch = store.inventory_components(id, after, 500).expect("lot");
            if batch.is_empty() {
                break;
            }
            sizes.push(batch.len());
            after = batch.last().expect("dernier").rowid;
            all.extend(batch.into_iter().map(|c| c.purl));
        }
        assert_eq!(sizes, [500, 500, 201]);
        let expected: Vec<String> = (0..1201)
            .map(|i| format!("pkg:composer/exemple/paquet-{i:04}@1.0.0"))
            .collect();
        assert_eq!(all, expected);
        assert!(
            store
                .inventory_components(id + 99, 0, 500)
                .expect("inconnu")
                .is_empty()
        );
    }
}

// --- Porte et signatures -----------------------------------------------------

/// Requête brute sur un vrai socket : en-têtes, un morceau de corps, puis
/// rien. Rend la ligne de statut reçue dans `wait`, ou `None`.
async fn stalled_request(addr: std::net::SocketAddr, site: &str, wait: Duration) -> Option<String> {
    use std::io::{Read, Write};
    let head = format!(
        "POST /r/v1/inventory HTTP/1.1\r\nHost: vigie.invalid\r\n{HEADER_SITE}: {site}\r\n\
         {HEADER_SIGNATURE}: AAAA\r\nTransfer-Encoding: chunked\r\n\r\n10\r\n0123456789abcdef\r\n"
    );
    tokio::task::spawn_blocking(move || {
        let mut stream = std::net::TcpStream::connect(addr).expect("connexion");
        stream.set_read_timeout(Some(wait)).expect("délai");
        stream.write_all(head.as_bytes()).expect("envoi");
        let mut buffer = vec![0u8; 256];
        match stream.read(&mut buffer) {
            Ok(n) if n > 0 => Some(
                String::from_utf8_lossy(&buffer[..n])
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_owned(),
            ),
            _ => None,
        }
    })
    .await
    .expect("tâche")
}

#[tokio::test]
async fn a_closed_unknown_or_keyless_site_is_refused_before_reading_the_body() {
    let h = Harness::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("écoute");
    let addr = listener.local_addr().expect("adresse");
    let router = h.router();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    for site in ["site-c", "site-z", "site-d", "Site-A"] {
        let status = stalled_request(addr, site, Duration::from_secs(3)).await;
        assert_eq!(
            status.as_deref(),
            Some("HTTP/1.1 404 Not Found"),
            "{site} : refus immédiat, corps jamais attendu"
        );
    }
    // Site ouvert : le corps est attendu (refus seulement après 10 s).
    assert_eq!(
        stalled_request(addr, "site-a", Duration::from_millis(800)).await,
        None
    );
    // Corps annoncé de 10 Mio sur un site fermé : refusé par la porte.
    let status = h
        .post(
            "/r/v1/inventory",
            "site-c",
            "AAAA",
            vec![b' '; 10 * 1024 * 1024],
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        journal()
            .iter()
            .any(|l| l.contains("inventaire : rapport refusé (site site-c)")
                && l.contains("[sites.inventory] absent"))
    );
}

#[tokio::test]
async fn signatures_are_bound_to_the_inventory_route() {
    let h = Harness::new();
    let doc = h.site_a();
    let body = serde_json::to_vec(&doc).expect("json");
    // Sans préfixe (comme un rapport) ou sous un autre des six domaines.
    let unprefixed = key::sign(&h.key, b"", &[&body]);
    assert_eq!(
        h.post("/r/v1/inventory", "site-a", &unprefixed, body.clone())
            .await,
        StatusCode::NOT_FOUND
    );
    for domain in [
        key::DOMAIN_PULL,
        key::DOMAIN_LOGS,
        key::DOMAIN_COMMANDS,
        key::DOMAIN_AUDIT,
        key::DOMAIN_ROTATE,
    ] {
        let signature = key::sign(&h.key, domain, &[&body]);
        assert_eq!(
            h.post("/r/v1/inventory", "site-a", &signature, body.clone())
                .await,
            StatusCode::NOT_FOUND
        );
    }
    // Inventaire bien signé, envoyé ailleurs.
    let signature = key::sign(&h.key, DOMAIN_INVENTORY, &[&body]);
    for route in ["/r/v1/report", "/r/v1/logs", "/r/v1/errors"] {
        assert_eq!(
            h.post(route, "site-a", &signature, body.clone()).await,
            StatusCode::NOT_FOUND,
            "{route}"
        );
    }
    // Un vrai rapport signé envoyé sur /r/v1/inventory.
    let report = serde_json::to_vec(&json!({
        "v": 1, "site": "site-a", "seq": 1, "sent_at": T0,
        "agent": "vigie-agent-php/0.5.0", "findings": [], "facts": {}, "files": {},
    }))
    .expect("json");
    let report_sig = key::sign(&h.key, b"", &[&report]);
    assert_eq!(
        h.post("/r/v1/inventory", "site-a", &report_sig, report.clone())
            .await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        h.post("/r/v1/report", "site-a", &report_sig, report).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(h.count("SELECT count(*) FROM site_inventory"), 0);
    // Le bon : accepté.
    assert_eq!(
        h.post("/r/v1/inventory", "site-a", &signature, body).await,
        StatusCode::NO_CONTENT
    );
}

// --- Séquence, débit, plafond, horloge ---------------------------------------

#[tokio::test]
async fn replay_rate_and_clock_are_enforced() {
    let h = Harness::new();
    let first = h.site_a();
    assert_eq!(h.send(&first).await, StatusCode::NO_CONTENT);
    // Moins de 240 s : refusé, même avec un contenu différent.
    h.clock.advance(239);
    let mut doc = h.site_a();
    components(&mut doc).pop();
    assert_eq!(h.send(&doc).await, StatusCode::NOT_FOUND);
    h.clock.advance(1);
    // seq rejoué ou plus petit.
    let mut replay = h.site_a();
    replay["seq"] = first["seq"].clone();
    assert_eq!(h.send(&replay).await, StatusCode::NOT_FOUND);
    // Horloge : 301 s d'écart.
    let mut late = h.site_a();
    late["sent_at"] = json!(h.clock.unix() - 301);
    assert_eq!(h.send(&late).await, StatusCode::NOT_FOUND);
    let mut early = h.site_a();
    early["sent_at"] = json!(h.clock.unix() + 301);
    assert_eq!(h.send(&early).await, StatusCode::NOT_FOUND);
    let mut doc = h.site_a();
    components(&mut doc).pop();
    assert_eq!(h.send(&doc).await, StatusCode::NO_CONTENT);
    assert_eq!(h.count("SELECT count(*) FROM site_inventory"), 2);
}

#[tokio::test]
async fn at_most_24_new_inventories_per_utc_day() {
    // 2026-10-17T01:00:00Z.
    let h = Harness::at(1_792_198_800);
    let send_version = |n: usize| {
        let mut doc = h.site_a();
        components(&mut doc)[2]["version"] = json!(format!("2.1.{n}"));
        components(&mut doc)[2]["purl"] =
            json!(format!("pkg:wordpress/plugin/exemple-cache@2.1.{n}"));
        doc
    };
    for n in 0..24 {
        assert_eq!(
            h.send(&send_version(n)).await,
            StatusCode::NO_CONTENT,
            "{n}"
        );
        h.clock.advance(241);
    }
    assert_eq!(h.send(&send_version(99)).await, StatusCode::NOT_FOUND);
    assert!(
        journal()
            .iter()
            .any(|l| l.contains("plafond quotidien des inventaires"))
    );
    // Un renvoi inchangé reste accepté.
    assert_eq!(h.send(&send_version(23)).await, StatusCode::NO_CONTENT);
    assert_eq!(h.count("SELECT count(*) FROM site_inventory"), 24);
    // Le lendemain UTC : accepté.
    h.clock.set(1_792_285_200 + 60);
    assert_eq!(h.send(&send_version(99)).await, StatusCode::NO_CONTENT);
    assert_eq!(h.count("SELECT count(*) FROM site_inventory"), 25);
}

// --- Liste blanche -----------------------------------------------------------

#[tokio::test]
async fn any_field_or_property_outside_the_whitelist_refuses_the_document() {
    let h = Harness::new();
    let mut variants: Vec<(&str, Value)> = Vec::new();
    for field in ["authors", "supplier", "licenses", "hashes", "bom-ref"] {
        let mut doc = h.site_a();
        components(&mut doc)[3][field] = json!("secret-xyz");
        variants.push((field, doc));
    }
    let mut doc = h.site_a();
    doc["bom"]["authors"] = json!([{"name": "secret-xyz"}]);
    variants.push(("bom.authors", doc));
    let mut doc = h.site_a();
    doc["bom"]["metadata"]["supplier"] = json!({"name": "secret-xyz"});
    variants.push(("metadata.supplier", doc));
    let mut doc = h.site_a();
    doc["extra"] = json!("secret-xyz");
    variants.push(("enveloppe", doc));
    let mut doc = h.site_a();
    components(&mut doc)[0]["properties"]
        .as_array_mut()
        .expect("properties")
        .push(json!({"name": "secret-xyz", "value": "1"}));
    variants.push(("propriété", doc));
    let mut doc = h.site_a();
    components(&mut doc)[0]["properties"]
        .as_array_mut()
        .expect("properties")
        .push(json!({"name": "vigie:path", "value": "secret-xyz"}));
    variants.push(("propriété en double", doc));
    let mut doc = h.site_a();
    doc["bom"]["specVersion"] = json!("1.5");
    variants.push(("1.5", doc));
    let mut doc = h.site_a();
    doc["bom"]["specVersion"] = json!("1.8");
    variants.push(("1.8", doc));
    let mut doc = h.site_a();
    doc["bom"]["metadata"]["component"]["name"] = json!("site-b");
    variants.push(("metadata.component.name", doc));
    let mut doc = h.site_a();
    doc["bom"]["serialNumber"] = json!("urn:uuid:secret-xyz");
    variants.push(("serialNumber", doc));
    let mut doc = h.site_a();
    doc["bom"]["metadata"]["timestamp"] = json!(iso(T0 - 31 * 86_400));
    variants.push(("timestamp", doc));
    let mut doc = h.site_a();
    doc["bom"]["bomFormat"] = json!("SPDX");
    variants.push(("bomFormat", doc));
    let mut doc = h.site_a();
    doc["complete"] = json!("secret-xyz");
    variants.push(("complete", doc));
    let mut doc = h.site_a();
    doc["skipped"] = json!(100_001);
    variants.push(("skipped", doc));
    let mut doc = h.site_a();
    let template = components(&mut doc)[8].clone();
    components(&mut doc).clear();
    for i in 0..2001 {
        let mut c = template.clone();
        c["purl"] = json!(format!("pkg:composer/exemple/p{i}@1.0.0"));
        components(&mut doc).push(c);
    }
    variants.push(("2 001 composants", doc));
    for (why, doc) in &variants {
        assert_eq!(h.send(doc).await, StatusCode::NOT_FOUND, "{why}");
    }
    // JSON illisible.
    let body = b"{\"v\":1,,\"secret-xyz\"}".to_vec();
    let signature = key::sign(&h.key, DOMAIN_INVENTORY, &[&body]);
    assert_eq!(
        h.post("/r/v1/inventory", "site-a", &signature, body).await,
        StatusCode::NOT_FOUND
    );
    // Corps de 512 Kio + 1 octet.
    let body = vec![b' '; MAX_INVENTORY_BYTES + 1];
    let signature = key::sign(&h.key, DOMAIN_INVENTORY, &[&body]);
    assert_eq!(
        h.post("/r/v1/inventory", "site-a", &signature, body).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(h.count("SELECT count(*) FROM site_inventory"), 0);

    // Raisons fixes au journal, sans aucun octet reçu.
    let lines = journal();
    for line in &lines {
        assert!(!line.contains("secret-xyz"), "{line}");
    }
    for reason in [
        "schéma : champ hors liste blanche",
        "schéma : propriété hors liste blanche",
        "schéma : propriété en double",
        "schéma : specVersion : 1.6 ou 1.7",
        "schéma : JSON illisible",
        "schéma : plus de 2 000 composants",
        "corps de plus de 512 Kio",
    ] {
        assert!(lines.iter().any(|l| l.contains(reason)), "{reason}");
    }

    // 1.6 : accepté.
    let mut doc = h.site_a();
    doc["bom"]["specVersion"] = json!("1.6");
    assert_eq!(h.send(&doc).await, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn bad_components_are_dropped_and_counted_not_refused() {
    let h = Harness::new();
    let mut doc = h.site_a();
    let list = components(&mut doc);
    // Non canoniques ou hors grammaire.
    list.push(component(
        "pkg:composer/Exemple/Majuscules@1.0.0",
        "1.0.0",
        "composer.lock",
        "required",
    ));
    list.push(component(
        "pkg:composer/exemple/tilde@1.0~beta",
        "1.0~beta",
        "composer.lock",
        "required",
    ));
    // Écosystème non admis pour un site WordPress.
    list.push(component(
        "pkg:prestashop/module/exemplemodule@1.0.0",
        "1.0.0",
        "modules/exemplemodule",
        "required",
    ));
    // Doublon (purl, path) d'un composant de la fixture.
    list.push(component(
        "pkg:npm/paquet-simple@4.17.21",
        "4.17.21",
        "package-lock.json",
        "required",
    ));
    // Incohérences.
    list.push(component(
        "pkg:composer/exemple/a@1.0.0",
        "1.0.1",
        "composer.lock",
        "required",
    ));
    list.push(component(
        "pkg:composer/exemple/b@1.0.0",
        "1.0.0",
        "../composer.lock",
        "required",
    ));
    list.push(component(
        "pkg:composer/exemple/c@1.0.0",
        "1.0.0",
        "composer.lock",
        "mu",
    ));
    let mut wrong_scope = component(
        "pkg:composer/exemple/d@1.0.0",
        "1.0.0",
        "composer.lock",
        "dev",
    );
    wrong_scope["scope"] = json!("required");
    list.push(wrong_scope);
    // Gardés : npm à scope et casse d'origine, cargo, même paquet à un autre
    // chemin.
    list.push(component(
        "pkg:npm/%40Scope/Nom@1.0.0",
        "1.0.0",
        "app/package-lock.json",
        "required",
    ));
    list.push(component(
        "pkg:cargo/exemple_crate@0.1.0",
        "0.1.0",
        "Cargo.lock",
        "required",
    ));
    list.push(component(
        "pkg:npm/paquet-simple@4.17.21",
        "4.17.21",
        "app/package-lock.json",
        "required",
    ));
    assert_eq!(h.send(&doc).await, StatusCode::NO_CONTENT);
    assert_eq!(h.dropped("site-a"), 8);
    let purls = h.purls("site-a");
    assert_eq!(purls.len(), 15);
    assert!(purls.contains(&"pkg:npm/%40Scope/Nom@1.0.0".to_owned()));
    assert!(purls.contains(&"pkg:cargo/exemple_crate@0.1.0".to_owned()));
    assert!(!purls.iter().any(|p| p.starts_with("pkg:prestashop")));
    // Le même module sur un site PrestaShop : gardé.
    let mut doc = h.doc(SITE_B);
    components(&mut doc).push(component(
        "pkg:wordpress/plugin/exemple-formulaire@1.0.0",
        "1.0.0",
        "wp-content/plugins/exemple-formulaire",
        "required",
    ));
    assert_eq!(h.send(&doc).await, StatusCode::NO_CONTENT);
    assert_eq!(h.dropped("site-b"), 1);
    assert_eq!(h.purls("site-b").len(), 4);
}

#[test]
fn the_digest_ignores_order_serial_and_timestamp() {
    let base: Value = serde_json::from_str(SITE_A).expect("fixture");
    let parse = |doc: &Value| {
        bom::parse(
            &serde_json::to_vec(doc).expect("json"),
            "site-a",
            SiteKind::Wordpress,
        )
        .expect("valide")
    };
    let mut other = base.clone();
    components(&mut other).reverse();
    other["bom"]["serialNumber"] = json!("urn:uuid:00000000-0000-4000-8000-000000000002");
    other["bom"]["metadata"]["timestamp"] = json!("2026-10-16T13:00:00Z");
    other["seq"] = json!(42);
    assert_eq!(parse(&base).digest, parse(&other).digest);
    let mut changed = base.clone();
    components(&mut changed)[0]["name"] = json!("noyau");
    assert_ne!(parse(&base).digest, parse(&changed).digest);
}

// --- Clés et conservation ----------------------------------------------------

#[tokio::test]
async fn remove_purges_and_rotate_keeps_the_inventory() {
    let h = Harness::new();
    assert_eq!(h.send(&h.site_a()).await, StatusCode::NO_CONTENT);
    assert_eq!(h.send(&h.doc(SITE_B)).await, StatusCode::NO_CONTENT);
    let other = SigningKey::from_bytes(&[20; 32]);
    h.store()
        .rotate_key("site-a", &other.verifying_key().to_bytes(), T0)
        .expect("rotation");
    let seq: i64 = h.count("SELECT last_inventory_seq FROM site_keys WHERE site = 'site-a'");
    assert_eq!(seq, 0);
    assert!(
        h.reader()
            .last_inventory("site-a", Source::Agent)
            .expect("lecture")
            .is_some()
    );

    assert!(h.store().remove_key("site-a", 0).expect("retrait"));
    assert_eq!(
        h.count("SELECT count(*) FROM site_inventory WHERE site = 'site-a'"),
        0
    );
    let b = h.last("site-b").id;
    assert_eq!(
        h.count(&format!(
            "SELECT count(*) FROM site_inventory_components WHERE inventory != {b}"
        )),
        0
    );
    assert_eq!(h.purls("site-b").len(), 4);
}

#[tokio::test]
async fn tick_keeps_the_last_inventory_and_30_days_of_history() {
    let h = Harness::new();
    assert_eq!(h.send(&h.site_a()).await, StatusCode::NO_CONTENT);
    assert_eq!(h.send(&h.doc(SITE_B)).await, StatusCode::NO_CONTENT);
    h.clock.advance(300);
    let mut doc = h.site_a();
    components(&mut doc).pop();
    assert_eq!(h.send(&doc).await, StatusCode::NO_CONTENT);
    let declared = agent_sources(&["site-a", "site-b"]);
    // J+29 : rien ne part.
    assert_eq!(
        h.store()
            .purge_inventory(T0 + 29 * 86_400, &declared)
            .expect("purge"),
        0
    );
    // J+31 : l'historique de site-a part, les derniers restent.
    let at = T0 + 31 * 86_400;
    assert_eq!(h.store().purge_inventory(at, &declared).expect("purge"), 1);
    assert_eq!(
        h.reader()
            .inventory_history("site-a", Source::Agent)
            .expect("historique")
            .len(),
        1
    );
    assert_eq!(h.purls("site-a").len(), 11);
    // site-b ne déclare plus [sites.inventory] depuis 31 jours : purgé aussi.
    assert_eq!(
        h.store()
            .purge_inventory(at, &agent_sources(&["site-a"]))
            .expect("purge"),
        1
    );
    assert_eq!(
        h.reader()
            .last_inventory("site-b", Source::Agent)
            .expect("lecture"),
        None
    );
    assert_eq!(
        h.count(
            "SELECT count(*) FROM site_inventory_components c
             JOIN site_inventory i ON i.id = c.inventory WHERE i.site = 'site-b'"
        ),
        0
    );
    assert!(
        h.reader()
            .last_inventory("site-a", Source::Agent)
            .expect("lecture")
            .is_some()
    );

    // Par `tick`, avec la configuration : site-a reste déclaré.
    let summary = vigie::tick::run_with(
        &Config {
            sites: Vec::new(),
            ..h.config.clone()
        },
        at,
        &vigie::tick::Options::default(),
        &vigie::alert::MemoryNotifier::default(),
    );
    summary.expect("tick");
    assert_eq!(
        h.reader()
            .last_inventory("site-a", Source::Agent)
            .expect("lecture"),
        None
    );
}
