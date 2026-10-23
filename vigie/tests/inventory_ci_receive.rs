//! Réception des inventaires par source (issue #20, phase 1) : la source `ci`
//! déclarée par `[sites.inventory] sources`, sa clé d'inventaire distincte de
//! la clé de rapport, le choix de la clé par la signature, et le stockage,
//! le débit et le plafond par (site, source). Clés Ed25519 générées ici,
//! `FakeClock`, BOM fictif de `fixtures/inventory/site-a-ci.json`.

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
use vigie::command::key::{self, DOMAIN_INVENTORY, DOMAIN_LOGS, DOMAIN_PULL};
use vigie::config::{Alerts, Config, InventorySource, Runtime, Site, SiteInventory, SiteKind};
use vigie::ingest::{HEADER_SIGNATURE, HEADER_SITE};
use vigie::inventory::{self, Source};
use vigie::serve;
use vigie::store::{InventoryHead, Store};

/// 2026-10-16T12:00:00Z.
const T0: i64 = 1_792_152_000;
const SITE_A_CI: &str = include_str!("fixtures/inventory/site-a-ci.json");
const SITE_A_WP: &str = include_str!("fixtures/inventory/site-a-wordpress.json");

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

fn journal() -> Vec<String> {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        log::set_boxed_logger(Box::new(Capture)).expect("logger");
        log::set_max_level(log::LevelFilter::Info);
    });
    LINES.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

// --- Veilleur de test ------------------------------------------------------

fn site(id: &str, kind: SiteKind, runtime: Option<Runtime>, sources: &[InventorySource]) -> Site {
    Site {
        id: id.into(),
        url: format!("https://{id}.example.org/"),
        kind,
        runtime,
        keyword_url: None,
        keyword: None,
        interval: 300,
        agent_silence: 900,
        logs: None,
        inventory: (!sources.is_empty()).then(|| SiteInventory::new(sources)),
        custom_checks: Vec::new(),
    }
}

/// Site A `static` à la source `ci` ; site B `wordpress` aux deux sources ;
/// site D `wordpress` à `agent-php` seul, sans clé d'agent mais avec une clé
/// d'inventaire restée en base ; site E `static` à `ci`, sans clé.
fn sites(b_sources: &[InventorySource]) -> Vec<Site> {
    use InventorySource::{AgentPhp, Ci};
    vec![
        site("site-a", SiteKind::Generic, Some(Runtime::Static), &[Ci]),
        site("site-b", SiteKind::Wordpress, None, b_sources),
        site("site-d", SiteKind::Wordpress, None, &[AgentPhp]),
        site("site-e", SiteKind::Generic, Some(Runtime::Static), &[Ci]),
    ]
}

fn config(dir: &Path, sites: Vec<Site>) -> Config {
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
        sites,
    }
}

fn signing(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// Clé d'inventaire du site A, clés d'agent et d'inventaire du site B, clé
/// d'inventaire du site D.
const INV_A: u8 = 61;
const AGENT_B: u8 = 62;
const INV_B: u8 = 63;
const INV_D: u8 = 64;

struct Harness {
    config: Config,
    clock: Arc<FakeClock>,
    seq: std::cell::Cell<i64>,
    _dir: tempfile::TempDir,
}

impl Harness {
    fn new() -> Self {
        journal();
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(
            dir.path(),
            sites(&[InventorySource::AgentPhp, InventorySource::Ci]),
        );
        let mut store = Store::open(&config.database).expect("base");
        let public = |seed| signing(seed).verifying_key().to_bytes();
        store
            .add_inventory_key("site-a", &public(INV_A), T0 - 600)
            .expect("clé A");
        store
            .add_key("site-b", &public(AGENT_B), T0 - 600)
            .expect("clé B");
        store
            .add_inventory_key("site-b", &public(INV_B), T0 - 600)
            .expect("clé d'inventaire B");
        store
            .add_inventory_key("site-d", &public(INV_D), T0 - 600)
            .expect("clé D");
        Self {
            config,
            clock: Arc::new(FakeClock::new(T0)),
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

    fn count(&self, sql: &str) -> i64 {
        rusqlite::Connection::open(&self.config.database)
            .expect("sqlite")
            .query_row(sql, [], |row| row.get(0))
            .expect(sql)
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

    /// Inventaire signé par la graine `seed` sous le domaine des inventaires.
    async fn send(&self, doc: &Value, seed: u8) -> StatusCode {
        let body = serde_json::to_vec(doc).expect("json");
        let signature = key::sign(&signing(seed), DOMAIN_INVENTORY, &[&body]);
        let site = doc["site"].as_str().unwrap_or("site-a").to_owned();
        self.post("/r/v1/inventory", &site, &signature, body).await
    }

    /// Fixture pour `site`, `seq` suivant et heure courante.
    fn doc(&self, fixture: &str, site: &str) -> Value {
        let mut doc: Value = serde_json::from_str(fixture).expect("fixture");
        self.seq.set(self.seq.get() + 1);
        doc["site"] = json!(site);
        doc["bom"]["metadata"]["component"]["name"] = json!(site);
        doc["seq"] = json!(self.seq.get());
        doc["sent_at"] = json!(self.clock.unix());
        doc["bom"]["metadata"]["timestamp"] = json!(vigie::iso_utc(self.clock.unix()));
        doc
    }

    /// Inventaire de CI (`source: ci`).
    fn ci(&self, site: &str) -> Value {
        self.doc(SITE_A_CI, site)
    }

    /// Inventaire de l'agent (sans `source`, comme l'agent 0.5.0).
    fn agent(&self, site: &str) -> Value {
        self.doc(SITE_A_WP, site)
    }

    fn last(&self, site: &str, source: Source) -> Option<InventoryHead> {
        self.reader().last_inventory(site, source).expect("lecture")
    }

    fn rows(&self, site: &str, source: Source) -> usize {
        self.reader()
            .inventory_history(site, source)
            .expect("historique")
            .len()
    }
}

fn components(doc: &mut Value) -> &mut Vec<Value> {
    doc["bom"]["components"].as_array_mut().expect("components")
}

/// Change le contenu : un composant de moins.
fn changed(mut doc: Value) -> Value {
    components(&mut doc).pop();
    doc
}

// --- Parcours nominal --------------------------------------------------------

#[tokio::test]
async fn a_ci_inventory_is_stored_under_its_own_source() {
    let h = Harness::new();
    assert_eq!(h.send(&h.ci("site-a"), INV_A).await, StatusCode::NO_CONTENT);
    let head = h.last("site-a", Source::Ci).expect("inventaire ci");
    assert_eq!(
        (head.source, head.complete, head.agent.as_str()),
        (Source::Ci, true, "vigie-inventory/0.1.0")
    );
    assert_eq!(h.last("site-a", Source::Agent), None);
    let rows = h
        .reader()
        .inventory_components(head.id, 0, 100)
        .expect("composants");
    assert_eq!(rows.len(), 5);
    assert_eq!(
        h.count("SELECT last_seq FROM site_inventory_keys WHERE site = 'site-a'"),
        h.seq.get()
    );
    // Pas une preuve de vie : ni rapport, ni incident.
    assert_eq!(h.count("SELECT count(*) FROM reports"), 0);
    assert_eq!(h.count("SELECT count(*) FROM incidents"), 0);
    // Journal : site, source, nombres ; jamais un purl ni un nom reçu.
    let lines = journal();
    assert!(
        lines
            .iter()
            .any(|l| l.contains("inventaire accepté (site site-a, source ci")
                && l.contains("nouveau")),
        "{lines:?}"
    );
    assert!(lines.iter().all(|l| !l.contains("exemple-rendu")));
}

#[tokio::test]
async fn a_site_keeps_one_last_inventory_per_source() {
    let h = Harness::new();
    assert_eq!(
        h.send(&h.agent("site-b"), AGENT_B).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(h.send(&h.ci("site-b"), INV_B).await, StatusCode::NO_CONTENT);
    let agent = h.last("site-b", Source::Agent).expect("agent");
    let ci = h.last("site-b", Source::Ci).expect("ci");
    assert_ne!(agent.id, ci.id);
    let heads = h.reader().inventory_heads().expect("têtes");
    assert_eq!(
        heads
            .iter()
            .map(|h| (h.site.as_str(), h.source))
            .collect::<Vec<_>>(),
        [("site-b", Source::Agent), ("site-b", Source::Ci)]
    );
    assert_eq!(heads, [agent, ci]);
}

// --- Débit, plafond, séquence ------------------------------------------------

#[tokio::test]
async fn the_ci_rate_limit_only_applies_to_an_unchanged_resend() {
    let h = Harness::new();
    assert_eq!(
        h.send(&h.agent("site-b"), AGENT_B).await,
        StatusCode::NO_CONTENT
    );
    let agent = h.last("site-b", Source::Agent).expect("agent");
    assert_eq!(h.send(&h.ci("site-b"), INV_B).await, StatusCode::NO_CONTENT);
    // Nouvel inventaire ci 180 s plus tard : accepté (deux déploiements).
    h.clock.advance(180);
    assert_eq!(
        h.send(&changed(h.ci("site-b")), INV_B).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(h.rows("site-b", Source::Ci), 2);
    // Renvoi inchangé 100 s après : débit.
    h.clock.advance(100);
    assert_eq!(
        h.send(&changed(h.ci("site-b")), INV_B).await,
        StatusCode::NOT_FOUND
    );
    // Nouvel inventaire de l'agent 100 s après le sien… 280 s : accepté ;
    // puis un autre 100 s plus tard : débit de F5, pour tout envoi.
    assert_eq!(
        h.send(&changed(h.agent("site-b")), AGENT_B).await,
        StatusCode::NO_CONTENT
    );
    h.clock.advance(100);
    assert_eq!(
        h.send(&h.agent("site-b"), AGENT_B).await,
        StatusCode::NOT_FOUND
    );
    // Renvoi ci inchangé 300 s après le dernier ci : seen_at avancé, pas de
    // nouvelle ligne ; l'inventaire de l'agent n'est pas touché.
    h.clock.advance(100);
    let before = h.last("site-b", Source::Agent).expect("agent");
    assert_eq!(
        h.send(&changed(h.ci("site-b")), INV_B).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(h.rows("site-b", Source::Ci), 2);
    let ci = h.last("site-b", Source::Ci).expect("ci");
    assert_eq!((ci.seen_at, ci.received_at), (T0 + 480, T0 + 180));
    assert_eq!(h.last("site-b", Source::Agent), Some(before));
    assert_ne!(
        h.last("site-b", Source::Agent).map(|a| a.id),
        Some(agent.id)
    );
}

#[tokio::test]
async fn at_most_24_new_ci_inventories_per_utc_day_and_the_agent_is_apart() {
    let h = Harness::new();
    for i in 0..24 {
        let mut doc = h.ci("site-b");
        components(&mut doc)[0]["version"] = json!(format!("3.4.{i}"));
        components(&mut doc)[0]["purl"] = json!(format!("pkg:npm/exemple-rendu@3.4.{i}"));
        assert_eq!(h.send(&doc, INV_B).await, StatusCode::NO_CONTENT, "{i}");
        h.clock.advance(60);
    }
    assert_eq!(h.rows("site-b", Source::Ci), 24);
    assert_eq!(
        h.send(&changed(h.ci("site-b")), INV_B).await,
        StatusCode::NOT_FOUND
    );
    assert!(
        journal()
            .iter()
            .any(|l| l.contains("site site-b") && l.contains("plafond quotidien des inventaires"))
    );
    assert_eq!(h.rows("site-b", Source::Ci), 24);
    // L'agent du même site, le même jour : accepté.
    assert_eq!(
        h.send(&h.agent("site-b"), AGENT_B).await,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn each_source_has_its_own_seq() {
    let h = Harness::new();
    let mut doc = h.ci("site-b");
    doc["seq"] = json!(1_000);
    assert_eq!(h.send(&doc, INV_B).await, StatusCode::NO_CONTENT);
    // seq ci rejoué : refusé.
    h.clock.advance(300);
    let mut replay = changed(h.ci("site-b"));
    replay["seq"] = json!(1_000);
    assert_eq!(h.send(&replay, INV_B).await, StatusCode::NOT_FOUND);
    // L'agent part de 1 : indépendant.
    let mut agent = h.agent("site-b");
    agent["seq"] = json!(1);
    assert_eq!(h.send(&agent, AGENT_B).await, StatusCode::NO_CONTENT);
    assert_eq!(
        h.count("SELECT last_inventory_seq FROM site_keys WHERE site = 'site-b'"),
        1
    );
    assert_eq!(
        h.count("SELECT last_seq FROM site_inventory_keys WHERE site = 'site-b'"),
        1_000
    );
}

// --- Clés et sources ---------------------------------------------------------

#[tokio::test]
async fn the_key_that_verifies_fixes_the_source() {
    let h = Harness::new();
    // Clé de rapport, enveloppe `source: ci` : refusée (schéma : source).
    assert_eq!(
        h.send(&h.ci("site-b"), AGENT_B).await,
        StatusCode::NOT_FOUND
    );
    assert!(
        journal()
            .iter()
            .any(|l| l.contains("site site-b") && l.contains("schéma : source"))
    );
    // Clé d'inventaire, `source` absente ou `agent` : refusée.
    let mut doc = h.ci("site-b");
    doc.as_object_mut().expect("objet").remove("source");
    assert_eq!(h.send(&doc, INV_B).await, StatusCode::NOT_FOUND);
    let mut doc = h.ci("site-b");
    doc["source"] = json!("agent");
    assert_eq!(h.send(&doc, INV_B).await, StatusCode::NOT_FOUND);
    // Valeur inconnue ou champ en plus : document refusé.
    let mut doc = h.ci("site-b");
    doc["source"] = json!("cd");
    assert_eq!(h.send(&doc, INV_B).await, StatusCode::NOT_FOUND);
    let mut doc = h.ci("site-b");
    doc["origine"] = json!("ci");
    assert_eq!(h.send(&doc, INV_B).await, StatusCode::NOT_FOUND);
    // Clé d'inventaire d'un autre site : signature invalide.
    assert_eq!(h.send(&h.ci("site-b"), INV_A).await, StatusCode::NOT_FOUND);
    assert_eq!(h.count("SELECT count(*) FROM site_inventory"), 0);

    // Site A à `ci` seul : une clé de rapport, même enregistrée, ne vérifie rien.
    rusqlite::Connection::open(&h.config.database)
        .expect("sqlite")
        .execute(
            "INSERT INTO site_keys (site, pubkey, added_at) VALUES ('site-a', ?1, 0)",
            [signing(70).verifying_key().to_bytes().as_slice()],
        )
        .expect("clé de rapport du site A");
    let mut doc = h.ci("site-a");
    doc.as_object_mut().expect("objet").remove("source");
    assert_eq!(h.send(&doc, 70).await, StatusCode::NOT_FOUND);
    assert_eq!(h.send(&h.ci("site-a"), 70).await, StatusCode::NOT_FOUND);
    assert_eq!(h.send(&h.ci("site-a"), INV_A).await, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn an_inventory_key_signs_nothing_else() {
    let h = Harness::new();
    let inventory_key = signing(INV_B);
    let body = br#"{"v":1}"#.to_vec();
    for (uri, domain) in [
        ("/r/v1/report", b"".as_slice()),
        ("/r/v1/logs", DOMAIN_LOGS),
        ("/r/v1/commands", DOMAIN_PULL),
    ] {
        let signature = key::sign(&inventory_key, domain, &[&body]);
        assert_eq!(
            h.post(uri, "site-b", &signature, body.clone()).await,
            StatusCode::NOT_FOUND,
            "{uri}"
        );
        // Site A n'a qu'une clé d'inventaire : inconnu de ces routes.
        let signature = key::sign(&signing(INV_A), domain, &[&body]);
        assert_eq!(
            h.post(uri, "site-a", &signature, body.clone()).await,
            StatusCode::NOT_FOUND,
            "{uri}"
        );
    }
    assert_eq!(h.count("SELECT count(*) FROM reports"), 0);
    assert_eq!(h.count("SELECT count(*) FROM log_batches"), 0);
}

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
async fn a_declared_source_without_its_key_is_refused_before_reading_the_body() {
    let h = Harness::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("écoute");
    let addr = listener.local_addr().expect("adresse");
    let router = h.router();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    // site D : `ci` non déclaré, sa clé d'inventaire restée en base n'ouvre
    // rien ; site E : `ci` déclaré, aucune clé.
    for site in ["site-d", "site-e"] {
        let status = stalled_request(addr, site, Duration::from_secs(3)).await;
        assert_eq!(
            status.as_deref(),
            Some("HTTP/1.1 404 Not Found"),
            "{site} : refus immédiat, corps jamais attendu"
        );
    }
    // Site A : `ci` déclaré et clé enregistrée, le corps est attendu.
    assert_eq!(
        stalled_request(addr, "site-a", Duration::from_millis(800)).await,
        None
    );
    // Corps de 10 Mio sur le site D : refusé par la porte.
    let status = h
        .post(
            "/r/v1/inventory",
            "site-d",
            "AAAA",
            vec![b' '; 10 * 1024 * 1024],
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(h.send(&h.ci("site-d"), INV_D).await, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn rotate_resets_the_ci_seq_and_keeps_the_inventory() {
    let h = Harness::new();
    let mut doc = h.ci("site-a");
    doc["seq"] = json!(5_000);
    assert_eq!(h.send(&doc, INV_A).await, StatusCode::NO_CONTENT);
    let kept = h.last("site-a", Source::Ci).expect("ci");
    let new = signing(71);
    assert_eq!(
        h.store()
            .rotate_inventory_key("site-a", &new.verifying_key().to_bytes(), T0)
            .expect("rotation"),
        vigie::store::KeyOutcome::Done
    );
    assert_eq!(
        h.count("SELECT last_seq FROM site_inventory_keys WHERE site = 'site-a'"),
        0
    );
    assert_eq!(h.last("site-a", Source::Ci), Some(kept.clone()));
    h.clock.advance(300);
    assert_eq!(
        h.send(&changed(h.ci("site-a")), INV_A).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        h.send(&changed(h.ci("site-a")), 71).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(h.rows("site-a", Source::Ci), 2);

    // `site remove` d'un site static sans clé d'agent : tout part.
    assert!(h.store().remove_key("site-a", 0).expect("retrait"));
    assert_eq!(
        h.count("SELECT count(*) FROM site_inventory WHERE site = 'site-a'"),
        0
    );
    assert_eq!(
        h.count("SELECT count(*) FROM site_inventory_keys WHERE site = 'site-a'"),
        0
    );
    assert_eq!(h.reader().inventory_key("site-a").expect("clé"), None);
}

#[tokio::test]
async fn tick_purges_the_last_ci_inventory_of_a_source_no_longer_declared() {
    let h = Harness::new();
    assert_eq!(
        h.send(&h.agent("site-b"), AGENT_B).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(h.send(&h.ci("site-b"), INV_B).await, StatusCode::NO_CONTENT);
    // `ci` retiré de la configuration de site B ; J+31.
    let at = T0 + 31 * 86_400;
    let config = Config {
        sites: sites(&[InventorySource::AgentPhp]),
        ..h.config.clone()
    };
    vigie::tick::run_with(
        &config,
        at,
        &vigie::tick::Options::default(),
        &vigie::alert::MemoryNotifier::default(),
    )
    .expect("tick");
    assert_eq!(h.last("site-b", Source::Ci), None);
    assert!(h.last("site-b", Source::Agent).is_some());
}

#[test]
fn staleness_is_set_per_source() {
    assert_eq!(
        inventory::stale_after(Source::Agent),
        Duration::from_secs(7 * 86_400)
    );
    assert_eq!(
        inventory::stale_after(Source::Ci),
        Duration::from_secs(35 * 86_400)
    );
}
