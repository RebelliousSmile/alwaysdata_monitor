//! Garde-fous transverses de `/api/v1` (issue #5, `docs/api-console.md`) :
//! limite de débit, journal des appels, en-têtes stricts, 415, liste blanche
//! des DTO et texte d'origine log assaini. Sur le routeur de `serve`, gardé
//! d'une requête à l'autre (les seaux vivent dans son état), une horloge
//! réglable et l'adresse du pair posée par `MockConnectInfo`.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

#[path = "support/veilleur.rs"]
mod veilleur;

use vigie::analysis::catalog::BotClass;
use vigie::analysis::findings::{self, Analysis, BotSeen, IpVerdict, RuleOutcome};
use vigie::analysis::load::{DEFAULT_THRESHOLD_US, HourLoad};
use vigie::analysis::rules::Scope;
use vigie::analysis::score::{Level, Reason};
use vigie::capability::CommandKind;
use vigie::clock::{Clock, FakeClock};
use vigie::config::{Api, Config, LogSourceKind, Runtime, SiteLogs};
use vigie::device::{self, PAIRING_TTL};
use vigie::finding::{Finding, Severity};
use vigie::serve;
use vigie::store::{AcceptedReport, RunRecord, Store};

const T0: i64 = 1_792_000_000;
const DAY: i64 = 86_400;
/// Pair ordinaire, hors boucle locale (RFC 5737).
const PEER: &str = "192.0.2.10:40000";
/// Caddy, sur la boucle locale.
const CADDY: &str = "127.0.0.1:50000";
const KEYS_FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/api-keys.json");

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

fn lines_with(needle: &str) -> Vec<String> {
    journal()
        .into_iter()
        .filter(|line| line.contains(needle))
        .collect()
}

// --- Veilleur de test ------------------------------------------------------

struct Veilleur {
    _dir: tempfile::TempDir,
    config: Config,
    clock: Arc<FakeClock>,
    router: Router,
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("json")
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    fn request_id(&self) -> &str {
        self.header("x-request-id").expect("x-request-id")
    }

    /// Erreur au format commun, avec les en-têtes stricts.
    fn assert_api_error(&self, code: &str, context: &str) {
        let json = self.json();
        assert_eq!(json["error"]["code"], code, "{context}");
        assert_eq!(json["error"].as_object().expect("error").len(), 3);
        assert_eq!(json["error"]["request_id"], self.request_id(), "{context}");
        self.assert_strict(context);
    }

    /// `nosniff`, `no-store`, JSON s'il y a un corps, aucun en-tête CORS.
    fn assert_strict(&self, context: &str) {
        assert_eq!(
            self.header("x-content-type-options"),
            Some("nosniff"),
            "{context}"
        );
        assert_eq!(self.header("cache-control"), Some("no-store"), "{context}");
        let expected = (!self.body.is_empty()).then_some("application/json");
        assert_eq!(self.header("content-type"), expected, "{context}");
        assert!(
            self.headers
                .keys()
                .all(|name| !name.as_str().starts_with("access-control-")),
            "{context} : en-tête CORS"
        );
    }
}

fn peer(text: &str) -> SocketAddr {
    text.parse().expect("adresse")
}

impl Veilleur {
    fn new() -> Self {
        Self::with(|_| {})
    }

    fn with(edit: impl FnOnce(&mut Config)) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = veilleur::config(dir.path().join("vigie.db"));
        edit(&mut config);
        Store::open(&config.database).expect("open");
        let clock = Arc::new(FakeClock::new(T0));
        let router = serve::router_with_clock(config.clone(), Arc::clone(&clock) as Arc<dyn Clock>);
        Self {
            _dir: dir,
            config,
            clock,
            router,
        }
    }

    fn store(&self) -> Store {
        Store::open(&self.config.database).expect("open")
    }

    /// Code d'appairage valide, comme `vigie device pair`.
    fn code(&self, name: &str) -> String {
        let code = device::new_code().expect("code");
        let now = self.clock.unix();
        self.store()
            .create_pairing(&device::hash(&code), name, now, now + PAIRING_TTL)
            .expect("pairing");
        code
    }

    async fn send_from(&self, from: &str, request: Request<Body>) -> Reply {
        let response = self
            .router
            .clone()
            .layer(MockConnectInfo(peer(from)))
            .oneshot(request)
            .await
            .expect("response");
        let (parts, body) = response.into_parts();
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: body.collect().await.expect("body").to_bytes().to_vec(),
        }
    }

    /// `POST /api/v1/pair` tel que l'envoie la console 0.1.1 (reqwest et
    /// `.json()`).
    fn pair_request(body: &str) -> Request<Body> {
        Request::post("/api/v1/pair")
            .header("content-type", "application/json")
            .header("content-length", body.len())
            .body(Body::from(body.to_owned()))
            .expect("request")
    }

    async fn pair_from(&self, from: &str, code: &str) -> Reply {
        let body = serde_json::json!({ "code": code }).to_string();
        self.send_from(from, Self::pair_request(&body)).await
    }

    /// Jeton d'un appareil appairé depuis `from`.
    async fn token_from(&self, from: &str, name: &str) -> String {
        let reply = self.pair_from(from, &self.code(name)).await;
        assert_eq!(reply.status, StatusCode::OK);
        reply.json()["token"].as_str().expect("token").to_owned()
    }

    async fn call_from(&self, from: &str, method: Method, path: &str, token: &str) -> Reply {
        let mut request = Request::builder()
            .method(method.clone())
            .uri(path)
            .header("authorization", format!("Bearer {token}"));
        // Comme reqwest : `Content-Length: 0` sur un POST sans corps.
        if method == Method::POST {
            request = request.header("content-length", "0");
        }
        self.send_from(from, request.body(Body::empty()).expect("request"))
            .await
    }

    async fn get(&self, path: &str, token: &str) -> Reply {
        self.call_from(PEER, Method::GET, path, token).await
    }
}

// --- Limite de débit -------------------------------------------------------

#[tokio::test]
async fn under_the_limit_a_call_is_answered_with_strict_headers_and_one_journal_line() {
    let v = Veilleur::new();
    let token = v.token_from(PEER, "poste").await;
    let reply = v.get("/api/v1/overview", &token).await;
    assert_eq!(reply.status, StatusCode::OK);
    reply.assert_strict("overview");

    let lines = lines_with(reply.request_id());
    assert_eq!(lines.len(), 1, "{lines:?}");
    let line = &lines[0];
    assert!(
        line.contains("appareil 1 GET /api/v1/overview 200 "),
        "{line}"
    );
    assert!(line.ends_with(" ms"), "{line}");
    assert!(!line.contains(&token), "jeton au journal : {line}");
}

#[tokio::test]
async fn the_31st_call_of_a_burst_is_a_429_with_retry_after() {
    let v = Veilleur::new();
    let token = v.token_from(PEER, "poste").await;
    for n in 1..=30 {
        let reply = v.get("/api/v1/settings", &token).await;
        assert_eq!(reply.status, StatusCode::OK, "appel {n}");
    }
    let reply = v.get("/api/v1/settings", &token).await;
    assert_eq!(reply.status, StatusCode::TOO_MANY_REQUESTS);
    reply.assert_api_error("too_many_requests", "31e appel");
    let retry: u64 = reply
        .header("retry-after")
        .expect("Retry-After")
        .parse()
        .expect("secondes");
    assert!(retry >= 1);
    // Un appel toutes les demi-secondes ensuite.
    v.clock
        .advance_monotonic(std::time::Duration::from_millis(500));
    assert_eq!(
        v.get("/api/v1/settings", &token).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn the_11th_pairing_from_an_ip_in_a_minute_is_a_429() {
    let v = Veilleur::new();
    for n in 1..=10 {
        let reply = v.pair_from(PEER, "inconnu").await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "essai {n}");
    }
    // Même avec un code valide : le seau est vide.
    let reply = v.pair_from(PEER, &v.code("poste")).await;
    assert_eq!(reply.status, StatusCode::TOO_MANY_REQUESTS);
    reply.assert_api_error("too_many_requests", "11e appairage");
    assert_eq!(reply.header("retry-after"), Some("6"));
    // Une autre IP n'en souffre pas.
    assert_eq!(
        v.pair_from("198.51.100.20:1", &v.code("autre"))
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn an_empty_ip_bucket_never_blocks_a_valid_token() {
    let v = Veilleur::new();
    let token = v.token_from("198.51.100.30:1", "poste").await;
    for n in 1..=10 {
        let reply = v.get("/api/v1/overview", "inconnu").await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "essai {n}");
    }
    let reply = v.get("/api/v1/overview", "inconnu").await;
    assert_eq!(reply.status, StatusCode::TOO_MANY_REQUESTS);
    reply.assert_api_error("too_many_requests", "jeton inconnu");
    // Sans jeton du tout : même seau.
    let reply = v
        .send_from(
            PEER,
            Request::get("/api/v1/overview")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
    assert_eq!(reply.status, StatusCode::TOO_MANY_REQUESTS);
    // Même IP (NAT partagé avec l'attaquant), jeton valide : servi.
    assert_eq!(
        v.get("/api/v1/overview", &token).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn sprayed_addresses_do_not_free_the_attacker() {
    let v = Veilleur::new();
    let attacker = "203.0.113.66:1";
    for _ in 0..10 {
        v.pair_from(attacker, "inconnu").await;
    }
    assert_eq!(
        v.pair_from(attacker, "inconnu").await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    let mut refused = 0;
    for n in 0..5_000u32 {
        let from = SocketAddr::new(std::net::Ipv4Addr::from_bits(0x0a00_0000 + n).into(), 1);
        let reply = v
            .send_from(&from.to_string(), Veilleur::pair_request(""))
            .await;
        if reply.status == StatusCode::TOO_MANY_REQUESTS {
            refused += 1;
        }
    }
    // Table pleine de seaux entamés : les nouvelles adresses sont refusées.
    assert!(refused > 0, "table bornée");
    assert_eq!(
        v.pair_from(attacker, "inconnu").await.status,
        StatusCode::TOO_MANY_REQUESTS,
        "l'attaquant reste limité"
    );
}

#[tokio::test]
async fn two_ipv6_of_the_same_64_share_a_bucket() {
    let v = Veilleur::new();
    for _ in 0..10 {
        v.pair_from("[2001:db8::1]:1", "inconnu").await;
    }
    assert_eq!(
        v.pair_from("[2001:db8::2]:1", "inconnu").await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        v.pair_from("[2001:db8:0:1::1]:1", "inconnu").await.status,
        StatusCode::UNAUTHORIZED
    );
}

fn pair_forwarded(forwarded: &str) -> Request<Body> {
    let mut request = Veilleur::pair_request("{\"code\":\"inconnu\"}");
    request
        .headers_mut()
        .insert("x-forwarded-for", forwarded.parse().expect("en-tête"));
    request
}

#[tokio::test]
async fn forwarded_for_counts_only_from_loopback_and_only_its_last_value() {
    let v = Veilleur::new();
    // Pair hors boucle locale : l'en-tête est forgé, ignoré.
    for n in 0..10 {
        let reply = v
            .send_from(PEER, pair_forwarded(&format!("198.51.100.{n}")))
            .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    }
    let reply = v.send_from(PEER, pair_forwarded("198.51.100.99")).await;
    assert_eq!(reply.status, StatusCode::TOO_MANY_REQUESTS);

    // Depuis Caddy : la dernière valeur, pas la première.
    for _ in 0..10 {
        let reply = v
            .send_from(CADDY, pair_forwarded("198.51.100.1, 203.0.113.5"))
            .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    }
    let reply = v
        .send_from(CADDY, pair_forwarded("198.51.100.1, 203.0.113.5"))
        .await;
    assert_eq!(reply.status, StatusCode::TOO_MANY_REQUESTS);
    let reply = v
        .send_from(CADDY, pair_forwarded("198.51.100.1, 203.0.113.6"))
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_429_of_one_ip_are_grouped_by_minute() {
    let v = Veilleur::new();
    let from = "203.0.113.77:1";
    for _ in 0..10 {
        v.pair_from(from, "inconnu").await;
    }
    for _ in 0..5 {
        let reply = v.pair_from(from, "inconnu").await;
        assert_eq!(reply.status, StatusCode::TOO_MANY_REQUESTS);
    }
    let grouped = lines_with("203.0.113.77");
    assert_eq!(grouped.len(), 1, "{grouped:?}");
    assert!(grouped[0].contains("POST /api/v1/pair 429"), "{grouped:?}");

    v.clock.advance(60);
    for _ in 0..10 {
        v.pair_from(from, "inconnu").await;
    }
    let reply = v.pair_from(from, "inconnu").await;
    assert_eq!(reply.status, StatusCode::TOO_MANY_REQUESTS);
    let grouped = lines_with("203.0.113.77");
    assert_eq!(grouped.len(), 3, "{grouped:?}");
    assert!(
        grouped
            .iter()
            .any(|line| line.contains("4 autre(s) 429 regroupé(s) pour 203.0.113.77")),
        "{grouped:?}"
    );
}

// --- En-têtes, CORS, 415 ---------------------------------------------------

#[tokio::test]
async fn the_exact_requests_of_console_0_1_1_are_still_accepted() {
    let v = Veilleur::new();
    let reply = v.pair_from(PEER, &v.code("poste")).await;
    assert_eq!(reply.status, StatusCode::OK);
    reply.assert_strict("pair");
    let token = reply.json()["token"].as_str().expect("token").to_owned();

    let id = open_incident(&v, "exposed", Severity::Critical, "/.env lisible");
    for path in [
        "/api/v1/overview".to_owned(),
        "/api/v1/sites/site-a".to_owned(),
        "/api/v1/sites/site-a/incidents".to_owned(),
        format!("/api/v1/incidents/{id}"),
        "/api/v1/settings".to_owned(),
    ] {
        let reply = v.get(&path, &token).await;
        assert_eq!(reply.status, StatusCode::OK, "{path}");
        reply.assert_strict(&path);
    }
    // Acquittement sans corps ni Content-Type.
    let reply = v
        .call_from(
            PEER,
            Method::POST,
            &format!("/api/v1/incidents/{id}/ack"),
            &token,
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json()["state"], "acked");
    reply.assert_strict("ack");
    // Retrait : 204, sans corps ni Content-Type.
    let reply = v
        .call_from(PEER, Method::DELETE, "/api/v1/devices/self", &token)
        .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert!(reply.body.is_empty());
    reply.assert_strict("devices/self");
}

#[tokio::test]
async fn options_with_an_origin_is_the_uniform_404_without_cors() {
    let v = Veilleur::new();
    for path in [
        "/api/v1/pair",
        "/api/v1/overview",
        "/api/v1/sites/site-a",
        "/api/v1/incidents/1/ack",
        "/api/v1/devices/self",
    ] {
        let reply = v
            .send_from(
                PEER,
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri(path)
                    .header("origin", "https://attaquant.example.org")
                    .header("access-control-request-method", "POST")
                    .header("access-control-request-headers", "authorization")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
        reply.assert_api_error("not_found", path);
    }
}

#[tokio::test]
async fn a_post_with_a_body_of_another_type_is_a_415() {
    let v = Veilleur::new();
    let token = v.token_from(PEER, "poste").await;
    let text = Request::post("/api/v1/pair")
        .header("content-type", "text/plain")
        .header("content-length", "17")
        .body(Body::from("{\"code\":\"abcdef\"}"))
        .expect("request");
    let reply = v.send_from(PEER, text).await;
    assert_eq!(reply.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    reply.assert_api_error("unsupported_media_type", "pair en text/plain");

    // Corps annoncé sur l'acquittement : 415 d'après les en-têtes.
    for (name, value) in [("content-length", "2"), ("transfer-encoding", "chunked")] {
        let request = Request::post("/api/v1/incidents/1/ack")
            .header("authorization", format!("Bearer {token}"))
            .header(name, value)
            .body(Body::from("{}"))
            .expect("request");
        let reply = v.send_from(PEER, request).await;
        assert_eq!(reply.status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{name}");
        reply.assert_api_error("unsupported_media_type", name);
    }

    // JSON avec paramètre : accepté ; JSON illisible sur pair : le 401 commun.
    let reply = v
        .send_from(
            PEER,
            Request::post("/api/v1/pair")
                .header("content-type", "Application/JSON; charset=utf-8")
                .header("content-length", "11")
                .body(Body::from("pas du json"))
                .expect("request"),
        )
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    reply.assert_api_error("unauthorized", "json illisible");
}

// --- Liste blanche des DTO -------------------------------------------------

/// Valeurs semées dans la base et la configuration : aucune ne doit sortir.
struct Seeds {
    token: String,
    code: String,
    pubkey: [u8; 32],
    signatures: Vec<String>,
    password: String,
}

impl Seeds {
    fn forbidden(&self, with_token: bool) -> Vec<String> {
        let mut out = Vec::new();
        let secret = |text: &str, out: &mut Vec<String>| {
            let hash = device::hash(text);
            out.push(hex(&hash));
            out.push(STANDARD.encode(hash));
            out.push(URL_SAFE_NO_PAD.encode(hash));
        };
        if with_token {
            out.push(self.token.clone());
        }
        secret(&self.token, &mut out);
        out.push(self.code.clone());
        secret(&self.code, &mut out);
        out.push(hex(&self.pubkey));
        out.push(STANDARD.encode(self.pubkey));
        out.push(URL_SAFE_NO_PAD.encode(self.pubkey));
        out.extend(self.signatures.iter().cloned());
        out.push(self.password.clone());
        out
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn open_incident(v: &Veilleur, check: &str, severity: Severity, detail: &str) -> i64 {
    let finding = Finding::new("site-a", check, severity, check, detail);
    let mut store = v.store();
    store
        .reconcile("site-a", check, std::slice::from_ref(&finding), T0 - DAY)
        .expect("reconcile");
    store
        .open_incidents()
        .expect("incidents")
        .into_iter()
        .find(|i| i.key == finding.incident_key())
        .expect("incident")
        .id
}

/// User-agent cité par le libellé d'une raison de l'instantané semé :
/// jamais servi.
const SEEDED_UA: &str = "curl/8.4.0-seme";

/// Instantané d'analyse de logs du site A : un robot, une règle dépassée,
/// une heure de charge, un verdict élevé dont la raison cite un UA.
fn seeded_analysis() -> Analysis {
    Analysis {
        site: "site-a".into(),
        generated_at: T0 - 60,
        reference_ms: (T0 - 120) * 1000,
        bots: vec![BotSeen {
            name: "GPTBot".into(),
            publisher: "OpenAI".into(),
            purpose: "entraînement".into(),
            robots_only: false,
            honours_robots: true,
            class: BotClass::AiTraining,
            protected: false,
            requests: 12,
        }],
        verdicts: vec![IpVerdict {
            ip: "192.0.2.77".parse().expect("ip"),
            score: 85,
            own_score: 85,
            level: Level::High,
            class: BotClass::Tool,
            bot: None,
            requests: 40,
            shared: false,
            reasons: vec![Reason {
                points: 20,
                label: format!("user-agent d'outil, pas de navigateur ({SEEDED_UA})"),
            }],
        }],
        scored: 1,
        unscored: 0,
        rules: vec![RuleOutcome {
            rule: "spike-404".into(),
            scope: Scope::Site,
            severity: Severity::Warning,
            window_secs: 300,
            min_count: 100,
            min_ips: 1,
            count: 140,
            distinct_ips: 1,
            keys_over: 0,
            exceeded: true,
            ips: vec!["192.0.2.77".parse().expect("ip")],
            keys: Vec::new(),
        }],
        load: vec![HourLoad {
            requests: 52,
            ..HourLoad::new((T0 - 120) / 3600)
        }],
        load_threshold_us: DEFAULT_THRESHOLD_US,
    }
}

/// Base peuplée : agent et relevé, passages avec valeurs mesurées, incidents
/// ouverts, acquittés et fermés, canal de commandes et son audit, mot de
/// passe SMTP dans `password_file`, adresse publique, instantané d'analyse
/// de logs.
async fn populated() -> (Veilleur, Seeds) {
    let v = Veilleur::with(|config| {
        config.api = Some(Api {
            public_url: "https://vigie.example.org".into(),
        });
        config.sites[0].logs = Some(SiteLogs {
            source: Some(LogSourceKind::Alwaysdata),
            hosts: vec!["site-a.example.org".into()],
            ..SiteLogs::default()
        });
    });
    let password = "mot-de-passe-smtp-seme-5f2c9a".to_owned();
    std::fs::write(&v.config.alerts.password_file, &password).expect("mot de passe");

    let pubkey: [u8; 32] = std::array::from_fn(|i| 0xa0 ^ i as u8);
    let mut store = v.store();
    store
        .add_key("site-a", &pubkey, T0 - 10 * DAY)
        .expect("add_key");
    store
        .accept_report(
            &AcceptedReport {
                site: "site-a",
                pubkey: &pubkey,
                seq: 1,
                agent: "vigie-agent 1.0.0",
                facts: "{\"php\":\"8.3\"}",
                files: "{}",
                findings: &[],
            },
            T0 - 300,
        )
        .expect("accept_report");
    store
        .record_result(
            "site-a",
            "tls",
            T0 - 90,
            &RunRecord::concluded(&[])
                .with_duration(std::time::Duration::from_millis(80))
                .with_observed(Some(format!("{{\"tls_not_after\":{}}}", T0 + 40 * DAY))),
        )
        .expect("record_result");
    let hsts = Finding::new(
        "site-a",
        "headers",
        Severity::Warning,
        "hsts",
        "HSTS absent",
    );
    store
        .reconcile(
            "site-a",
            "headers",
            std::slice::from_ref(&hsts),
            T0 - 3 * DAY,
        )
        .expect("reconcile");
    store
        .reconcile("site-a", "headers", &[], T0 - 2 * DAY)
        .expect("reconcile");
    let audit_key = SigningKey::from_bytes(&[33; 32]);
    store
        .set_commands_enabled("site-a", true, T0 - DAY, &audit_key)
        .expect("canal");
    store
        .enqueue_command(
            "site-a",
            CommandKind::Ping,
            Runtime::Php,
            "{}",
            "typologie",
            &vigie::command::uuid_v7(v.clock.unix_ms()).expect("uuid"),
            T0 - DAY,
            false,
            &audit_key,
        )
        .expect("enqueue")
        .expect("en file");
    let signatures = store
        .audit_records("site-a")
        .expect("audit")
        .into_iter()
        .map(|r| r.signature)
        .collect::<Vec<_>>();
    assert!(!signatures.is_empty());
    findings::persist(&mut store, &seeded_analysis()).expect("instantané");
    drop(store);
    open_incident(&v, "exposed", Severity::Critical, "/.env lisible");

    let code = v.code("poste");
    let reply = v.pair_from(PEER, &code).await;
    assert_eq!(reply.status, StatusCode::OK);
    let token = reply.json()["token"].as_str().expect("token").to_owned();
    let seeds = Seeds {
        token,
        code,
        pubkey,
        signatures,
        password,
    };
    (v, seeds)
}

/// Chemins de clés d'une valeur JSON : `a.b`, `a[].c`. `facts` et `observed`
/// (objets plats bornés par `protocole-agent.md`) sont nommés sans leurs
/// clés.
fn key_paths(value: &Value, prefix: &str, out: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                out.insert(path.clone());
                if key != "facts" && key != "observed" {
                    key_paths(child, &path, out);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                key_paths(item, &format!("{prefix}[]"), out);
            }
        }
        _ => {}
    }
}

/// Différences entre l'instantané relu et les clés servies.
fn snapshot_diff(
    expected: &BTreeMap<String, BTreeSet<String>>,
    actual: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<String> {
    let routes: BTreeSet<&String> = expected.keys().chain(actual.keys()).collect();
    let empty = BTreeSet::new();
    let mut diff = Vec::new();
    for route in routes {
        let (want, got) = (
            expected.get(route).unwrap_or(&empty),
            actual.get(route).unwrap_or(&empty),
        );
        diff.extend(
            got.difference(want)
                .map(|k| format!("{route} : clé nouvelle {k}")),
        );
        diff.extend(
            want.difference(got)
                .map(|k| format!("{route} : clé disparue {k}")),
        );
    }
    diff
}

#[tokio::test]
async fn every_route_serves_only_the_reviewed_keys_and_no_seeded_secret() {
    let (v, seeds) = populated().await;
    let token = seeds.token.clone();
    let mut bodies: Vec<(String, Reply)> = Vec::new();
    for (route, path) in [
        ("GET /api/v1/overview", "/api/v1/overview".to_owned()),
        ("GET /api/v1/sites/{id}", "/api/v1/sites/site-a".to_owned()),
        (
            "GET /api/v1/sites/{id}/incidents",
            "/api/v1/sites/site-a/incidents".to_owned(),
        ),
        (
            "GET /api/v1/incidents/{id}",
            "/api/v1/incidents/1".to_owned(),
        ),
        ("GET /api/v1/settings", "/api/v1/settings".to_owned()),
        (
            "GET /api/v1/sites/{id}/logs",
            "/api/v1/sites/site-a/logs".to_owned(),
        ),
        (
            "GET /api/v1/sites/{id}/logs/ips",
            "/api/v1/sites/site-a/logs/ips".to_owned(),
        ),
        ("erreur", "/api/v1/sites/inconnu".to_owned()),
    ] {
        bodies.push((route.to_owned(), v.get(&path, &token).await));
    }
    let open = v.store().open_incidents().expect("incidents")[0].id;
    bodies.push((
        "POST /api/v1/incidents/{id}/ack".to_owned(),
        v.call_from(
            PEER,
            Method::POST,
            &format!("/api/v1/incidents/{open}/ack"),
            &token,
        )
        .await,
    ));

    // Appairage : le jeton sort une fois, ici seulement.
    let pair_code = v.code("second");
    let pair = v.pair_from(PEER, &pair_code).await;
    assert_eq!(pair.status, StatusCode::OK);
    let second_token = pair.json()["token"].as_str().expect("token").to_owned();
    for forbidden in seeds.forbidden(true) {
        assert!(
            !String::from_utf8_lossy(&pair.body).contains(&forbidden),
            "pair : valeur semée {forbidden:.12}…"
        );
    }
    assert!(!String::from_utf8_lossy(&pair.body).contains(&pair_code));

    let mut actual: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut paths = BTreeSet::new();
    key_paths(&pair.json(), "", &mut paths);
    actual.insert("POST /api/v1/pair".into(), paths);
    for (route, reply) in &bodies {
        assert!(
            reply.status.is_success() || route == "erreur",
            "{route} : {}",
            reply.status
        );
        let text = String::from_utf8_lossy(&reply.body);
        assert!(!text.contains(SEEDED_UA), "{route} : user-agent servi");
        let headers = format!("{:?}", reply.headers);
        for forbidden in seeds
            .forbidden(true)
            .into_iter()
            .chain([second_token.clone()])
        {
            assert!(
                !text.contains(&forbidden),
                "{route} : valeur semée {forbidden:.12}…"
            );
            assert!(
                !headers.contains(&forbidden),
                "{route} : valeur semée en en-tête"
            );
        }
        let mut paths = BTreeSet::new();
        key_paths(&reply.json(), "", &mut paths);
        actual.insert(route.clone(), paths);
    }

    if std::env::var_os("VIGIE_WRITE_API_KEYS").is_some() {
        let text = serde_json::to_string_pretty(&actual).expect("json") + "\n";
        std::fs::write(KEYS_FIXTURE, text).expect("instantané");
    }
    let expected: BTreeMap<String, BTreeSet<String>> =
        serde_json::from_str(&std::fs::read_to_string(KEYS_FIXTURE).expect("instantané"))
            .expect("instantané lisible");
    let diff = snapshot_diff(&expected, &actual);
    assert!(
        diff.is_empty(),
        "clés JSON hors de tests/fixtures/api-keys.json, à relire puis enregistrer (VIGIE_WRITE_API_KEYS=1) :\n{}",
        diff.join("\n")
    );

    // Rien de semé au journal non plus, ni aucun en-tête d'autorisation.
    for line in journal() {
        for forbidden in seeds
            .forbidden(true)
            .into_iter()
            .chain([second_token.clone()])
        {
            assert!(!line.contains(&forbidden), "journal : {line}");
        }
        assert!(!line.contains("Bearer"), "journal : {line}");
    }

    // Une clé ajoutée à une route fait échouer la comparaison.
    let mut grown = actual.clone();
    grown
        .get_mut("GET /api/v1/settings")
        .expect("settings")
        .insert("alerts.smtp_host".into());
    assert_eq!(
        snapshot_diff(&expected, &grown),
        ["GET /api/v1/settings : clé nouvelle alerts.smtp_host"]
    );
}

#[tokio::test]
async fn the_detail_of_a_logs_incident_is_sanitized() {
    let v = Veilleur::new();
    let token = v.token_from(PEER, "poste").await;
    open_incident(
        &v,
        "logs",
        Severity::Warning,
        "robot \u{1b}[2J inconnu \u{202e}gnp.exe",
    );
    let reply = v.get("/api/v1/overview", &token).await;
    assert_eq!(reply.status, StatusCode::OK);
    let detail = reply.json()["sites"][0]["worst"]["detail"]
        .as_str()
        .expect("détail")
        .to_owned();
    assert_eq!(detail, "robot \u{fffd}[2J inconnu \u{fffd}gnp.exe");

    // Un autre contrôle garde son texte.
    let other = open_incident(&v, "content", Severity::Warning, "mot-clé\tabsent");
    let reply = v.get(&format!("/api/v1/incidents/{other}"), &token).await;
    assert_eq!(reply.json()["detail"], "mot-clé\tabsent");
}
