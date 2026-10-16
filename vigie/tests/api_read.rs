//! Routes de lecture et d'acquittement de `/api/v1` (`docs/api-console.md`),
//! sur le routeur de `serve`, une base remplie à la main et une horloge fixe.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

#[path = "support/veilleur.rs"]
mod veilleur;

use vigie::alert::MemoryNotifier;
use vigie::checks::CheckKind;
use vigie::clock::{Clock, FakeClock};
use vigie::config::{Api, Config, Site, SiteKind};
use vigie::device::{self, PAIRING_TTL};
use vigie::finding::{Finding, Severity};
use vigie::serve;
use vigie::store::{AcceptedReport, REMINDER_PERIOD, ReportOutcome, RunRecord, Store};
use vigie::tick::{self, Options};

const T0: i64 = 1_792_000_000;
const DAY: i64 = 86_400;
/// Plancher de l'intervalle de tls et headers (`checks::SLOW_INTERVAL`).
const SLOW: i64 = 3600;

struct Veilleur {
    _dir: tempfile::TempDir,
    config: Config,
    clock: Arc<FakeClock>,
}

struct Reply {
    status: StatusCode,
    cache_control: Option<String>,
    request_id: Option<String>,
    body: Vec<u8>,
}

impl Reply {
    /// Erreur au format commun : code attendu pour le statut, request_id
    /// égal à l'en-tête `X-Request-Id`, aucune cause exposée.
    fn assert_api_error(&self, context: &str) {
        let code = match self.status.as_u16() {
            401 => "unauthorized",
            404 => "not_found",
            409 => "conflict",
            429 => "too_many_requests",
            500 => "internal",
            other => panic!("{context} : statut {other} sans code d'erreur"),
        };
        let json: serde_json::Value = serde_json::from_slice(&self.body).expect("json");
        let error = json["error"].as_object().expect("error");
        assert_eq!(error.len(), 3, "{context}");
        assert_eq!(json["error"]["code"], code, "{context}");
        assert_eq!(
            json["error"]["request_id"].as_str(),
            self.request_id.as_deref(),
            "{context}"
        );
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("json")
    }
}

fn site(id: &str, kind: SiteKind, interval: u64) -> Site {
    Site {
        id: id.into(),
        url: format!("https://{id}.example.org/"),
        kind,
        runtime: None,
        keyword_url: None,
        keyword: None,
        interval,
        agent_silence: 900,
        logs: None,
    }
}

impl Veilleur {
    /// Le seul site A de `support/veilleur.rs`, base migrée.
    fn new() -> Self {
        Self::with(|_| {})
    }

    /// Configuration de test retouchée par `edit`, base migrée.
    fn with(edit: impl FnOnce(&mut Config)) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = veilleur::config(dir.path().join("vigie.db"));
        edit(&mut config);
        Store::open(&config.database).expect("open");
        Self {
            _dir: dir,
            config,
            clock: Arc::new(FakeClock::new(T0)),
        }
    }

    fn db(&self) -> &Path {
        &self.config.database
    }

    fn store(&self) -> Store {
        Store::open(self.db()).expect("open")
    }

    fn now(&self) -> i64 {
        self.clock.unix()
    }

    /// Appareil appairé comme par la console : son jeton.
    async fn token(&self, name: &str) -> String {
        let code = device::new_code().expect("code");
        let now = self.now();
        self.store()
            .create_pairing(&device::hash(&code), name, now, now + PAIRING_TTL)
            .expect("pairing");
        let reply = self
            .send(
                Request::post("/api/v1/pair")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::json!({ "code": code }).to_string()))
                    .expect("request"),
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK);
        reply.json()["token"].as_str().expect("token").to_owned()
    }

    async fn send(&self, request: Request<Body>) -> Reply {
        let router = serve::router_with_clock(
            self.config.clone(),
            Arc::clone(&self.clock) as Arc<dyn Clock>,
        );
        let response = router.oneshot(request).await.expect("response");
        let status = response.status();
        let cache_control = response
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let request_id = response
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes()
            .to_vec();
        Reply {
            status,
            cache_control,
            request_id,
            body,
        }
    }

    async fn call(&self, method: Method, path: &str, token: &str) -> Reply {
        self.send(
            Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
    }

    async fn get(&self, path: &str, token: &str) -> Reply {
        let reply = self.call(Method::GET, path, token).await;
        if reply.status == StatusCode::OK {
            assert_eq!(reply.cache_control.as_deref(), Some("no-store"), "{path}");
        }
        reply
    }

    /// Ouvre un incident par un constat du contrôle `check`. Le passage est
    /// complet : il clôt les autres incidents ouverts de ce contrôle.
    fn open(&self, site: &str, check: &str, severity: Severity, key: &str, at: i64) -> i64 {
        let finding = Finding::new(site, check, severity, key, format!("constat {key}"));
        let mut store = self.store();
        store
            .reconcile(site, check, std::slice::from_ref(&finding), at)
            .expect("reconcile");
        store
            .open_incidents()
            .expect("incidents")
            .into_iter()
            .find(|i| i.key == finding.incident_key())
            .expect("incident ouvert")
            .id
    }

    /// Passage concluant sans constat de chaque contrôle externe du site.
    fn all_clear(&self, site: &str, at: i64) {
        let site = self
            .config
            .sites
            .iter()
            .find(|s| s.id == site)
            .expect("site")
            .clone();
        let mut store = self.store();
        for kind in CheckKind::ALL.into_iter().filter(|k| k.applies(&site)) {
            store
                .record_result(&site.id, kind.name(), at, &RunRecord::concluded(&[]))
                .expect("record_result");
        }
    }
}

/// Octets de la base et de son journal WAL.
fn database_bytes(db: &Path) -> Vec<u8> {
    let mut bytes = std::fs::read(db).expect("base");
    let mut wal = db.as_os_str().to_owned();
    wal.push("-wal");
    if let Ok(more) = std::fs::read(PathBuf::from(wal)) {
        bytes.extend(more);
    }
    bytes
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

#[tokio::test]
async fn overview_orders_sites_by_state_then_configuration() {
    let v = Veilleur::with(|config| {
        config.sites = ["site-a", "site-b", "site-c", "site-d", "site-e", "site-f"]
            .into_iter()
            .map(|id| site(id, SiteKind::Generic, 300))
            .collect();
    });
    // A : tout est passé sans constat.
    v.all_clear("site-a", T0 - 60);
    // B : critique ouvert.
    v.all_clear("site-b", T0 - 60);
    v.open("site-b", "headers", Severity::Warning, "hsts", T0 - 2 * DAY);
    let critical = v.open("site-b", "exposed", Severity::Critical, ".env", T0 - DAY);
    // C : silence d'agent, critique mais qui ne rend pas le site non conforme.
    v.open(
        "site-c",
        "heartbeat",
        Severity::Critical,
        "silence",
        T0 - 600,
    );
    // D : avertissement ouvert.
    v.open("site-d", "headers", Severity::Warning, "hsts", T0 - 600);
    // E : rien n'est connu.
    // F : un contrôle non concluant, sans incident.
    v.all_clear("site-f", T0 - 60);
    v.store()
        .record_result(
            "site-f",
            "tls",
            T0 - 30,
            &RunRecord::failed("délai dépassé"),
        )
        .expect("record_result");
    v.store().record_tick(T0 - 30).expect("tick");

    let token = v.token("pc").await;
    let reply = v.get("/api/v1/overview", &token).await;
    assert_eq!(reply.status, StatusCode::OK);
    let json = reply.json();
    assert_eq!(json["server_time"], T0);
    assert_eq!(json["last_tick"], T0 - 30);
    let sites = json["sites"].as_array().expect("sites");
    let order: Vec<(&str, &str)> = sites
        .iter()
        .map(|s| (s["id"].as_str().unwrap(), s["state"].as_str().unwrap()))
        .collect();
    assert_eq!(
        order,
        [
            ("site-b", "non_compliant"),
            ("site-c", "blind"),
            ("site-d", "to_check"),
            ("site-f", "to_check"),
            ("site-e", "first_read"),
            ("site-a", "ok"),
        ]
    );

    let b = &sites[0];
    assert_eq!(b["open_count"], 2);
    assert_eq!(b["worst"]["id"], critical);
    assert_eq!(b["worst"]["severity"], "critical");
    assert_eq!(b["worst"]["state"], "open");
    assert_eq!(b["kind"], "generic");
    assert_eq!(b["url"], "https://site-b.example.org/");
    assert_eq!(b["last_read"], T0 - 60);
    // Première lecture : aucune valeur inventée.
    let e = &sites[4];
    assert_eq!(e["open_count"], 0);
    assert_eq!(e["worst"], Value::Null);
    assert_eq!(e["last_read"], Value::Null);
    assert_eq!(sites[3]["last_read"], T0 - 30);
}

#[tokio::test]
async fn a_site_on_first_read_shows_its_checks_without_any_value() {
    let v = Veilleur::new();
    let token = v.token("pc").await;
    let json = v.get("/api/v1/sites/site-a", &token).await.json();
    assert_eq!(json["id"], "site-a");
    assert_eq!(json["state"], "first_read");
    assert_eq!(json["last_read"], Value::Null);
    assert_eq!(json["agent"], Value::Null);
    assert_eq!(json["interval"], 300);
    assert_eq!(json["agent_silence"], 900);
    assert_eq!(json["open_incidents"], serde_json::json!([]));
    let checks = json["checks"].as_array().expect("checks");
    let names: Vec<&str> = checks.iter().map(|c| c["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["content", "exposed", "tls", "headers"]);
    for check in checks {
        for field in [
            "last_run",
            "result",
            "severity",
            "detail",
            "duration_ms",
            "observed",
        ] {
            assert_eq!(check[field], Value::Null, "{field} : {check}");
        }
    }
    assert_eq!(checks[0]["interval"], 300);
    // tls et headers ne passent pas plus d'une fois par heure.
    assert_eq!(checks[2]["interval"], SLOW);

    // Un passage avec ses valeurs observées.
    v.store()
        .record_result(
            "site-a",
            "content",
            T0 - 60,
            &RunRecord::concluded(&[])
                .with_duration(std::time::Duration::from_millis(120))
                .with_observed(Some("{\"http_status\":200}".into())),
        )
        .expect("record_result");
    let json = v.get("/api/v1/sites/site-a", &token).await.json();
    assert_eq!(json["state"], "ok");
    assert_eq!(json["last_read"], T0 - 60);
    let content = &json["checks"][0];
    assert_eq!(content["last_run"], T0 - 60);
    assert_eq!(content["result"], "ok");
    assert_eq!(content["duration_ms"], 120);
    assert_eq!(content["observed"]["http_status"], 200);
}

#[tokio::test]
async fn a_site_with_an_agent_shows_its_report_and_agent_checks() {
    let v = Veilleur::new();
    let pubkey = [7u8; 32];
    v.store()
        .add_key("site-a", &pubkey, T0 - DAY)
        .expect("add_key");
    let findings = [Finding::new(
        "site-a",
        "agent:core",
        Severity::Warning,
        "maj",
        "mise à jour disponible",
    )];
    let outcome = v
        .store()
        .accept_report(
            &AcceptedReport {
                site: "site-a",
                pubkey: &pubkey,
                seq: 1,
                agent: "vigie-agent 1.0.0",
                facts: "{\"php\":\"8.3\"}",
                files: "{}",
                findings: &findings,
            },
            T0 - 120,
        )
        .expect("accept_report");
    assert_eq!(outcome, ReportOutcome::Accepted);

    let token = v.token("pc").await;
    let json = v.get("/api/v1/sites/site-a", &token).await.json();
    assert_eq!(json["state"], "to_check");
    assert_eq!(json["last_read"], T0 - 120);
    assert_eq!(json["agent"]["declared_at"], T0 - DAY);
    assert_eq!(json["agent"]["last_report_at"], T0 - 120);
    assert_eq!(json["agent"]["agent"], "vigie-agent 1.0.0");
    assert_eq!(json["agent"]["facts"]["php"], "8.3");
    assert_eq!(json["open_incidents"][0]["check"], "agent:core");

    let checks = json["checks"].as_array().expect("checks");
    let heartbeat = checks
        .iter()
        .find(|c| c["name"] == "heartbeat")
        .expect("heartbeat");
    assert_eq!(heartbeat["interval"], 900);
    let core = checks
        .iter()
        .find(|c| c["name"] == "agent:core")
        .expect("agent:core");
    assert_eq!(core["interval"], Value::Null);
    assert_eq!(core["last_run"], T0 - 120);
    assert_eq!(core["result"], "finding");
    assert_eq!(core["severity"], "warning");
    assert_eq!(core["detail"], "mise à jour disponible");
}

#[tokio::test]
async fn unknown_sites_and_incidents_get_a_404() {
    let v = Veilleur::new();
    let token = v.token("pc").await;
    for (method, path) in [
        (Method::GET, "/api/v1/sites/inconnu"),
        (Method::GET, "/api/v1/sites/inconnu/incidents"),
        (Method::GET, "/api/v1/incidents/999"),
        (Method::GET, "/api/v1/incidents/abc"),
        (Method::POST, "/api/v1/incidents/999/ack"),
        (Method::POST, "/api/v1/incidents/abc/ack"),
        (Method::GET, "/api/v1/incidents/1/ack"),
        (Method::GET, "/api/v1/devices/self"),
    ] {
        let reply = v.call(method.clone(), path, &token).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{method} {path}");
        reply.assert_api_error(&format!("{method} {path}"));
    }
    // Sans jeton, toujours 401 : l'existence d'un site ne se devine pas.
    let reply = v
        .send(
            Request::get("/api/v1/sites/site-a")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn site_incidents_lists_what_closed_in_the_last_30_days() {
    let v = Veilleur::new();
    let old = v.open(
        "site-a",
        "exposed",
        Severity::Critical,
        "old",
        T0 - 40 * DAY,
    );
    let recent = v.open(
        "site-a",
        "headers",
        Severity::Warning,
        "recent",
        T0 - 10 * DAY,
    );
    let mut store = v.store();
    store
        .reconcile("site-a", "exposed", &[], T0 - 31 * DAY)
        .expect("clôture ancienne");
    store
        .reconcile("site-a", "headers", &[], T0 - DAY)
        .expect("clôture récente");
    drop(store);
    let still_open = v.open("site-a", "tls", Severity::Warning, "open", T0 - DAY);

    let token = v.token("pc").await;
    let json = v.get("/api/v1/sites/site-a/incidents", &token).await.json();
    assert_eq!(json["site"], "site-a");
    assert_eq!(json["since"], T0 - 30 * DAY);
    let ids: Vec<i64> = json["incidents"]
        .as_array()
        .expect("incidents")
        .iter()
        .map(|i| i["id"].as_i64().unwrap())
        .collect();
    assert_eq!(ids, [recent]);
    assert_eq!(json["incidents"][0]["state"], "closed");
    assert_eq!(json["incidents"][0]["closed_at"], T0 - DAY);
    assert!(!ids.contains(&old) && !ids.contains(&still_open));
}

#[tokio::test]
async fn an_acked_incident_gets_no_more_reminders() {
    // Contrôles faits et intervalle d'un jour : le tick n'envoie aucune requête.
    let v =
        Veilleur::with(|config| config.sites = vec![site("site-a", SiteKind::Generic, DAY as u64)]);
    let acked = v.open("site-a", "exposed", Severity::Critical, ".env", T0 - 60);
    let other = v.open("site-a", "headers", Severity::Warning, "hsts", T0 - 60);
    for id in [acked, other] {
        v.store().mark_open_notified(id, T0 - 60).expect("notifié");
    }

    let token = v.token("pc").await;
    let path = format!("/api/v1/incidents/{acked}/ack");
    let reply = v.call(Method::POST, &path, &token).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.cache_control.as_deref(), Some("no-store"));
    let json = reply.json();
    assert_eq!(json["id"], acked);
    assert_eq!(json["state"], "acked");
    assert_eq!(json["acked_at"], T0);
    assert_eq!(json["closed_at"], Value::Null);
    // Rejoué : même réponse, la date d'acquittement ne bouge pas.
    v.clock.advance(30);
    let again = v.call(Method::POST, &path, &token).await;
    assert_eq!(again.status, StatusCode::OK);
    assert_eq!(again.json()["acked_at"], T0);
    let detail = v
        .get(&format!("/api/v1/incidents/{acked}"), &token)
        .await
        .json();
    assert_eq!(detail["state"], "acked");
    assert_eq!(detail["open_notified_at"], T0 - 60);

    let later = T0 - 60 + REMINDER_PERIOD;
    {
        let mut store = v.store();
        for kind in CheckKind::ALL {
            store
                .record_run("site-a", kind.name(), later)
                .expect("record_run");
        }
    }
    let mail = MemoryNotifier::new();
    tick::run_with(&v.config, later, &Options::default(), &mail).expect("tick");
    let sent = mail.take();
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert!(
        sent[0].body.contains(&format!("Incident n° {other}")),
        "{sent:?}"
    );
    let store = v.store();
    assert_eq!(
        store.incident(acked).unwrap().unwrap().last_reminder_at,
        None
    );
    assert_eq!(
        store.incident(other).unwrap().unwrap().last_reminder_at,
        Some(later)
    );
}

#[tokio::test]
async fn acking_a_closed_incident_is_a_conflict_that_writes_nothing() {
    let v = Veilleur::new();
    let id = v.open("site-a", "exposed", Severity::Critical, ".env", T0 - DAY);
    v.store()
        .reconcile("site-a", "exposed", &[], T0 - 60)
        .expect("clôture");
    let token = v.token("pc").await;
    // La première requête pose « vu le » ; la seconde n'écrit rien et, en
    // fermant la dernière connexion, vide le journal WAL dans la base.
    for _ in 0..2 {
        assert_eq!(
            v.get("/api/v1/overview", &token).await.status,
            StatusCode::OK
        );
    }
    let before = database_bytes(v.db());
    let reply = v
        .call(Method::POST, &format!("/api/v1/incidents/{id}/ack"), &token)
        .await;
    assert_eq!(reply.status, StatusCode::CONFLICT);
    reply.assert_api_error("");
    assert_eq!(database_bytes(v.db()), before);
    assert_eq!(v.store().incident(id).unwrap().unwrap().acked_at, None);
}

#[tokio::test]
async fn settings_show_the_configuration_without_any_secret() {
    let v = Veilleur::with(|config| {
        config.api = Some(Api {
            public_url: "https://vigie.example.org".into(),
        });
        config.sites.push(site("site-b", SiteKind::Wordpress, 600));
    });
    v.store()
        .add_key("site-b", &[9u8; 32], T0)
        .expect("add_key");
    let other = v.token("téléphone").await;
    let token = v.token("pc").await;

    let reply = v.get("/api/v1/settings", &token).await;
    assert_eq!(reply.status, StatusCode::OK);
    let json = reply.json();
    assert_eq!(json["alerts"]["to"], "a***@e***.org");
    assert_eq!(json["alerts"].as_object().expect("alerts").len(), 1);
    assert_eq!(json["reminder_period"], REMINDER_PERIOD);
    assert_eq!(json["public_url"], "https://vigie.example.org");

    let sites = json["sites"].as_array().expect("sites");
    assert_eq!(sites.len(), 2);
    assert_eq!(sites[0]["agent"], false);
    assert_eq!(sites[1]["agent"], true);
    assert_eq!(sites[1]["kind"], "wordpress");
    assert_eq!(sites[1]["runtime"], "php", "impliqué par le CMS");
    assert!(sites[0]["runtime"].is_null(), "generic sans runtime");
    assert_eq!(
        sites[1]["checks"],
        serde_json::json!({
            "content": 600, "exposed": 600, "headers": SLOW, "installer": 600, "tls": SLOW
        })
    );

    let devices = json["devices"].as_array().expect("devices");
    let current: Vec<(&str, bool)> = devices
        .iter()
        .map(|d| (d["name"].as_str().unwrap(), d["current"].as_bool().unwrap()))
        .collect();
    assert_eq!(current, [("téléphone", false), ("pc", true)]);

    for secret in [
        token.as_str(),
        other.as_str(),
        "alertes@",
        "@example.org",
        "smtp",
        "password",
        "vigie@example.org",
        "token",
    ] {
        assert!(!contains(&reply.body, secret), "« {secret} » dans {json}");
    }
}

#[tokio::test]
async fn a_device_revokes_itself_and_its_token_stops_working() {
    let v = Veilleur::new();
    let other = v.token("téléphone").await;
    let token = v.token("pc").await;

    let reply = v.call(Method::DELETE, "/api/v1/devices/self", &token).await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert!(reply.body.is_empty());

    let reply = v.get("/api/v1/overview", &token).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    reply.assert_api_error("");
    assert_eq!(
        v.call(Method::DELETE, "/api/v1/devices/self", &token)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );

    let devices = v.store().devices().expect("devices");
    let pc = devices.iter().find(|d| d.name == "pc").expect("pc");
    let phone = devices
        .iter()
        .find(|d| d.name == "téléphone")
        .expect("téléphone");
    assert_eq!(pc.revoked_at, Some(T0));
    assert_eq!(phone.revoked_at, None);
    // L'autre appareil n'est pas touché.
    assert_eq!(
        v.get("/api/v1/overview", &other).await.status,
        StatusCode::OK
    );
}
