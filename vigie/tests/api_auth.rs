//! Appairage et authentification de `/api/v1` (`docs/api-console.md`), sur le
//! routeur de `serve` et une horloge réglable.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

#[path = "support/veilleur.rs"]
mod veilleur;

use vigie::clock::{Clock, FakeClock};
use vigie::device::{self, PAIRING_TTL};
use vigie::serve;
use vigie::store::Store;

const T0: i64 = 1_792_000_000;

struct Veilleur {
    _dir: tempfile::TempDir,
    db: PathBuf,
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

    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("json")
    }
}

impl Veilleur {
    /// Base migrée au dernier schéma, comme après le démarrage de `serve`.
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("vigie.db");
        Store::open(&db).expect("open");
        Self::at(dir, db)
    }

    fn without_database() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("vigie.db");
        Self::at(dir, db)
    }

    fn at(dir: tempfile::TempDir, db: PathBuf) -> Self {
        Self {
            _dir: dir,
            db,
            clock: Arc::new(FakeClock::new(T0)),
        }
    }

    fn advance(&self, seconds: i64) {
        self.clock.advance(seconds);
    }

    fn now(&self) -> i64 {
        self.clock.unix()
    }

    /// Ce que fait `vigie device pair` : un code, son empreinte en base.
    fn pairing(&self, name: &str) -> String {
        let code = device::new_code().expect("code");
        let now = self.now();
        Store::open(&self.db)
            .expect("open")
            .create_pairing(&device::hash(&code), name, now, now + PAIRING_TTL)
            .expect("pairing");
        code
    }

    async fn send(&self, request: Request<Body>) -> Reply {
        let router = serve::router_with_clock(
            veilleur::config(self.db.clone()),
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

    async fn pair(&self, body: impl Into<Body>) -> Reply {
        self.send(
            Request::post("/api/v1/pair")
                .header("content-type", "application/json")
                .body(body.into())
                .expect("request"),
        )
        .await
    }

    async fn pair_code(&self, code: &str) -> Reply {
        self.pair(serde_json::json!({ "code": code }).to_string())
            .await
    }

    async fn overview(&self, authorization: Option<&str>) -> Reply {
        let mut request = Request::get("/api/v1/overview");
        if let Some(value) = authorization {
            request = request.header("authorization", value);
        }
        self.send(request.body(Body::empty()).expect("request"))
            .await
    }

    fn device_count(&self) -> usize {
        Store::open(&self.db)
            .expect("open")
            .devices()
            .expect("devices")
            .len()
    }
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
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
async fn a_code_gives_a_token_once_and_the_token_opens_the_api() {
    let v = Veilleur::new();
    Store::open(&v.db)
        .expect("open")
        .record_tick(T0 - 30)
        .expect("tick");
    let code = v.pairing("téléphone");

    let reply = v.pair_code(&code).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.cache_control.as_deref(), Some("no-store"));
    let json = reply.json();
    let token = json["token"].as_str().expect("token").to_owned();
    assert_eq!(json["name"], "téléphone");
    assert_eq!(json["device_id"], 1);
    assert_eq!(token.len(), 43);

    // Rejoué : 401, aucun nouvel appareil, et le jeton remis reste valable.
    let replay = v.pair_code(&code).await;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
    replay.assert_api_error("");
    assert_eq!(v.device_count(), 1);

    let reply = v.overview(Some(&bearer(&token))).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.cache_control.as_deref(), Some("no-store"));
    let json = reply.json();
    assert_eq!(json["server_time"], T0);
    assert_eq!(json["last_tick"], T0 - 30);

    // « Vu le » est posé par la requête authentifiée.
    let store = Store::open(&v.db).expect("open");
    assert_eq!(store.devices().expect("devices")[0].seen_at, Some(T0));

    // Aucun secret en clair dans la base ni dans son journal.
    drop(store);
    let bytes = database_bytes(&v.db);
    assert!(!contains(&bytes, &token), "jeton en clair dans la base");
    assert!(!contains(&bytes, &code), "code en clair dans la base");
}

#[tokio::test]
async fn an_expired_code_gives_nothing() {
    let v = Veilleur::new();
    let code = v.pairing("pc");
    v.advance(PAIRING_TTL);
    let reply = v.pair_code(&code).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    reply.assert_api_error("");
    assert_eq!(v.device_count(), 0);
}

#[tokio::test]
async fn a_code_one_second_before_expiry_still_works() {
    let v = Veilleur::new();
    let code = v.pairing("pc");
    v.advance(PAIRING_TTL - 1);
    assert_eq!(v.pair_code(&code).await.status, StatusCode::OK);
}

#[tokio::test]
async fn bad_pairing_requests_get_the_same_401() {
    let v = Veilleur::new();
    let code = v.pairing("pc");
    let oversized = format!(
        "{{\"code\":\"{code}\",\"pad\":\"{}\"}}",
        "x".repeat(vigie::api::MAX_PAIR_BYTES)
    );
    for body in [
        String::new(),
        "pas du json".into(),
        "{}".into(),
        "{\"code\":\"\"}".into(),
        format!(
            "{{\"code\":\"{}\"}}",
            "a".repeat(device::MAX_SECRET_LEN + 1)
        ),
        "{\"code\":\"inconnu\"}".into(),
        oversized,
    ] {
        let reply = v.pair(body.clone()).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{body:.40}");
        reply.assert_api_error(&format!("{body:.40}"));
    }
    assert_eq!(v.device_count(), 0);
    // Le code n'a pas été consommé par ces essais.
    assert_eq!(v.pair_code(&code).await.status, StatusCode::OK);
}

#[tokio::test]
async fn overview_needs_an_active_token() {
    let v = Veilleur::new();
    let code = v.pairing("pc");
    let token = v.pair_code(&code).await.json()["token"]
        .as_str()
        .expect("token")
        .to_owned();

    for authorization in [
        None,
        Some(String::new()),
        Some("Bearer ".into()),
        Some(format!("Basic {token}")),
        Some(format!("bearer{token}")),
        Some(bearer("inconnu")),
        Some(bearer(&format!("{token}x"))),
    ] {
        let reply = v.overview(authorization.as_deref()).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{authorization:?}");
        reply.assert_api_error(&format!("{authorization:?}"));
    }
    assert_eq!(
        v.overview(Some(&bearer(&token))).await.status,
        StatusCode::OK
    );

    let id = Store::open(&v.db)
        .expect("open")
        .devices()
        .expect("devices")[0]
        .id;
    Store::open(&v.db)
        .expect("open")
        .revoke_device(id, v.now())
        .expect("revoke");
    let reply = v.overview(Some(&bearer(&token))).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    reply.assert_api_error("");
}

#[tokio::test]
async fn the_api_never_creates_the_database() {
    let v = Veilleur::without_database();
    assert_eq!(v.pair_code("code").await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        v.overview(Some(&bearer("jeton"))).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert!(!v.db.exists());
}

/// Pendant un déploiement, l'ancien `serve` garde son binaire face à une base
/// que le nouveau `tick` a déjà migrée : ses écritures doivent passer.
#[tokio::test]
async fn a_newer_schema_still_pairs_and_authenticates() {
    let v = Veilleur::new();
    let code = v.pairing("téléphone");
    let conn = rusqlite::Connection::open(&v.db).expect("raw");
    conn.pragma_update(None, "user_version", 7).expect("bump");
    drop(conn);

    let reply = v.pair_code(&code).await;
    assert_eq!(reply.status, StatusCode::OK);
    let token = reply.json()["token"].as_str().expect("token").to_owned();
    let reply = v.overview(Some(&bearer(&token))).await;
    assert_eq!(reply.status, StatusCode::OK);

    let store = Store::open_read(&v.db).expect("open_read").expect("base");
    assert_eq!(store.schema_version().expect("version"), 7);
    let devices = store.devices().expect("devices");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].seen_at, Some(T0));
}

#[tokio::test]
async fn health_and_report_routes_are_unchanged() {
    let v = Veilleur::new();
    Store::open(&v.db)
        .expect("open")
        .record_tick(T0 - 10)
        .expect("tick");
    let health = v
        .send(
            Request::get("/health")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
    assert_eq!(health.status, StatusCode::OK);
    assert_eq!(health.json()["status"], "ok");
    // Rapport sans signature : le 404 commun, pas un 401.
    let report = v
        .send(
            Request::post("/r/v1/report")
                .body(Body::from("{}"))
                .expect("request"),
        )
        .await;
    assert_eq!(report.status, StatusCode::NOT_FOUND);
    assert!(report.body.is_empty());
    // Une méthode inconnue sur l'API : 404 aussi.
    let get_pair = v
        .send(
            Request::get("/api/v1/pair")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
    assert_eq!(get_pair.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn every_response_carries_its_own_request_id() {
    let v = Veilleur::new();
    let code = v.pairing("pc");
    let token = v.pair_code(&code).await.json()["token"]
        .as_str()
        .expect("token")
        .to_owned();
    let first = v.overview(Some(&bearer(&token))).await;
    let second = v.overview(Some(&bearer(&token))).await;
    assert_eq!(first.status, StatusCode::OK);
    let (a, b) = (
        first.request_id.expect("id"),
        second.request_id.expect("id"),
    );
    assert_eq!(a.len(), 32);
    assert_ne!(a, b);
    // Le 404 muet du point d'entrée des agents porte l'en-tête, rien d'autre.
    let report = v
        .send(
            Request::post("/r/v1/report")
                .body(Body::from("{}"))
                .expect("request"),
        )
        .await;
    assert!(report.body.is_empty());
    assert!(report.request_id.is_some());
}

#[tokio::test]
async fn an_incoming_request_id_is_ignored() {
    let v = Veilleur::new();
    let reply = v
        .send(
            Request::get("/api/v1/overview")
                .header("x-request-id", "0123456789abcdef0123456789abcdef")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    reply.assert_api_error("jeton absent");
    assert_ne!(
        reply.request_id.as_deref(),
        Some("0123456789abcdef0123456789abcdef")
    );
}
