//! `vigie serve` : service systemd `vigie-serve`, publié par Caddy.
//!
//! Trois familles de routes :
//!
//! - `GET /health` publie l'heure du dernier `tick`, sans aucun nom de site :
//!   `vigie/scripts/deploy.mjs` en a besoin pour prouver qu'un `tick` du
//!   nouveau binaire est passé ;
//! - `POST /r/v1/report` reçoit les rapports signés des agents
//!   (`docs/protocole-agent.md`) et n'envoie jamais d'e-mail : `tick` notifie ;
//! - `/api/v1` sert la console, authentifiée par appareil (`api.rs`,
//!   `docs/api-console.md`).
//!
//! Tout le reste, autre route comme autre méthode, et tout rapport refusé
//! reçoivent le même 404 sans corps, pour ne rien dire de l'outil à qui balaie
//! les URL ou sonde le point d'entrée.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::Json;
use axum::Router;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::http::header::CONTENT_LENGTH;
use axum::routing::{get, post};
use serde::Serialize;

use crate::ingest::{self, HEADER_SIGNATURE, HEADER_SITE, Reason, Refusal};
use crate::store::Store;

/// Au-delà, `tick` est considéré comme arrêté (timer chaque minute).
pub const TICK_MAX_AGE: i64 = 180;

/// Taille maximale du corps d'un rapport, en octets.
pub const MAX_REPORT_BYTES: usize = 64 * 1024;
/// Délai de réception du corps entier.
pub const REPORT_BODY_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Health {
    pub status: &'static str,
    pub last_tick: Option<i64>,
    pub age_seconds: Option<i64>,
}

pub fn health(last_tick: Option<i64>, now: i64) -> (StatusCode, Health) {
    match last_tick {
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Health {
                status: "never",
                last_tick: None,
                age_seconds: None,
            },
        ),
        Some(at) => {
            let age = (now - at).max(0);
            let fresh = age < TICK_MAX_AGE;
            (
                if fresh {
                    StatusCode::OK
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                },
                Health {
                    status: if fresh { "ok" } else { "late" },
                    last_tick: Some(at),
                    age_seconds: Some(age),
                },
            )
        }
    }
}

/// Heure courante en secondes Unix ; remplaçable dans les tests.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

pub(crate) struct AppState {
    pub(crate) database: PathBuf,
    /// Identifiants des sites de la configuration.
    pub(crate) sites: Vec<String>,
    pub(crate) clock: Clock,
}

pub fn router(database: PathBuf, sites: Vec<String>) -> Router {
    router_with_clock(database, sites, Arc::new(crate::now))
}

pub fn router_with_clock(database: PathBuf, sites: Vec<String>, clock: Clock) -> Router {
    Router::new()
        .route("/health", get(health_handler).fallback(not_found))
        .route("/r/v1/report", post(report_handler).fallback(not_found))
        .merge(crate::api::routes())
        .fallback(not_found)
        .with_state(Arc::new(AppState {
            database,
            sites,
            clock,
        }))
}

pub(crate) async fn not_found() -> StatusCode {
    StatusCode::NOT_FOUND
}

async fn health_handler(State(state): State<Arc<AppState>>) -> (StatusCode, Json<Health>) {
    let database = state.database.clone();
    let last = tokio::task::spawn_blocking(move || match Store::open_read(&database)? {
        Some(store) => store.last_tick(),
        None => Ok(None),
    })
    .await;
    match last {
        Ok(Ok(last)) => {
            let (code, body) = health(last, (state.clock)());
            (code, Json(body))
        }
        Ok(Err(err)) => {
            log::error!("/health : lecture de la base impossible : {err:#}");
            unavailable()
        }
        Err(err) => {
            log::error!("/health : tâche interrompue : {err}");
            unavailable()
        }
    }
}

fn unavailable() -> (StatusCode, Json<Health>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(Health {
            status: "error",
            last_tick: None,
            age_seconds: None,
        }),
    )
}

/// Journalise un refus et répond le 404 commun à tous les refus.
fn refuse(refusal: Refusal) -> StatusCode {
    if matches!(refusal.reason, Reason::Internal(_)) {
        log::error!("{refusal}");
    } else {
        log::warn!("{refusal}");
    }
    StatusCode::NOT_FOUND
}

/// 204 si le rapport est accepté, 404 sans corps sinon. La raison d'un refus
/// va au journal, avec le site et le `seq` quand ils sont lisibles.
///
/// La taille et le délai sont vérifiés ici plutôt que par des couches
/// `tower-http`, qui répondraient 413 ou 408 au lieu du 404 commun.
async fn report_handler(State(state): State<Arc<AppState>>, request: Request) -> StatusCode {
    let (parts, body) = request.into_parts();
    let header = |name: &str| {
        parts
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let site = header(HEADER_SITE);
    let signature = header(HEADER_SIGNATURE);

    // Taille et délai, avant toute lecture du JSON.
    let announced = header(CONTENT_LENGTH.as_str()).and_then(|v| v.parse::<u64>().ok());
    if announced.is_some_and(|len| len > MAX_REPORT_BYTES as u64) {
        return refuse(Refusal::new(site.as_deref(), Reason::TooLarge));
    }
    let read = axum::body::to_bytes(body, MAX_REPORT_BYTES);
    let bytes = match tokio::time::timeout(REPORT_BODY_TIMEOUT, read).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(err)) => {
            let too_large = err
                .into_inner()
                .downcast_ref::<http_body_util::LengthLimitError>()
                .is_some();
            let reason = if too_large {
                Reason::TooLarge
            } else {
                Reason::Truncated
            };
            return refuse(Refusal::new(site.as_deref(), reason));
        }
        Err(_) => return refuse(Refusal::new(site.as_deref(), Reason::TooSlow)),
    };

    let now = (state.clock)();
    let task_site = site.clone();
    let task_state = Arc::clone(&state);
    let outcome = tokio::task::spawn_blocking(move || {
        ingest::ingest(
            &task_state.database,
            &task_state.sites,
            task_site.as_deref(),
            signature.as_deref(),
            &bytes,
            now,
        )
    })
    .await;
    match outcome {
        Ok(Ok(accepted)) => {
            log::info!(
                "rapport accepté (site {}, seq {})",
                accepted.site,
                accepted.seq
            );
            StatusCode::NO_CONTENT
        }
        Ok(Err(refusal)) => refuse(refusal),
        Err(err) => refuse(Refusal::new(
            site.as_deref(),
            Reason::Internal(format!("tâche interrompue : {err}")),
        )),
    }
}

pub fn run(database: PathBuf, sites: Vec<String>, ip: IpAddr, port: u16) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("démarrage du runtime tokio")?;
    // Une base existante est migrée dès le démarrage, sans attendre le
    // prochain `tick` : `/api/v1` en a besoin. `serve` ne crée pas la base.
    if database.is_file()
        && let Err(err) = Store::open(&database)
    {
        log::error!("migration de la base au démarrage impossible : {err:#}");
    }
    runtime.block_on(async move {
        let addr = SocketAddr::new(ip, port);
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("écoute sur {addr} impossible"))?;
        log::info!("serve à l'écoute sur {addr}");
        axum::serve(listener, router(database, sites))
            .with_graceful_shutdown(shutdown_signal())
            .await
            .context("serveur HTTP")
    })
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    log::info!("arrêt demandé");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[test]
    fn health_thresholds() {
        assert_eq!(health(None, 1_000).0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(health(Some(1_000), 1_000).0, StatusCode::OK);
        assert_eq!(
            health(Some(1_000), 1_000 + TICK_MAX_AGE - 1).0,
            StatusCode::OK
        );
        assert_eq!(
            health(Some(1_000), 1_000 + TICK_MAX_AGE).0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        // Horloge du tick en avance : pas d'âge négatif.
        assert_eq!(health(Some(1_100), 1_000).1.age_seconds, Some(0));
    }

    async fn send(database: PathBuf, request: Request<Body>) -> (StatusCode, Vec<u8>) {
        let response = router(database, vec!["site-a".into()])
            .oneshot(request)
            .await
            .expect("response");
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        (status, body.to_vec())
    }

    async fn get(database: PathBuf, uri: &str) -> (StatusCode, Vec<u8>) {
        send(
            database,
            Request::get(uri).body(Body::empty()).expect("request"),
        )
        .await
    }

    #[tokio::test]
    async fn health_is_200_after_a_recent_tick() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("vigie.db");
        let now = crate::now();
        Store::open(&db)
            .expect("open")
            .record_tick(now)
            .expect("tick");
        let (status, body) = get(db, "/health").await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["status"], "ok");
        assert_eq!(json["last_tick"], now);
    }

    #[tokio::test]
    async fn health_is_503_after_an_old_tick() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("vigie.db");
        Store::open(&db)
            .expect("open")
            .record_tick(crate::now() - TICK_MAX_AGE - 1)
            .expect("tick");
        let (status, body) = get(db, "/health").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["status"], "late");
    }

    #[tokio::test]
    async fn health_is_503_without_any_tick() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("vigie.db");
        let (status, body) = get(db.clone(), "/health").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["status"], "never");
        // /health ne crée pas la base : seul `tick` le fait.
        assert!(!db.exists());
    }

    #[tokio::test]
    async fn other_routes_and_methods_are_a_silent_404() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("vigie.db");
        for uri in [
            "/",
            "/admin",
            "/health/x",
            "/.env",
            "/r/v1/report",
            "/r/v1",
            "/api/v1",
            "/api/v1/pair",
            "/api/v1/inconnu",
        ] {
            let (status, body) = get(db.clone(), uri).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
            assert!(body.is_empty(), "{uri}");
        }
        let post_health = Request::post("/health")
            .body(Body::empty())
            .expect("request");
        let (status, body) = send(db.clone(), post_health).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.is_empty());
        // Rapport sans en-têtes : refusé sans créer la base.
        let report = Request::post("/r/v1/report")
            .body(Body::from("{}"))
            .expect("request");
        let (status, body) = send(db.clone(), report).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.is_empty());
        assert!(!db.exists());
    }
}
