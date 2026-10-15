//! `monitor serve` : service systemd `monitor-serve`, publié par Caddy.
//!
//! Phase 1 : seule la route `/health` existe. Tout le reste répond 404 sans
//! corps, pour ne rien dire de l'outil à qui balaie les URL. `/health` publie
//! l'heure du dernier `tick`, sans aucun nom de site : `monitor/scripts/deploy.mjs`
//! en a besoin pour prouver qu'un `tick` du nouveau binaire est passé.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use serde::Serialize;

use crate::store::Store;

/// Au-delà, `tick` est considéré comme arrêté (timer chaque minute).
pub const TICK_MAX_AGE: i64 = 180;

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

struct AppState {
    database: PathBuf,
}

pub fn router(database: PathBuf) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .fallback(|| async { StatusCode::NOT_FOUND })
        .with_state(Arc::new(AppState { database }))
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
            let (code, body) = health(last, crate::now());
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

pub fn run(database: PathBuf, ip: IpAddr, port: u16) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("démarrage du runtime tokio")?;
    runtime.block_on(async move {
        let addr = SocketAddr::new(ip, port);
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("écoute sur {addr} impossible"))?;
        log::info!("serve à l'écoute sur {addr}");
        axum::serve(listener, router(database))
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

    async fn get(database: PathBuf, uri: &str) -> (StatusCode, Vec<u8>) {
        let response = router(database)
            .oneshot(Request::get(uri).body(Body::empty()).expect("request"))
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

    #[tokio::test]
    async fn health_is_200_after_a_recent_tick() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("monitor.db");
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
        let db = dir.path().join("monitor.db");
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
        let db = dir.path().join("monitor.db");
        let (status, body) = get(db.clone(), "/health").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["status"], "never");
        // /health ne crée pas la base : seul `tick` le fait.
        assert!(!db.exists());
    }

    #[tokio::test]
    async fn other_routes_are_a_silent_404() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("monitor.db");
        for uri in ["/", "/admin", "/health/x", "/.env"] {
            let (status, body) = get(db.clone(), uri).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
            assert!(body.is_empty(), "{uri}");
        }
    }
}
