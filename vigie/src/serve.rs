//! `vigie serve` : service systemd `vigie-serve`, publié par Caddy.
//!
//! Trois familles de routes :
//!
//! - `GET /health` publie l'heure du dernier `tick`, sans aucun nom de site :
//!   `vigie/scripts/deploy.mjs` en a besoin pour prouver qu'un `tick` du
//!   nouveau binaire est passé ;
//! - `POST /r/v1/report` reçoit les rapports signés des agents
//!   (`docs/protocole-agent.md`) et n'envoie jamais d'e-mail : `tick` notifie ;
//! - `POST /r/v1/commands` sert à l'agent sa commande signée et reçoit le
//!   résultat de la précédente (`command/pull.rs`,
//!   `docs/protocole-commandes.md`), fermé tant que `[commands]` manque ;
//! - `POST /r/v1/logs` reçoit les lots de logs signés des agents
//!   (`logs/receive.rs`, `docs/logs.md`), fermé pour un site sans
//!   `[sites.logs] source` ;
//! - `/api/v1` sert la console, authentifiée par appareil (`api.rs`,
//!   `docs/api-console.md`).
//!
//! Tout le reste, autre route comme autre méthode, et tout rapport refusé
//! reçoivent le même 404 sans corps, pour ne rien dire de l'outil à qui balaie
//! les URL ou sonde le point d'entrée.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
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

use crate::clock::{Clock, SystemClock};
use crate::config::{Config, TypologyRecord};
use crate::ingest::{self, HEADER_SIGNATURE, HEADER_SITE, Reason, Refusal};
use crate::store::{META_TYPOLOGY_SERVE, Store};
use crate::writer::Writer;

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

pub(crate) struct AppState {
    /// Configuration lue au démarrage : la console en publie une partie.
    pub(crate) config: Config,
    /// Identifiants des sites de la configuration, dans son ordre.
    pub(crate) site_ids: Vec<String>,
    pub(crate) clock: Arc<dyn Clock>,
    /// Seule connexion qui écrit dans `serve`. À n'appeler que depuis
    /// `spawn_blocking` : `serve` tourne sur un runtime à un seul thread.
    pub(crate) writer: Writer,
    /// Fichier de configuration, relu à chaque retrait de commande : `serve`
    /// ne lit sinon la configuration qu'à son démarrage. `None` dans les tests
    /// qui n'en ont pas : la configuration chargée sert alors.
    pub(crate) config_path: Option<PathBuf>,
    /// Limite de débit et regroupement des 429 de `/api/v1`.
    pub(crate) api: crate::api::Guards,
}

impl AppState {
    pub(crate) fn database(&self) -> &Path {
        &self.config.database
    }
}

pub fn router(config: Config) -> Router {
    router_with_clock(config, Arc::new(SystemClock))
}

pub fn router_with_clock(config: Config, clock: Arc<dyn Clock>) -> Router {
    router_with(config, clock, None)
}

/// Routeur complet ; `config_path` est relu à chaque retrait de commande.
///
/// L'IP cliente vient de `ConnectInfo<SocketAddr>` : `run` sert le routeur
/// par `into_make_service_with_connect_info`, un test par `MockConnectInfo`.
/// Sans elle, toutes les requêtes partagent un même seau d'IP.
pub fn router_with(config: Config, clock: Arc<dyn Clock>, config_path: Option<PathBuf>) -> Router {
    let site_ids = config.sites.iter().map(|s| s.id.clone()).collect();
    let writer = Writer::new(&config.database);
    let state = Arc::new(AppState {
        config,
        site_ids,
        clock,
        writer,
        config_path,
        api: crate::api::Guards::default(),
    });
    Router::new()
        .route("/health", get(health_handler).fallback(not_found))
        .route("/r/v1/report", post(report_handler).fallback(not_found))
        .route(
            crate::command::pull::ROUTE,
            post(commands_handler).fallback(not_found),
        )
        .route(
            crate::logs::receive::ROUTE,
            post(logs_handler).fallback(not_found),
        )
        .merge(crate::api::routes())
        .fallback(not_found)
        .with_state(Arc::clone(&state))
        .layer(axum::middleware::from_fn(crate::request_id::layer))
        // Extérieure à `request_id` : voit les corps d'erreur déjà écrits.
        .layer(axum::middleware::from_fn_with_state(
            state,
            crate::api::guard,
        ))
}

pub(crate) async fn not_found() -> StatusCode {
    StatusCode::NOT_FOUND
}

async fn health_handler(State(state): State<Arc<AppState>>) -> (StatusCode, Json<Health>) {
    let database = state.database().to_path_buf();
    let last = tokio::task::spawn_blocking(move || match Store::open_read(&database)? {
        Some(store) => store.last_tick(),
        None => Ok(None),
    })
    .await;
    match last {
        Ok(Ok(last)) => {
            let (code, body) = health(last, state.clock.unix());
            (code, Json(body))
        }
        Ok(Err(err)) => {
            log::error!(
                "[{}] /health : lecture de la base impossible : {err:#}",
                crate::request_id::current()
            );
            unavailable()
        }
        Err(err) => {
            log::error!(
                "[{}] /health : tâche interrompue : {err}",
                crate::request_id::current()
            );
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
    let rid = crate::request_id::current();
    if matches!(refusal.reason, Reason::Internal(_)) {
        log::error!("[{rid}] {refusal}");
    } else {
        log::warn!("[{rid}] {refusal}");
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

    let now = state.clock.unix();
    let task_site = site.clone();
    let task_state = Arc::clone(&state);
    let outcome = tokio::task::spawn_blocking(move || {
        let refusal = |reason| Refusal::new(task_site.as_deref(), reason);
        let written = task_state.writer.write(|store| {
            Ok(ingest::ingest(
                store,
                &task_state.site_ids,
                task_site.as_deref(),
                signature.as_deref(),
                &bytes,
                now,
            ))
        });
        match written {
            Ok(Some(result)) => result,
            // Sans base, aucune clé : refusé comme un site inconnu.
            Ok(None) => Err(refusal(Reason::UnknownSite)),
            Err(err) => Err(refusal(Reason::Internal(format!("{err:#}")))),
        }
    })
    .await;
    match outcome {
        Ok(Ok(accepted)) => {
            log::info!(
                "[{}] rapport accepté (site {}, seq {})",
                crate::request_id::current(),
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

/// Lit le corps d'une requête d'agent avec les limites de `/r/v1/report` ;
/// `Err` : la raison du refus.
async fn read_agent_body(
    body: axum::body::Body,
    announced: Option<u64>,
) -> Result<axum::body::Bytes, Reason> {
    if announced.is_some_and(|len| len > MAX_REPORT_BYTES as u64) {
        return Err(Reason::TooLarge);
    }
    let read = axum::body::to_bytes(body, MAX_REPORT_BYTES);
    match tokio::time::timeout(REPORT_BODY_TIMEOUT, read).await {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(err)) => {
            let too_large = err
                .into_inner()
                .downcast_ref::<http_body_util::LengthLimitError>()
                .is_some();
            Err(if too_large {
                Reason::TooLarge
            } else {
                Reason::Truncated
            })
        }
        Err(_) => Err(Reason::TooSlow),
    }
}

/// 200 et la réponse signée, ou le 404 commun. Configuration relue et clés
/// lues à chaque retrait : sans `[commands]` ou sans clé lisible, rien n'est
/// servi ni accusé.
async fn commands_handler(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> axum::response::Response {
    use axum::response::IntoResponse;
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
    let announced = header(CONTENT_LENGTH.as_str()).and_then(|v| v.parse::<u64>().ok());
    let bytes = match read_agent_body(body, announced).await {
        Ok(bytes) => bytes,
        Err(reason) => return refuse_pull(Refusal::new(site.as_deref(), reason)),
    };
    let now = state.clock.unix();
    let task_state = Arc::clone(&state);
    let task_site = site.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        let refusal = |reason| Refusal::new(task_site.as_deref(), reason);
        let internal = |why: String| refusal(Reason::Internal(why));
        let config = match &task_state.config_path {
            Some(path) => {
                crate::config::load(path).map_err(|e| internal(format!("configuration : {e}")))?
            }
            None => task_state.config.clone(),
        };
        let Some(commands) = &config.commands else {
            return Err(refusal(Reason::UnknownSite));
        };
        let command_key = crate::command::key::load(&commands.key_file)
            .map_err(|e| internal(format!("clé de commandes : {e}")))?;
        let audit_key = crate::command::key::load(&commands.audit_key_file)
            .map_err(|e| internal(format!("clé d'audit : {e}")))?;
        let keys = crate::command::pull::Keys {
            commands: &command_key,
            audit: &audit_key,
        };
        let written = task_state.writer.write(|store| {
            Ok(crate::command::pull::pull(
                store,
                &config,
                &keys,
                task_site.as_deref(),
                signature.as_deref(),
                &bytes,
                now,
            ))
        });
        match written {
            Ok(Some(result)) => result,
            Ok(None) => Err(refusal(Reason::UnknownSite)),
            Err(err) => Err(internal(format!("{err:#}"))),
        }
    })
    .await;
    match outcome {
        Ok(Ok((signed, served))) => {
            log::info!(
                "[{}] retrait accepté (site {}, seq {}, accusé {:?}, commande {:?})",
                crate::request_id::current(),
                served.site,
                served.seq,
                served.acked,
                served.command
            );
            let mut response = (StatusCode::OK, signed.body).into_response();
            let headers = response.headers_mut();
            headers.insert(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("application/json"),
            );
            headers.insert(
                axum::http::header::CACHE_CONTROL,
                axum::http::HeaderValue::from_static("no-store"),
            );
            if let (Ok(ts), Ok(sig)) = (
                axum::http::HeaderValue::from_str(&signed.timestamp.to_string()),
                axum::http::HeaderValue::from_str(&signed.signature),
            ) {
                headers.insert(crate::command::pull::HEADER_TIMESTAMP, ts);
                headers.insert(HEADER_SIGNATURE, sig);
            }
            response
        }
        Ok(Err(refusal)) => refuse_pull(refusal),
        Err(err) => refuse_pull(Refusal::new(
            site.as_deref(),
            Reason::Internal(format!("tâche interrompue : {err}")),
        )),
    }
}

/// 204 si le lot est accepté ou déjà reçu, 404 sans corps sinon. Mêmes
/// limites de taille et de délai que `/r/v1/report` ; la configuration est
/// celle du démarrage, comme pour les rapports.
async fn logs_handler(State(state): State<Arc<AppState>>, request: Request) -> StatusCode {
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
    let announced = header(CONTENT_LENGTH.as_str()).and_then(|v| v.parse::<u64>().ok());
    let bytes = match read_agent_body(body, announced).await {
        Ok(bytes) => bytes,
        Err(reason) => return refuse_logs(Refusal::new(site.as_deref(), reason)),
    };
    let now = state.clock.unix();
    let task_state = Arc::clone(&state);
    let task_site = site.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        let refusal = |reason| Refusal::new(task_site.as_deref(), reason);
        let written = task_state.writer.write(|store| {
            Ok(crate::logs::receive::receive(
                store,
                &task_state.config,
                task_site.as_deref(),
                signature.as_deref(),
                &bytes,
                now,
            ))
        });
        match written {
            Ok(Some(result)) => result,
            Ok(None) => Err(refusal(Reason::UnknownSite)),
            Err(err) => Err(refusal(Reason::Internal(format!("{err:#}")))),
        }
    })
    .await;
    match outcome {
        Ok(Ok(received)) => {
            let rid = crate::request_id::current();
            let what = match &received.stored {
                crate::logs::receive::Stored::Duplicate => "déjà reçu".to_owned(),
                crate::logs::receive::Stored::Accepted {
                    accepted,
                    rejected,
                    gap,
                } => format!("{accepted} entrée(s), rejets {rejected:?}, trou de {gap} octet(s)"),
            };
            log::info!(
                "[{rid}] lot de logs accepté (site {}, seq {}, {} gen {} {}..{}) : {what}",
                received.site,
                received.seq,
                received.file,
                received.generation,
                received.start,
                received.end
            );
            if received.skipped_files > 0 {
                log::warn!(
                    "[{rid}] site {} : {} fichier(s) de logs sautés par l'agent (introuvables ou tronqués)",
                    received.site,
                    received.skipped_files
                );
            }
            StatusCode::NO_CONTENT
        }
        Ok(Err(refusal)) => refuse_logs(refusal),
        Err(err) => refuse_logs(Refusal::new(
            site.as_deref(),
            Reason::Internal(format!("tâche interrompue : {err}")),
        )),
    }
}

fn refuse_logs(refusal: Refusal) -> StatusCode {
    let rid = crate::request_id::current();
    if matches!(refusal.reason, Reason::Internal(_)) {
        log::error!("[{rid}] lot de logs : {refusal}");
    } else {
        log::warn!("[{rid}] lot de logs : {refusal}");
    }
    StatusCode::NOT_FOUND
}

fn refuse_pull(refusal: Refusal) -> axum::response::Response {
    use axum::response::IntoResponse;
    let rid = crate::request_id::current();
    if matches!(refusal.reason, Reason::Internal(_)) {
        log::error!("[{rid}] retrait de commande : {refusal}");
    } else {
        log::warn!("[{rid}] retrait de commande : {refusal}");
    }
    StatusCode::NOT_FOUND.into_response()
}

pub fn run(config: Config, config_path: PathBuf, ip: IpAddr, port: u16) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("démarrage du runtime tokio")?;
    // Une base existante est migrée dès le démarrage, sans attendre le
    // prochain `tick` : `/api/v1` en a besoin. `serve` ne crée pas la base.
    // La typologie chargée y est notée : `vigie status` dit si `serve` doit
    // être relancé pour voir une configuration modifiée. Aucun échec ici
    // n'arrête `serve`.
    let typology = TypologyRecord::of(&config);
    log::info!("typologie chargée, empreinte {}", typology.fingerprint);
    if config.database.is_file() {
        let written = Store::open(&config.database).and_then(|mut store| {
            store.set_meta(
                META_TYPOLOGY_SERVE,
                &serde_json::to_string(&typology)?,
                crate::now(),
            )
        });
        if let Err(err) = written {
            log::error!("migration ou écriture de la typologie au démarrage impossible : {err:#}");
        }
    }
    runtime.block_on(async move {
        let addr = SocketAddr::new(ip, port);
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("écoute sur {addr} impossible"))?;
        log::info!("serve à l'écoute sur {addr}");
        axum::serve(
            listener,
            router_with(config, Arc::new(SystemClock), Some(config_path))
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
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
    use std::path::PathBuf;

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::config::{Alerts, Site, SiteKind};

    fn config(database: PathBuf) -> Config {
        Config {
            alerts: Alerts {
                to: "alertes@example.org".into(),
                from: "vigie@example.org".into(),
                smtp_host: "smtp.example.org".into(),
                smtp_port: 587,
                smtp_user: None,
                password_file: database.with_file_name("smtp-password"),
            },
            database,
            api: None,
            commands: None,
            logs: Default::default(),
            sites: vec![Site {
                id: "site-a".into(),
                url: "https://site-a.example.org/".into(),
                kind: SiteKind::Generic,
                runtime: None,
                keyword_url: None,
                keyword: None,
                interval: 300,
                agent_silence: 900,
                logs: None,
            }],
        }
    }

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
        let response = router(config(database))
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
            "/r/v1/commands",
            "/r/v1/logs",
            "/r/v1",
            "/api/v1",
            "/api/v1/inconnu",
        ] {
            let (status, body) = get(db.clone(), uri).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
            assert!(body.is_empty(), "{uri}");
        }
        // Méthode refusée sur une route de l'API : erreur au format commun.
        let (status, body) = get(db.clone(), "/api/v1/pair").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["error"]["code"], "not_found");
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
