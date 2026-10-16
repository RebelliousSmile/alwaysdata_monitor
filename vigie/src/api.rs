//! `/api/v1` : API de la console (`docs/api-console.md`).
//!
//! `POST /api/v1/pair` échange un code d'appairage contre un jeton d'appareil ;
//! toute autre route exige `Authorization: Bearer <jeton>`. Un échec reçoit un
//! 401 sans corps, quelle qu'en soit la raison. Ni jeton ni code n'entrent
//! dans le journal : seulement l'id et le nom de l'appareil.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::{FromRequestParts, Request, State};
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};

use crate::device;
use crate::serve::{AppState, not_found};
use crate::store::{Device, SCHEMA_DEVICES, Store};

/// Taille maximale du corps de `POST /api/v1/pair`, en octets.
pub const MAX_PAIR_BYTES: usize = 1024;
/// Délai de réception du corps de `POST /api/v1/pair`.
pub const PAIR_BODY_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/pair", post(pair_handler).fallback(not_found))
        .route(
            "/api/v1/overview",
            get(overview_handler).fallback(not_found),
        )
}

/// Ouvre la base en lecteur, si elle existe et connaît les appareils : l'API
/// ne crée jamais la base.
fn open_devices(state: &AppState) -> anyhow::Result<Option<Store>> {
    match Store::open_read(&state.database)? {
        Some(store) if store.schema_version()? >= SCHEMA_DEVICES => Ok(Some(store)),
        _ => Ok(None),
    }
}

/// Réponse portant un secret ou un état : jamais mise en cache.
fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[derive(Deserialize)]
struct PairRequest {
    code: String,
}

#[derive(Serialize)]
struct PairResponse {
    token: String,
    device_id: i64,
    name: String,
}

/// 200 et le jeton, remis une seule fois ; 401 sans corps sinon.
async fn pair_handler(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let read = axum::body::to_bytes(request.into_body(), MAX_PAIR_BYTES);
    let Ok(Ok(bytes)) = tokio::time::timeout(PAIR_BODY_TIMEOUT, read).await else {
        log::warn!("appairage refusé : corps trop gros, interrompu ou trop lent");
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(PairRequest { code }) = serde_json::from_slice::<PairRequest>(&bytes) else {
        log::warn!("appairage refusé : corps illisible");
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if code.is_empty() || code.len() > device::MAX_SECRET_LEN {
        log::warn!("appairage refusé : code de longueur invalide");
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let token = match device::new_token() {
        Ok(token) => token,
        Err(err) => {
            log::error!("appairage : {err:#}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let code_hash = device::hash(&code);
    let token_hash = device::hash(&token);
    let now = (state.clock)();
    let task_state = Arc::clone(&state);
    let outcome = tokio::task::spawn_blocking(move || match open_devices(&task_state)? {
        Some(mut store) => store.consume_pairing(&code_hash, &token_hash, now),
        None => Ok(None),
    })
    .await;
    match outcome {
        Ok(Ok(Some(device))) => {
            log::info!("appareil {} « {} » appairé", device.id, device.name);
            no_store(
                Json(PairResponse {
                    token,
                    device_id: device.id,
                    name: device.name,
                })
                .into_response(),
            )
        }
        Ok(Ok(None)) => {
            log::warn!("appairage refusé : code inconnu, déjà utilisé ou expiré");
            StatusCode::UNAUTHORIZED.into_response()
        }
        Ok(Err(err)) => {
            log::error!("appairage : {err:#}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(err) => {
            log::error!("appairage : tâche interrompue : {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Appareil authentifié par `Authorization: Bearer <jeton>`.
pub(crate) struct Authenticated(pub Device);

impl FromRequestParts<Arc<AppState>> for Authenticated {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .filter(|t| !t.is_empty() && t.len() <= device::MAX_SECRET_LEN)
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let token_hash = device::hash(token);
        let now = (state.clock)();
        let task_state = Arc::clone(state);
        let found = tokio::task::spawn_blocking(move || {
            let Some(mut store) = open_devices(&task_state)? else {
                return Ok(None);
            };
            let device = store.device_by_token_hash(&token_hash)?;
            if let Some(device) = &device
                && let Err(err) = store.touch_seen(device.id, now)
            {
                // « Vu le » n'est qu'une indication : la requête passe.
                log::warn!("appareil {} : « vu le » non écrit : {err:#}", device.id);
            }
            anyhow::Ok(device)
        })
        .await;
        match found {
            Ok(Ok(Some(device))) => Ok(Self(device)),
            Ok(Ok(None)) => {
                log::warn!("jeton refusé : inconnu ou révoqué");
                Err(StatusCode::UNAUTHORIZED)
            }
            Ok(Err(err)) => {
                log::error!("authentification : {err:#}");
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
            Err(err) => {
                log::error!("authentification : tâche interrompue : {err}");
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }
}

#[derive(Serialize)]
struct Overview {
    server_time: i64,
    last_tick: Option<i64>,
}

async fn overview_handler(
    State(state): State<Arc<AppState>>,
    Authenticated(_device): Authenticated,
) -> Response {
    let now = (state.clock)();
    let task_state = Arc::clone(&state);
    let last = tokio::task::spawn_blocking(move || match open_devices(&task_state)? {
        Some(store) => store.last_tick(),
        None => Ok(None),
    })
    .await;
    match last {
        Ok(Ok(last_tick)) => no_store(
            Json(Overview {
                server_time: now,
                last_tick,
            })
            .into_response(),
        ),
        Ok(Err(err)) => {
            log::error!("/api/v1/overview : {err:#}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(err) => {
            log::error!("/api/v1/overview : tâche interrompue : {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
