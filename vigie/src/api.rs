//! `/api/v1` : API de la console (`docs/api-console.md`).
//!
//! `POST /api/v1/pair` échange un code d'appairage contre un jeton d'appareil ;
//! toute autre route exige `Authorization: Bearer <jeton>`. Un échec reçoit le
//! même 401, quelle qu'en soit la raison. Toute erreur porte le corps commun de
//! [`crate::error`] et l'identifiant de requête, cité aussi par le journal. Ni jeton ni code n'entrent
//! dans le journal : seulement l'id et le nom de l'appareil.
//!
//! Garde-fous transverses (issue #5) : limite de débit ([`limit`]), une ligne
//! de journal par appel et en-têtes stricts (couche [`guard`], extérieure à
//! celle de `request_id`), 415 pour un `POST` dont le corps n'est pas du JSON,
//! texte d'origine log assaini ([`log_text`]), pagination par clé de toute
//! liste qui croît ([`page`]).
//!
//! L'état d'un site (`SiteState`) est calculé ici et nulle part ailleurs : la
//! console l'affiche sans rien recalculer.

pub mod limit;
pub mod log_text;
pub mod page;

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::Json;
use axum::Router;
use axum::body::HttpBody;
use axum::extract::connect_info::MockConnectInfo;
use axum::extract::rejection::PathRejection;
use axum::extract::{ConnectInfo, FromRequestParts, MatchedPath, Path, Request, State};
use axum::http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING,
    X_CONTENT_TYPE_OPTIONS,
};
use axum::http::request::Parts;
use axum::http::{Extensions, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use serde::{Deserialize, Serialize};

use crate::analysis::catalog::BotClass;
use crate::analysis::findings::{self as log_findings, Analysis, VERDICT_RETENTION_SECS};
use crate::analysis::score::Level;
use crate::capability::{self, Control};
use crate::checks::heartbeat;
use crate::config::{Runtime, Site};
use crate::device;
use crate::error::{self, ApiError, not_found};
use crate::finding::Severity;
use crate::request_id;
use crate::serve::AppState;
use crate::store::{
    AckOutcome, Agent, CheckRun, Device, Incident, RevokeOutcome, RunResult, SCHEMA_CHECK_RESULTS,
    SCHEMA_FINDINGS, Store,
};

use limit::{IpKey, Limiter};
use log_text::LogText;
use page::{IncidentCursor, Page, PageQuery, VerdictCursor};

/// Taille maximale du corps de `POST /api/v1/pair`, en octets.
pub const MAX_PAIR_BYTES: usize = 1024;
/// Délai de réception du corps de `POST /api/v1/pair`.
pub const PAIR_BODY_TIMEOUT: Duration = Duration::from_secs(10);
/// Préfixe des routes de la console.
pub const PREFIX: &str = "/api/v1";
/// Contrôle dont les incidents et les passages portent du texte de logs
/// (analyse de #8).
pub const LOGS_CHECK: &str = "logs";

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/pair", post(pair_handler).fallback(not_found))
        .route(
            "/api/v1/overview",
            get(overview_handler).fallback(not_found),
        )
        .route("/api/v1/sites/{id}", get(site_handler).fallback(not_found))
        .route(
            "/api/v1/sites/{id}/incidents",
            get(site_incidents_handler).fallback(not_found),
        )
        .route(
            "/api/v1/sites/{id}/logs",
            get(site_logs_handler).fallback(not_found),
        )
        .route(
            "/api/v1/sites/{id}/logs/ips",
            get(site_log_ips_handler).fallback(not_found),
        )
        .route(
            "/api/v1/incidents/{id}",
            get(incident_handler).fallback(not_found),
        )
        .route(
            "/api/v1/incidents/{id}/ack",
            post(ack_handler).fallback(not_found),
        )
        .route(
            "/api/v1/settings",
            get(settings_handler).fallback(not_found),
        )
        .route(
            "/api/v1/devices/self",
            delete(device_self_handler).fallback(not_found),
        )
        .route_layer(axum::middleware::from_fn(media_type))
}

/// État des garde-fous de `/api/v1`, partagé par les requêtes de `serve`.
#[derive(Debug, Default)]
pub(crate) struct Guards {
    pub(crate) limiter: Limiter,
    rejections: Mutex<Rejections>,
}

/// IP cliente de la requête, posée en extension par [`guard`].
#[derive(Debug, Clone, Copy)]
struct ClientIp(IpKey);

/// Clé d'IP de la requête ; inconnue hors de [`guard`].
fn client_key(extensions: &Extensions) -> IpKey {
    extensions
        .get::<ClientIp>()
        .map_or(IpKey::Unknown, |ip| ip.0)
}

/// Appareil de l'appel, posé par l'extracteur [`Authenticated`] dans
/// l'extension créée par [`guard`], qui le cite au journal.
#[derive(Debug, Clone, Default)]
struct CallDevice(Arc<Mutex<Option<i64>>>);

impl CallDevice {
    fn set(&self, id: i64) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(id);
    }

    fn get(&self) -> Option<i64> {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Fenêtre de regroupement des 429 d'une même IP.
const REJECTION_WINDOW: Duration = Duration::from_secs(60);

/// 429 regroupés par IP : la première ligne d'une minute est écrite, les
/// suivants sont comptés, et le compte est écrit à la minute suivante.
/// Bornée comme la table des IP ; au-delà, une fenêtre commune.
#[derive(Debug, Default)]
struct Rejections {
    by_ip: HashMap<IpKey, Window>,
    overflow: Option<Window>,
}

#[derive(Debug, Clone, Copy)]
struct Window {
    start: Instant,
    silenced: u64,
}

impl Window {
    fn new(now: Instant) -> Self {
        Self {
            start: now,
            silenced: 0,
        }
    }

    fn is_open(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.start) < REJECTION_WINDOW
    }
}

/// Compte des 429 tus d'une fenêtre close, au journal.
fn flush_rejections(who: &dyn std::fmt::Display, silenced: u64) {
    if silenced > 0 {
        log::warn!("[-] /api/v1 : {silenced} autre(s) 429 regroupé(s) pour {who} sur une minute");
    }
}

impl Rejections {
    /// `true` : écrire la ligne de ce 429 ; `false` : il est compté.
    fn note(&mut self, key: IpKey, now: Instant) -> bool {
        if let Some(window) = self.by_ip.get_mut(&key) {
            if window.is_open(now) {
                window.silenced += 1;
                return false;
            }
            flush_rejections(&key, window.silenced);
            *window = Window::new(now);
            return true;
        }
        if self.by_ip.len() >= limit::MAX_IPS {
            self.by_ip.retain(|key, window| {
                let open = window.is_open(now);
                if !open {
                    flush_rejections(key, window.silenced);
                }
                open
            });
        }
        if self.by_ip.len() < limit::MAX_IPS {
            self.by_ip.insert(key, Window::new(now));
            return true;
        }
        match &mut self.overflow {
            Some(window) if window.is_open(now) => {
                window.silenced += 1;
                false
            }
            overflow => {
                if let Some(window) = overflow {
                    flush_rejections(&"d'autres adresses", window.silenced);
                }
                *overflow = Some(Window::new(now));
                true
            }
        }
    }
}

/// Couche de `/api/v1`, extérieure à celle de `request_id` : elle voit le
/// corps d'erreur déjà écrit. Pose l'IP cliente, puis, sur la réponse, les
/// en-têtes stricts et une ligne de journal : request_id, appareil, méthode,
/// gabarit de route (jamais le chemin brut ni la query), statut, durée. Ni
/// jeton, ni code, ni en-tête. Hors de `/api/v1`, la requête passe telle quelle.
pub(crate) async fn guard(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if path != PREFIX && !path.starts_with("/api/v1/") {
        return next.run(request).await;
    }
    let started = Instant::now();
    let method = request.method().clone();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "-".to_owned(), |m| m.as_str().to_owned());
    // Comme l'extracteur `ConnectInfo` : l'adresse réelle, sinon celle d'un
    // test (`MockConnectInfo`).
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0)
        .or_else(|| {
            request
                .extensions()
                .get::<MockConnectInfo<SocketAddr>>()
                .map(|info| info.0)
        });
    let ip = IpKey::of(limit::client_ip(peer, request.headers()));
    let device = CallDevice::default();
    request.extensions_mut().insert(ClientIp(ip));
    request.extensions_mut().insert(device.clone());

    let mut response = next.run(request).await;
    strict_headers(&mut response);

    let status = response.status().as_u16();
    let rid = response
        .headers()
        .get(request_id::HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_owned();
    let device = device
        .get()
        .map_or_else(|| "-".to_owned(), |id| id.to_string());
    let ms = started.elapsed().as_millis();
    if response.status() == StatusCode::TOO_MANY_REQUESTS {
        let first = state
            .api
            .rejections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .note(ip, state.clock.monotonic());
        if first {
            log::warn!(
                "[{rid}] appel /api/v1 : appareil {device} {method} {route} {status} {ms} ms, ip {ip} (429 suivants de cette ip regroupés sur une minute)"
            );
        }
    } else {
        log::info!("[{rid}] appel /api/v1 : appareil {device} {method} {route} {status} {ms} ms");
    }
    response
}

/// `nosniff`, `no-store`, `Content-Type: application/json` s'il y a un corps,
/// aucun en-tête CORS : la console appelle depuis Rust, aucun navigateur
/// n'est à autoriser.
fn strict_headers(response: &mut Response) {
    let empty = response.body().size_hint().exact() == Some(0);
    let headers = response.headers_mut();
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if empty {
        headers.remove(CONTENT_TYPE);
    } else {
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    }
    let cors: Vec<HeaderName> = headers
        .keys()
        .filter(|name| name.as_str().starts_with("access-control-"))
        .cloned()
        .collect();
    for name in cors {
        headers.remove(name);
    }
}

/// Le `POST` annonce un corps : `Content-Length` non nul (ou illisible), ou
/// `Transfer-Encoding`.
fn announces_body(headers: &HeaderMap) -> bool {
    if headers.contains_key(TRANSFER_ENCODING) {
        return true;
    }
    headers.get(CONTENT_LENGTH).is_some_and(|value| {
        value
            .to_str()
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            != Some(0)
    })
}

fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|essence| essence.trim().eq_ignore_ascii_case("application/json"))
}

/// 415 pour un `POST` qui annonce un corps d'un autre type que
/// `application/json`, d'après les seuls en-têtes : le corps n'est pas lu.
/// Un `POST` sans corps ni `Content-Type` (acquittement de la console 0.1.1)
/// passe.
async fn media_type(request: Request, next: Next) -> Response {
    if request.method() == Method::POST
        && announces_body(request.headers())
        && !is_json(request.headers())
    {
        return ApiError::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    next.run(request).await
}

/// Ouvre la base en lecteur, si elle existe et porte le schéma de l'API
/// (appareils et résultats des passages) : l'API ne crée jamais la base.
fn open_devices(state: &AppState) -> anyhow::Result<Option<Store>> {
    match Store::open_read(state.database())? {
        Some(store) if store.schema_version()? >= SCHEMA_CHECK_RESULTS => Ok(Some(store)),
        _ => Ok(None),
    }
}

/// Écrit par l'écrivain unique de `serve`, sous les mêmes conditions que
/// [`open_devices`] : `None` si la base est absente ou précède le schéma de
/// l'API. À appeler depuis `spawn_blocking`.
fn write_devices<R>(
    state: &AppState,
    f: impl FnOnce(&mut Store) -> anyhow::Result<R>,
) -> anyhow::Result<Option<R>> {
    let written = state.writer.write(|store| {
        if store.schema_version()? >= SCHEMA_CHECK_RESULTS {
            f(store).map(Some)
        } else {
            Ok(None)
        }
    })?;
    Ok(written.flatten())
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

/// 200 et le jeton, remis une seule fois ; 401 sinon.
/// Avant tout traitement, l'appairage puise dans le seau de l'IP cliente :
/// 429 s'il est vide.
async fn pair_handler(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let ip = client_key(request.extensions());
    if let Err(limited) = state.api.limiter.ip(ip, state.clock.monotonic()) {
        return error::too_many_requests(limited.retry_after);
    }
    let read = axum::body::to_bytes(request.into_body(), MAX_PAIR_BYTES);
    let Ok(Ok(bytes)) = tokio::time::timeout(PAIR_BODY_TIMEOUT, read).await else {
        log::warn!(
            "[{}] appairage refusé : corps trop gros, interrompu ou trop lent",
            request_id::current()
        );
        return ApiError::UNAUTHORIZED.into_response();
    };
    let Ok(PairRequest { code }) = serde_json::from_slice::<PairRequest>(&bytes) else {
        log::warn!(
            "[{}] appairage refusé : corps illisible",
            request_id::current()
        );
        return ApiError::UNAUTHORIZED.into_response();
    };
    if code.is_empty() || code.len() > device::MAX_SECRET_LEN {
        log::warn!(
            "[{}] appairage refusé : code de longueur invalide",
            request_id::current()
        );
        return ApiError::UNAUTHORIZED.into_response();
    }
    let token = match device::new_token() {
        Ok(token) => token,
        Err(err) => {
            log::error!("[{}] appairage : {err:#}", request_id::current());
            return ApiError::INTERNAL.into_response();
        }
    };
    let code_hash = device::hash(&code);
    let token_hash = device::hash(&token);
    let now = state.clock.unix();
    let task_state = Arc::clone(&state);
    let outcome = tokio::task::spawn_blocking(move || {
        write_devices(&task_state, |store| {
            store.consume_pairing(&code_hash, &token_hash, now)
        })
        .map(Option::flatten)
    })
    .await;
    match outcome {
        Ok(Ok(Some(device))) => {
            log::info!(
                "[{}] appareil {} « {} » appairé",
                request_id::current(),
                device.id,
                device.name
            );
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
            log::warn!(
                "[{}] appairage refusé : code inconnu, déjà utilisé ou expiré",
                request_id::current()
            );
            ApiError::UNAUTHORIZED.into_response()
        }
        Ok(Err(err)) => {
            log::error!("[{}] appairage : {err:#}", request_id::current());
            ApiError::INTERNAL.into_response()
        }
        Err(err) => {
            log::error!(
                "[{}] appairage : tâche interrompue : {err}",
                request_id::current()
            );
            ApiError::INTERNAL.into_response()
        }
    }
}

/// Appareil authentifié par `Authorization: Bearer <jeton>`.
///
/// Le jeton est cherché d'abord ; un appareil trouvé puise ensuite dans son
/// seau, et « vu le » n'est écrit que s'il reste sous la limite. Un échec
/// d'authentification puise dans le seau de l'IP cliente : 429 au lieu du 401
/// quand il est vide.
pub(crate) struct Authenticated(pub Device);

/// Échec d'authentification : 401, ou 429 si l'IP a épuisé son seau. La
/// raison n'est journalisée que pour un 401 : les 429 sont regroupés par
/// [`guard`].
fn refused(state: &AppState, ip: IpKey, why: Option<&str>) -> Response {
    match state.api.limiter.ip(ip, state.clock.monotonic()) {
        Ok(()) => {
            if let Some(why) = why {
                log::warn!("[{}] {why}", request_id::current());
            }
            ApiError::UNAUTHORIZED.into_response()
        }
        Err(limited) => error::too_many_requests(limited.retry_after),
    }
}

impl FromRequestParts<Arc<AppState>> for Authenticated {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let ip = client_key(&parts.extensions);
        let Some(token) = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .filter(|t| !t.is_empty() && t.len() <= device::MAX_SECRET_LEN)
        else {
            return Err(refused(state, ip, None));
        };
        let token_hash = device::hash(token);
        let task_state = Arc::clone(state);
        let found = tokio::task::spawn_blocking(move || {
            let Some(store) = open_devices(&task_state)? else {
                return Ok(None);
            };
            store.device_by_token_hash(&token_hash)
        })
        .await;
        let device = match found {
            Ok(Ok(Some(device))) => device,
            Ok(Ok(None)) => {
                return Err(refused(
                    state,
                    ip,
                    Some("jeton refusé : inconnu ou révoqué"),
                ));
            }
            Ok(Err(err)) => {
                log::error!("[{}] authentification : {err:#}", request_id::current());
                return Err(ApiError::INTERNAL.into_response());
            }
            Err(err) => {
                log::error!(
                    "[{}] authentification : tâche interrompue : {err}",
                    request_id::current()
                );
                return Err(ApiError::INTERNAL.into_response());
            }
        };
        if let Some(call) = parts.extensions.get::<CallDevice>() {
            call.set(device.id);
        }
        if let Err(limited) = state.api.limiter.device(device.id, state.clock.monotonic()) {
            return Err(error::too_many_requests(limited.retry_after));
        }
        let now = state.clock.unix();
        let (task_state, id, rid) = (Arc::clone(state), device.id, request_id::current());
        let touched = tokio::task::spawn_blocking(move || {
            write_devices(&task_state, |writer| writer.touch_seen(id, now))
        })
        .await;
        // « Vu le » n'est qu'une indication : la requête passe.
        match touched {
            Ok(Ok(_)) => {}
            Ok(Err(err)) => log::warn!("[{rid}] appareil {id} : « vu le » non écrit : {err:#}"),
            Err(err) => log::warn!("[{rid}] appareil {id} : « vu le » non écrit : {err}"),
        }
        Ok(Self(device))
    }
}

/// Incidents fermés montrés par `GET /api/v1/sites/{id}/incidents` : clos
/// depuis 30 jours au plus.
pub const CLOSED_WINDOW: i64 = 30 * 86_400;

/// 200, la valeur en JSON, jamais mise en cache.
fn json<T: Serialize>(body: &T) -> Response {
    no_store(Json(body).into_response())
}

/// Exécute `f` sur la base, hors du runtime. 500 sur erreur, et
/// aussi si la base a disparu entre l'authentification et la lecture.
async fn with_store<F>(state: &Arc<AppState>, route: &'static str, f: F) -> Response
where
    F: FnOnce(&AppState, Store) -> anyhow::Result<Response> + Send + 'static,
{
    let task_state = Arc::clone(state);
    let outcome = tokio::task::spawn_blocking(move || match open_devices(&task_state)? {
        Some(store) => f(&task_state, store).map(Some),
        None => Ok(None),
    })
    .await;
    finish(route, outcome)
}

/// Comme [`with_store`], mais `f` écrit : il passe par l'écrivain unique de
/// `serve`, qui lit aussi ce qu'il vient d'écrire.
async fn with_writer<F>(state: &Arc<AppState>, route: &'static str, f: F) -> Response
where
    F: FnOnce(&mut Store) -> anyhow::Result<Response> + Send + 'static,
{
    let task_state = Arc::clone(state);
    let outcome = tokio::task::spawn_blocking(move || write_devices(&task_state, f)).await;
    finish(route, outcome)
}

/// Réponse d'une tâche de base : 500 sur base absente, erreur ou
/// tâche interrompue.
fn finish(
    route: &'static str,
    outcome: Result<anyhow::Result<Option<Response>>, tokio::task::JoinError>,
) -> Response {
    match outcome {
        Ok(Ok(Some(response))) => response,
        Ok(Ok(None)) => {
            log::error!(
                "[{}] {route} : base absente ou pas encore migrée",
                request_id::current()
            );
            ApiError::INTERNAL.into_response()
        }
        Ok(Err(err)) => {
            log::error!("[{}] {route} : {err:#}", request_id::current());
            ApiError::INTERNAL.into_response()
        }
        Err(err) => {
            log::error!(
                "[{}] {route} : tâche interrompue : {err}",
                request_id::current()
            );
            ApiError::INTERNAL.into_response()
        }
    }
}

/// Identifiant d'incident lu en entier, sinon `None` (404).
fn incident_id(id: Result<Path<String>, PathRejection>) -> Option<i64> {
    id.ok()?.0.parse().ok()
}

/// État d'un site, dans l'ordre de l'écran Main : le plus urgent d'abord.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SiteState {
    /// Incident critique ouvert, hors silence d'agent.
    NonCompliant,
    /// Silence d'agent ouvert : le veilleur ne voit plus le site de l'intérieur.
    Blind,
    /// Avertissement ouvert, ou dernier passage d'un contrôle non concluant.
    ToCheck,
    /// Aucun passage, aucun rapport, aucun incident : rien n'est encore connu.
    FirstRead,
    Ok,
}

/// Ce que le veilleur sait d'un site, lu une fois pour toutes les routes.
struct SiteView {
    agent: Option<Agent>,
    /// Contexte du registre des capacités : clé d'agent, référence.
    ctx: capability::Ctx,
    /// Incidents ouverts, de gravité décroissante puis du plus ancien.
    open: Vec<Incident>,
    /// Derniers passages des contrôles encore surveillés.
    runs: Vec<CheckRun>,
}

impl SiteView {
    fn read(
        site: &Site,
        agents: &[Agent],
        baselines: &[String],
        open: &[Incident],
        runs: &[CheckRun],
    ) -> Self {
        let agent = agents.iter().find(|a| a.site == site.id).cloned();
        let ctx = capability::Ctx {
            agent: agent.is_some(),
            baseline: baselines.contains(&site.id),
        };
        let mut open: Vec<Incident> = open.iter().filter(|i| i.site == site.id).cloned().collect();
        open.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then(a.opened_at.cmp(&b.opened_at))
                .then(a.id.cmp(&b.id))
        });
        // Même verdict que `tick` et l'ingestion : celui du registre.
        let runs = runs
            .iter()
            .filter(|r| r.site == site.id && capability::watched(site, &r.check_name, &ctx))
            .cloned()
            .collect();
        Self {
            agent,
            ctx,
            open,
            runs,
        }
    }

    /// Incidents qui comptent : avertissements et critiques.
    fn serious(&self) -> impl Iterator<Item = &Incident> {
        self.open.iter().filter(|i| i.severity != Severity::Info)
    }

    fn state(&self) -> SiteState {
        let is_heartbeat = |i: &&Incident| i.check_name == heartbeat::NAME;
        if self
            .serious()
            .any(|i| i.severity == Severity::Critical && !is_heartbeat(&i))
        {
            SiteState::NonCompliant
        } else if self.serious().any(|i| is_heartbeat(&i)) {
            SiteState::Blind
        } else if self.serious().next().is_some()
            || self.runs.iter().any(|r| r.result == Some(RunResult::Error))
        {
            SiteState::ToCheck
        } else if self.runs.is_empty() && self.last_report().is_none() && self.open.is_empty() {
            SiteState::FirstRead
        } else {
            SiteState::Ok
        }
    }

    fn last_report(&self) -> Option<i64> {
        self.agent.as_ref().and_then(|a| a.last_valid_at)
    }

    /// Dernière lecture du site : passage d'un contrôle ou rapport d'agent.
    fn last_read(&self) -> Option<i64> {
        self.runs
            .iter()
            .map(|r| r.last_run)
            .chain(self.last_report())
            .max()
    }
}

#[derive(Serialize)]
struct IncidentJson {
    id: i64,
    key: String,
    site: String,
    check: String,
    severity: &'static str,
    detail: String,
    opened_at: i64,
    closed_at: Option<i64>,
    acked_at: Option<i64>,
    open_notified_at: Option<i64>,
    close_notified_at: Option<i64>,
    last_reminder_at: Option<i64>,
    /// `open`, `acked` ou `closed`.
    state: &'static str,
}

/// Texte d'un incident ou d'un passage : assaini par [`LogText`] pour le
/// contrôle `logs`, dont il vient des logs (déjà assaini à l'écriture par
/// #8 ; la lecture ne s'y fie pas).
fn check_text(check: &str, text: &str) -> String {
    if check == LOGS_CHECK {
        LogText::detail(text).into()
    } else {
        text.to_owned()
    }
}

impl From<&Incident> for IncidentJson {
    fn from(i: &Incident) -> Self {
        Self {
            id: i.id,
            key: check_text(&i.check_name, &i.key),
            site: i.site.clone(),
            check: i.check_name.clone(),
            severity: i.severity.as_str(),
            detail: check_text(&i.check_name, &i.detail),
            opened_at: i.opened_at,
            closed_at: i.closed_at,
            acked_at: i.acked_at,
            open_notified_at: i.open_notified_at,
            close_notified_at: i.close_notified_at,
            last_reminder_at: i.last_reminder_at,
            state: match (i.closed_at, i.acked_at) {
                (Some(_), _) => "closed",
                (None, Some(_)) => "acked",
                (None, None) => "open",
            },
        }
    }
}

#[derive(Serialize)]
struct OverviewSite {
    id: String,
    url: String,
    kind: &'static str,
    /// Runtime effectif : déclaré, sinon impliqué par le CMS ; `null` sinon.
    runtime: Option<&'static str>,
    state: SiteState,
    /// Avertissements et critiques ouverts.
    open_count: usize,
    /// Le plus grave d'entre eux, le plus ancien à gravité égale.
    worst: Option<IncidentJson>,
    last_read: Option<i64>,
}

#[derive(Serialize)]
struct Overview {
    server_time: i64,
    last_tick: Option<i64>,
    sites: Vec<OverviewSite>,
}

async fn overview_handler(
    State(state): State<Arc<AppState>>,
    Authenticated(_device): Authenticated,
) -> Response {
    let now = state.clock.unix();
    with_store(&state, "/api/v1/overview", move |state, store| {
        let agents = store.agents()?;
        let baselines = store.baseline_sites()?;
        let open = store.open_incidents()?;
        let runs = store.check_results()?;
        let mut sites: Vec<(usize, OverviewSite)> = state
            .config
            .sites
            .iter()
            .enumerate()
            .map(|(rank, site)| {
                let view = SiteView::read(site, &agents, &baselines, &open, &runs);
                let line = OverviewSite {
                    id: site.id.clone(),
                    url: site.url.clone(),
                    kind: site.kind.as_str(),
                    runtime: site.effective_runtime().map(Runtime::as_str),
                    state: view.state(),
                    open_count: view.serious().count(),
                    worst: view.serious().next().map(IncidentJson::from),
                    last_read: view.last_read(),
                };
                (rank, line)
            })
            .collect();
        // Par état, puis dans l'ordre de la configuration.
        sites.sort_by_key(|(rank, line)| (line.state, *rank));
        Ok(json(&Overview {
            server_time: now,
            last_tick: store.last_tick()?,
            sites: sites.into_iter().map(|(_, line)| line).collect(),
        }))
    })
    .await
}

#[derive(Serialize)]
struct AgentJson {
    declared_at: i64,
    last_report_at: Option<i64>,
    /// Version déclarée par l'agent dans son dernier rapport.
    agent: Option<String>,
    /// Dernier relevé accepté, tel que l'agent l'a envoyé.
    facts: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct CheckJson {
    name: String,
    /// Secondes entre deux passages ; `null` pour les contrôles d'agent, qui
    /// suivent les rapports.
    interval: Option<u64>,
    last_run: Option<i64>,
    result: Option<&'static str>,
    severity: Option<&'static str>,
    detail: Option<String>,
    duration_ms: Option<i64>,
    observed: Option<serde_json::Value>,
}

impl CheckJson {
    fn new(name: &str, interval: Option<u64>, run: Option<&CheckRun>) -> Self {
        Self {
            name: name.to_owned(),
            interval,
            last_run: run.map(|r| r.last_run),
            result: run.and_then(|r| r.result).map(RunResult::as_str),
            severity: run.and_then(|r| r.severity).map(Severity::as_str),
            detail: run
                .and_then(|r| r.detail.as_deref())
                .map(|d| check_text(name, d)),
            duration_ms: run.and_then(|r| r.duration_ms),
            observed: run
                .and_then(|r| r.observed.as_deref())
                .and_then(|o| serde_json::from_str(o).ok()),
        }
    }
}

#[derive(Serialize)]
struct SiteDetail {
    id: String,
    url: String,
    kind: &'static str,
    /// Runtime effectif : déclaré, sinon impliqué par le CMS ; `null` sinon.
    runtime: Option<&'static str>,
    interval: u64,
    agent_silence: u64,
    state: SiteState,
    last_read: Option<i64>,
    agent: Option<AgentJson>,
    open_incidents: Vec<IncidentJson>,
    checks: Vec<CheckJson>,
}

async fn site_handler(
    State(state): State<Arc<AppState>>,
    Authenticated(_device): Authenticated,
    id: Result<Path<String>, PathRejection>,
) -> Response {
    let Some(index) = site_index(&state, id) else {
        return ApiError::NOT_FOUND.into_response();
    };
    with_store(&state, "/api/v1/sites", move |state, store| {
        let site = &state.config.sites[index];
        let view = SiteView::read(
            site,
            &store.agents()?,
            &store.baseline_sites()?,
            &store.open_incidents()?,
            &store.check_results()?,
        );
        let run_of = |name: &str| view.runs.iter().find(|r| r.check_name == name);
        // Contrôles du registre surveillés pour ce site : les contrôles
        // externes et le silence de l'agent toujours, les autres dès leur
        // premier passage.
        let mut checks: Vec<CheckJson> = Vec::new();
        for control in capability::allowed_controls(site, &view.ctx) {
            let name = control.name();
            match control {
                Control::Check(kind) => {
                    checks.push(CheckJson::new(
                        name,
                        Some(kind.interval(site)),
                        run_of(name),
                    ));
                }
                Control::Heartbeat => {
                    checks.push(CheckJson::new(name, Some(site.agent_silence), run_of(name)));
                }
                Control::Integrity | Control::Agent(_) | Control::Logs | Control::Typology => {
                    if let Some(run) = run_of(name) {
                        checks.push(CheckJson::new(name, None, Some(run)));
                    }
                }
            }
        }
        let agent = match &view.agent {
            Some(agent) => Some(AgentJson {
                declared_at: agent.added_at,
                last_report_at: agent.last_valid_at,
                agent: agent.agent.clone(),
                facts: store
                    .last_facts(&site.id)?
                    .and_then(|facts| serde_json::from_str(&facts).ok()),
            }),
            None => None,
        };
        Ok(json(&SiteDetail {
            id: site.id.clone(),
            url: site.url.clone(),
            kind: site.kind.as_str(),
            runtime: site.effective_runtime().map(Runtime::as_str),
            interval: site.interval,
            agent_silence: site.agent_silence,
            state: view.state(),
            last_read: view.last_read(),
            agent,
            open_incidents: view.open.iter().map(IncidentJson::from).collect(),
            checks,
        }))
    })
    .await
}

/// Rang du site dans la configuration, si l'identifiant y figure.
fn site_index(state: &AppState, id: Result<Path<String>, PathRejection>) -> Option<usize> {
    let Path(id) = id.ok()?;
    state.site_ids.iter().position(|s| *s == id)
}

/// Incidents clos d'un site, une page. La console 0.1.1 lit `incidents` :
/// le nom reste, la liste devient la première page.
#[derive(Serialize)]
struct SiteIncidents {
    site: String,
    since: i64,
    incidents: Vec<IncidentJson>,
    next_cursor: Option<String>,
}

/// Incidents clos des 30 derniers jours, les plus récents d'abord, par pages
/// (`limit`, `cursor`). Un incident clos pendant le parcours se place avant
/// la première page : il n'est pas revu, et aucun autre ne manque.
async fn site_incidents_handler(
    State(state): State<Arc<AppState>>,
    Authenticated(_device): Authenticated,
    id: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Response {
    let Some(index) = site_index(&state, id) else {
        return ApiError::NOT_FOUND.into_response();
    };
    let page = match PageQuery::parse(uri.query()) {
        Ok(page) => page,
        Err(err) => return err.into_response(),
    };
    let after = match page
        .cursor
        .as_deref()
        .map(IncidentCursor::decode)
        .transpose()
    {
        Ok(after) => after.map(|c| (c.closed_at, c.id)),
        Err(err) => return err.into_response(),
    };
    let since = state.clock.unix() - CLOSED_WINDOW;
    with_store(&state, "/api/v1/sites/incidents", move |state, store| {
        let site = &state.site_ids[index];
        let mut closed = store.closed_incidents_page(site, since, after, page.limit + 1)?;
        let more = page::split(&mut closed, page.limit);
        let next_cursor = closed
            .last()
            .filter(|_| more)
            .and_then(|last| {
                last.closed_at.map(|closed_at| IncidentCursor {
                    closed_at,
                    id: last.id,
                })
            })
            .map(IncidentCursor::encode);
        Ok(json(&SiteIncidents {
            site: site.clone(),
            since,
            incidents: closed.iter().map(IncidentJson::from).collect(),
            next_cursor,
        }))
    })
    .await
}

/// Rang d'un site qui a une source de logs ; `None` (404) sinon.
fn logs_site_index(state: &AppState, id: Result<Path<String>, PathRejection>) -> Option<usize> {
    site_index(state, id).filter(|&index| {
        state.config.sites[index]
            .logs
            .as_ref()
            .is_some_and(|logs| logs.source.is_some())
    })
}

/// Robot du catalogue vu sur 24 h. Les textes viennent du catalogue mais
/// sont relus du résumé en base : servis comme du texte d'origine log.
#[derive(Serialize)]
struct BotJson {
    name: LogText,
    publisher: LogText,
    purpose: LogText,
    robots_only: bool,
    honours_robots: bool,
    class: BotClass,
    protected: bool,
    requests: u64,
}

/// Règle sur sa fenêtre, finie à l'heure de référence ; jamais d'IP.
#[derive(Serialize)]
struct RuleJson {
    rule: LogText,
    scope: &'static str,
    severity: &'static str,
    window_secs: u32,
    min_count: u32,
    min_ips: u32,
    count: u64,
    distinct_ips: usize,
    keys_over: usize,
    exceeded: bool,
}

/// Charge d'une heure (tranche `timestamp_ms / 3 600 000`).
#[derive(Serialize)]
struct LoadJson {
    hour: i64,
    requests: u64,
    refused: u64,
    timed: u64,
    service_us: u64,
    facets: u64,
    facets_us: u64,
    bots: u64,
    bots_us: u64,
}

/// Dernier instantané de l'analyse des logs d'un site, sans IP.
#[derive(Serialize)]
struct AnalysisJson {
    /// Heure du veilleur, en secondes.
    generated_at: i64,
    /// Heure de référence des fenêtres, en ms (heure des données).
    reference_ms: i64,
    bots: Vec<BotJson>,
    scored: u64,
    unscored: u64,
    rules: Vec<RuleJson>,
    load: Vec<LoadJson>,
    load_threshold_us: u64,
}

impl From<Analysis> for AnalysisJson {
    fn from(a: Analysis) -> Self {
        Self {
            generated_at: a.generated_at,
            reference_ms: a.reference_ms,
            bots: a
                .bots
                .iter()
                .map(|b| BotJson {
                    name: LogText::detail(&b.name),
                    publisher: LogText::detail(&b.publisher),
                    purpose: LogText::detail(&b.purpose),
                    robots_only: b.robots_only,
                    honours_robots: b.honours_robots,
                    class: b.class,
                    protected: b.protected,
                    requests: b.requests,
                })
                .collect(),
            scored: a.scored,
            unscored: a.unscored,
            rules: a
                .rules
                .iter()
                .map(|r| RuleJson {
                    rule: LogText::detail(&r.rule),
                    scope: r.scope.as_str(),
                    severity: r.severity.as_str(),
                    window_secs: r.window_secs,
                    min_count: r.min_count,
                    min_ips: r.min_ips,
                    count: r.count,
                    distinct_ips: r.distinct_ips,
                    keys_over: r.keys_over,
                    exceeded: r.exceeded,
                })
                .collect(),
            load: a
                .load
                .iter()
                .map(|h| LoadJson {
                    hour: h.hour,
                    requests: h.requests,
                    refused: h.refused,
                    timed: h.timed,
                    service_us: h.service_us,
                    facets: h.facets,
                    facets_us: h.facets_us,
                    bots: h.bots,
                    bots_us: h.bots_us,
                })
                .collect(),
            load_threshold_us: a.load_threshold_us,
        }
    }
}

#[derive(Serialize)]
struct SiteLogs {
    /// `null` tant que `tick` n'a écrit aucun instantané pour ce site.
    analysis: Option<AnalysisJson>,
}

/// Dernier instantané de l'analyse des logs (#8) : robots, règles, charge.
/// 404 pour un site sans source de logs.
async fn site_logs_handler(
    State(state): State<Arc<AppState>>,
    Authenticated(_device): Authenticated,
    id: Result<Path<String>, PathRejection>,
) -> Response {
    let Some(index) = logs_site_index(&state, id) else {
        return ApiError::NOT_FOUND.into_response();
    };
    with_store(&state, "/api/v1/sites/logs", move |state, store| {
        let analysis = if store.schema_version()? >= SCHEMA_FINDINGS {
            log_findings::latest_summary(&store, &state.site_ids[index])?
        } else {
            None
        };
        Ok(json(&SiteLogs {
            analysis: analysis.map(AnalysisJson::from),
        }))
    })
    .await
}

/// Verdict d'une IP, en liste blanche : ni user-agent, ni chemin, ni
/// libellé (il peut citer l'un ou l'autre), seulement des codes de raison.
#[derive(Serialize)]
struct VerdictJson {
    ip: LogText,
    score: u8,
    /// `moyen` ou `eleve`.
    level: Level,
    reasons: Vec<&'static str>,
    class: BotClass,
}

/// Verdicts d'un instantané, une page.
#[derive(Serialize)]
struct SiteLogIps {
    site: String,
    /// Instantané paginé ; `null` s'il n'y en a pas de moins de 48 h.
    generated_at: Option<i64>,
    #[serde(flatten)]
    page: Page<VerdictJson>,
}

/// Plus longue écriture d'une adresse IP (IPv6 avec IPv4 finale).
const MAX_IP_CHARS: usize = 45;

/// Verdicts moyens et élevés du dernier instantané de moins de 48 h, du
/// plus haut score au plus bas, par pages. Le curseur fixe l'instantané :
/// une page suivante le relit même après un nouveau `tick` ; s'il a été
/// purgé, 409 `cursor_expired` et le client reprend au début.
async fn site_log_ips_handler(
    State(state): State<Arc<AppState>>,
    Authenticated(_device): Authenticated,
    id: Result<Path<String>, PathRejection>,
    uri: Uri,
) -> Response {
    let Some(index) = logs_site_index(&state, id) else {
        return ApiError::NOT_FOUND.into_response();
    };
    let page = match PageQuery::parse(uri.query()) {
        Ok(page) => page,
        Err(err) => return err.into_response(),
    };
    let cursor = match page
        .cursor
        .as_deref()
        .map(VerdictCursor::decode)
        .transpose()
    {
        Ok(cursor) => cursor,
        Err(err) => return err.into_response(),
    };
    let oldest = state.clock.unix() - VERDICT_RETENTION_SECS;
    with_store(&state, "/api/v1/sites/logs/ips", move |state, store| {
        let site = &state.site_ids[index];
        let readable = store.schema_version()? >= SCHEMA_FINDINGS;
        let snapshot = match &cursor {
            Some(cursor) => {
                if !readable
                    || cursor.generated_at < oldest
                    || !log_findings::snapshot_exists(&store, site, cursor.generated_at)?
                {
                    return Ok(ApiError::CURSOR_EXPIRED.into_response());
                }
                Some(cursor.generated_at)
            }
            None if readable => log_findings::latest_summary(&store, site)?
                .map(|a| a.generated_at)
                .filter(|&at| at >= oldest),
            None => None,
        };
        let Some(generated_at) = snapshot else {
            return Ok(json(&SiteLogIps {
                site: site.clone(),
                generated_at: None,
                page: Page {
                    items: Vec::new(),
                    next_cursor: None,
                },
            }));
        };
        let after = cursor.as_ref().map(|c| (c.score, c.ip.as_str()));
        let mut rows =
            log_findings::verdicts_page(&store, site, generated_at, after, page.limit + 1)?;
        let more = page::split(&mut rows, page.limit);
        let next_cursor = rows
            .last()
            .filter(|_| more)
            .map(|(score, ip, _)| VerdictCursor {
                generated_at,
                score: *score,
                ip: ip.clone(),
            })
            .map(|c| c.encode());
        let items = rows
            .into_iter()
            .filter_map(|(_, _, verdict)| verdict)
            .filter(|v| matches!(v.level, Level::Medium | Level::High))
            .map(|v| VerdictJson {
                ip: LogText::new(&v.ip.to_string(), MAX_IP_CHARS),
                score: v.score,
                level: v.level,
                reasons: v.reasons.iter().map(|r| r.code()).collect(),
                class: v.class,
            })
            .collect();
        Ok(json(&SiteLogIps {
            site: site.clone(),
            generated_at: Some(generated_at),
            page: Page { items, next_cursor },
        }))
    })
    .await
}

async fn incident_handler(
    State(state): State<Arc<AppState>>,
    Authenticated(_device): Authenticated,
    id: Result<Path<String>, PathRejection>,
) -> Response {
    let Some(id) = incident_id(id) else {
        return ApiError::NOT_FOUND.into_response();
    };
    with_store(&state, "/api/v1/incidents", move |_, store| {
        Ok(match store.incident(id)? {
            Some(incident) => json(&IncidentJson::from(&incident)),
            None => ApiError::NOT_FOUND.into_response(),
        })
    })
    .await
}

/// Même effet que `vigie ack` : arrête les rappels, la clôture reste.
async fn ack_handler(
    State(state): State<Arc<AppState>>,
    Authenticated(device): Authenticated,
    id: Result<Path<String>, PathRejection>,
) -> Response {
    let Some(id) = incident_id(id) else {
        return ApiError::NOT_FOUND.into_response();
    };
    let now = state.clock.unix();
    let rid = request_id::current();
    with_writer(&state, "/api/v1/incidents/ack", move |store| {
        Ok(match store.ack(id, now)? {
            AckOutcome::Acked | AckOutcome::AlreadyAcked => {
                log::info!(
                    "[{}] incident {id} acquitté par l'appareil {}",
                    rid,
                    device.id
                );
                match store.incident(id)? {
                    Some(incident) => json(&IncidentJson::from(&incident)),
                    None => ApiError::NOT_FOUND.into_response(),
                }
            }
            AckOutcome::AlreadyClosed => ApiError::CONFLICT.into_response(),
            AckOutcome::NotFound => ApiError::NOT_FOUND.into_response(),
        })
    })
    .await
}

#[derive(Serialize)]
struct SettingsSite {
    id: String,
    url: String,
    kind: &'static str,
    /// Runtime effectif : déclaré, sinon impliqué par le CMS ; `null` sinon.
    runtime: Option<&'static str>,
    interval: u64,
    agent_silence: u64,
    /// Un agent est déclaré pour ce site.
    agent: bool,
    /// Contrôles externes applicables et leur intervalle, en secondes.
    checks: BTreeMap<&'static str, u64>,
}

#[derive(Serialize)]
struct SettingsAlerts {
    /// Destinataire masqué : `a***@e***.org`.
    to: String,
}

#[derive(Serialize)]
struct SettingsDevice {
    id: i64,
    name: String,
    created_at: i64,
    seen_at: Option<i64>,
    revoked_at: Option<i64>,
    /// L'appareil qui fait la requête.
    current: bool,
}

#[derive(Serialize)]
struct Settings {
    sites: Vec<SettingsSite>,
    alerts: SettingsAlerts,
    /// Secondes entre deux rappels d'un incident non acquitté.
    reminder_period: i64,
    public_url: Option<String>,
    devices: Vec<SettingsDevice>,
}

/// `alertes@example.org` devient `a***@e***.org` : assez pour reconnaître
/// l'adresse, pas assez pour la récolter.
pub fn mask_email(address: &str) -> String {
    let first = |part: &str| part.chars().next().map(String::from).unwrap_or_default();
    let Some((local, domain)) = address.rsplit_once('@') else {
        return "***".into();
    };
    let masked_domain = match domain.rsplit_once('.') {
        Some((name, tld)) => format!("{}***.{tld}", first(name)),
        None => format!("{}***", first(domain)),
    };
    format!("{}***@{masked_domain}", first(local))
}

async fn settings_handler(
    State(state): State<Arc<AppState>>,
    Authenticated(device): Authenticated,
) -> Response {
    with_store(&state, "/api/v1/settings", move |state, store| {
        let agents = store.agents()?;
        let sites = state
            .config
            .sites
            .iter()
            .map(|site| SettingsSite {
                id: site.id.clone(),
                url: site.url.clone(),
                kind: site.kind.as_str(),
                runtime: site.effective_runtime().map(Runtime::as_str),
                interval: site.interval,
                agent_silence: site.agent_silence,
                agent: agents.iter().any(|a| a.site == site.id),
                checks: capability::allowed_controls(site, &capability::Ctx::default())
                    .into_iter()
                    .filter_map(|control| match control {
                        Control::Check(kind) => Some((kind.name(), kind.interval(site))),
                        Control::Heartbeat
                        | Control::Integrity
                        | Control::Agent(_)
                        | Control::Logs
                        | Control::Typology => None,
                    })
                    .collect(),
            })
            .collect();
        let devices = store
            .devices()?
            .into_iter()
            .map(|d| SettingsDevice {
                current: d.id == device.id,
                id: d.id,
                name: d.name,
                created_at: d.created_at,
                seen_at: d.seen_at,
                revoked_at: d.revoked_at,
            })
            .collect();
        Ok(json(&Settings {
            sites,
            alerts: SettingsAlerts {
                to: mask_email(&state.config.alerts.to),
            },
            reminder_period: crate::store::REMINDER_PERIOD,
            public_url: state.config.api.as_ref().map(|a| a.public_url.clone()),
            devices,
        }))
    })
    .await
}

/// L'appareil appelant se révoque : 204, puis 401 avec ce jeton.
async fn device_self_handler(
    State(state): State<Arc<AppState>>,
    Authenticated(device): Authenticated,
) -> Response {
    let now = state.clock.unix();
    let rid = request_id::current();
    with_writer(&state, "/api/v1/devices/self", move |store| {
        Ok(match store.revoke_device(device.id, now)? {
            RevokeOutcome::Revoked | RevokeOutcome::AlreadyRevoked => {
                log::info!(
                    "[{}] appareil {} « {} » révoqué par lui-même",
                    rid,
                    device.id,
                    device.name
                );
                no_store(StatusCode::NO_CONTENT.into_response())
            }
            RevokeOutcome::NotFound => ApiError::UNAUTHORIZED.into_response(),
        })
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_recipient_is_masked() {
        assert_eq!(mask_email("alertes@example.org"), "a***@e***.org");
        assert_eq!(mask_email("x@localhost"), "x***@l***");
        assert_eq!(mask_email("sans-arobase"), "***");
    }
}
