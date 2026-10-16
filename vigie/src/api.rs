//! `/api/v1` : API de la console (`docs/api-console.md`).
//!
//! `POST /api/v1/pair` échange un code d'appairage contre un jeton d'appareil ;
//! toute autre route exige `Authorization: Bearer <jeton>`. Un échec reçoit un
//! 401 sans corps, quelle qu'en soit la raison. Ni jeton ni code n'entrent
//! dans le journal : seulement l'id et le nom de l'appareil.
//!
//! L'état d'un site (`SiteState`) est calculé ici et nulle part ailleurs : la
//! console l'affiche sans rien recalculer.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::rejection::PathRejection;
use axum::extract::{FromRequestParts, Path, Request, State};
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use serde::{Deserialize, Serialize};

use crate::checks::{CheckKind, heartbeat};
use crate::config::{Site, SiteKind};
use crate::device;
use crate::finding::Severity;
use crate::serve::{AppState, not_found};
use crate::store::{
    AGENT_PREFIX, AckOutcome, Agent, CheckRun, Device, Incident, RevokeOutcome, RunResult,
    SCHEMA_CHECK_RESULTS, Store,
};

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
        .route("/api/v1/sites/{id}", get(site_handler).fallback(not_found))
        .route(
            "/api/v1/sites/{id}/incidents",
            get(site_incidents_handler).fallback(not_found),
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
}

/// Ouvre la base en lecteur, si elle existe et porte le schéma de l'API
/// (appareils et résultats des passages) : l'API ne crée jamais la base.
fn open_devices(state: &AppState) -> anyhow::Result<Option<Store>> {
    match Store::open_read(state.database())? {
        Some(store) if store.schema_version()? >= SCHEMA_CHECK_RESULTS => Ok(Some(store)),
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

/// Incidents fermés montrés par `GET /api/v1/sites/{id}/incidents`.
pub const CLOSED_WINDOW: i64 = 30 * 86_400;

/// 200, la valeur en JSON, jamais mise en cache.
fn json<T: Serialize>(body: &T) -> Response {
    no_store(Json(body).into_response())
}

/// Exécute `f` sur la base, hors du runtime. 500 sans corps sur erreur, et
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
    match outcome {
        Ok(Ok(Some(response))) => response,
        Ok(Ok(None)) => {
            log::error!("{route} : base absente ou pas encore migrée");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Ok(Err(err)) => {
            log::error!("{route} : {err:#}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(err) => {
            log::error!("{route} : tâche interrompue : {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
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
    /// Incidents ouverts, de gravité décroissante puis du plus ancien.
    open: Vec<Incident>,
    /// Derniers passages des contrôles encore surveillés.
    runs: Vec<CheckRun>,
}

impl SiteView {
    fn read(site: &Site, agents: &[Agent], open: &[Incident], runs: &[CheckRun]) -> Self {
        let agent = agents.iter().find(|a| a.site == site.id).cloned();
        let mut open: Vec<Incident> = open.iter().filter(|i| i.site == site.id).cloned().collect();
        open.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then(a.opened_at.cmp(&b.opened_at))
                .then(a.id.cmp(&b.id))
        });
        let watched = |check: &str| {
            if check == heartbeat::NAME || check.starts_with(AGENT_PREFIX) {
                agent.is_some()
            } else {
                CheckKind::ALL
                    .into_iter()
                    .any(|kind| kind.applies(site) && kind.name() == check)
            }
        };
        let runs = runs
            .iter()
            .filter(|r| r.site == site.id && watched(&r.check_name))
            .cloned()
            .collect();
        Self { agent, open, runs }
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

fn kind_name(kind: SiteKind) -> &'static str {
    match kind {
        SiteKind::Generic => "generic",
        SiteKind::Wordpress => "wordpress",
        SiteKind::Prestashop => "prestashop",
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

impl From<&Incident> for IncidentJson {
    fn from(i: &Incident) -> Self {
        Self {
            id: i.id,
            key: i.key.clone(),
            site: i.site.clone(),
            check: i.check_name.clone(),
            severity: i.severity.as_str(),
            detail: i.detail.clone(),
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
    let now = (state.clock)();
    with_store(&state, "/api/v1/overview", move |state, store| {
        let agents = store.agents()?;
        let open = store.open_incidents()?;
        let runs = store.check_results()?;
        let mut sites: Vec<(usize, OverviewSite)> = state
            .config
            .sites
            .iter()
            .enumerate()
            .map(|(rank, site)| {
                let view = SiteView::read(site, &agents, &open, &runs);
                let line = OverviewSite {
                    id: site.id.clone(),
                    url: site.url.clone(),
                    kind: kind_name(site.kind),
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
            detail: run.and_then(|r| r.detail.clone()),
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
        return StatusCode::NOT_FOUND.into_response();
    };
    with_store(&state, "/api/v1/sites", move |state, store| {
        let site = &state.config.sites[index];
        let view = SiteView::read(
            site,
            &store.agents()?,
            &store.open_incidents()?,
            &store.check_results()?,
        );
        let run_of = |name: &str| view.runs.iter().find(|r| r.check_name == name);
        let mut checks: Vec<CheckJson> = CheckKind::ALL
            .into_iter()
            .filter(|kind| kind.applies(site))
            .map(|kind| CheckJson::new(kind.name(), Some(kind.interval(site)), run_of(kind.name())))
            .collect();
        if view.agent.is_some() {
            checks.push(CheckJson::new(
                heartbeat::NAME,
                Some(site.agent_silence),
                run_of(heartbeat::NAME),
            ));
            checks.extend(
                view.runs
                    .iter()
                    .filter(|r| r.check_name.starts_with(AGENT_PREFIX))
                    .map(|r| CheckJson::new(&r.check_name, None, Some(r))),
            );
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
            kind: kind_name(site.kind),
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

#[derive(Serialize)]
struct SiteIncidents {
    site: String,
    since: i64,
    incidents: Vec<IncidentJson>,
}

async fn site_incidents_handler(
    State(state): State<Arc<AppState>>,
    Authenticated(_device): Authenticated,
    id: Result<Path<String>, PathRejection>,
) -> Response {
    let Some(index) = site_index(&state, id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let since = (state.clock)() - CLOSED_WINDOW;
    with_store(&state, "/api/v1/sites/incidents", move |state, store| {
        let site = &state.site_ids[index];
        let closed = store.closed_incidents(site, since)?;
        Ok(json(&SiteIncidents {
            site: site.clone(),
            since,
            incidents: closed.iter().map(IncidentJson::from).collect(),
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
        return StatusCode::NOT_FOUND.into_response();
    };
    with_store(&state, "/api/v1/incidents", move |_, store| {
        Ok(match store.incident(id)? {
            Some(incident) => json(&IncidentJson::from(&incident)),
            None => StatusCode::NOT_FOUND.into_response(),
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
        return StatusCode::NOT_FOUND.into_response();
    };
    let now = (state.clock)();
    with_store(&state, "/api/v1/incidents/ack", move |_, mut store| {
        Ok(match store.ack(id, now)? {
            AckOutcome::Acked | AckOutcome::AlreadyAcked => {
                log::info!("incident {id} acquitté par l'appareil {}", device.id);
                match store.incident(id)? {
                    Some(incident) => json(&IncidentJson::from(&incident)),
                    None => StatusCode::NOT_FOUND.into_response(),
                }
            }
            AckOutcome::AlreadyClosed => StatusCode::CONFLICT.into_response(),
            AckOutcome::NotFound => StatusCode::NOT_FOUND.into_response(),
        })
    })
    .await
}

#[derive(Serialize)]
struct SettingsSite {
    id: String,
    url: String,
    kind: &'static str,
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
                kind: kind_name(site.kind),
                interval: site.interval,
                agent_silence: site.agent_silence,
                agent: agents.iter().any(|a| a.site == site.id),
                checks: CheckKind::ALL
                    .into_iter()
                    .filter(|kind| kind.applies(site))
                    .map(|kind| (kind.name(), kind.interval(site)))
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
    let now = (state.clock)();
    with_store(&state, "/api/v1/devices/self", move |_, mut store| {
        Ok(match store.revoke_device(device.id, now)? {
            RevokeOutcome::Revoked | RevokeOutcome::AlreadyRevoked => {
                log::info!(
                    "appareil {} « {} » révoqué par lui-même",
                    device.id,
                    device.name
                );
                no_store(StatusCode::NO_CONTENT.into_response())
            }
            RevokeOutcome::NotFound => StatusCode::UNAUTHORIZED.into_response(),
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
