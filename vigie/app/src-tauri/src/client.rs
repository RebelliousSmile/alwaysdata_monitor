//! Client de l'API du veilleur (`vigie/docs/api-console.md`). Le jeton est
//! ajouté ici, côté Rust : le webview ne reçoit que les réponses lues.
//!
//! Les types ne portent que les champs que la console affiche. Un champ
//! facultatif reste requis dans la réponse (`nullable`) : un champ renommé
//! ou retiré côté veilleur fait échouer la lecture, et le test de contrat.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::RETRY_AFTER;
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use url::Url;

/// Délai d'établissement de la connexion.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Délai total d'une requête : la console préfère « hors ligne » à l'attente.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Erreur rendue au webview, sérialisée en `{kind, message}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApiError {
    pub kind: ErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// Veilleur injoignable ou trop lent.
    Offline,
    /// Jeton inconnu ou révoqué, ou code d'appairage refusé.
    Unauthorized,
    NotFound,
    /// Acquittement d'un incident fermé.
    Conflict,
    /// Curseur d'une liste dont l'instantané a été purgé : reprendre au
    /// début, sans curseur (`409 cursor_expired`).
    CursorExpired,
    /// Paramètre de pagination refusé (`400 bad_request`).
    BadRequest,
    /// Corps d'un autre type que JSON (`415`).
    UnsupportedMediaType,
    /// Limite de débit dépassée (`429`) : aucune relance automatique.
    TooManyRequests,
    /// Réponse 5xx, ou réponse illisible.
    Server,
    /// Lien d'appairage mal formé ou adresse refusée.
    InvalidLink,
    /// Aucun appareil appairé sur ce poste.
    NotPaired,
    /// Fichier du jeton illisible ou impossible à écrire.
    Storage,
}

impl ApiError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ApiError {}

/// `Option` présent dans la réponse, à `null` ou non : jamais absent.
fn nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentState {
    Open,
    Acked,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SiteState {
    NonCompliant,
    Blind,
    ToCheck,
    FirstRead,
    Ok,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Incident {
    pub id: i64,
    pub site: String,
    pub check: String,
    pub severity: Severity,
    pub detail: String,
    pub opened_at: i64,
    #[serde(deserialize_with = "nullable")]
    pub closed_at: Option<i64>,
    #[serde(deserialize_with = "nullable")]
    pub acked_at: Option<i64>,
    #[serde(deserialize_with = "nullable")]
    pub open_notified_at: Option<i64>,
    #[serde(deserialize_with = "nullable")]
    pub close_notified_at: Option<i64>,
    #[serde(deserialize_with = "nullable")]
    pub last_reminder_at: Option<i64>,
    pub state: IncidentState,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OverviewSite {
    pub id: String,
    pub url: String,
    pub kind: String,
    pub state: SiteState,
    pub open_count: u32,
    #[serde(deserialize_with = "nullable")]
    pub worst: Option<Incident>,
    #[serde(deserialize_with = "nullable")]
    pub last_read: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Overview {
    pub server_time: i64,
    #[serde(deserialize_with = "nullable")]
    pub last_tick: Option<i64>,
    pub sites: Vec<OverviewSite>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Agent {
    pub declared_at: i64,
    #[serde(deserialize_with = "nullable")]
    pub last_report_at: Option<i64>,
    #[serde(deserialize_with = "nullable")]
    pub agent: Option<String>,
    /// Dernier relevé de l'agent, tel qu'il l'a envoyé, ou `null`.
    pub facts: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Check {
    pub name: String,
    #[serde(deserialize_with = "nullable")]
    pub interval: Option<u64>,
    #[serde(deserialize_with = "nullable")]
    pub last_run: Option<i64>,
    /// `ok`, `finding` ou `error`.
    #[serde(deserialize_with = "nullable")]
    pub result: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub severity: Option<Severity>,
    #[serde(deserialize_with = "nullable")]
    pub detail: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub duration_ms: Option<i64>,
    /// Valeurs relevées par le passage (`tls_not_after` pour tls), ou `null`.
    pub observed: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SiteDetail {
    pub id: String,
    pub url: String,
    pub kind: String,
    pub interval: u64,
    pub agent_silence: u64,
    pub state: SiteState,
    #[serde(deserialize_with = "nullable")]
    pub last_read: Option<i64>,
    #[serde(deserialize_with = "nullable")]
    pub agent: Option<Agent>,
    pub open_incidents: Vec<Incident>,
    pub checks: Vec<Check>,
}

/// Une page des incidents clos. `next_cursor` manque chez un veilleur
/// antérieur à la pagination : il vaut alors `null`, dernière page.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SiteIncidents {
    pub site: String,
    pub since: i64,
    pub incidents: Vec<Incident>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// Robot du catalogue vu sur 24 h. Ses textes viennent des logs : le
/// webview ne les affiche qu'en texte.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bot {
    pub name: String,
    pub publisher: String,
    pub purpose: String,
    pub honours_robots: bool,
    /// `search_engine`, `ai_training`… (`BotClass` du veilleur).
    pub class: String,
    /// Jamais visé par une action robots.txt ou user-agent.
    pub protected: bool,
    pub requests: u64,
}

/// Règle de l'analyse sur sa fenêtre ; aucune IP.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    pub rule: String,
    /// `ip` ou `site`.
    pub scope: String,
    pub severity: Severity,
    pub window_secs: u32,
    pub min_count: u32,
    pub count: u64,
    pub distinct_ips: u64,
    pub exceeded: bool,
}

/// Charge d'une heure (`timestamp_ms / 3 600 000`), temps en µs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoadHour {
    pub hour: i64,
    pub requests: u64,
    pub refused: u64,
    /// Requêtes dont le log porte une durée.
    pub timed: u64,
    pub service_us: u64,
    pub bots: u64,
}

/// Dernier instantané de l'analyse des logs d'un site.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Analysis {
    pub generated_at: i64,
    pub bots: Vec<Bot>,
    pub scored: u64,
    pub unscored: u64,
    pub rules: Vec<Rule>,
    pub load: Vec<LoadHour>,
    pub load_threshold_us: u64,
}

/// Réponse de `GET /api/v1/sites/{id}/logs` : `null` tant qu'aucune
/// analyse n'a été écrite.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SiteLogs {
    #[serde(deserialize_with = "nullable")]
    pub analysis: Option<Analysis>,
}

/// Verdict d'une IP : codes de raison, jamais de user-agent ni de chemin.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    pub ip: String,
    pub score: u8,
    /// `moyen` ou `eleve`.
    pub level: String,
    pub reasons: Vec<String>,
    pub class: String,
}

/// Une page des verdicts d'IP d'un instantané.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogIps {
    pub site: String,
    /// Instantané lu ; `null` s'il n'y en a pas de moins de 48 h.
    #[serde(deserialize_with = "nullable")]
    pub generated_at: Option<i64>,
    pub items: Vec<Verdict>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

// Failles des composants (#21). Les identifiants, liens et attributions
// viennent de sources tierces : le webview ne les affiche qu'en texte.

/// Runs actifs de chaque source d'inventaire, servis avec chaque page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Runs {
    #[serde(deserialize_with = "nullable")]
    pub agent: Option<i64>,
    #[serde(deserialize_with = "nullable")]
    pub ci: Option<i64>,
}

/// Composant du dernier inventaire d'une source ; jamais son chemin.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Component {
    /// `agent` ou `ci`.
    pub source: String,
    pub purl: String,
    #[serde(deserialize_with = "nullable")]
    pub version: Option<String>,
    pub scope: String,
    pub vulns: u64,
    #[serde(deserialize_with = "nullable")]
    pub severity: Option<Severity>,
}

/// Une page des composants d'un site.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SiteComponents {
    pub site: String,
    pub runs: Runs,
    pub items: Vec<Component>,
    #[serde(deserialize_with = "nullable")]
    pub next_cursor: Option<String>,
}

/// Version d'un composant vue par une source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VulnVersion {
    pub source: String,
    #[serde(deserialize_with = "nullable")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Kev {
    pub date_added: String,
    pub ransomware: bool,
}

/// Score EPSS et percentile, en millionièmes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Epss {
    pub score: u32,
    pub percentile: u32,
}

/// Dérogation d'une faille : jamais son motif ni son auteur.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Waiver {
    pub source: String,
    pub until: i64,
    /// `valid`, `expired`, `version_changed`, `group_changed`, `kev`.
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Link {
    pub source: String,
    pub url: String,
}

/// Faille d'un composant, fusionnée par alias, avec son composant et la
/// version vue par chaque source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Vuln {
    pub group: String,
    pub ids: Vec<String>,
    pub component: String,
    pub versions: Vec<VulnVersion>,
    /// `affected`, `version_unknown` ou `range_unknown`.
    pub verdict: String,
    pub corrected: bool,
    pub fixed: Vec<String>,
    pub severity: Severity,
    pub rule: String,
    #[serde(deserialize_with = "nullable")]
    pub kev: Option<Kev>,
    #[serde(deserialize_with = "nullable")]
    pub epss: Option<Epss>,
    /// CVSS en dixièmes.
    #[serde(deserialize_with = "nullable")]
    pub score: Option<u8>,
    /// `internal`, `facts_only` ou `free`.
    pub redistribution: String,
    #[serde(deserialize_with = "nullable")]
    pub waiver: Option<Waiver>,
    pub links: Vec<Link>,
    pub attributions: Vec<String>,
}

/// Une page des failles d'un site.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SiteVulns {
    pub site: String,
    pub runs: Runs,
    pub items: Vec<Vuln>,
    #[serde(deserialize_with = "nullable")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Dataset {
    pub version: String,
    pub released: i64,
}

/// Constat `vulns-sync` ouvert d'une source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceIncident {
    pub id: i64,
    pub severity: Severity,
    pub opened_at: i64,
}

/// Source de failles ou table d'enrichissement du veilleur.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VulnSource {
    pub id: String,
    /// `vulns` ou `enrichment`.
    pub kind: String,
    #[serde(deserialize_with = "nullable")]
    pub last_success_at: Option<i64>,
    #[serde(deserialize_with = "nullable")]
    pub last_outcome: Option<String>,
    pub entries: i64,
    pub license: String,
    pub attribution: String,
    pub redistribution: String,
    #[serde(deserialize_with = "nullable")]
    pub dataset: Option<Dataset>,
    #[serde(deserialize_with = "nullable")]
    pub incident: Option<SourceIncident>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VulnSources {
    pub sources: Vec<VulnSource>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SettingsSite {
    pub id: String,
    pub url: String,
    pub kind: String,
    pub interval: u64,
    pub agent_silence: u64,
    pub agent: bool,
    pub checks: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SettingsAlerts {
    /// Destinataire masqué par le veilleur.
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Device {
    pub id: i64,
    pub name: String,
    pub created_at: i64,
    #[serde(deserialize_with = "nullable")]
    pub seen_at: Option<i64>,
    #[serde(deserialize_with = "nullable")]
    pub revoked_at: Option<i64>,
    pub current: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    pub sites: Vec<SettingsSite>,
    pub alerts: SettingsAlerts,
    pub reminder_period: i64,
    #[serde(deserialize_with = "nullable")]
    pub public_url: Option<String>,
    pub devices: Vec<Device>,
}

/// Réponse de `POST /api/v1/pair`. Le jeton ne quitte jamais le Rust.
#[derive(Clone, Deserialize)]
pub struct Paired {
    pub token: String,
    pub device_id: i64,
    pub name: String,
}

impl std::fmt::Debug for Paired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Paired")
            .field("device_id", &self.device_id)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// Client HTTP : rustls et ring, racines de webpki-roots, délais courts.
fn http() -> Result<reqwest::Client, ApiError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| ApiError::new(ErrorKind::Server, format!("TLS : {err}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        // Une redirection emporterait le jeton vers une autre adresse.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| ApiError::new(ErrorKind::Server, format!("client HTTP : {err}")))
}

/// Client d'un veilleur, appairé (`token`) ou non.
#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    base: Url,
    token: Option<String>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("base", &self.base.as_str())
            .field("paired", &self.token.is_some())
            .finish()
    }
}

impl Client {
    /// Client sans jeton, pour l'appairage. `base` a été validée par
    /// `pairing::parse_link` ou relue du fichier de l'appareil.
    pub fn new(base: &str) -> Result<Self, ApiError> {
        let base = Url::parse(base)
            .map_err(|_| ApiError::new(ErrorKind::InvalidLink, "adresse du veilleur illisible"))?;
        if base.cannot_be_a_base() {
            return Err(ApiError::new(
                ErrorKind::InvalidLink,
                "adresse du veilleur illisible",
            ));
        }
        Ok(Self {
            http: http()?,
            base,
            token: None,
        })
    }

    pub fn with_token(mut self, token: String) -> Self {
        self.token = Some(token);
        self
    }

    /// `<base>/api/v1/<segments>`, chaque segment encodé.
    fn url(&self, segments: &[&str]) -> Url {
        let mut url = self.base.clone();
        url.set_query(None);
        url.set_fragment(None);
        url.path_segments_mut()
            .expect("base vérifiée par Client::new")
            .pop_if_empty()
            .extend(["api", "v1"])
            .extend(segments);
        url
    }

    /// URL d'une page : `?cursor=<next_cursor>` après la première. `limit`
    /// n'est jamais envoyé : 50 par défaut, le même à chaque page.
    fn page_url(&self, segments: &[&str], cursor: Option<&str>) -> Url {
        let mut url = self.url(segments);
        if let Some(cursor) = cursor {
            url.query_pairs_mut().append_pair("cursor", cursor);
        }
        url
    }

    async fn send(
        &self,
        method: Method,
        segments: &[&str],
        cursor: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> Result<reqwest::Response, ApiError> {
        let mut request = self.http.request(method, self.page_url(segments, cursor));
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.map_err(|err| {
            ApiError::new(
                ErrorKind::Offline,
                if err.is_timeout() {
                    "le veilleur ne répond pas".to_owned()
                } else {
                    "veilleur injoignable".to_owned()
                },
            )
        })?;
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok());
        // Seul `error.code` est lu : `message` n'est qu'indicatif.
        let code = if status == StatusCode::CONFLICT {
            response
                .bytes()
                .await
                .ok()
                .and_then(|body| serde_json::from_slice::<ErrorBody>(&body).ok())
                .map(|body| body.error.code)
        } else {
            None
        };
        Err(classify(status, code.as_deref(), retry_after))
    }

    async fn read<T: DeserializeOwned>(
        &self,
        method: Method,
        segments: &[&str],
        cursor: Option<&str>,
    ) -> Result<T, ApiError> {
        let response = self.send(method, segments, cursor, None).await?;
        decode(response).await
    }

    /// Échange le code contre un jeton. 401 : code inconnu, utilisé ou expiré.
    pub async fn pair(&self, code: &str) -> Result<Paired, ApiError> {
        let response = self
            .send(
                Method::POST,
                &["pair"],
                None,
                Some(serde_json::json!({ "code": code })),
            )
            .await
            .map_err(|err| match err.kind {
                ErrorKind::Unauthorized => ApiError::new(
                    ErrorKind::Unauthorized,
                    "code refusé : expiré, déjà utilisé ou inconnu",
                ),
                _ => err,
            })?;
        decode(response).await
    }

    pub async fn overview(&self) -> Result<Overview, ApiError> {
        self.read(Method::GET, &["overview"], None).await
    }

    pub async fn site(&self, id: &str) -> Result<SiteDetail, ApiError> {
        self.read(Method::GET, &["sites", id], None).await
    }

    /// Une page des incidents clos ; `cursor` est le `next_cursor` de la
    /// page précédente, `None` pour la première.
    pub async fn incidents(
        &self,
        site: &str,
        cursor: Option<&str>,
    ) -> Result<SiteIncidents, ApiError> {
        self.read(Method::GET, &["sites", site, "incidents"], cursor)
            .await
    }

    /// Dernière analyse des logs du site. 404 : site sans source de logs,
    /// ou veilleur antérieur à cette route.
    pub async fn logs(&self, site: &str) -> Result<SiteLogs, ApiError> {
        self.read(Method::GET, &["sites", site, "logs"], None).await
    }

    /// Une page des verdicts d'IP. `CursorExpired` : l'instantané du
    /// curseur a été purgé, reprendre sans curseur.
    pub async fn log_ips(&self, site: &str, cursor: Option<&str>) -> Result<LogIps, ApiError> {
        self.read(Method::GET, &["sites", site, "logs", "ips"], cursor)
            .await
    }

    /// Une page des composants d'un site. 404 : site sans source
    /// d'inventaire, jamais rapproché, ou veilleur antérieur à cette route ;
    /// `CursorExpired` : un run a basculé, reprendre sans curseur.
    pub async fn components(
        &self,
        site: &str,
        cursor: Option<&str>,
    ) -> Result<SiteComponents, ApiError> {
        self.read(Method::GET, &["sites", site, "components"], cursor)
            .await
    }

    /// Une page des failles d'un site ; mêmes erreurs que `components`.
    pub async fn vulns(&self, site: &str, cursor: Option<&str>) -> Result<SiteVulns, ApiError> {
        self.read(Method::GET, &["sites", site, "vulns"], cursor)
            .await
    }

    /// Sources de failles déclarées du veilleur.
    pub async fn vuln_sources(&self) -> Result<VulnSources, ApiError> {
        self.read(Method::GET, &["vulns", "sources"], None).await
    }

    pub async fn incident(&self, id: i64) -> Result<Incident, ApiError> {
        self.read(Method::GET, &["incidents", &id.to_string()], None)
            .await
    }

    pub async fn ack(&self, id: i64) -> Result<Incident, ApiError> {
        self.read(Method::POST, &["incidents", &id.to_string(), "ack"], None)
            .await
    }

    pub async fn settings(&self) -> Result<Settings, ApiError> {
        self.read(Method::GET, &["settings"], None).await
    }

    /// Révoque cet appareil côté veilleur.
    pub async fn unpair(&self) -> Result<(), ApiError> {
        self.send(Method::DELETE, &["devices", "self"], None, None)
            .await
            .map(drop)
    }
}

/// Corps d'erreur commun : `{"error": {"code", "message", "request_id"}}`.
#[derive(Deserialize)]
struct ErrorBody {
    error: ErrorCode,
}

#[derive(Deserialize)]
struct ErrorCode {
    code: String,
}

/// Erreur d'une réponse non réussie. Messages fixes : rien de la réponse
/// n'y est recopié, hormis le délai de `Retry-After`.
fn classify(status: StatusCode, code: Option<&str>, retry_after: Option<u64>) -> ApiError {
    match status {
        StatusCode::UNAUTHORIZED => {
            ApiError::new(ErrorKind::Unauthorized, "appareil inconnu ou révoqué")
        }
        StatusCode::NOT_FOUND => ApiError::new(ErrorKind::NotFound, "introuvable"),
        StatusCode::CONFLICT if code == Some("cursor_expired") => ApiError::new(
            ErrorKind::CursorExpired,
            "la liste a changé depuis la première page : elle reprend au début",
        ),
        StatusCode::CONFLICT => ApiError::new(ErrorKind::Conflict, "l'incident est déjà fermé"),
        StatusCode::BAD_REQUEST => ApiError::new(
            ErrorKind::BadRequest,
            "requête refusée par le veilleur : pagination illisible",
        ),
        StatusCode::UNSUPPORTED_MEDIA_TYPE => ApiError::new(
            ErrorKind::UnsupportedMediaType,
            "requête refusée par le veilleur : type de contenu non accepté",
        ),
        StatusCode::TOO_MANY_REQUESTS => ApiError::new(
            ErrorKind::TooManyRequests,
            match retry_after {
                Some(seconds) => format!("trop de requêtes, réessayer dans {seconds} s"),
                None => "trop de requêtes, réessayer dans un moment".to_owned(),
            },
        ),
        status => ApiError::new(
            ErrorKind::Server,
            format!("le veilleur a répondu {}", status.as_u16()),
        ),
    }
}

async fn decode<T: DeserializeOwned>(response: reqwest::Response) -> Result<T, ApiError> {
    let bytes = response
        .bytes()
        .await
        .map_err(|_| ApiError::new(ErrorKind::Offline, "réponse interrompue"))?;
    serde_json::from_slice(&bytes)
        .map_err(|err| ApiError::new(ErrorKind::Server, format!("réponse illisible : {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nullable_field_must_be_present() {
        let device = |json: &str| serde_json::from_str::<Device>(json);
        let full = r#"{"id":1,"name":"poste","created_at":1,"seen_at":null,"revoked_at":null,"current":true}"#;
        assert_eq!(device(full).expect("complet").seen_at, None);
        let missing = r#"{"id":1,"name":"poste","created_at":1,"revoked_at":null,"current":true}"#;
        let err = device(missing).expect_err("seen_at absent");
        assert!(err.to_string().contains("seen_at"), "{err}");
    }

    #[test]
    fn urls_keep_the_base_path_and_encode_segments() {
        let client = Client::new("https://veilleur.example.org/").expect("client");
        assert_eq!(
            client.url(&["sites", "site a/b"]).as_str(),
            "https://veilleur.example.org/api/v1/sites/site%20a%2Fb"
        );
        let nested = Client::new("https://example.org/vigie").expect("client");
        assert_eq!(
            nested.url(&["overview"]).as_str(),
            "https://example.org/vigie/api/v1/overview"
        );
    }

    #[test]
    fn the_token_never_shows_in_debug_output() {
        let client = Client::new("https://veilleur.example.org")
            .expect("client")
            .with_token("secret-du-jeton".into());
        assert!(!format!("{client:?}").contains("secret-du-jeton"));
        let paired = Paired {
            token: "secret-du-jeton".into(),
            device_id: 1,
            name: "poste".into(),
        };
        assert!(!format!("{paired:?}").contains("secret-du-jeton"));
    }

    #[test]
    fn statuses_map_to_typed_errors_with_fixed_messages() {
        let expired = classify(StatusCode::CONFLICT, Some("cursor_expired"), None);
        assert_eq!(expired.kind, ErrorKind::CursorExpired);
        let conflict = classify(StatusCode::CONFLICT, Some("conflict"), None);
        assert_eq!(conflict.kind, ErrorKind::Conflict);
        assert_eq!(
            classify(StatusCode::CONFLICT, None, None).kind,
            ErrorKind::Conflict
        );
        let bad = classify(StatusCode::BAD_REQUEST, None, None);
        assert_eq!(bad.kind, ErrorKind::BadRequest);
        let media = classify(StatusCode::UNSUPPORTED_MEDIA_TYPE, None, None);
        assert_eq!(media.kind, ErrorKind::UnsupportedMediaType);
        let limited = classify(StatusCode::TOO_MANY_REQUESTS, None, Some(12));
        assert_eq!(limited.kind, ErrorKind::TooManyRequests);
        assert_eq!(limited.message, "trop de requêtes, réessayer dans 12 s");
        let unknown = classify(StatusCode::TOO_MANY_REQUESTS, None, None);
        assert_eq!(
            unknown.message,
            "trop de requêtes, réessayer dans un moment"
        );
        assert_eq!(
            classify(StatusCode::BAD_GATEWAY, None, None).message,
            "le veilleur a répondu 502"
        );
    }

    #[test]
    fn next_cursor_may_be_missing_on_an_older_veilleur() {
        let page: SiteIncidents =
            serde_json::from_str(r#"{"site":"site-a","since":1,"incidents":[]}"#).expect("page");
        assert_eq!(page.next_cursor, None);
        let logs = serde_json::from_str::<SiteLogs>("{}").expect_err("analysis requis");
        assert!(logs.to_string().contains("analysis"), "{logs}");
    }

    #[test]
    fn the_cursor_goes_in_the_query_string() {
        let client = Client::new("https://veilleur.example.org/").expect("client");
        let segments = ["sites", "site-a", "logs", "ips"];
        assert_eq!(
            client.page_url(&segments, Some("djF8+/=")).as_str(),
            "https://veilleur.example.org/api/v1/sites/site-a/logs/ips?cursor=djF8%2B%2F%3D"
        );
        assert_eq!(
            client.page_url(&segments, None).as_str(),
            "https://veilleur.example.org/api/v1/sites/site-a/logs/ips"
        );
    }

    #[test]
    fn errors_serialize_as_kind_and_message() {
        let json =
            serde_json::to_value(ApiError::new(ErrorKind::NotPaired, "non appairé")).expect("json");
        assert_eq!(
            json,
            serde_json::json!({ "kind": "not_paired", "message": "non appairé" })
        );
    }
}
