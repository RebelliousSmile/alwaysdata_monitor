//! Client de l'API du veilleur (`vigie/docs/api-console.md`). Le jeton est
//! ajouté ici, côté Rust : le webview ne reçoit que les réponses lues.
//!
//! Les types ne portent que les champs que la console affiche. Un champ
//! facultatif reste requis dans la réponse (`nullable`) : un champ renommé
//! ou retiré côté veilleur fait échouer la lecture, et le test de contrat.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SiteIncidents {
    pub site: String,
    pub since: i64,
    pub incidents: Vec<Incident>,
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

    async fn send(
        &self,
        method: Method,
        segments: &[&str],
        body: Option<serde_json::Value>,
    ) -> Result<reqwest::Response, ApiError> {
        let mut request = self.http.request(method, self.url(segments));
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
        match response.status() {
            status if status.is_success() => Ok(response),
            StatusCode::UNAUTHORIZED => Err(ApiError::new(
                ErrorKind::Unauthorized,
                "appareil inconnu ou révoqué",
            )),
            StatusCode::NOT_FOUND => Err(ApiError::new(ErrorKind::NotFound, "introuvable")),
            StatusCode::CONFLICT => Err(ApiError::new(
                ErrorKind::Conflict,
                "l'incident est déjà fermé",
            )),
            status => Err(ApiError::new(
                ErrorKind::Server,
                format!("le veilleur a répondu {}", status.as_u16()),
            )),
        }
    }

    async fn read<T: DeserializeOwned>(
        &self,
        method: Method,
        segments: &[&str],
    ) -> Result<T, ApiError> {
        let response = self.send(method, segments, None).await?;
        decode(response).await
    }

    /// Échange le code contre un jeton. 401 : code inconnu, utilisé ou expiré.
    pub async fn pair(&self, code: &str) -> Result<Paired, ApiError> {
        let response = self
            .send(
                Method::POST,
                &["pair"],
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
        self.read(Method::GET, &["overview"]).await
    }

    pub async fn site(&self, id: &str) -> Result<SiteDetail, ApiError> {
        self.read(Method::GET, &["sites", id]).await
    }

    pub async fn incidents(&self, site: &str) -> Result<SiteIncidents, ApiError> {
        self.read(Method::GET, &["sites", site, "incidents"]).await
    }

    pub async fn incident(&self, id: i64) -> Result<Incident, ApiError> {
        self.read(Method::GET, &["incidents", &id.to_string()])
            .await
    }

    pub async fn ack(&self, id: i64) -> Result<Incident, ApiError> {
        self.read(Method::POST, &["incidents", &id.to_string(), "ack"])
            .await
    }

    pub async fn settings(&self) -> Result<Settings, ApiError> {
        self.read(Method::GET, &["settings"]).await
    }

    /// Révoque cet appareil côté veilleur.
    pub async fn unpair(&self) -> Result<(), ApiError> {
        self.send(Method::DELETE, &["devices", "self"], None)
            .await
            .map(drop)
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
    fn errors_serialize_as_kind_and_message() {
        let json =
            serde_json::to_value(ApiError::new(ErrorKind::NotPaired, "non appairé")).expect("json");
        assert_eq!(
            json,
            serde_json::json!({ "kind": "not_paired", "message": "non appairé" })
        );
    }
}
