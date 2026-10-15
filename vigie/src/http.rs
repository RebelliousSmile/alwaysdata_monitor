//! Client HTTP des contrôles : un agent `ureq` sur rustls, borné et poli.
//!
//! - délai par requête : 10 s au plus, et jamais au-delà de l'échéance du passage ;
//! - corps tronqué à 2 Mo ;
//! - User-Agent `vigie/<version>`, pour que l'hébergeur reconnaisse le veilleur ;
//! - redirections suivies à la main, 5 au plus, en https seulement et vers le
//!   même hôte au `www.` près : un site détourné ne fait pas sonder un tiers.

use std::io::Read;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::CertificateDer;
use ureq::Agent;
use ureq::http::HeaderMap;
use ureq::tls::{Certificate, RootCerts, TlsConfig};
use url::Url;

pub const USER_AGENT: &str = concat!("vigie/", env!("CARGO_PKG_VERSION"));
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_BODY: u64 = 2 * 1024 * 1024;
pub const MAX_REDIRECTS: usize = 5;
/// En deçà, une requête n'est pas lancée : elle n'aurait pas le temps d'aboutir.
const MIN_REMAINING: Duration = Duration::from_millis(500);

/// Racines de confiance TLS : celles de Mozilla en production, une autorité
/// de test dans les tests d'intégration.
#[derive(Debug, Clone, Default)]
pub enum Trust {
    #[default]
    WebPki,
    Custom(Vec<CertificateDer<'static>>),
}

impl Trust {
    pub fn root_store(&self) -> rustls::RootCertStore {
        match self {
            Self::WebPki => rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            },
            Self::Custom(certs) => {
                let mut store = rustls::RootCertStore::empty();
                for cert in certs {
                    // Une autorité de test illisible fait échouer la poignée de
                    // main, ce que les tests voient aussitôt.
                    let _ = store.add(cert.clone());
                }
                store
            }
        }
    }
}

/// Erreur réseau ou TLS : aucune réponse HTTP exploitable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct HttpError {
    pub message: String,
    /// L'échéance du passage a empêché ou écourté la requête : le site n'y
    /// est pour rien, et le contrôle sera rejoué au passage suivant.
    pub cut_short: bool,
}

impl HttpError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            cut_short: false,
        }
    }

    fn cut_short(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            cut_short: true,
        }
    }
}

#[derive(Debug)]
pub struct Page {
    /// URL de la dernière réponse, après les redirections suivies.
    pub url: Url,
    pub status: u16,
    pub headers: HeaderMap,
    pub body: String,
}

impl Page {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

pub struct Http {
    agent: Agent,
    request_timeout: Duration,
    max_body: u64,
}

impl Http {
    pub fn new(trust: &Trust, request_timeout: Duration) -> Self {
        let roots = match trust {
            Trust::WebPki => RootCerts::WebPki,
            Trust::Custom(certs) => RootCerts::Specific(Arc::new(
                certs
                    .iter()
                    .map(|c| Certificate::from_der(c.as_ref()).to_owned())
                    .collect(),
            )),
        };
        let agent = Agent::config_builder()
            .https_only(true)
            .max_redirects(0)
            .http_status_as_error(false)
            .user_agent(USER_AGENT)
            .timeout_connect(Some(request_timeout))
            .tls_config(TlsConfig::builder().root_certs(roots).build())
            .build()
            .new_agent();
        Self {
            agent,
            request_timeout,
            max_body: MAX_BODY,
        }
    }

    /// GET, en suivant les redirections autorisées si `follow`. Une redirection
    /// refusée (autre hôte, http, trop nombreuses) rend la réponse 3xx telle quelle.
    pub fn get(&self, url: &Url, follow: bool, deadline: Instant) -> Result<Page, HttpError> {
        let mut current = url.clone();
        let mut hops = 0;
        loop {
            let page = self.get_once(&current, deadline)?;
            if !follow || !matches!(page.status, 301 | 302 | 303 | 307 | 308) {
                return Ok(page);
            }
            let next = page
                .header("location")
                .and_then(|location| current.join(location).ok());
            match next {
                Some(next) if hops < MAX_REDIRECTS && same_site(url, &next) => {
                    hops += 1;
                    current = next;
                }
                _ => return Ok(page),
            }
        }
    }

    fn get_once(&self, url: &Url, deadline: Instant) -> Result<Page, HttpError> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining < MIN_REMAINING {
            return Err(HttpError::cut_short("échéance du passage atteinte"));
        }
        let timeout = remaining.min(self.request_timeout);
        let clipped = timeout < self.request_timeout;
        let response = self
            .agent
            .get(url.as_str())
            .config()
            .timeout_global(Some(timeout))
            .build()
            .call()
            .map_err(|err| match err {
                ureq::Error::Timeout(_) if clipped => {
                    HttpError::cut_short("délai écourté par l'échéance du passage")
                }
                other => HttpError::new(describe(&other)),
            })?;
        let status = response.status().as_u16();
        let (parts, body) = response.into_parts();
        let mut bytes = Vec::new();
        body.into_reader()
            .take(self.max_body)
            .read_to_end(&mut bytes)
            .map_err(|err| HttpError::new(format!("lecture du corps : {err}")))?;
        Ok(Page {
            url: url.clone(),
            status,
            headers: parts.headers,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        })
    }
}

fn describe(err: &ureq::Error) -> String {
    match err {
        ureq::Error::Timeout(_) => "délai dépassé".into(),
        ureq::Error::HostNotFound => "nom d'hôte introuvable".into(),
        ureq::Error::ConnectionFailed => "connexion refusée ou impossible".into(),
        other => other.to_string(),
    }
}

fn bare_host(url: &Url) -> Option<String> {
    let host = url.host_str()?.to_ascii_lowercase();
    Some(host.strip_prefix("www.").map(str::to_owned).unwrap_or(host))
}

/// Même hôte au `www.` près, même port, en https.
pub fn same_site(origin: &Url, target: &Url) -> bool {
    target.scheme() == "https"
        && target.port_or_known_default() == origin.port_or_known_default()
        && bare_host(origin).is_some()
        && bare_host(origin) == bare_host(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).expect("url")
    }

    #[test]
    fn same_site_ignores_www_only() {
        let origin = url("https://www.example.org/kb/");
        assert!(same_site(&origin, &url("https://example.org/")));
        assert!(same_site(&origin, &url("https://WWW.example.org/x")));
        assert!(!same_site(&origin, &url("http://www.example.org/")));
        assert!(!same_site(&origin, &url("https://www.example.org:8443/")));
        assert!(!same_site(&origin, &url("https://evil.example.org/")));
        assert!(!same_site(&origin, &url("https://example.org.evil.net/")));
    }

    #[test]
    fn refuses_to_start_a_request_after_the_deadline() {
        let http = Http::new(&Trust::WebPki, REQUEST_TIMEOUT);
        let err = http
            .get(&url("https://127.0.0.1:9/"), true, Instant::now())
            .expect_err("échéance");
        assert!(err.cut_short, "{err}");
    }
}
