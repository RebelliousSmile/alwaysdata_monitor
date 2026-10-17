//! Téléchargeur borné d'un dump, propriétaire du dossier de travail de la
//! source.
//!
//! - origines : liste blanche de la source ([`Origins`]), revérifiée à chaque
//!   redirection (suivies à la main, [`MAX_REDIRECTS`] au plus) ; en-têtes
//!   sensibles (F3 : `Authorization`) retirés dès que l'origine change,
//!   jamais journalisés ;
//! - requête conditionnelle (`If-None-Match`, `If-Modified-Since`) si les
//!   validateurs connus le permettent ; 304 → [`Fetched::NotModified`] ;
//! - `Accept-Encoding: identity` : un corps encodé ne serait pas le dump dont
//!   on calcule l'empreinte ; toute autre `Content-Encoding` est refusée ;
//! - 200 : `Content-Length` au-delà du plafond refusé avant lecture, corps
//!   écrit en flux avec son SHA-256, longueur différente de `Content-Length`
//!   refusée (corps tronqué) ; empreinte égale à celle de la génération
//!   active → [`Fetched::SameDigest`], le dump n'est pas ouvert ;
//! - autres statuts : [`SyncError::Status`] (`Retry-After` borné à 24 h),
//!   401 et 403 à part ; leur corps n'est jamais lu ;
//! - échéance de la source sur l'appel entier (`timeout_global`).

use std::fmt;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use ureq::Agent;
use ureq::http::{HeaderMap, HeaderValue};
use url::Url;

use super::origin::Origins;
use super::workdir::WorkDir;
use super::{Limits, SyncError};

/// Redirections suivies au plus.
pub const MAX_REDIRECTS: usize = 3;
/// Borne d'un `Retry-After`.
pub const MAX_RETRY_AFTER: u64 = 24 * 3600;
/// Longueur maximale d'un ETag gardé.
pub const MAX_ETAG: usize = 256;

/// Requête d'un dump.
#[derive(Clone)]
pub struct Request {
    pub url: Url,
    /// En-têtes envoyés à l'origine de départ seulement (`Authorization`),
    /// valeurs marquées sensibles (`HeaderValue::set_sensitive`).
    pub sensitive_headers: Vec<(String, HeaderValue)>,
}

impl Request {
    pub fn get(url: Url) -> Self {
        Self {
            url,
            sensitive_headers: Vec::new(),
        }
    }
}

impl fmt::Debug for Request {
    /// Les valeurs des en-têtes sensibles ne s'écrivent jamais.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let headers: Vec<String> = self
            .sensitive_headers
            .iter()
            .map(|(name, _)| format!("{name}: ***"))
            .collect();
        f.debug_struct("Request")
            .field("url", &self.url.as_str())
            .field("sensitive_headers", &headers)
            .finish()
    }
}

/// Ce que l'on sait du dump actif, pour une requête conditionnelle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Validators {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    /// SHA-256 du dump de la génération active.
    pub active_sha256: Option<String>,
    /// Faux si `LOADER_VERSION` a changé (ou n'est pas connue) : requête sans
    /// en-têtes conditionnels, empreinte jamais comparée, dump rechargé.
    pub conditional: bool,
}

/// Validateurs d'une réponse 200, filtrés : ETag en ASCII imprimable de 1 à
/// [`MAX_ETAG`] caractères, `Last-Modified` gardé s'il est une date HTTP
/// valide (réécrit sous sa forme RFC 9110).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Received {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

/// Dump écrit dans le dossier de travail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpFile {
    pub path: PathBuf,
    pub sha256: String,
    pub bytes: u64,
    pub validators: Received,
}

/// Issue d'un téléchargement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetched {
    /// 304 sur une requête conditionnelle.
    NotModified,
    /// Corps identique au dump actif : rien n'est gardé sur le disque.
    SameDigest {
        validators: Received,
        bytes: u64,
    },
    Dump(DumpFile),
}

/// Téléchargeur d'une source.
pub struct Download {
    agent: Agent,
    origins: Origins,
    validators: Validators,
    limits: Limits,
    deadline: Instant,
    workdir: WorkDir,
    files: usize,
    /// URL du dump de la source, origine remplacée par les tests.
    url: Option<Url>,
}

impl Download {
    pub fn new(
        agent: Agent,
        origins: Origins,
        validators: Validators,
        limits: Limits,
        deadline: Instant,
        workdir: WorkDir,
    ) -> Self {
        Self {
            agent,
            origins,
            validators,
            limits,
            deadline,
            workdir,
            files: 0,
            url: None,
        }
    }

    /// URL du dump de la source (posée par le moteur).
    pub fn with_url(mut self, url: Url) -> Self {
        self.url = Some(url);
        self
    }

    pub fn url(&self) -> Option<&Url> {
        self.url.as_ref()
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn validators(&self) -> &Validators {
        &self.validators
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    pub fn workdir(&self) -> &WorkDir {
        &self.workdir
    }

    /// Télécharge le dump de `request` dans le dossier de travail.
    pub fn get_to_file(&mut self, request: &Request) -> Result<Fetched, SyncError> {
        let first = self.origins.admit(&request.url)?;
        let mut url = request.url.clone();
        let mut sensitive = true;
        let mut hops = 0;
        loop {
            let origin = self.origins.admit(&url)?;
            // Retirés pour de bon dès que l'origine change.
            sensitive &= origin == first;
            let remaining = self.remaining()?;
            let mut builder = self
                .agent
                .get(url.as_str())
                .header("Accept-Encoding", "identity");
            if self.validators.conditional {
                if let Some(etag) = &self.validators.etag {
                    builder = builder.header("If-None-Match", etag.as_str());
                }
                if let Some(lm) = &self.validators.last_modified {
                    builder = builder.header("If-Modified-Since", lm.as_str());
                }
            }
            if sensitive {
                for (name, value) in &request.sensitive_headers {
                    builder = builder.header(name.as_str(), value.clone());
                }
            }
            let response = builder
                .config()
                .timeout_global(Some(remaining))
                .build()
                .call()
                .map_err(|err| match err {
                    ureq::Error::Timeout(_) => SyncError::Deadline,
                    other => SyncError::Network(crate::http::describe(&other)),
                })?;
            let status = response.status().as_u16();
            match status {
                200 => return self.save(response),
                304 if self.validators.conditional => return Ok(Fetched::NotModified),
                301 | 302 | 303 | 307 | 308 => {
                    if hops == MAX_REDIRECTS {
                        return Err(SyncError::Redirect("plus de 3 redirections"));
                    }
                    let location = response
                        .headers()
                        .get("location")
                        .and_then(|v| v.to_str().ok())
                        .ok_or(SyncError::Redirect("redirection sans Location"))?;
                    url = url
                        .join(location)
                        .map_err(|_| SyncError::Redirect("Location illisible"))?;
                    hops += 1;
                }
                401 => return Err(SyncError::Unauthorized),
                403 => return Err(SyncError::Forbidden),
                code => {
                    return Err(SyncError::Status {
                        code,
                        retry_after: retry_after(response.headers()),
                    });
                }
            }
        }
    }

    fn remaining(&self) -> Result<Duration, SyncError> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(SyncError::Deadline);
        }
        Ok(remaining)
    }

    /// Corps d'une réponse 200, écrit en flux avec son empreinte.
    fn save(&mut self, response: ureq::http::Response<ureq::Body>) -> Result<Fetched, SyncError> {
        let headers = response.headers();
        if let Some(encoding) = headers
            .get("content-encoding")
            .map(|v| String::from_utf8_lossy(v.as_bytes()).trim().to_owned())
            .filter(|e| !e.is_empty() && !e.eq_ignore_ascii_case("identity"))
        {
            let shown: String = encoding
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ',' | ' '))
                .take(32)
                .collect();
            return Err(SyncError::ContentEncoding(shown));
        }
        let announced = headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok());
        let limit = self.limits.compressed;
        if announced.is_some_and(|n| n > limit) {
            return Err(SyncError::TooLarge {
                what: "dump compressé (Content-Length)",
            });
        }
        self.workdir.ensure_space(announced.unwrap_or(limit))?;
        let validators = Received {
            etag: headers
                .get("etag")
                .and_then(|v| v.to_str().ok())
                .filter(|e| valid_etag(e))
                .map(str::to_owned),
            last_modified: headers
                .get("last-modified")
                .and_then(|v| v.to_str().ok())
                .and_then(http_date),
        };
        self.files += 1;
        let (mut file, path) = self
            .workdir
            .create_file(&format!("dump-{}.part", self.files))?;
        let written = (|| {
            let mut reader = response.into_body().into_reader().take(limit + 1);
            let mut hasher = Sha256::new();
            let mut total: u64 = 0;
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(err) => {
                        return Err(read_error(&err, announced, total, self.deadline));
                    }
                };
                total += n as u64;
                if total > limit {
                    return Err(SyncError::TooLarge {
                        what: "dump compressé",
                    });
                }
                hasher.update(&buf[..n]);
                file.write_all(&buf[..n])
                    .map_err(|e| SyncError::io("écriture du dump", &e))?;
            }
            if announced.is_some_and(|n| n != total) {
                return Err(SyncError::Truncated);
            }
            file.flush()
                .map_err(|e| SyncError::io("écriture du dump", &e))?;
            Ok((hex(&hasher.finalize()), total))
        })();
        drop(file);
        let (sha256, bytes) = match written {
            Ok(done) => done,
            Err(err) => {
                let _ = std::fs::remove_file(&path);
                return Err(err);
            }
        };
        if self.validators.conditional
            && self.validators.active_sha256.as_deref() == Some(sha256.as_str())
        {
            let _ = std::fs::remove_file(&path);
            return Ok(Fetched::SameDigest { validators, bytes });
        }
        Ok(Fetched::Dump(DumpFile {
            path,
            sha256,
            bytes,
            validators,
        }))
    }
}

/// Erreur de lecture du corps : échéance, corps tronqué ou réseau.
fn read_error(
    err: &std::io::Error,
    announced: Option<u64>,
    total: u64,
    deadline: Instant,
) -> SyncError {
    if err.kind() == std::io::ErrorKind::TimedOut || Instant::now() >= deadline {
        SyncError::Deadline
    } else if announced.is_some_and(|n| total < n) {
        SyncError::Truncated
    } else {
        SyncError::Network(format!("lecture du corps : {}", err.kind()))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// ETag gardé : ASCII imprimable, de 1 à [`MAX_ETAG`] caractères.
pub fn valid_etag(etag: &str) -> bool {
    (1..=MAX_ETAG).contains(&etag.len()) && etag.bytes().all(|b| (0x20..0x7f).contains(&b))
}

/// Date HTTP (RFC 9110, lue par `jiff`), réécrite sous sa forme canonique ;
/// `None` si illisible.
pub fn http_date(raw: &str) -> Option<String> {
    let parsed = jiff::fmt::rfc2822::DateTimeParser::new()
        .parse_timestamp(raw.trim())
        .ok()?;
    jiff::fmt::rfc2822::DateTimePrinter::new()
        .timestamp_to_rfc9110_string(&parsed)
        .ok()
}

/// `Retry-After` en secondes ou en date HTTP, borné à [`MAX_RETRY_AFTER`].
fn retry_after(headers: &HeaderMap) -> Option<u64> {
    let raw = headers.get("retry-after")?.to_str().ok()?.trim();
    let seconds = match raw.parse::<u64>() {
        Ok(s) => s,
        Err(_) => {
            let at = jiff::fmt::rfc2822::DateTimeParser::new()
                .parse_timestamp(raw)
                .ok()?;
            let delta = at.as_second() - jiff::Timestamp::now().as_second();
            u64::try_from(delta).unwrap_or(0)
        }
    };
    Some(seconds.min(MAX_RETRY_AFTER))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etags_are_filtered() {
        assert!(valid_etag("\"abc\""));
        assert!(valid_etag(&"a".repeat(256)));
        assert!(!valid_etag(&"a".repeat(257)));
        assert!(!valid_etag(""));
        assert!(!valid_etag("a\u{7}b"));
        assert!(!valid_etag("é"));
    }

    #[test]
    fn http_dates_are_canonical() {
        assert_eq!(
            http_date("Sun, 06 Nov 1994 08:49:37 GMT").as_deref(),
            Some("Sun, 06 Nov 1994 08:49:37 GMT")
        );
        assert_eq!(http_date("hier"), None);
        assert_eq!(http_date(""), None);
    }

    #[test]
    fn retry_after_is_bounded() {
        let mut headers = HeaderMap::new();
        headers.insert("retry-after", "3600".parse().unwrap());
        assert_eq!(retry_after(&headers), Some(3600));
        headers.insert("retry-after", "999999".parse().unwrap());
        assert_eq!(retry_after(&headers), Some(MAX_RETRY_AFTER));
        headers.insert(
            "retry-after",
            "Sun, 06 Nov 1994 08:49:37 GMT".parse().unwrap(),
        );
        assert_eq!(retry_after(&headers), Some(0));
        headers.insert(
            "retry-after",
            "bientôt".parse().unwrap_or_else(|_| "x".parse().unwrap()),
        );
        assert_eq!(retry_after(&headers), None);
    }

    #[test]
    fn debug_masks_sensitive_headers() {
        let request = Request {
            url: Url::parse("https://dumps.example.org/all.zip").unwrap(),
            sensitive_headers: vec![(
                "Authorization".into(),
                HeaderValue::from_static("Bearer secret"),
            )],
        };
        let shown = format!("{request:?}");
        assert!(shown.contains("Authorization: ***"), "{shown}");
        assert!(!shown.contains("secret"), "{shown}");
    }
}
