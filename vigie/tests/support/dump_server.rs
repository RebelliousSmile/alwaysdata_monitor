//! Serveur HTTPS local générique des tests de synchronisation
//! (`vulns_download.rs`, `vulns_sync.rs`, puis F4), inclus par `#[path]`.
//!
//! Autorité de test et certificat à SAN IP `127.0.0.1`, comme
//! `external_checks.rs` ; plusieurs instances sur des ports distincts
//! partagent la même autorité (cas multi-origines). Les routes
//! (`chemin → Reply`) se programment en cours de test ; chaque instance
//! compte les requêtes et garde leurs en-têtes. Aucun réseau.

#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

/// Réponse programmée d'une route.
#[derive(Debug, Clone)]
pub enum Reply {
    /// 200 ; 304 si `If-None-Match` vaut l'ETag (ou, sans ETag,
    /// `If-Modified-Since` vaut `Last-Modified`).
    Ok {
        body: Arc<Vec<u8>>,
        etag: Option<String>,
        last_modified: Option<String>,
        content_encoding: Option<String>,
    },
    /// Statut sans corps utile, avec `Retry-After` éventuel.
    Status {
        code: u16,
        retry_after: Option<String>,
    },
    /// 302 vers l'URL donnée.
    Redirect(String),
    /// Annonce `announced` octets, n'envoie que `body`, puis ferme.
    Truncated { body: Vec<u8>, announced: u64 },
    /// `Content-Length` d'un téraoctet, puis quelques octets.
    HugeLength,
    /// Corps sans `Content-Length`, sans fin.
    Endless,
    /// Lit la requête et ne répond jamais.
    Hang,
}

impl Reply {
    pub fn ok(body: Vec<u8>) -> Self {
        Self::Ok {
            body: Arc::new(body),
            etag: None,
            last_modified: None,
            content_encoding: None,
        }
    }

    pub fn ok_etag(body: Vec<u8>, etag: &str, last_modified: &str) -> Self {
        Self::Ok {
            body: Arc::new(body),
            etag: Some(etag.into()),
            last_modified: Some(last_modified.into()),
            content_encoding: None,
        }
    }
}

/// Requête reçue : chemin et en-têtes (noms en minuscules).
#[derive(Debug, Clone)]
pub struct Seen {
    pub path: String,
    pub headers: Vec<(String, String)>,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

type Routes = Arc<Mutex<HashMap<String, Reply>>>;

/// Une instance du serveur.
pub struct DumpServer {
    pub port: u16,
    pub ca: CertificateDer<'static>,
    routes: Routes,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl DumpServer {
    /// Une instance, avec sa propre autorité.
    pub fn start() -> Self {
        Self::start_many(1).pop().expect("instance")
    }

    /// `n` instances, une même autorité.
    pub fn start_many(n: usize) -> Vec<Self> {
        let (ca, leaf, key) = certificates();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("versions TLS")
            .with_no_client_auth()
            .with_single_cert(vec![leaf], key)
            .expect("certificat du serveur");
        let tls = Arc::new(tls);
        (0..n)
            .map(|_| {
                let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
                let port = listener.local_addr().expect("adresse").port();
                let routes: Routes = Arc::default();
                let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
                let (tls, r, s) = (Arc::clone(&tls), Arc::clone(&routes), Arc::clone(&seen));
                thread::spawn(move || {
                    for stream in listener.incoming().flatten() {
                        let (tls, r, s) = (Arc::clone(&tls), Arc::clone(&r), Arc::clone(&s));
                        thread::spawn(move || serve(stream, tls, &r, &s));
                    }
                });
                Self {
                    port,
                    ca: ca.clone(),
                    routes,
                    seen,
                }
            })
            .collect()
    }

    pub fn route(&self, path: &str, reply: Reply) {
        self.routes
            .lock()
            .expect("routes")
            .insert(path.into(), reply);
    }

    pub fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{path}", self.port)
    }

    pub fn base(&self) -> url::Url {
        url::Url::parse(&self.url("/")).expect("url")
    }

    pub fn requests(&self) -> usize {
        self.seen.lock().expect("requêtes").len()
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("requêtes").clone()
    }

    pub fn reset(&self) {
        self.seen.lock().expect("requêtes").clear();
    }
}

fn serve(stream: TcpStream, tls: Arc<ServerConfig>, routes: &Routes, seen: &Mutex<Vec<Seen>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let Ok(conn) = ServerConnection::new(tls) else {
        return;
    };
    let mut tls = StreamOwned::new(conn, stream);
    let mut request = Vec::new();
    let mut buf = [0u8; 1024];
    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
        match tls.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => request.extend_from_slice(&buf[..n]),
        }
    }
    let head = String::from_utf8_lossy(&request).into_owned();
    let mut lines = head.split("\r\n");
    let path = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_owned();
    let headers: Vec<(String, String)> = lines
        .take_while(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let request = Seen { path, headers };
    seen.lock().expect("requêtes").push(request.clone());
    let reply = routes.lock().expect("routes").get(&request.path).cloned();
    let reply = reply.unwrap_or(Reply::Status {
        code: 404,
        retry_after: None,
    });
    let head_of = |status: &str, extra: &str| {
        format!("HTTP/1.1 {status}\r\nConnection: close\r\n{extra}\r\n").into_bytes()
    };
    match reply {
        Reply::Ok {
            body,
            etag,
            last_modified,
            content_encoding,
        } => {
            let fresh = match (&etag, &last_modified) {
                (Some(e), _) => request.header("if-none-match") == Some(e.as_str()),
                (None, Some(lm)) => request.header("if-modified-since") == Some(lm.as_str()),
                (None, None) => false,
            };
            let mut extra = String::new();
            if let Some(e) = &etag {
                extra.push_str(&format!("ETag: {e}\r\n"));
            }
            if let Some(lm) = &last_modified {
                extra.push_str(&format!("Last-Modified: {lm}\r\n"));
            }
            if fresh {
                let _ = tls.write_all(&head_of("304 Not Modified", &extra));
            } else {
                if let Some(ce) = &content_encoding {
                    extra.push_str(&format!("Content-Encoding: {ce}\r\n"));
                }
                extra.push_str(&format!("Content-Length: {}\r\n", body.len()));
                let _ = tls.write_all(&head_of("200 OK", &extra));
                for chunk in body.chunks(64 * 1024) {
                    if tls.write_all(chunk).is_err() {
                        return;
                    }
                }
            }
        }
        Reply::Status { code, retry_after } => {
            let mut extra = String::from("Content-Length: 5\r\n");
            if let Some(ra) = retry_after {
                extra.push_str(&format!("Retry-After: {ra}\r\n"));
            }
            let _ = tls.write_all(&head_of(&format!("{code} Statut"), &extra));
            let _ = tls.write_all(b"corps");
        }
        Reply::Redirect(to) => {
            let extra = format!("Location: {to}\r\nContent-Length: 0\r\n");
            let _ = tls.write_all(&head_of("302 Found", &extra));
        }
        Reply::Truncated { body, announced } => {
            let extra = format!("Content-Length: {announced}\r\n");
            let _ = tls.write_all(&head_of("200 OK", &extra));
            let _ = tls.write_all(&body);
        }
        Reply::HugeLength => {
            let extra = "Content-Length: 1000000000000\r\n";
            let _ = tls.write_all(&head_of("200 OK", extra));
            let _ = tls.write_all(&[0u8; 1024]);
        }
        Reply::Endless => {
            let _ = tls.write_all(&head_of("200 OK", ""));
            let chunk = vec![0x5au8; 64 * 1024];
            while tls.write_all(&chunk).is_ok() {}
            return;
        }
        Reply::Hang => {
            thread::sleep(Duration::from_secs(10));
            return;
        }
    }
    tls.conn.send_close_notify();
    while tls.conn.wants_write() {
        if tls.conn.write_tls(&mut tls.sock).is_err() {
            break;
        }
    }
}

/// Autorité de test, et certificat du serveur (SAN IP 127.0.0.1) signé par
/// elle.
fn certificates() -> (
    CertificateDer<'static>,
    CertificateDer<'static>,
    PrivateKeyDer<'static>,
) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("paramètres");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Autorité de test des dumps");
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().expect("clé"))
        .expect("autorité");
    let leaf_key = KeyPair::generate().expect("clé");
    let mut params = CertificateParams::new(vec!["127.0.0.1".to_owned()]).expect("paramètres");
    params.not_before = (SystemTime::now() - Duration::from_secs(86_400)).into();
    params.not_after = (SystemTime::now() + Duration::from_secs(30 * 86_400)).into();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = params.signed_by(&leaf_key, &*ca).expect("certificat");
    (
        ca.der().clone(),
        leaf.der().clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    )
}
