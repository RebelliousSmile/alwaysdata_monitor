//! Site A tel que les contrôles externes le voient, sain ou dans l'état de
//! l'incident du 2026-09-07 : installeur `setup-config.php` servi avec son
//! formulaire, page surveillée sans son mot-clé.
//!
//! Partagé par `tests/replay_2026_09_07.rs` et `examples/replay_local.rs`
//! (inclus par `#[path]`) : un serveur HTTPS local et son autorité de test.

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

const HOME: &str = include_str!("../fixtures/home.html");
const KB_HEALTHY: &str = include_str!("../fixtures/kb_healthy.html");
const KB_INCIDENT: &str = include_str!("../fixtures/kb_incident.html");
const INSTALL_ALREADY: &str = include_str!("../fixtures/install_already.html");
const SETUP_CONFIG_OPEN: &str = include_str!("../fixtures/setup_config_open.html");
const NOT_FOUND: &str = include_str!("../fixtures/not_found.html");

const SECURITY_HEADERS: &str = "Strict-Transport-Security: max-age=31536000\r\n\
     X-Content-Type-Options: nosniff\r\n\
     X-Frame-Options: SAMEORIGIN\r\n";

const DAY: u64 = 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Healthy,
    Incident,
}

fn route(mode: Mode, path: &str) -> (u16, &'static str) {
    match (mode, path) {
        (_, "/") => (200, HOME),
        (Mode::Incident, "/kb/") => (200, KB_INCIDENT),
        (_, "/kb/") => (200, KB_HEALTHY),
        (_, "/wp-admin/install.php") => (200, INSTALL_ALREADY),
        (Mode::Incident, "/wp-admin/setup-config.php") => (200, SETUP_CONFIG_OPEN),
        _ => (404, NOT_FOUND),
    }
}

pub struct IncidentSite {
    pub port: u16,
    pub ca: CertificateDer<'static>,
    mode: Arc<Mutex<Mode>>,
}

impl IncidentSite {
    /// Écoute sur 127.0.0.1, au port donné (0 : choisi par le système).
    pub fn start(port: u16) -> Self {
        let (ca, leaf, key) = certificates();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("versions TLS")
            .with_no_client_auth()
            .with_single_cert(vec![leaf], key)
            .expect("certificat du serveur");
        let tls = Arc::new(tls);
        let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind");
        let port = listener.local_addr().expect("adresse").port();
        let mode = Arc::new(Mutex::new(Mode::Healthy));
        let shared = Arc::clone(&mode);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (tls, mode) = (Arc::clone(&tls), Arc::clone(&shared));
                thread::spawn(move || serve(stream, tls, &mode));
            }
        });
        Self { port, ca, mode }
    }

    pub fn set(&self, mode: Mode) {
        *self.mode.lock().expect("mode") = mode;
    }

    pub fn base(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
    }
}

fn serve(stream: TcpStream, tls: Arc<ServerConfig>, mode: &Mutex<Mode>) {
    let mode = *mode.lock().expect("mode");
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
    let head = String::from_utf8_lossy(&request);
    let path = head.split_whitespace().nth(1).unwrap_or("/");
    let (status, body) = route(mode, path);
    let reason = if status == 200 { "OK" } else { "Not Found" };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n{SECURITY_HEADERS}\r\n{body}",
        body.len()
    );
    let _ = tls.write_all(response.as_bytes());
    tls.conn.send_close_notify();
    while tls.conn.wants_write() {
        if tls.conn.write_tls(&mut tls.sock).is_err() {
            break;
        }
    }
}

/// Autorité de test, et certificat du serveur signé par elle.
fn certificates() -> (
    CertificateDer<'static>,
    CertificateDer<'static>,
    PrivateKeyDer<'static>,
) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("paramètres");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Autorité de test du veilleur");
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().expect("clé"))
        .expect("autorité");

    let leaf_key = KeyPair::generate().expect("clé");
    let mut params = CertificateParams::new(vec!["127.0.0.1".to_owned()]).expect("paramètres");
    params.not_before = (SystemTime::now() - Duration::from_secs(DAY)).into();
    params.not_after = (SystemTime::now() + Duration::from_secs(90 * DAY)).into();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = params.signed_by(&leaf_key, &*ca).expect("certificat");
    (
        ca.der().clone(),
        leaf.der().clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    )
}
