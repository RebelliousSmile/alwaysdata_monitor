//! Contrôles externes et passages complets contre un serveur HTTPS local.
//!
//! Le serveur de fixtures tourne dans un thread, sur 127.0.0.1, avec un
//! certificat signé par une autorité de test que seuls ces tests reconnaissent.
//! Son mode (sain, incident, page générique…) change en cours de test, et il
//! compte les requêtes HTTP reçues.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use vigie::alert::MemoryNotifier;
use vigie::checks::{CheckError, CheckKind, Ctx};
use vigie::config::{Alerts, Config, Site, SiteKind};
use vigie::finding::{Finding, Severity};
use vigie::http::{Http, Trust};
use vigie::store::{REMINDER_PERIOD, Store};
use vigie::tick::{self, Options};

const HOME: &str = include_str!("fixtures/home.html");
const KB_HEALTHY: &str = include_str!("fixtures/kb_healthy.html");
const KB_INCIDENT: &str = include_str!("fixtures/kb_incident.html");
const INSTALL_ALREADY: &str = include_str!("fixtures/install_already.html");
const SETUP_CONFIG_OPEN: &str = include_str!("fixtures/setup_config_open.html");
const NOT_FOUND: &str = include_str!("fixtures/not_found.html");
const CATCH_ALL: &str = include_str!("fixtures/catch_all.html");
const ENV: &str = include_str!("fixtures/env.txt");
const GIT_HEAD: &str = include_str!("fixtures/git_head.txt");

const SECURITY_HEADERS: &str = "Strict-Transport-Security: max-age=31536000\r\n\
     X-Content-Type-Options: nosniff\r\n\
     X-Frame-Options: SAMEORIGIN\r\n";

/// Instant arbitraire des passages : seul l'écart entre deux passages compte.
const T0: i64 = 1_800_000_000;
const DAY: u64 = 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// WordPress installé, en-têtes de sécurité, mot-clé présent.
    Healthy,
    /// Mot-clé absent et `setup-config.php` ouvert.
    Incident,
    /// 200 partout, avec une même page qui ressemble à toutes les signatures.
    CatchAll,
    /// `.env` et `.git/HEAD` servis.
    Exposed,
    /// Accepte la connexion TCP, puis ne répond jamais.
    Hang,
}

fn route(mode: Mode, path: &str) -> (u16, &'static str) {
    match (mode, path) {
        (Mode::CatchAll, _) => (200, CATCH_ALL),
        (_, "/") => (200, HOME),
        (Mode::Incident, "/kb/") => (200, KB_INCIDENT),
        (_, "/kb/") => (200, KB_HEALTHY),
        // Un WordPress installé répond 200 « déjà installé », sans formulaire.
        (_, "/wp-admin/install.php") => (200, INSTALL_ALREADY),
        (Mode::Incident, "/wp-admin/setup-config.php") => (200, SETUP_CONFIG_OPEN),
        (Mode::Exposed, "/.env") => (200, ENV),
        (Mode::Exposed, "/.git/HEAD") => (200, GIT_HEAD),
        _ => (404, NOT_FOUND),
    }
}

struct Fixture {
    port: u16,
    ca: CertificateDer<'static>,
    mode: Arc<Mutex<Mode>>,
    requests: Arc<AtomicUsize>,
}

impl Fixture {
    fn start(mode: Mode) -> Self {
        Self::with_certificate(mode, 90 * DAY, "127.0.0.1")
    }

    /// Certificat valable `lifetime` secondes à partir de maintenant, au nom de `name`.
    fn with_certificate(mode: Mode, lifetime: u64, name: &str) -> Self {
        let (ca, leaf, key) = certificates(lifetime, name);
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("versions TLS")
            .with_no_client_auth()
            .with_single_cert(vec![leaf], key)
            .expect("certificat du serveur");
        let tls = Arc::new(tls);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("adresse").port();
        let mode = Arc::new(Mutex::new(mode));
        let requests = Arc::new(AtomicUsize::new(0));
        let (shared_mode, shared_requests) = (Arc::clone(&mode), Arc::clone(&requests));
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (tls, mode, requests) = (
                    Arc::clone(&tls),
                    Arc::clone(&shared_mode),
                    Arc::clone(&shared_requests),
                );
                thread::spawn(move || serve(stream, tls, &mode, &requests));
            }
        });
        Self {
            port,
            ca,
            mode,
            requests,
        }
    }

    fn set(&self, mode: Mode) {
        *self.mode.lock().expect("mode") = mode;
    }

    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    fn base(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
    }

    fn options(&self) -> Options {
        Options {
            trust: Trust::Custom(vec![self.ca.clone()]),
            request_timeout: Duration::from_secs(5),
            ..Options::default()
        }
    }
}

fn serve(stream: TcpStream, tls: Arc<ServerConfig>, mode: &Mutex<Mode>, requests: &AtomicUsize) {
    let mode = *mode.lock().expect("mode");
    if mode == Mode::Hang {
        thread::sleep(Duration::from_secs(10));
        return;
    }
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let Ok(conn) = ServerConnection::new(tls) else {
        return;
    };
    let mut tls = StreamOwned::new(conn, stream);
    let mut request = Vec::new();
    let mut buf = [0u8; 1024];
    // Le contrôle `tls` ferme la connexion après la poignée de main : rien à compter.
    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
        match tls.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => request.extend_from_slice(&buf[..n]),
        }
    }
    requests.fetch_add(1, Ordering::SeqCst);
    let head = String::from_utf8_lossy(&request);
    let path = head.split_whitespace().nth(1).unwrap_or("/");
    let (status, body) = route(mode, path);
    let reason = if status == 200 { "OK" } else { "Not Found" };
    // La page générique d'un hébergement mal réglé : aucun en-tête de sécurité.
    let security = if mode == Mode::CatchAll {
        ""
    } else {
        SECURITY_HEADERS
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n{security}\r\n{body}",
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
fn certificates(
    lifetime: u64,
    name: &str,
) -> (
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
    let mut params = CertificateParams::new(vec![name.to_owned()]).expect("paramètres");
    params.not_before = (SystemTime::now() - Duration::from_secs(DAY)).into();
    params.not_after = (SystemTime::now() + Duration::from_secs(lifetime)).into();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = params.signed_by(&leaf_key, &*ca).expect("certificat");
    (
        ca.der().clone(),
        leaf.der().clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    )
}

fn site(base: &str) -> Site {
    Site {
        id: "site-a".into(),
        url: format!("{base}/"),
        kind: SiteKind::Wordpress,
        keyword_url: Some(format!("{base}/kb/")),
        keyword: Some("/problemes/".into()),
        interval: 300,
        agent_silence: 900,
    }
}

fn config(dir: &Path, base: &str) -> Config {
    Config {
        database: dir.join("data").join("vigie.db"),
        alerts: Alerts {
            to: "alertes@example.org".into(),
            from: "vigie@example.org".into(),
            smtp_host: "smtp.example.org".into(),
            smtp_port: 587,
            smtp_user: None,
            password_file: dir.join("smtp-password"),
        },
        sites: vec![site(base)],
    }
}

/// Un contrôle seul, hors passage.
fn run_check(kind: CheckKind, fixture: &Fixture) -> Result<Vec<Finding>, CheckError> {
    let options = fixture.options();
    let http = Http::new(&options.trust, options.request_timeout);
    let ctx = Ctx {
        http: &http,
        trust: &options.trust,
        request_timeout: options.request_timeout,
        deadline: Instant::now() + options.check_budget,
    };
    kind.run(&site(&fixture.base()), &ctx)
}

fn open_keys(config: &Config) -> Vec<String> {
    let store = Store::open(&config.database).expect("base");
    store
        .open_incidents()
        .expect("incidents")
        .into_iter()
        .map(|i| i.key)
        .collect()
}

#[test]
fn a_repeated_finding_is_one_incident_with_one_open_and_one_close_email() {
    let fixture = Fixture::start(Mode::Healthy);
    let dir = tempfile::tempdir().expect("tempdir");
    let config = config(dir.path(), &fixture.base());
    let options = fixture.options();
    let mail = MemoryNotifier::new();

    let summary = tick::run_with(&config, T0, &options, &mail).expect("tick sain");
    assert_eq!(summary.checks_run, 5, "{summary:?}");
    assert_eq!(summary.inconclusive, 0, "{summary:?}");
    assert!(mail.take().is_empty());
    assert!(open_keys(&config).is_empty());

    fixture.set(Mode::Incident);
    let summary = tick::run_with(&config, T0 + 300, &options, &mail).expect("tick incident");
    // tls et headers attendent leur heure.
    assert_eq!(summary.checks_run, 3, "{summary:?}");
    let opened = mail.take();
    assert_eq!(opened.len(), 2, "{opened:?}");
    assert!(opened.iter().all(|e| e.body.contains("vigie ack")));
    let keys = open_keys(&config);
    assert_eq!(
        keys,
        [
            "site-a/content/keyword",
            "site-a/installer/wp-admin/setup-config.php"
        ]
    );
    let store = Store::open(&config.database).expect("base");
    let incidents = store.open_incidents().expect("incidents");
    assert!(incidents.iter().all(|i| i.severity == Severity::Critical));
    drop(store);

    let summary = tick::run_with(&config, T0 + 600, &options, &mail).expect("tick répété");
    assert_eq!(summary.emails_sent, 0, "{summary:?}");
    assert!(mail.take().is_empty());
    assert_eq!(open_keys(&config), keys);

    fixture.set(Mode::Healthy);
    let summary = tick::run_with(&config, T0 + 900, &options, &mail).expect("tick rétabli");
    assert_eq!(summary.emails_pending, 0, "{summary:?}");
    let closed = mail.take();
    assert_eq!(closed.len(), 2, "{closed:?}");
    assert!(closed.iter().all(|e| e.subject.contains("rétabli")));
    assert!(open_keys(&config).is_empty());

    let summary = tick::run_with(&config, T0 + 1200, &options, &mail).expect("tick calme");
    assert_eq!(summary.emails_sent, 0, "{summary:?}");
}

#[test]
fn a_site_that_answers_200_everywhere_exposes_nothing() {
    let fixture = Fixture::start(Mode::CatchAll);
    assert_eq!(run_check(CheckKind::Exposed, &fixture), Ok(Vec::new()));
    assert_eq!(run_check(CheckKind::Installer, &fixture), Ok(Vec::new()));
}

#[test]
fn served_secrets_and_git_head_are_critical() {
    let fixture = Fixture::start(Mode::Exposed);
    let findings = run_check(CheckKind::Exposed, &fixture).expect("concluant");
    let keys: Vec<_> = findings.iter().map(|f| f.key.as_str()).collect();
    assert_eq!(keys, [".env", ".git/HEAD"], "{findings:?}");
    assert!(findings.iter().all(|f| f.severity == Severity::Critical));
    assert!(
        findings
            .iter()
            .all(|f| !f.detail.contains("pas-un-vrai-secret")),
        "{findings:?}"
    );
}

#[test]
fn an_open_installer_is_critical_and_an_installed_one_is_not() {
    let fixture = Fixture::start(Mode::Healthy);
    assert_eq!(run_check(CheckKind::Installer, &fixture), Ok(Vec::new()));
    fixture.set(Mode::Incident);
    let findings = run_check(CheckKind::Installer, &fixture).expect("concluant");
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].key, "wp-admin/setup-config.php");
    assert_eq!(findings[0].severity, Severity::Critical);
    let content = run_check(CheckKind::Content, &fixture).expect("concluant");
    assert_eq!(content.len(), 1, "{content:?}");
    assert_eq!(content[0].key, "keyword");
    assert_eq!(content[0].severity, Severity::Critical);
}

#[test]
fn missing_security_headers_are_information_only() {
    let fixture = Fixture::start(Mode::Healthy);
    assert_eq!(run_check(CheckKind::Headers, &fixture), Ok(Vec::new()));
    fixture.set(Mode::CatchAll);
    let findings = run_check(CheckKind::Headers, &fixture).expect("concluant");
    let keys: Vec<_> = findings.iter().map(|f| f.key.as_str()).collect();
    assert_eq!(keys, ["hsts", "nosniff", "frame"], "{findings:?}");
    assert!(findings.iter().all(|f| f.severity == Severity::Info));

    // Jamais d'e-mail pour un en-tête manquant.
    let dir = tempfile::tempdir().expect("tempdir");
    let config = config(dir.path(), &fixture.base());
    let mail = MemoryNotifier::new();
    let summary = tick::run_with(&config, T0, &fixture.options(), &mail).expect("tick");
    assert_eq!(summary.emails_pending, 0, "{summary:?}");
    let store = Store::open(&config.database).expect("base");
    let open = store.open_incidents().expect("incidents");
    let info = open.iter().filter(|i| i.severity == Severity::Info).count();
    assert_eq!(info, 3, "{open:?}");
    // Le mot-clé manque aussi sur la page générique : seul cet incident part.
    let sent = mail.take();
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert!(sent[0].subject.contains("/problemes/"), "{sent:?}");
}

#[test]
fn a_closed_port_gives_a_single_unreachable_incident_quickly() {
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("adresse").port()
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let config = config(dir.path(), &format!("https://127.0.0.1:{port}"));
    let mail = MemoryNotifier::new();
    let started = Instant::now();
    let summary = tick::run_with(&config, T0, &Options::default(), &mail).expect("tick");
    assert!(
        started.elapsed() < Duration::from_secs(50),
        "{:?}",
        started.elapsed()
    );
    // Les autres contrôles sont sautés : ils ne concluraient rien.
    assert_eq!(summary.checks_run, 1, "{summary:?}");
    assert_eq!(open_keys(&config), ["site-a/content/unreachable"]);
    assert_eq!(mail.take().len(), 1);
}

#[test]
fn a_hanging_site_is_unreachable_within_the_request_timeout() {
    let fixture = Fixture::start(Mode::Hang);
    let dir = tempfile::tempdir().expect("tempdir");
    let config = config(dir.path(), &fixture.base());
    let options = Options {
        request_timeout: Duration::from_secs(1),
        ..fixture.options()
    };
    let mail = MemoryNotifier::new();
    let started = Instant::now();
    let summary = tick::run_with(&config, T0, &options, &mail).expect("tick");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(summary.checks_run, 1, "{summary:?}");
    assert_eq!(open_keys(&config), ["site-a/content/unreachable"]);
}

#[test]
fn certificates_close_to_expiry_or_for_another_name_are_reported() {
    let soon = Fixture::with_certificate(Mode::Healthy, 7 * DAY, "127.0.0.1");
    let findings = run_check(CheckKind::Tls, &soon).expect("concluant");
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].key, "expiry");
    assert_eq!(findings[0].severity, Severity::Warning);

    let imminent = Fixture::with_certificate(Mode::Healthy, 2 * DAY, "127.0.0.1");
    let findings = run_check(CheckKind::Tls, &imminent).expect("concluant");
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].key, "expiry");
    assert_eq!(findings[0].severity, Severity::Critical);

    let healthy = Fixture::start(Mode::Healthy);
    assert_eq!(run_check(CheckKind::Tls, &healthy), Ok(Vec::new()));

    let wrong_name = Fixture::with_certificate(Mode::Healthy, 90 * DAY, "localhost");
    let findings = run_check(CheckKind::Tls, &wrong_name).expect("concluant");
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].key, "invalid");
    assert_eq!(findings[0].severity, Severity::Critical);
}

#[test]
fn an_acknowledged_incident_gets_no_reminder() {
    let fixture = Fixture::start(Mode::Incident);
    let dir = tempfile::tempdir().expect("tempdir");
    let config = config(dir.path(), &fixture.base());
    let options = fixture.options();
    let mail = MemoryNotifier::new();
    tick::run_with(&config, T0, &options, &mail).expect("tick");
    assert_eq!(mail.take().len(), 2);

    let mut store = Store::open(&config.database).expect("base");
    let incidents = store.open_incidents().expect("incidents");
    let (acked, other) = (incidents[0].id, incidents[1].id);
    store.ack(acked, T0 + 60).expect("ack");
    drop(store);

    let summary =
        tick::run_with(&config, T0 + REMINDER_PERIOD - 60, &options, &mail).expect("tick");
    assert_eq!(summary.emails_sent, 0, "trop tôt : {summary:?}");

    let summary = tick::run_with(&config, T0 + REMINDER_PERIOD, &options, &mail).expect("tick");
    assert_eq!(summary.emails_pending, 0, "{summary:?}");
    let reminders = mail.take();
    assert_eq!(reminders.len(), 1, "{reminders:?}");
    assert!(reminders[0].subject.contains("toujours en cours"));
    assert!(
        reminders[0]
            .body
            .contains(&format!("Incident n° {other}\n"))
    );
}

#[test]
fn a_failed_send_is_retried_and_checks_wait_for_their_interval() {
    let fixture = Fixture::start(Mode::Incident);
    let dir = tempfile::tempdir().expect("tempdir");
    let config = config(dir.path(), &fixture.base());
    let options = fixture.options();
    let mail = MemoryNotifier::new();

    mail.set_failing(true);
    let summary = tick::run_with(&config, T0, &options, &mail).expect("tick");
    assert_eq!(summary.emails_sent, 0, "{summary:?}");
    assert_eq!(summary.emails_pending, 2, "{summary:?}");
    let requests = fixture.requests();

    mail.set_failing(false);
    let summary = tick::run_with(&config, T0 + 60, &options, &mail).expect("tick");
    assert_eq!(summary.checks_run, 0, "{summary:?}");
    assert_eq!(
        fixture.requests(),
        requests,
        "aucune requête avant l'intervalle"
    );
    assert_eq!(summary.emails_sent, 2, "{summary:?}");
    assert_eq!(summary.emails_pending, 0, "{summary:?}");
    assert_eq!(mail.take().len(), 2);

    let summary = tick::run_with(&config, T0 + 299, &options, &mail).expect("tick");
    assert_eq!(summary.checks_run, 0, "{summary:?}");
    let summary = tick::run_with(&config, T0 + 300, &options, &mail).expect("tick");
    assert_eq!(summary.checks_run, 3, "{summary:?}");
    assert!(mail.take().is_empty(), "le même incident ne renvoie rien");
}

#[test]
fn check_once_writes_nothing() {
    let fixture = Fixture::start(Mode::Healthy);
    let dir = tempfile::tempdir().expect("tempdir");
    let config = config(dir.path(), &fixture.base());
    let report = tick::check_once(&config, "site-a", &fixture.options()).expect("rapport");
    assert_eq!(report.len(), 5, "{report:?}");
    assert!(
        report
            .iter()
            .all(|(_, r)| r.as_ref().is_ok_and(Vec::is_empty)),
        "{report:?}"
    );
    assert!(fixture.requests() > 0);
    assert!(!config.database.exists());
    assert!(!dir.path().join("data").exists());
}

#[cfg(unix)]
#[test]
fn a_readable_password_file_is_refused_before_any_connection() {
    use std::os::unix::fs::PermissionsExt;

    use vigie::alert::{self, Notifier, SmtpNotifier};

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("non bloquant");
    let dir = tempfile::tempdir().expect("tempdir");
    let mut alerts = config(dir.path(), "https://127.0.0.1").alerts;
    alerts.smtp_host = "127.0.0.1".into();
    alerts.smtp_port = listener.local_addr().expect("adresse").port();
    std::fs::write(&alerts.password_file, "s3cret-de-test\n").expect("écriture");
    std::fs::set_permissions(
        &alerts.password_file,
        std::fs::Permissions::from_mode(0o644),
    )
    .expect("chmod");

    let err = SmtpNotifier::new(alerts)
        .send(&alert::test_email(T0), Duration::from_secs(5))
        .expect_err("refusé");
    assert!(err.contains("644"), "{err}");
    assert!(!err.contains("s3cret"), "{err}");
    let accepted = listener.accept();
    assert!(
        matches!(&accepted, Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
        "{accepted:?}"
    );
}
