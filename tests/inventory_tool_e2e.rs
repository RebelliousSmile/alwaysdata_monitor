//! `vigie-inventory` de bout en bout (issue #20, phase 3) : le binaire réel
//! pousse sur `serve::router_with` en `127.0.0.1` (`--allow-http-loopback`).
//! L'outil prend l'heure réelle, le veilleur une `FakeClock` posée avant
//! chaque envoi par rapport à l'heure réelle, à ±270 s au plus sauf pour le
//! cas du décalage d'horloge.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::SigningKey;

use vigie::clock::{Clock, FakeClock, SystemClock};
use vigie::command::key::{self, DOMAIN_LOGS};
use vigie::config::{Alerts, Config, InventorySource, Runtime, Site, SiteInventory, SiteKind};
use vigie::ingest::{HEADER_SIGNATURE, HEADER_SITE};
use vigie::inventory::Source;
use vigie::serve;
use vigie::store::Store;

const INV_A: [u8; 32] = [81; 32];
const AGENT_B: [u8; 32] = [82; 32];
const INV_B: [u8; 32] = [83; 32];

fn site(id: &str, kind: SiteKind, runtime: Option<Runtime>, sources: &[InventorySource]) -> Site {
    Site {
        id: id.into(),
        url: format!("https://{id}.example.org/"),
        kind,
        runtime,
        keyword_url: None,
        keyword: None,
        interval: 300,
        agent_silence: 900,
        logs: None,
        inventory: Some(SiteInventory::new(sources)),
        custom_checks: Vec::new(),
    }
}

struct Veilleur {
    config: Config,
    clock: Arc<FakeClock>,
    port: u16,
    _dir: tempfile::TempDir,
}

impl Veilleur {
    fn start() -> Self {
        use InventorySource::{AgentPhp, Ci};
        let dir = tempfile::tempdir().expect("tempdir");
        let config = Config {
            database: dir.path().join("vigie.db"),
            api: None,
            commands: None,
            logs: Default::default(),
            vulns: None,
            alerts: Alerts {
                to: "alertes@example.org".into(),
                from: "vigie@example.org".into(),
                smtp_host: "smtp.example.org".into(),
                smtp_port: 587,
                smtp_user: None,
                password_file: dir.path().join("smtp-password"),
            },
            sites: vec![
                site("site-a", SiteKind::Generic, Some(Runtime::Static), &[Ci]),
                site("site-b", SiteKind::Wordpress, None, &[AgentPhp, Ci]),
            ],
        };
        let public = |seed: [u8; 32]| SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let now = SystemClock.unix();
        let mut store = Store::open(&config.database).expect("base");
        store
            .add_inventory_key("site-a", &public(INV_A), now)
            .expect("clé A");
        store
            .add_key("site-b", &public(AGENT_B), now)
            .expect("clé B");
        store
            .add_inventory_key("site-b", &public(INV_B), now)
            .expect("clé d'inventaire B");
        let clock = Arc::new(FakeClock::new(now));
        let listener = TcpListener::bind("127.0.0.1:0").expect("écoute");
        listener.set_nonblocking(true).expect("non bloquant");
        let port = listener.local_addr().expect("adresse").port();
        let router = serve::router_with(config.clone(), Arc::clone(&clock) as Arc<dyn Clock>, None);
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).expect("écoute");
                axum::serve(listener, router).await
            })
        });
        Self {
            config,
            clock,
            port,
            _dir: dir,
        }
    }

    /// Horloge du veilleur à `offset` secondes de l'heure réelle.
    fn at(&self, offset: i64) {
        self.clock.set(SystemClock.unix() + offset);
        if offset.abs() <= 270 {
            assert!((self.clock.unix() - SystemClock.unix()).abs() <= 270);
        }
    }

    fn endpoint(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn reader(&self) -> Store {
        Store::open_read(&self.config.database)
            .expect("lecture")
            .expect("base")
    }

    fn rows(&self, site: &str) -> usize {
        self.reader()
            .inventory_history(site, Source::Ci)
            .expect("historique")
            .len()
    }
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/inventory-tool")
}

fn project(dir: &str) -> tempfile::TempDir {
    let out = tempfile::tempdir().expect("tempdir");
    for entry in std::fs::read_dir(fixtures().join(dir)).expect(dir) {
        let path = entry.expect("entrée").path();
        let name = path.file_name().and_then(|n| n.to_str()).expect("nom");
        std::fs::copy(
            &path,
            out.path()
                .join(name.strip_suffix(".fixture").expect("suffixe")),
        )
        .expect("copie");
    }
    out
}

/// `push` du binaire réel vers `endpoint`, graine `seed`, environnement
/// propre augmenté de `env`.
fn push(
    endpoint: &str,
    site: &str,
    dir: &Path,
    seed: [u8; 32],
    extra: &[&str],
    env: &[(&str, String)],
) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_vigie-inventory"));
    command
        .args([
            "push",
            "--site",
            site,
            "--endpoint",
            endpoint,
            "--allow-http-loopback",
        ])
        .arg("--project-dir")
        .arg(dir)
        .args(extra)
        .env("VIGIE_INVENTORY_KEY", STANDARD.encode(seed));
    for name in [
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "https_proxy",
        "http_proxy",
        "ALL_PROXY",
        "NO_PROXY",
        "no_proxy",
    ] {
        command.env_remove(name);
    }
    for (name, value) in env {
        command.env(name, value);
    }
    command.output().expect("vigie-inventory")
}

/// Écouteur qui compte les connexions et répond `response` à chacune.
fn listener(response: &'static str) -> (String, Arc<AtomicUsize>) {
    let socket = TcpListener::bind("127.0.0.1:0").expect("écoute");
    let address = format!("http://{}", socket.local_addr().expect("adresse"));
    let count = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&count);
    std::thread::spawn(move || {
        for stream in socket.incoming() {
            let Ok(mut stream) = stream else { continue };
            seen.fetch_add(1, Ordering::SeqCst);
            read_request(&mut stream);
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    (address, count)
}

/// Plafond de la requête lue par [`listener`].
const MAX_REQUEST: usize = 8 * 1024 * 1024;

/// Lit toute la requête avant de répondre : en-têtes jusqu'à `\r\n\r\n`,
/// puis exactement `Content-Length` octets de corps (plafonnés). Sous
/// Windows, fermer un socket aux données non lues envoie un RST, que le
/// client reçoit avant la réponse.
fn read_request(stream: &mut std::net::TcpStream) {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let mut request = Vec::new();
    let mut chunk = [0u8; 8192];
    let head_end = loop {
        if let Some(i) = request.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if request.len() > MAX_REQUEST {
            return;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => request.extend_from_slice(&chunk[..n]),
        }
    };
    let length = String::from_utf8_lossy(&request[..head_end])
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .unwrap_or(0)
        .min(MAX_REQUEST);
    let mut body = request.len() - head_end;
    while body < length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => body += n,
        }
    }
}

#[test]
fn a_ci_inventory_is_pushed_rated_and_refused_across_keys() {
    let v = Veilleur::start();
    let npm = project("npm-v3");
    let output = npm.path().join("sbom.json");

    // Premier envoi (veilleur à −240 s), BOM écrit au passage, proxy de
    // l'environnement ignoré.
    let (proxy, connections) = listener("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
    v.at(-240);
    let out = push(
        &v.endpoint(),
        "site-a",
        npm.path(),
        INV_A,
        &["--output", &output.display().to_string()],
        &[
            ("HTTPS_PROXY", proxy.clone()),
            ("HTTP_PROXY", proxy.clone()),
            ("ALL_PROXY", proxy),
        ],
    );
    assert!(out.status.success(), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("inventaire envoyé"));
    assert_eq!(connections.load(Ordering::SeqCst), 0, "proxy ignoré");
    assert!(output.is_file());
    let first = v
        .reader()
        .last_inventory("site-a", Source::Ci)
        .expect("lecture")
        .expect("inventaire ci");
    assert_eq!(first.agent, "vigie-inventory/0.1.0");
    assert_eq!(v.rows("site-a"), 1);

    // Lockfile changé, 180 s plus tard : nouvel inventaire accepté.
    let composer = project("composer");
    v.at(-60);
    let out = push(&v.endpoint(), "site-a", composer.path(), INV_A, &[], &[]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(v.rows("site-a"), 2);
    // Renvoi inchangé 241 s plus tard : seen_at avance, pas de ligne.
    v.at(181);
    let out = push(&v.endpoint(), "site-a", composer.path(), INV_A, &[], &[]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(v.rows("site-a"), 2);
    let last = v
        .reader()
        .last_inventory("site-a", Source::Ci)
        .expect("lecture")
        .expect("ci");
    assert!(last.seen_at > last.received_at);

    // Clé de rapport du site B comme clé d'inventaire du site A, clé
    // d'inventaire d'un autre site : refusées, code 1.
    v.at(181 + 300);
    for seed in [AGENT_B, INV_B] {
        let out = push(&v.endpoint(), "site-a", npm.path(), seed, &[], &[]);
        assert_eq!(out.status.code(), Some(1), "{out:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("journalctl -u vigie-serve"));
    }
    assert_eq!(v.rows("site-a"), 2);

    // Horloge de la machine décalée de 6 min : refus.
    v.at(360);
    let out = push(&v.endpoint(), "site-a", npm.path(), INV_A, &[], &[]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
}

#[test]
fn a_signed_inventory_replays_nowhere_else() {
    let v = Veilleur::start();
    let npm = project("npm-v3");
    // Enveloppe de --dry-run, signée par le test avec la graine d'inventaire.
    let out = Command::new(env!("CARGO_BIN_EXE_vigie-inventory"))
        .args([
            "push",
            "--site",
            "site-b",
            "--endpoint",
            "https://vigie.example.org",
            "--dry-run",
        ])
        .arg("--project-dir")
        .arg(npm.path())
        .env_remove("VIGIE_INVENTORY_KEY")
        .output()
        .expect("dry-run");
    assert!(out.status.success(), "{out:?}");
    let envelope: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    let body = serde_json::to_vec(&envelope).expect("json");
    let inventory_key = SigningKey::from_bytes(&INV_B);
    let agent = ureq::Agent::config_builder()
        .proxy(None)
        .http_status_as_error(false)
        .build()
        .new_agent();
    let post = |route: &str, signature: &str| {
        agent
            .post(&format!("{}{route}", v.endpoint()))
            .header(HEADER_SITE, "site-b")
            .header(HEADER_SIGNATURE, signature)
            .send(&body[..])
            .expect("réponse")
            .status()
            .as_u16()
    };
    v.at(0);
    for (route, domain) in [
        ("/r/v1/report", b"".as_slice()),
        ("/r/v1/logs", DOMAIN_LOGS),
        ("/r/v1/errors", key::DOMAIN_ERRORS),
        ("/r/v1/report", key::DOMAIN_INVENTORY),
        ("/r/v1/logs", key::DOMAIN_INVENTORY),
    ] {
        let signature = key::sign(&inventory_key, domain, &[&body]);
        assert_eq!(post(route, &signature), 404, "{route}");
    }
    let signature = key::sign(&inventory_key, key::DOMAIN_INVENTORY, &[&body]);
    assert_eq!(post("/r/v1/inventory", &signature), 204);
}

#[test]
fn redirects_are_not_followed() {
    let (server, connections) = listener(
        "HTTP/1.1 301 Moved Permanently\r\nLocation: http://127.0.0.1:9/\r\nContent-Length: 0\r\n\r\n",
    );
    let npm = project("npm-v3");
    let out = push(&server, "site-a", npm.path(), INV_A, &[], &[]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("HTTP 301"),
        "{out:?}"
    );
    assert_eq!(connections.load(Ordering::SeqCst), 1);
}

#[test]
fn a_project_over_2000_components_is_sent_incomplete_with_a_warning() {
    let v = Veilleur::start();
    let dir = tempfile::tempdir().expect("tempdir");
    let mut lock = String::from("version = 4\n");
    for i in 0..2001 {
        lock.push_str(&format!(
            "\n[[package]]\nname = \"c{i}\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
        ));
    }
    std::fs::write(dir.path().join("Cargo.lock"), lock).expect("écriture");
    v.at(0);
    let out = push(&v.endpoint(), "site-b", dir.path(), INV_B, &[], &[]);
    assert!(out.status.success(), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--omit-dev") && stderr.contains("incomplet"),
        "{stderr}"
    );
    let head = v
        .reader()
        .last_inventory("site-b", Source::Ci)
        .expect("lecture")
        .expect("ci");
    assert!(!head.complete);
    assert_eq!(
        v.reader()
            .inventory_components(head.id, 0, 5000)
            .expect("composants")
            .len(),
        2000
    );
}
