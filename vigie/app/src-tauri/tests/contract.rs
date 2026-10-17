//! Contrat entre la console et le veilleur : chaque appel de `client.rs`
//! contre le routeur de `vigie serve`, servi sur un vrai port de la boucle
//! locale, sur une base remplie à la main. Un champ consommé par la console
//! qui change de nom, de type ou disparaît fait échouer la lecture.
//!
//! IP des plages de documentation (RFC 5737).

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[path = "../../../tests/support/veilleur.rs"]
mod veilleur;

use vigie::alert::MemoryNotifier;
use vigie::checks::CheckKind;
use vigie::clock::FakeClock;
use vigie::config::{Api, Config, LogSourceKind, Site, SiteKind, SiteLogs as LogsConfig};
use vigie::device::{self, PAIRING_TTL};
use vigie::finding::{Finding, Severity as VSeverity};
use vigie::logs::Entry;
use vigie::logs::source::{LogSource, MemorySource};
use vigie::serve;
use vigie::store::{AcceptedReport, ReportOutcome, RunRecord, Store};
use vigie::tick::{self, Options};
use vigie_console_lib::Console;
use vigie_console_lib::client::{Client, ErrorKind, IncidentState, Severity, SiteState};
use vigie_console_lib::secret::{MemoryStore, TokenStorage};

const T0: i64 = 1_792_000_000;
const DAY: i64 = 86_400;

struct Veilleur {
    _dir: tempfile::TempDir,
    config: Config,
    clock: Arc<FakeClock>,
    base: String,
}

fn site_b() -> Site {
    Site {
        id: "site-b".into(),
        url: "https://site-b.example.org/".into(),
        kind: SiteKind::Wordpress,
        runtime: None,
        keyword_url: None,
        keyword: None,
        interval: 600,
        agent_silence: 900,
        logs: None,
    }
}

impl Veilleur {
    /// Site A non conforme avec un agent, site B sans constat ; le routeur
    /// écoute sur 127.0.0.1, horloge fixée à `T0`.
    async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    /// Comme `start`, la configuration retouchée par `configure`.
    async fn start_with(configure: impl FnOnce(&mut Config)) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = veilleur::config(dir.path().join("vigie.db"));
        config.api = Some(Api {
            public_url: "https://vigie.example.org".into(),
        });
        config.sites.push(site_b());
        configure(&mut config);
        Store::open(&config.database).expect("open");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        let clock = Arc::new(FakeClock::new(T0));
        let router = serve::router_with_clock(config.clone(), clock.clone());
        // Comme `vigie serve` : l'adresse du pair sert à la limite de débit.
        let service = router.into_make_service_with_connect_info::<std::net::SocketAddr>();
        tokio::spawn(async move { axum::serve(listener, service).await.expect("serve") });
        let v = Self {
            _dir: dir,
            config,
            clock,
            base,
        };
        v.fill();
        v
    }

    fn db(&self) -> PathBuf {
        self.config.database.clone()
    }

    fn store(&self) -> Store {
        Store::open(&self.db()).expect("open")
    }

    fn all_clear(&self, id: &str, at: i64) {
        let site = self
            .config
            .sites
            .iter()
            .find(|s| s.id == id)
            .expect("site")
            .clone();
        let mut store = self.store();
        for kind in CheckKind::ALL.into_iter().filter(|k| k.applies(&site)) {
            store
                .record_result(&site.id, kind.name(), at, &RunRecord::concluded(&[]))
                .expect("record_result");
        }
    }

    fn reconcile(&self, check: &str, findings: &[Finding], at: i64) {
        self.store()
            .reconcile("site-a", check, findings, at)
            .expect("reconcile");
    }

    fn fill(&self) {
        self.all_clear("site-a", T0 - 120);
        self.all_clear("site-b", T0 - 60);
        self.store()
            .record_result(
                "site-a",
                "tls",
                T0 - 90,
                &RunRecord::concluded(&[])
                    .with_duration(std::time::Duration::from_millis(80))
                    .with_observed(Some(format!("{{\"tls_not_after\":{}}}", T0 + 40 * DAY))),
            )
            .expect("record_result");
        // Un incident ouvert puis fermé : il reste dans l'historique.
        let hsts = Finding::new(
            "site-a",
            "headers",
            VSeverity::Warning,
            "hsts",
            "HSTS absent",
        );
        self.reconcile("headers", std::slice::from_ref(&hsts), T0 - 3 * DAY);
        self.reconcile("headers", &[], T0 - 2 * DAY);
        // Un critique ouvert, et un info qui ne compte pas.
        let env = Finding::new(
            "site-a",
            "exposed",
            VSeverity::Critical,
            ".env",
            "/.env lisible",
        );
        self.reconcile("exposed", std::slice::from_ref(&env), T0 - DAY);
        // Agent déclaré, un rapport accepté avec ses faits.
        let pubkey = [7u8; 32];
        self.store()
            .add_key("site-a", &pubkey, T0 - 10 * DAY)
            .expect("add_key");
        let findings = [Finding::new(
            "site-a",
            "agent:core",
            VSeverity::Info,
            "maj",
            "mise à jour disponible",
        )];
        let outcome = self
            .store()
            .accept_report(
                &AcceptedReport {
                    site: "site-a",
                    pubkey: &pubkey,
                    seq: 1,
                    agent: "vigie-agent 1.0.0",
                    facts: "{\"php\":\"8.3\"}",
                    files: "{}",
                    findings: &findings,
                },
                T0 - 300,
            )
            .expect("accept_report");
        assert_eq!(outcome, ReportOutcome::Accepted);
    }

    /// Code d'appairage valide, comme `vigie device pair`.
    fn code(&self, name: &str) -> String {
        let code = device::new_code().expect("code");
        self.store()
            .create_pairing(&device::hash(&code), name, T0, T0 + PAIRING_TTL)
            .expect("pairing");
        code
    }

    /// Lien `vigie://pair` vers ce veilleur, comme `vigie device pair`.
    fn link(&self, name: &str) -> String {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("u", &self.base)
            .append_pair("c", &self.code(name))
            .finish();
        format!("vigie://pair?{query}")
    }

    async fn paired(&self, name: &str) -> Client {
        let client = Client::new(&self.base).expect("client");
        let paired = client.pair(&self.code(name)).await.expect("pair");
        assert_eq!(paired.name, name);
        assert!(paired.device_id > 0);
        client.with_token(paired.token)
    }
}

#[tokio::test]
async fn pairing_accepts_a_code_once() {
    let v = Veilleur::start().await;
    let client = Client::new(&v.base).expect("client");
    let code = v.code("poste");
    client.pair(&code).await.expect("première fois");
    let again = client.pair(&code).await.expect_err("code déjà utilisé");
    assert_eq!(again.kind, ErrorKind::Unauthorized);
    let unknown = client
        .pair("abcdefghijklmnopqrstuv")
        .await
        .expect_err("code inconnu");
    assert_eq!(unknown.kind, ErrorKind::Unauthorized);
}

#[tokio::test]
async fn reads_overview_site_incidents_and_settings() {
    let v = Veilleur::start().await;
    let client = v.paired("poste").await;

    let overview = client.overview().await.expect("overview");
    assert_eq!(overview.server_time, T0);
    let ids: Vec<(&str, SiteState)> = overview
        .sites
        .iter()
        .map(|s| (s.id.as_str(), s.state))
        .collect();
    assert_eq!(
        ids,
        [
            ("site-a", SiteState::NonCompliant),
            ("site-b", SiteState::Ok)
        ]
    );
    let a = &overview.sites[0];
    assert_eq!(a.open_count, 1, "l'info ne compte pas");
    let worst = a.worst.as_ref().expect("pire");
    assert_eq!(worst.severity, Severity::Critical);
    assert_eq!(worst.check, "exposed");
    assert_eq!(overview.sites[1].worst, None);
    assert_eq!(overview.sites[1].last_read, Some(T0 - 60));

    let detail = client.site("site-a").await.expect("site");
    assert_eq!(detail.state, SiteState::NonCompliant);
    assert_eq!(detail.interval, 300);
    let agent = detail.agent.as_ref().expect("agent");
    assert_eq!(agent.declared_at, T0 - 10 * DAY);
    assert_eq!(agent.last_report_at, Some(T0 - 300));
    assert_eq!(agent.facts["php"], "8.3");
    assert_eq!(detail.open_incidents.len(), 2);
    let tls = detail.checks.iter().find(|c| c.name == "tls").expect("tls");
    assert_eq!(tls.result.as_deref(), Some("ok"));
    assert_eq!(tls.duration_ms, Some(80));
    assert_eq!(tls.observed["tls_not_after"], T0 + 40 * DAY);
    assert!(detail.checks.iter().any(|c| c.name == "heartbeat"));
    assert!(detail.checks.iter().any(|c| c.name.starts_with("agent:")));

    let history = client.incidents("site-a", None).await.expect("incidents");
    assert_eq!(history.site, "site-a");
    let closed = history
        .incidents
        .iter()
        .find(|i| i.check == "headers")
        .expect("incident fermé");
    assert_eq!(closed.state, IncidentState::Closed);
    assert_eq!(closed.closed_at, Some(T0 - 2 * DAY));

    let settings = client.settings().await.expect("settings");
    assert_eq!(
        settings.public_url.as_deref(),
        Some("https://vigie.example.org")
    );
    assert_ne!(
        settings.alerts.to, "alertes@example.org",
        "destinataire masqué"
    );
    assert_eq!(settings.sites.len(), 2);
    assert!(settings.sites[0].agent);
    assert!(!settings.sites[1].agent);
    let me: Vec<_> = settings.devices.iter().filter(|d| d.current).collect();
    assert_eq!(me.len(), 1);
    assert_eq!(me[0].name, "poste");

    let missing = client.site("inconnu").await.expect_err("site inconnu");
    assert_eq!(missing.kind, ErrorKind::NotFound);
}

#[tokio::test]
async fn acknowledges_an_open_incident_only() {
    let v = Veilleur::start().await;
    let client = v.paired("poste").await;
    let detail = client.site("site-a").await.expect("site");
    let open = detail
        .open_incidents
        .iter()
        .find(|i| i.check == "exposed")
        .expect("ouvert");

    let incident = client.incident(open.id).await.expect("incident");
    assert_eq!(incident.state, IncidentState::Open);
    assert_eq!(incident.acked_at, None);

    let acked = client.ack(open.id).await.expect("ack");
    assert_eq!(acked.state, IncidentState::Acked);
    assert_eq!(acked.acked_at, Some(T0));
    assert_eq!(acked.closed_at, None, "acquitté, toujours ouvert");

    let history = client.incidents("site-a", None).await.expect("incidents");
    let closed = history
        .incidents
        .iter()
        .find(|i| i.state == IncidentState::Closed)
        .expect("fermé");
    let conflict = client.ack(closed.id).await.expect_err("fermé");
    assert_eq!(conflict.kind, ErrorKind::Conflict);
    let unknown = client.ack(999_999).await.expect_err("inconnu");
    assert_eq!(unknown.kind, ErrorKind::NotFound);
    let unknown = client.incident(999_999).await.expect_err("inconnu");
    assert_eq!(unknown.kind, ErrorKind::NotFound);
}

#[tokio::test]
async fn a_revoked_device_is_unauthorized() {
    let v = Veilleur::start().await;
    let client = v.paired("poste").await;
    client.unpair().await.expect("révoqué");
    let err = client.overview().await.expect_err("révoqué");
    assert_eq!(err.kind, ErrorKind::Unauthorized);
    let anonymous = Client::new(&v.base).expect("client");
    let err = anonymous.overview().await.expect_err("sans jeton");
    assert_eq!(err.kind, ErrorKind::Unauthorized);
}

#[tokio::test]
async fn an_unreachable_veilleur_is_offline() {
    // Port libéré juste après l'avoir obtenu : plus personne n'y écoute.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    let client = Client::new(&format!("http://{addr}"))
        .expect("client")
        .with_token("jeton".into());
    let err = client.overview().await.expect_err("injoignable");
    assert_eq!(err.kind, ErrorKind::Offline);
}

/// Appairage par la console : jeton dans le store, `device.json` sans lui,
/// puis retrait qui efface les deux côtés.
#[tokio::test]
async fn the_console_keeps_the_token_in_its_store() {
    let v = Veilleur::start().await;
    let dir = tempfile::tempdir().expect("dossier");
    let secrets = Arc::new(MemoryStore::new());
    let console = Console::new(dir.path().to_path_buf(), secrets.clone());
    let status = console.pair(&v.link("poste"), true).await.expect("appairé");
    assert_eq!(status.token_storage, TokenStorage::Keyring);
    let token = secrets.secret().expect("jeton rangé");
    let file = std::fs::read_to_string(dir.path().join("device.json")).expect("fichier");
    assert!(!file.contains(&token), "{file}");

    // Relancée, la console relit le jeton du store et appelle le veilleur.
    let console = Console::new(dir.path().to_path_buf(), secrets.clone());
    assert_eq!(console.status(), Some(status));
    console
        .call(|client| async move { client.overview().await })
        .await
        .expect("overview");

    let unpaired = console.unpair().await.expect("retiré");
    assert!(unpaired.revoked);
    assert_eq!(secrets.secret(), None);
    assert!(!dir.path().join("device.json").exists());
}

/// Écriture refusée par le store pendant l'appairage : le jeton émis est
/// révoqué, rien ne reste sur le poste, et l'erreur ne cite pas le jeton.
#[tokio::test]
async fn a_refused_store_revokes_the_new_token() {
    let v = Veilleur::start().await;
    for (name, secrets) in [
        ("refusé", MemoryStore::failing_write()),
        ("faussé", MemoryStore::altered_readback()),
    ] {
        let dir = tempfile::tempdir().expect("dossier");
        let secrets = Arc::new(secrets);
        let console = Console::new(dir.path().to_path_buf(), secrets.clone());
        let err = console
            .pair(&v.link(name), true)
            .await
            .expect_err("store refusé");
        assert_eq!(err.kind, ErrorKind::Storage);
        assert!(err.message.contains("révoqué"), "{err:?}");
        assert_eq!(console.status(), None);
        assert!(!dir.path().join("device.json").exists());
        if let Some(kept) = secrets.secret() {
            assert!(!err.message.contains(&kept), "{err:?}");
        }
    }
    let witness = v.paired("témoin").await;
    let settings = witness.settings().await.expect("settings");
    for name in ["refusé", "faussé"] {
        let device = settings
            .devices
            .iter()
            .find(|d| d.name == name)
            .expect("appareil");
        assert!(device.revoked_at.is_some(), "{name} révoqué");
    }
}

/// 120 incidents clos sur le site B : trois pages de 50, 50 et 20, sans
/// doublon ni trou, chacune demandée avec le curseur de la précédente.
#[tokio::test]
async fn closed_incidents_come_in_three_pages_without_duplicate() {
    let v = Veilleur::start().await;
    let mut store = v.store();
    // Chaque constat ferme le précédent : 121 ouverts, 120 clos.
    for i in 0..=120 {
        let finding = Finding::new(
            "site-b",
            "content",
            VSeverity::Warning,
            format!("k{i}"),
            format!("constat {i}"),
        );
        store
            .reconcile("site-b", "content", &[finding], T0 - DAY + i * 60)
            .expect("reconcile");
    }
    let client = v.paired("poste").await;
    let mut pages = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = client
            .incidents("site-b", cursor.as_deref())
            .await
            .expect("page");
        assert_eq!(page.site, "site-b");
        assert!(
            page.incidents
                .iter()
                .all(|i| i.state == IncidentState::Closed)
        );
        pages.push(page.incidents.iter().map(|i| i.id).collect::<Vec<_>>());
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
        assert!(pages.len() < 3, "trop de pages");
    }
    let sizes: Vec<usize> = pages.iter().map(Vec::len).collect();
    assert_eq!(sizes, [50, 50, 20]);
    let seen: Vec<i64> = pages.concat();
    let unique: HashSet<i64> = seen.iter().copied().collect();
    assert_eq!(unique.len(), 120, "doublon");

    // Un curseur illisible : 400, message fixe.
    let err = client
        .incidents("site-b", Some("!!!"))
        .await
        .expect_err("curseur illisible");
    assert_eq!(err.kind, ErrorKind::BadRequest);
    assert!(!err.message.contains("!!!"), "{err:?}");
}

const CURL: &str = "curl/8.4.0";
const FIREFOX: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0";
const GPTBOT: &str = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2)";
/// IP aux verdicts élevés et moyens du jeu de logs.
const HIGH: u8 = 60;
const MEDIUM: u8 = 15;

fn ip(text: &str) -> IpAddr {
    text.parse().expect("ip")
}

fn hit(timestamp_ms: i64, from: IpAddr, path: &str, ua: &str, facet: bool) -> Entry {
    Entry {
        ip: Some(from),
        method: Some("GET".into()),
        user_agent: ua.into(),
        query_keys: if facet { vec!["q".into()] } else { Vec::new() },
        ..Entry::new(timestamp_ms, path, 200)
    }
}

/// Logs des dix minutes avant `now` : 60 IP en curl sur des facettes
/// (élevé), 15 en Firefox sur des facettes (moyen), GPTBot (faible).
fn scraped(now: i64) -> Vec<Entry> {
    let start = (now - 600) * 1000;
    let mut entries = Vec::new();
    for n in 1..=HIGH {
        for j in 0..20 {
            let at = start + i64::from(n) * 100 + j * 1000;
            entries.push(hit(
                at,
                ip(&format!("192.0.2.{n}")),
                "/categorie",
                CURL,
                true,
            ));
        }
    }
    for n in 1..=MEDIUM {
        for j in 0..20 {
            let at = start + 30_000 + i64::from(n) * 100 + j * 1000;
            let from = ip(&format!("198.51.100.{n}"));
            entries.push(hit(at, from, "/categorie", FIREFOX, true));
        }
    }
    for j in 0..10 {
        let at = start + 90_000 + j * 100;
        entries.push(hit(at, ip("203.0.113.50"), "/article", GPTBOT, false));
    }
    entries
}

/// Site A avec une source de logs, site B sans.
async fn with_logs() -> Veilleur {
    Veilleur::start_with(|config| {
        config.sites[0].logs = Some(LogsConfig {
            source: Some(LogSourceKind::Alwaysdata),
            hosts: vec!["site-a.example.org".into()],
            ..LogsConfig::default()
        });
    })
    .await
}

/// Un passage de `tick` à `now` sur ces logs, puis l'horloge du routeur
/// avancée à `now`.
fn tick_logs(v: &Veilleur, now: i64, entries: &[Entry]) {
    let options = Options {
        check_budget: Duration::ZERO,
        ..Options::default()
    };
    let mail = MemoryNotifier::new();
    let summary = tick::run_with_sources(&v.config, now, &options, &mail, &|site| {
        (site.id == "site-a")
            .then(|| Box::new(MemorySource::new("memoire", entries.to_vec())) as Box<dyn LogSource>)
    })
    .expect("tick");
    assert!(summary.logs_folded > 0, "{summary:?}");
    v.clock.set(now);
}

/// Trois états de la vue des logs : 404 sans source, `null` avant toute
/// analyse, puis robots, règles et charge.
#[tokio::test]
async fn the_logs_view_reads_three_states() {
    let v = with_logs().await;
    let client = v.paired("poste").await;

    for site in ["site-b", "inconnu"] {
        let err = client.logs(site).await.expect_err("sans source");
        assert_eq!(err.kind, ErrorKind::NotFound, "{site}");
        let err = client.log_ips(site, None).await.expect_err("sans source");
        assert_eq!(err.kind, ErrorKind::NotFound, "{site}");
    }

    let logs = client.logs("site-a").await.expect("logs");
    assert_eq!(logs.analysis, None, "analyse en attente");
    let ips = client.log_ips("site-a", None).await.expect("ips");
    assert_eq!(ips.generated_at, None);
    assert!(ips.items.is_empty());
    assert_eq!(ips.next_cursor, None);

    let entries = scraped(T0);
    tick_logs(&v, T0, &entries);
    let analysis = client
        .logs("site-a")
        .await
        .expect("logs")
        .analysis
        .expect("analyse");
    assert_eq!(analysis.generated_at, T0);
    assert_eq!(analysis.scored, u64::from(HIGH + MEDIUM) + 1);
    let gptbot = analysis
        .bots
        .iter()
        .find(|b| b.name == "GPTBot")
        .expect("GPTBot");
    assert_eq!(gptbot.publisher, "OpenAI");
    assert_eq!(gptbot.class, "ai_training");
    assert_eq!(gptbot.requests, 10);
    assert!(!analysis.rules.is_empty());
    let load: u64 = analysis.load.iter().map(|h| h.requests).sum();
    assert_eq!(load, entries.len() as u64);
    assert!(analysis.load_threshold_us > 0);
}

/// Verdicts d'IP par pages, sans doublon ; un curseur purgé rend
/// `CursorExpired` et la liste reprend au début.
#[tokio::test]
async fn ip_verdicts_are_paged_and_an_expired_cursor_restarts() {
    let v = with_logs().await;
    let client = v.paired("poste").await;
    let mut entries = scraped(T0);
    tick_logs(&v, T0, &entries);

    let first = client.log_ips("site-a", None).await.expect("page 1");
    assert_eq!(first.site, "site-a");
    assert_eq!(first.generated_at, Some(T0));
    assert_eq!(first.items.len(), 50);
    let cursor = first.next_cursor.clone().expect("curseur");
    let second = client
        .log_ips("site-a", Some(&cursor))
        .await
        .expect("page 2");
    assert_eq!(second.next_cursor, None);
    let ips: HashSet<&str> = first
        .items
        .iter()
        .chain(&second.items)
        .map(|item| item.ip.as_str())
        .collect();
    assert_eq!(ips.len(), usize::from(HIGH + MEDIUM), "doublon ou trou");
    for item in first.items.iter().chain(&second.items) {
        assert!(
            ["moyen", "eleve"].contains(&item.level.as_str()),
            "{item:?}"
        );
        assert!(!item.reasons.is_empty(), "{item:?}");
    }

    // Plus de 15 minutes après, un autre instantané : le premier est purgé.
    let purged = T0 + 1300;
    entries.push(hit(
        (purged - 10) * 1000,
        ip("203.0.113.9"),
        "/",
        FIREFOX,
        false,
    ));
    tick_logs(&v, purged, &entries);
    let err = client
        .log_ips("site-a", Some(&cursor))
        .await
        .expect_err("instantané purgé");
    assert_eq!(err.kind, ErrorKind::CursorExpired);
    let again = client.log_ips("site-a", None).await.expect("reprise");
    assert_eq!(again.generated_at, Some(purged));

    let err = client
        .log_ips("site-a", Some("!!!"))
        .await
        .expect_err("curseur illisible");
    assert_eq!(err.kind, ErrorKind::BadRequest);
}

/// Au-delà de la rafale de l'appareil : 429 avec le délai de `Retry-After`.
#[tokio::test]
async fn too_many_requests_carry_the_retry_delay() {
    let v = Veilleur::start().await;
    let client = v.paired("poste").await;
    let mut limited = None;
    for _ in 0..60 {
        if let Err(err) = client.overview().await {
            limited = Some(err);
            break;
        }
    }
    let err = limited.expect("limite de débit atteinte");
    assert_eq!(err.kind, ErrorKind::TooManyRequests);
    let seconds = err
        .message
        .strip_prefix("trop de requêtes, réessayer dans ")
        .and_then(|rest| rest.strip_suffix(" s"))
        .and_then(|n| n.parse::<u64>().ok());
    assert!(seconds.is_some_and(|s| s >= 1), "{err:?}");
}
