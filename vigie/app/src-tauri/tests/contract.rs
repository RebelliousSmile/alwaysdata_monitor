//! Contrat entre la console et le veilleur : chaque appel de `client.rs`
//! contre le routeur de `vigie serve`, servi sur un vrai port de la boucle
//! locale, sur une base remplie à la main. Un champ consommé par la console
//! qui change de nom, de type ou disparaît fait échouer la lecture.

use std::path::PathBuf;
use std::sync::Arc;

#[path = "../../../tests/support/veilleur.rs"]
mod veilleur;

use vigie::checks::CheckKind;
use vigie::clock::FakeClock;
use vigie::config::{Api, Config, Site, SiteKind};
use vigie::device::{self, PAIRING_TTL};
use vigie::finding::{Finding, Severity as VSeverity};
use vigie::serve;
use vigie::store::{AcceptedReport, ReportOutcome, RunRecord, Store};
use vigie_console_lib::client::{Client, ErrorKind, IncidentState, Severity, SiteState};

const T0: i64 = 1_792_000_000;
const DAY: i64 = 86_400;

struct Veilleur {
    _dir: tempfile::TempDir,
    config: Config,
    base: String,
}

fn site_b() -> Site {
    Site {
        id: "site-b".into(),
        url: "https://site-b.example.org/".into(),
        kind: SiteKind::Wordpress,
        keyword_url: None,
        keyword: None,
        interval: 600,
        agent_silence: 900,
    }
}

impl Veilleur {
    /// Site A non conforme avec un agent, site B sans constat ; le routeur
    /// écoute sur 127.0.0.1, horloge fixée à `T0`.
    async fn start() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = veilleur::config(dir.path().join("vigie.db"));
        config.api = Some(Api {
            public_url: "https://vigie.example.org".into(),
        });
        config.sites.push(site_b());
        Store::open(&config.database).expect("open");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        let router = serve::router_with_clock(config.clone(), Arc::new(FakeClock::new(T0)));
        tokio::spawn(async move { axum::serve(listener, router).await.expect("serve") });
        let v = Self {
            _dir: dir,
            config,
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

    let history = client.incidents("site-a").await.expect("incidents");
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

    let history = client.incidents("site-a").await.expect("incidents");
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
