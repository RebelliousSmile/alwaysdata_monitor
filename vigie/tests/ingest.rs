//! Rapports d'agent de bout en bout : `POST /r/v1/report` par le routeur de
//! `serve`, puis `tick` avec un notifier en mémoire.
//!
//! Les contrôles externes sont marqués comme faits à `T0`, avec un intervalle
//! d'un jour : `tick` ne fait aucune requête HTTP et ne traite que les agents.

use std::path::Path;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vigie::alert::MemoryNotifier;
use vigie::checks::CheckKind;
use vigie::clock::{Clock, FakeClock};
use vigie::config::{Alerts, Config, Site, SiteKind};
use vigie::ingest::{self, HEADER_SIGNATURE, HEADER_SITE, Reason};
use vigie::store::{Agent, Store};
use vigie::tick::{self, Options};
use vigie::{report, serve};

/// Instant arbitraire : seuls les écarts comptent.
const T0: i64 = 1_800_000_000;

fn site() -> Site {
    Site {
        id: "site-a".into(),
        url: "https://site-a.example.org/".into(),
        kind: SiteKind::Wordpress,
        runtime: None,
        keyword_url: None,
        keyword: None,
        interval: 86_400,
        agent_silence: 900,
        logs: None,
        inventory: None,
        custom_checks: Vec::new(),
    }
}

fn config(dir: &Path) -> Config {
    Config {
        database: dir.join("vigie.db"),
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
            password_file: dir.join("smtp-password"),
        },
        sites: vec![site()],
    }
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

struct Harness {
    config: Config,
    clock: Arc<FakeClock>,
    mail: MemoryNotifier,
    _dir: tempfile::TempDir,
}

impl Harness {
    /// Base prête, contrôles externes faits, clé `key` enregistrée à `T0`.
    fn new(key: &SigningKey) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path());
        let mut store = Store::open(&config.database).expect("base");
        for kind in CheckKind::ALL {
            store
                .record_run("site-a", kind.name(), T0)
                .expect("record_run");
        }
        store
            .add_key("site-a", &key.verifying_key().to_bytes(), T0)
            .expect("add_key");
        Self {
            config,
            clock: Arc::new(FakeClock::new(T0)),
            mail: MemoryNotifier::new(),
            _dir: dir,
        }
    }

    fn set_now(&self, now: i64) {
        self.clock.set(now);
    }

    fn now(&self) -> i64 {
        self.clock.unix()
    }

    async fn post(&self, request: Request<Body>) -> (StatusCode, Vec<u8>) {
        let router = serve::router_with_clock(
            self.config.clone(),
            Arc::clone(&self.clock) as Arc<dyn Clock>,
        );
        let response = router.oneshot(request).await.expect("réponse");
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("corps")
            .to_bytes();
        (status, body.to_vec())
    }

    /// Rapport signé par `key`, envoyé maintenant.
    async fn send(&self, key: &SigningKey, report: &Value) -> (StatusCode, Vec<u8>) {
        let body = serde_json::to_vec(report).expect("json");
        self.post(signed("site-a", key, body)).await
    }

    fn tick(&self) -> tick::Summary {
        tick::run_with(&self.config, self.now(), &Options::default(), &self.mail).expect("tick")
    }

    fn store(&self) -> Store {
        Store::open(&self.config.database).expect("base")
    }

    fn agent(&self) -> Agent {
        self.store()
            .agent("site-a")
            .expect("agent")
            .expect("clé présente")
    }

    fn open_keys(&self) -> Vec<String> {
        self.store()
            .open_incidents()
            .expect("incidents")
            .into_iter()
            .map(|i| i.key)
            .collect()
    }
}

fn signed(site: &str, key: &SigningKey, body: Vec<u8>) -> Request<Body> {
    let signature = STANDARD.encode(key.sign(&body).to_bytes());
    Request::post("/r/v1/report")
        .header(HEADER_SITE, site)
        .header(HEADER_SIGNATURE, signature)
        .body(Body::from(body))
        .expect("requête")
}

fn report(seq: u64, sent_at: i64, findings: Value) -> Value {
    json!({
        "v": 1,
        "site": "site-a",
        "seq": seq,
        "sent_at": sent_at,
        "agent": "agent-php/0.1.0",
        "findings": findings,
        "facts": {"php_version": "8.3.12", "wp_plugins": 12}
    })
}

fn display_errors() -> Value {
    json!([{
        "check": "critical-file",
        "severity": "critical",
        "key": "display_errors",
        "detail": "display_errors activé en production"
    }])
}

fn assert_silent_404((status, body): (StatusCode, Vec<u8>), case: &str) {
    assert_eq!(status, StatusCode::NOT_FOUND, "{case}");
    assert!(body.is_empty(), "{case} : corps {body:?}");
}

#[tokio::test]
async fn an_accepted_report_opens_incidents_that_only_tick_announces() {
    let key = signing_key(7);
    let h = Harness::new(&key);
    h.set_now(T0 + 60);

    let (status, body) = h.send(&key, &report(1, T0 + 60, display_errors())).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(body.is_empty());
    assert_eq!(h.open_keys(), ["site-a/agent:critical-file/display_errors"]);
    // `serve` n'envoie rien : l'ouverture attend `tick`.
    let store = h.store();
    assert_eq!(store.pending_notifications(h.now()).expect("attente"), 1);
    let facts = store.last_facts("site-a").expect("facts").expect("relevé");
    assert!(facts.contains("8.3.12"), "{facts}");
    drop(store);
    let agent = h.agent();
    assert_eq!(agent.last_seq, 1);
    assert_eq!(agent.last_valid_at, Some(T0 + 60));
    assert_eq!(agent.agent.as_deref(), Some("agent-php/0.1.0"));

    let summary = h.tick();
    assert_eq!(summary.checks_run, 0, "{summary:?}");
    assert_eq!(summary.emails_sent, 1, "{summary:?}");
    let sent = h.mail.take();
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert!(sent[0].body.contains("display_errors"), "{}", sent[0].body);
    assert!(h.tick().emails_sent == 0);

    // Le rapport suivant ne porte plus le constat : l'incident est clos.
    h.set_now(T0 + 200);
    let (status, _) = h.send(&key, &report(2, T0 + 200, json!([]))).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(h.open_keys().is_empty());
    assert_eq!(h.tick().emails_sent, 1);
    let sent = h.mail.take();
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert!(sent[0].subject.contains("rétabli"), "{}", sent[0].subject);
}

#[tokio::test]
async fn a_critical_file_that_changes_opens_a_warning_until_accepted() {
    let key = signing_key(7);
    let h = Harness::new(&key);
    let with_htaccess = |seq: u64, at: i64, hash: &str| {
        let mut value = report(seq, at, json!([]));
        value["files"] = json!({".htaccess": hash, "wp-config.php": null});
        value
    };
    let before = "33bf0cf98fa40b5f4c44e053816b75487245c5fc01e66dd65470e2e70cbee0d8";
    let after = "8978bc0aa6aece0fc74de901712dd160c804917cda1ade8afb59f29f526ff94a";

    h.set_now(T0 + 60);
    let first = with_htaccess(1, T0 + 60, before);
    assert_eq!(h.send(&key, &first).await.0, StatusCode::NO_CONTENT);
    assert!(h.open_keys().is_empty());

    h.set_now(T0 + 400);
    let second = with_htaccess(2, T0 + 400, after);
    assert_eq!(h.send(&key, &second).await.0, StatusCode::NO_CONTENT);
    assert_eq!(h.open_keys(), ["site-a/agent:integrity/modified:.htaccess"]);
    let open = h.store().open_incidents().expect("incidents");
    assert_eq!(open[0].severity, vigie::finding::Severity::Warning);
    assert_eq!(h.tick().emails_sent, 1);
    let sent = h.mail.take();
    assert!(sent[0].body.contains(".htaccess"), "{}", sent[0].body);

    // Modification voulue : acceptée, l'incident est clos et ne revient pas.
    assert!(
        h.store()
            .accept_baseline("site-a", T0 + 500)
            .expect("accept")
    );
    assert!(h.open_keys().is_empty());
    h.set_now(T0 + 700);
    let third = with_htaccess(3, T0 + 700, after);
    assert_eq!(h.send(&key, &third).await.0, StatusCode::NO_CONTENT);
    assert!(h.open_keys().is_empty());
}

#[tokio::test]
async fn an_agent_cannot_report_the_integrity_check_itself() {
    let key = signing_key(7);
    let h = Harness::new(&key);
    h.set_now(T0 + 60);
    let forged = report(
        1,
        T0 + 60,
        json!([{"check": "integrity", "severity": "info", "key": "x", "detail": "x"}]),
    );
    assert_silent_404(h.send(&key, &forged).await, "contrôle réservé");
}

#[tokio::test]
async fn every_refusal_is_the_same_silent_404_and_stores_nothing() {
    let key = signing_key(7);
    let h = Harness::new(&key);
    h.set_now(T0 + 60);
    let first = report(1, T0 + 60, display_errors());
    assert_eq!(h.send(&key, &first).await.0, StatusCode::NO_CONTENT);
    let before = h.agent();
    let facts_before = h.store().last_facts("site-a").expect("facts");

    // Moins de 60 s après le précédent.
    h.set_now(T0 + 90);
    assert_silent_404(h.send(&key, &report(2, T0 + 90, json!([]))).await, "débit");

    h.set_now(T0 + 200);
    // Rejeu à l'identique du premier rapport.
    assert_silent_404(h.send(&key, &first).await, "rejeu");
    // Un octet modifié après signature.
    let body = serde_json::to_vec(&report(2, T0 + 200, json!([]))).expect("json");
    let mut request = signed("site-a", &key, body.clone());
    let mut tampered = body.clone();
    let at = tampered.len() / 2;
    tampered[at] ^= 0x01;
    *request.body_mut() = Body::from(tampered);
    assert_silent_404(h.post(request).await, "octet modifié");
    // Horloge de l'agent décalée de 10 min.
    assert_silent_404(
        h.send(&key, &report(2, T0 + 200 - 600, json!([]))).await,
        "décalage",
    );
    // Plus de 64 Ko, signés et conformes au schéma : seule la taille les refuse.
    let mut big = report(2, T0 + 200, json!([]));
    big["findings"] = (0..report::MAX_FINDINGS)
        .map(|i| {
            json!({
                "check": "critical-file",
                "severity": "info",
                "key": format!("{i:0>200}"),
                "detail": "d".repeat(300)
            })
        })
        .collect();
    big["facts"] = (0..report::MAX_FACTS)
        .map(|i| (format!("k{i}"), json!("x".repeat(256))))
        .collect::<serde_json::Map<_, _>>()
        .into();
    let raw = serde_json::to_vec(&big).expect("json");
    assert!(raw.len() > serve::MAX_REPORT_BYTES, "{} octets", raw.len());
    report::parse(&raw, "site-a").expect("conforme au schéma");
    assert_silent_404(h.send(&key, &big).await, "plus de 64 Ko");
    // Taille annoncée trop grande.
    let mut request = signed("site-a", &key, body.clone());
    request
        .headers_mut()
        .insert("content-length", (200_u32 * 1024).into());
    assert_silent_404(h.post(request).await, "Content-Length");
    // Site hors configuration, même signé par une clé connue.
    let mut other = report(2, T0 + 200, json!([]));
    other["site"] = json!("site-b");
    let other = serde_json::to_vec(&other).expect("json");
    assert_silent_404(h.post(signed("site-b", &key, other)).await, "site inconnu");
    // Autre clé que celle enregistrée.
    assert_silent_404(
        h.send(&signing_key(8), &report(2, T0 + 200, json!([])))
            .await,
        "autre clé",
    );
    // Sans signature.
    let request = Request::post("/r/v1/report")
        .header(HEADER_SITE, "site-a")
        .body(Body::from(body.clone()))
        .expect("requête");
    assert_silent_404(h.post(request).await, "sans signature");
    // Route ou méthode inconnues.
    let request = Request::put("/r/v1/report")
        .body(Body::from(body.clone()))
        .expect("requête");
    assert_silent_404(h.post(request).await, "PUT");
    let request = Request::post("/r/v2/report")
        .body(Body::from(body))
        .expect("requête");
    assert_silent_404(h.post(request).await, "route inconnue");

    assert_eq!(h.agent(), before);
    assert_eq!(h.store().last_facts("site-a").expect("facts"), facts_before);
    assert_eq!(h.open_keys(), ["site-a/agent:critical-file/display_errors"]);
}

#[tokio::test]
async fn after_a_rotation_the_old_key_is_refused() {
    let old = signing_key(7);
    let new = signing_key(9);
    let h = Harness::new(&old);
    h.set_now(T0 + 60);
    assert_eq!(
        h.send(&old, &report(5, T0 + 60, json!([]))).await.0,
        StatusCode::NO_CONTENT
    );

    h.set_now(T0 + 300);
    h.store()
        .rotate_key("site-a", &new.verifying_key().to_bytes(), T0 + 300)
        .expect("rotation");
    assert_silent_404(
        h.send(&old, &report(6, T0 + 300, json!([]))).await,
        "ancienne clé",
    );
    // La séquence repart pour le nouvel agent.
    assert_eq!(
        h.send(&new, &report(1, T0 + 300, json!([]))).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(h.agent().last_seq, 1);
}

#[tokio::test]
async fn a_silent_agent_opens_a_heartbeat_incident_that_its_next_report_closes() {
    let key = signing_key(7);
    let h = Harness::new(&key);
    h.set_now(T0 + 60);
    assert_eq!(
        h.send(&key, &report(1, T0 + 60, json!([]))).await.0,
        StatusCode::NO_CONTENT
    );

    // 900 s exactement : pas encore un silence.
    h.set_now(T0 + 60 + 900);
    assert_eq!(h.tick().emails_sent, 0);
    assert!(h.open_keys().is_empty());

    h.set_now(T0 + 60 + 901);
    assert_eq!(h.tick().emails_sent, 1);
    assert_eq!(h.open_keys(), ["site-a/heartbeat/silent"]);
    let sent = h.mail.take();
    assert!(
        sent[0].body.contains("aucun rapport valide"),
        "{}",
        sent[0].body
    );

    h.set_now(T0 + 1_000);
    assert_eq!(
        h.send(&key, &report(2, T0 + 1_000, json!([]))).await.0,
        StatusCode::NO_CONTENT
    );
    assert!(h.open_keys().is_empty());
    assert_eq!(h.tick().emails_sent, 1);
    assert!(h.mail.take()[0].subject.contains("rétabli"));
}

#[tokio::test]
async fn a_key_without_any_report_falls_silent_after_its_registration() {
    let key = signing_key(7);
    let h = Harness::new(&key);
    h.set_now(T0 + 901);
    assert_eq!(h.tick().emails_sent, 1);
    let sent = h.mail.take();
    assert!(
        sent[0].body.contains("depuis l'enregistrement de sa clé"),
        "{}",
        sent[0].body
    );
}

#[test]
fn a_refusal_never_quotes_the_body() {
    let key = signing_key(7);
    let h = Harness::new(&key);
    let secret = "SECRET-dans-le-corps";
    let mut value = report(1, T0, json!([]));
    value[secret] = json!(secret);
    value["findings"] = json!([{
        "check": "critical-file", "severity": secret, "key": secret, "detail": secret
    }]);
    let body = serde_json::to_vec(&value).expect("json");
    let signature = STANDARD.encode(key.sign(&body).to_bytes());
    let refusal = ingest::ingest(
        &mut h.store(),
        &h.config.sites,
        Some("site-a"),
        Some(&signature),
        &body,
        T0,
    )
    .expect_err("schéma refusé");
    assert!(matches!(refusal.reason, Reason::Schema(_)), "{refusal:?}");
    let line = refusal.to_string();
    assert!(line.starts_with("rapport refusé (site site-a)"), "{line}");
    assert!(!line.contains(secret), "{line}");
}

#[test]
fn a_site_without_a_key_is_unknown() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = Store::open(&dir.path().join("vigie.db")).expect("base");
    let refusal =
        ingest::ingest(&mut store, &[site()], Some("site-a"), None, b"{}", T0).expect_err("refusé");
    assert_eq!(refusal.reason, Reason::UnknownSite);
}

#[tokio::test]
async fn a_report_without_a_database_is_a_silent_404_and_creates_nothing() {
    let key = signing_key(7);
    let dir = tempfile::tempdir().expect("tempdir");
    let config = config(dir.path());
    let body = serde_json::to_vec(&report(1, T0, json!([]))).expect("json");
    let response = serve::router_with_clock(config.clone(), Arc::new(FakeClock::new(T0)))
        .oneshot(signed("site-a", &key, body))
        .await
        .expect("réponse");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = response.into_body().collect().await.expect("corps");
    assert!(body.to_bytes().is_empty());
    assert!(!config.database.exists());
}

fn hex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2), "hex de longueur impaire");
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn rfc8032_vectors_verify_strictly() {
    let vectors: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/rfc8032.json")).expect("vecteurs");
    assert_eq!(vectors.len(), 4);
    for v in vectors {
        let name = v["name"].as_str().expect("nom");
        let field = |k: &str| hex(v[k].as_str().expect(k));
        let secret: [u8; 32] = field("secret_key").try_into().expect("32 octets");
        let public: [u8; 32] = field("public_key").try_into().expect("32 octets");
        let signature: [u8; 64] = field("signature").try_into().expect("64 octets");
        let message = field("message");

        let key = SigningKey::from_bytes(&secret);
        assert_eq!(key.verifying_key().to_bytes(), public, "{name}");
        assert_eq!(key.sign(&message).to_bytes(), signature, "{name}");
        let public = VerifyingKey::from_bytes(&public).expect(name);
        let signature = Signature::from_bytes(&signature);
        public.verify_strict(&message, &signature).expect(name);

        let mut altered = message.clone();
        altered.push(0);
        assert!(
            public.verify_strict(&altered, &signature).is_err(),
            "{name}"
        );
    }
}
