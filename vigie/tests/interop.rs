//! Interopérabilité avec l'agent PHP : `fixtures/php-signed-report.json` est
//! un rapport signé par sodium avec une graine fixe
//! (`agent/php/tests/make-interop-fixture.php`). ed25519-dalek doit accepter
//! sa signature, et l'ingestion réelle doit l'accepter tel quel.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use http_body_util::BodyExt;
use serde::Deserialize;
use tower::ServiceExt;

#[path = "support/veilleur.rs"]
mod veilleur;

use vigie::clock::FakeClock;
use vigie::ingest::{HEADER_SIGNATURE, HEADER_SITE};
use vigie::serve;
use vigie::store::Store;

/// `sent_at` du rapport de la fixture.
const SENT_AT: i64 = 1_792_079_580;

#[derive(Deserialize)]
struct Fixture {
    seed_hex: String,
    public_key: String,
    body: String,
    signature: String,
}

fn fixture() -> Fixture {
    let raw = include_str!("fixtures/php-signed-report.json");
    serde_json::from_str(raw).expect("fixture JSON")
}

fn public_key(fixture: &Fixture) -> VerifyingKey {
    let raw = STANDARD.decode(&fixture.public_key).expect("base64");
    VerifyingKey::from_bytes(&raw.try_into().expect("32 octets")).expect("point")
}

fn signature(fixture: &Fixture) -> Signature {
    let raw = STANDARD.decode(&fixture.signature).expect("base64");
    Signature::from_bytes(&raw.try_into().expect("64 octets"))
}

#[test]
fn the_php_key_derives_from_the_seed_like_dalek() {
    let fixture = fixture();
    let seed: Vec<u8> = (0..fixture.seed_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&fixture.seed_hex[i..i + 2], 16).expect("hex"))
        .collect();
    let key = SigningKey::from_bytes(&seed.try_into().expect("graine de 32 octets"));
    assert_eq!(key.verifying_key(), public_key(&fixture));
}

#[test]
fn dalek_verifies_the_sodium_signature_and_only_on_the_exact_bytes() {
    let fixture = fixture();
    let key = public_key(&fixture);
    let signature = signature(&fixture);
    key.verify_strict(fixture.body.as_bytes(), &signature)
        .expect("signature sodium acceptée");

    let mut altered = fixture.body.clone().into_bytes();
    let last = altered.len() - 2;
    altered[last] ^= 1;
    assert!(key.verify_strict(&altered, &signature).is_err());
    let spaced = fixture.body.replacen("{\"v\":1", "{ \"v\":1", 1);
    assert!(key.verify_strict(spaced.as_bytes(), &signature).is_err());
}

#[tokio::test]
async fn the_ingestion_accepts_the_php_report_as_is() {
    let fixture = fixture();
    let dir = tempfile::tempdir().expect("tempdir");
    let database = dir.path().join("vigie.db");
    Store::open(&database)
        .expect("base")
        .add_key("site-a", &public_key(&fixture).to_bytes(), SENT_AT - 600)
        .expect("add_key");

    let router = serve::router_with_clock(
        veilleur::config(database.clone()),
        Arc::new(FakeClock::new(SENT_AT)),
    );
    let request = Request::post("/r/v1/report")
        .header(HEADER_SITE, "site-a")
        .header(HEADER_SIGNATURE, &fixture.signature)
        .body(Body::from(fixture.body.clone()))
        .expect("requête");
    let response = router.oneshot(request).await.expect("réponse");
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("corps")
        .to_bytes();
    assert_eq!(status, StatusCode::NO_CONTENT, "{body:?}");

    let store = Store::open(&database).expect("base");
    let mut keys: Vec<String> = store
        .open_incidents()
        .expect("incidents")
        .into_iter()
        .map(|i| i.key)
        .collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "site-a/agent:must-contain/.htaccess",
            "site-a/agent:uploads-php/wp-content/uploads/2026/10/shell.php",
        ]
    );
    let agent = store.agent("site-a").expect("agent").expect("clé");
    assert_eq!(agent.agent.as_deref(), Some("vigie-agent-php/0.4.0"));
    let facts = store.last_facts("site-a").expect("facts").expect("relevé");
    assert!(facts.contains(r#""wp_version":"6.6.2""#), "{facts}");
    // Le premier rapport pose la référence des empreintes.
    let (baseline, set_at) = store.baseline("site-a").expect("référence").expect("posée");
    assert_eq!(set_at, SENT_AT);
    assert!(baseline.contains(r#"".htaccess":"33bf0cf9"#), "{baseline}");
}
