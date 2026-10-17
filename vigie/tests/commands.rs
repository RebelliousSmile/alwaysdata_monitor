//! Canal de commandes `/r/v1/commands` (`docs/protocole-commandes.md`), sur
//! le routeur de `serve`, une horloge fixe et une configuration relue depuis
//! un fichier à chaque retrait.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vigie::capability::CommandKind;
use vigie::clock::{Clock, FakeClock};
use vigie::command::audit::{self, Entry};
use vigie::command::key::{self, DOMAIN_COMMANDS, DOMAIN_PULL, DOMAIN_ROTATE};
use vigie::command::{COMMAND_TTL, State, uuid_v7};
use vigie::config::{self, Config, Runtime};
use vigie::serve;
use vigie::store::Store;

const T0: i64 = 1_800_000_000;
const AGENT_SEED: [u8; 32] = [21; 32];

struct Veilleur {
    dir: tempfile::TempDir,
    clock: Arc<FakeClock>,
    seq: std::cell::Cell<i64>,
}

struct Reply {
    status: StatusCode,
    timestamp: Option<String>,
    signature: Option<String>,
    body: Vec<u8>,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("json")
    }
}

fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir
}

fn config_text(dir: &Path, sites: &str, commands: bool) -> String {
    let commands = if commands {
        format!(
            "[commands]\nkey_file = '{}'\naudit_key_file = '{}'\n",
            dir.join("commands.key").display(),
            dir.join("audit.key").display()
        )
    } else {
        String::new()
    };
    format!(
        "database = '{}'\n{commands}[alerts]\nto = \"alertes@example.org\"\nfrom = \"vigie@example.org\"\nsmtp_host = \"smtp.example.org\"\npassword_file = '{}'\n{sites}",
        dir.join("vigie.db").display(),
        dir.join("smtp-password").display()
    )
}

const SITES: &str = "[[sites]]\nid = \"site-a\"\nurl = \"https://site-a.example.org/\"\nkind = \"wordpress\"\n\n[[sites]]\nid = \"site-b\"\nurl = \"https://site-b.example.org/\"\nruntime = \"php\"\n";

impl Veilleur {
    fn new() -> Self {
        let dir = private_dir();
        key::create(&dir.path().join("commands.key")).expect("clé de commandes");
        key::create(&dir.path().join("audit.key")).expect("clé d'audit");
        let v = Self {
            dir,
            clock: Arc::new(FakeClock::new(T0)),
            seq: std::cell::Cell::new(0),
        };
        v.write_config(SITES, true);
        let mut store = Store::open(&v.db()).expect("base");
        store
            .add_key("site-a", &agent().verifying_key().to_bytes(), T0)
            .unwrap();
        store
            .add_key(
                "site-b",
                &SigningKey::from_bytes(&[22; 32]).verifying_key().to_bytes(),
                T0,
            )
            .unwrap();
        store
            .set_commands_enabled("site-a", true, T0, &v.audit_key())
            .unwrap();
        v
    }

    fn db(&self) -> PathBuf {
        self.dir.path().join("vigie.db")
    }

    fn config_path(&self) -> PathBuf {
        self.dir.path().join("config.toml")
    }

    fn write_config(&self, sites: &str, commands: bool) {
        std::fs::write(
            self.config_path(),
            config_text(self.dir.path(), sites, commands),
        )
        .unwrap();
    }

    fn config(&self) -> Config {
        config::load(&self.config_path()).expect("configuration")
    }

    fn audit_key(&self) -> SigningKey {
        key::load(&self.dir.path().join("audit.key")).unwrap()
    }

    fn command_public(&self) -> ed25519_dalek::VerifyingKey {
        key::load(&self.dir.path().join("commands.key"))
            .unwrap()
            .verifying_key()
    }

    fn store(&self) -> Store {
        Store::open(&self.db()).unwrap()
    }

    fn enqueue(&self, kind: CommandKind) -> String {
        let id = uuid_v7(self.clock.unix_ms()).unwrap();
        let typology = config::typology_fingerprint(&self.config());
        self.store()
            .enqueue_command(
                "site-a",
                kind,
                Runtime::Php,
                "{}",
                &typology,
                &id,
                self.clock.unix(),
                false,
                &self.audit_key(),
            )
            .unwrap()
            .expect("en file");
        id
    }

    fn next_seq(&self) -> i64 {
        self.seq.set(self.seq.get() + 1);
        self.seq.get()
    }

    fn body(&self, site: &str, result: Option<Value>) -> Value {
        let mut body = json!({
            "v": 1, "type": "pull", "site": site, "seq": self.next_seq(),
            "sent_at": self.clock.unix(), "nonce": "Tm9uY2VEZVRlc3RBMTIzNDU2", "agent": "agent-php/0.2.0"
        });
        if let Some(result) = result {
            body["result"] = result;
        }
        body
    }

    async fn send_raw(&self, site: &str, body: Vec<u8>, signature: String) -> Reply {
        let router = serve::router_with(
            self.config(),
            Arc::clone(&self.clock) as Arc<dyn Clock>,
            Some(self.config_path()),
        );
        let request = Request::post("/r/v1/commands")
            .header("x-vigie-site", site)
            .header("x-vigie-signature", signature)
            .body(Body::from(body))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        let (status, timestamp, signature) = (
            response.status(),
            header("x-vigie-timestamp"),
            header("x-vigie-signature"),
        );
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        Reply {
            status,
            timestamp,
            signature,
            body,
        }
    }

    /// Retrait de l'agent du site A, signé comme il se doit.
    async fn pull(&self, result: Option<Value>) -> Reply {
        let body = serde_json::to_vec(&self.body("site-a", result)).unwrap();
        let signature = key::sign(&agent(), DOMAIN_PULL, &[&body]);
        self.send_raw("site-a", body, signature).await
    }

    fn assert_signed(&self, reply: &Reply) {
        let ts = reply.timestamp.as_deref().expect("X-Vigie-Timestamp");
        let sig = reply.signature.as_deref().expect("X-Vigie-Signature");
        assert!(key::verify(
            &self.command_public(),
            DOMAIN_COMMANDS,
            &[ts.as_bytes(), b"\n", &reply.body],
            sig
        ));
        assert_eq!(reply.json()["server_time"].to_string(), ts);
    }

    fn events(&self) -> Vec<String> {
        self.store()
            .audit_records("site-a")
            .unwrap()
            .iter()
            .map(|r| serde_json::from_str::<Entry>(&r.entry).unwrap().event)
            .collect()
    }

    fn state(&self, id: &str) -> State {
        self.store().command(id).unwrap().unwrap().state
    }

    fn advance(&self, seconds: i64) {
        self.clock.advance(seconds);
    }
}

fn agent() -> SigningKey {
    SigningKey::from_bytes(&AGENT_SEED)
}

fn result(id: &str, status: &str) -> Value {
    json!({"command_id": id, "status": status, "detail": "pong"})
}

#[tokio::test]
async fn a_command_is_served_signed_then_acknowledged_once() {
    let v = Veilleur::new();
    let id = v.enqueue(CommandKind::Ping);

    let reply = v.pull(None).await;
    assert_eq!(reply.status, StatusCode::OK);
    v.assert_signed(&reply);
    let json = reply.json();
    assert_eq!(json["acked"], Value::Null);
    let command = &json["command"];
    assert_eq!(command["id"], id);
    assert_eq!(command["site"], "site-a");
    assert_eq!(command["v"], 1);
    assert_eq!(command["seq"], 1);
    assert_eq!(command["name"], "ping");
    assert_eq!(command["runtime"], "php");
    assert_eq!(command["params"], json!({}));
    assert_eq!(command["expires_at"], T0 + COMMAND_TTL);
    assert_eq!(v.state(&id), State::Served);

    // Re-servie à l'identique tant qu'aucun résultat n'arrive.
    v.advance(30);
    assert_eq!(v.pull(None).await.json()["command"], *command);

    v.advance(30);
    let reply = v.pull(Some(result(&id, "ok"))).await;
    v.assert_signed(&reply);
    assert_eq!(reply.json()["acked"], id);
    assert_eq!(reply.json()["accepted"], true);
    assert_eq!(reply.json()["command"], Value::Null);
    assert_eq!(v.state(&id), State::Done);

    // Accusé perdu : le même résultat revient, sans nouvelle entrée d'audit.
    let before = v.events();
    v.advance(30);
    let reply = v.pull(Some(result(&id, "ok"))).await;
    assert_eq!(
        (
            reply.json()["acked"].clone(),
            reply.json()["accepted"].clone()
        ),
        (json!(id), json!(true))
    );
    assert_eq!(v.events(), before);
    assert_eq!(before, ["enabled", "created", "served", "result"]);
    audit::verify(
        "site-a",
        &v.store().audit_records("site-a").unwrap(),
        &v.audit_key().verifying_key(),
        Some(&v.store().audit_head("site-a").unwrap()),
    )
    .unwrap();
}

#[tokio::test]
async fn foreign_late_or_unknown_results_are_acknowledged_but_not_accepted() {
    let v = Veilleur::new();
    // Inconnue.
    let ghost = uuid_v7(0).unwrap();
    let reply = v.pull(Some(result(&ghost, "ok"))).await;
    assert_eq!(
        (
            reply.json()["acked"].clone(),
            reply.json()["accepted"].clone()
        ),
        (json!(ghost), json!(false))
    );
    // Annulée.
    let id = v.enqueue(CommandKind::Ping);
    v.store()
        .cancel_command("site-a", T0, &v.audit_key())
        .unwrap();
    v.advance(30);
    let reply = v.pull(Some(result(&id, "ok"))).await;
    assert_eq!(reply.json()["accepted"], false);
    assert_eq!(v.state(&id), State::Cancelled);
    assert!(v.events().contains(&"result-late".to_owned()));
    // Servie sans résultat 24 h : unknown, puis résultat tardif accepté.
    let id = v.enqueue(CommandKind::Ping);
    v.advance(30);
    v.pull(None).await;
    v.advance(COMMAND_TTL);
    v.store()
        .expire_commands(v.clock.unix(), &v.audit_key())
        .unwrap();
    assert_eq!(v.state(&id), State::Unknown);
    let reply = v.pull(Some(result(&id, "ok"))).await;
    assert_eq!(reply.json()["accepted"], true);
    assert_eq!(v.state(&id), State::Done);
}

#[tokio::test]
async fn replays_forgeries_and_wrong_routes_get_the_silent_404() {
    let v = Veilleur::new();
    v.enqueue(CommandKind::Ping);
    let body = serde_json::to_vec(&v.body("site-a", None)).unwrap();
    let signed = key::sign(&agent(), DOMAIN_PULL, &[&body]);
    assert_eq!(
        v.send_raw("site-a", body.clone(), signed.clone())
            .await
            .status,
        StatusCode::OK
    );
    // Rejeu, même 30 s plus tard.
    v.advance(30);
    let replay = v.send_raw("site-a", body.clone(), signed).await;
    assert_eq!(replay.status, StatusCode::NOT_FOUND);
    assert!(replay.body.is_empty());

    // Signature sans préfixe de domaine (comme un rapport).
    let body = serde_json::to_vec(&v.body("site-a", None)).unwrap();
    let raw = STANDARD.encode(agent().sign(&body).to_bytes());
    assert_eq!(
        v.send_raw("site-a", body, raw).await.status,
        StatusCode::NOT_FOUND
    );

    // Clé de A avec X-Vigie-Site B.
    let body = serde_json::to_vec(&v.body("site-b", None)).unwrap();
    let signed = key::sign(&agent(), DOMAIN_PULL, &[&body]);
    assert_eq!(
        v.send_raw("site-b", body, signed).await.status,
        StatusCode::NOT_FOUND
    );

    // Champ en trop (attaquant installé sur le site qui tente de pousser une commande).
    let mut forged = v.body("site-a", None);
    forged["command"] = json!({"name": "shell", "params": {"cmd": "id"}});
    let body = serde_json::to_vec(&forged).unwrap();
    let signed = key::sign(&agent(), DOMAIN_PULL, &[&body]);
    assert_eq!(
        v.send_raw("site-a", body, signed).await.status,
        StatusCode::NOT_FOUND
    );

    // Horloge décalée.
    let mut late = v.body("site-a", None);
    late["sent_at"] = json!(T0 - 1_000);
    let body = serde_json::to_vec(&late).unwrap();
    let signed = key::sign(&agent(), DOMAIN_PULL, &[&body]);
    assert_eq!(
        v.send_raw("site-a", body, signed).await.status,
        StatusCode::NOT_FOUND
    );

    // Aucun chemin ne crée de commande : seule celle de l'exploitant existe.
    assert_eq!(v.store().commands("site-a").unwrap().len(), 1);
}

#[tokio::test]
async fn the_channel_is_closed_by_default() {
    let v = Veilleur::new();
    let id = v.enqueue(CommandKind::Ping);
    // Site désactivé : réponse signée, sans commande.
    v.store()
        .set_commands_enabled("site-a", false, T0, &v.audit_key())
        .unwrap();
    let reply = v.pull(None).await;
    assert_eq!(reply.status, StatusCode::OK);
    v.assert_signed(&reply);
    assert_eq!(reply.json()["command"], Value::Null);
    assert_eq!(v.state(&id), State::Cancelled);
    // Sans [commands] : 404.
    v.write_config(SITES, false);
    v.advance(30);
    assert_eq!(v.pull(None).await.status, StatusCode::NOT_FOUND);
    // Site retiré de la configuration, sans relancer serve : 404.
    v.write_config(
        "[[sites]]\nid = \"site-b\"\nurl = \"https://site-b.example.org/\"\n",
        true,
    );
    v.advance(30);
    assert_eq!(v.pull(None).await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delivery_rechecks_the_configuration_and_the_expiry() {
    let v = Veilleur::new();
    let id = v.enqueue(CommandKind::Ping);
    // Runtime retiré : site-a devient generic sans runtime, serve non relancé.
    v.write_config(
        "[[sites]]\nid = \"site-a\"\nurl = \"https://site-a.example.org/\"\n",
        true,
    );
    let reply = v.pull(None).await;
    assert_eq!(reply.json()["command"], Value::Null);
    assert_eq!(v.state(&id), State::Refused);

    // Commande expirée que tick n'a pas encore vue : jamais servie.
    v.write_config(SITES, true);
    let id = v.enqueue(CommandKind::Ping);
    v.advance(COMMAND_TTL + 1);
    assert_eq!(v.pull(None).await.json()["command"], Value::Null);
    assert_eq!(v.state(&id), State::Pending);
}

#[tokio::test]
async fn an_unreadable_audit_key_means_nothing_is_acknowledged() {
    let v = Veilleur::new();
    let id = v.enqueue(CommandKind::Ping);
    v.pull(None).await;
    std::fs::remove_file(v.dir.path().join("audit.key")).unwrap();
    v.advance(30);
    let reply = v.pull(Some(result(&id, "ok"))).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(v.state(&id), State::Served);
}

#[tokio::test]
async fn pulls_are_rate_limited() {
    let v = Veilleur::new();
    assert_eq!(v.pull(None).await.status, StatusCode::OK);
    v.advance(29);
    assert_eq!(v.pull(None).await.status, StatusCode::NOT_FOUND);
    v.advance(1);
    assert_eq!(v.pull(None).await.status, StatusCode::OK);
}

fn rotation_result(id: &str, new: &SigningKey, prover: &SigningKey) -> Value {
    let new_pub = STANDARD.encode(new.verifying_key().to_bytes());
    let proof = key::sign(
        prover,
        DOMAIN_ROTATE,
        &[b"site-a", b"\n", id.as_bytes(), b"\n", new_pub.as_bytes()],
    );
    json!({"command_id": id, "status": "ok", "detail": "nouvelle clé", "data": {"new_pubkey": new_pub, "proof": proof}})
}

#[tokio::test]
async fn rotate_key_needs_a_proof_and_switches_atomically() {
    let v = Veilleur::new();
    let new = SigningKey::from_bytes(&[33; 32]);

    // Preuve signée par une autre clé que celle annoncée.
    let id = v.enqueue(CommandKind::RotateKey);
    v.pull(None).await;
    v.advance(30);
    let wrong = rotation_result(&id, &new, &SigningKey::from_bytes(&[34; 32]));
    let reply = v.pull(Some(wrong)).await;
    assert_eq!(reply.json()["accepted"], false);
    assert_eq!(v.state(&id), State::Failed);
    assert_eq!(
        v.store().agent("site-a").unwrap().unwrap().pubkey,
        agent().verifying_key().to_bytes()
    );

    // Clé déjà celle du site B.
    let id = v.enqueue(CommandKind::RotateKey);
    v.advance(30);
    v.pull(None).await;
    v.advance(30);
    let b = SigningKey::from_bytes(&[22; 32]);
    assert_eq!(
        v.pull(Some(rotation_result(&id, &b, &b))).await.json()["accepted"],
        false
    );

    // Bonne preuve : bascule, séquences remises à zéro (logs et inventaire
    // compris).
    rusqlite::Connection::open(&v.config().database)
        .unwrap()
        .execute(
            "UPDATE site_keys SET last_logs_seq = 7, last_inventory_seq = 9 WHERE site = 'site-a'",
            [],
        )
        .unwrap();
    let id = v.enqueue(CommandKind::RotateKey);
    v.advance(30);
    v.pull(None).await;
    v.advance(30);
    let reply = v.pull(Some(rotation_result(&id, &new, &new))).await;
    assert_eq!(
        (
            reply.json()["acked"].clone(),
            reply.json()["accepted"].clone()
        ),
        (json!(id), json!(true))
    );
    assert_eq!(v.state(&id), State::Done);
    let store = v.store();
    assert_eq!(
        store.agent("site-a").unwrap().unwrap().pubkey,
        new.verifying_key().to_bytes()
    );
    let seqs: (i64, i64) = rusqlite::Connection::open(&v.config().database)
        .unwrap()
        .query_row(
            "SELECT last_logs_seq, last_inventory_seq FROM site_keys WHERE site = 'site-a'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(seqs, (0, 0));
    // L'ancienne clé ne retire plus rien.
    v.advance(30);
    assert_eq!(v.pull(None).await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_late_proof_never_replaces_a_key_set_by_the_operator() {
    let v = Veilleur::new();
    let id = v.enqueue(CommandKind::RotateKey);
    v.pull(None).await;
    // L'exploitant change la clé hors canal (comme `vigie site rotate-key`).
    let operator = SigningKey::from_bytes(&[44; 32]);
    let mut store = v.store();
    store
        .reset_commands("site-a", T0 + 10, Some(&v.audit_key()), "site rotate-key")
        .unwrap();
    store
        .rotate_key("site-a", &operator.verifying_key().to_bytes(), T0 + 10)
        .unwrap();
    // La preuve tardive arrive, signée par l'ancienne clé : refusée.
    v.advance(30);
    let new = SigningKey::from_bytes(&[33; 32]);
    let reply = v.pull(Some(rotation_result(&id, &new, &new))).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(
        v.store().agent("site-a").unwrap().unwrap().pubkey,
        operator.verifying_key().to_bytes()
    );
    assert_eq!(v.state(&id), State::Cancelled);
}

#[tokio::test]
async fn a_late_rotation_on_an_unknown_command_is_refused() {
    let v = Veilleur::new();
    let id = v.enqueue(CommandKind::RotateKey);
    v.pull(None).await;
    v.advance(COMMAND_TTL);
    v.store()
        .expire_commands(v.clock.unix(), &v.audit_key())
        .unwrap();
    assert_eq!(v.state(&id), State::Unknown);
    let new = SigningKey::from_bytes(&[33; 32]);
    let reply = v.pull(Some(rotation_result(&id, &new, &new))).await;
    assert_eq!(reply.json()["accepted"], false);
    assert_eq!(v.state(&id), State::Failed);
    assert_eq!(
        v.store().agent("site-a").unwrap().unwrap().pubkey,
        agent().verifying_key().to_bytes()
    );
}

#[test]
fn tick_expires_commands_and_sends_each_audit_head_once() {
    use std::time::Duration;
    use vigie::alert::MemoryNotifier;
    use vigie::tick::{self, Options};

    let v = Veilleur::new();
    let id = v.enqueue(CommandKind::Ping);
    let options = Options {
        check_budget: Duration::ZERO,
        ..Options::default()
    };
    let mail = MemoryNotifier::new();
    tick::run_with(&v.config(), T0, &options, &mail).expect("tick");
    let sent = mail.take();
    let head = v.store().audit_head("site-a").unwrap();
    let anchor: Vec<_> = sent
        .iter()
        .filter(|e| e.subject.contains("journal des commandes"))
        .collect();
    assert_eq!(anchor.len(), 1, "{sent:?}");
    assert!(anchor[0].body.contains(&head));
    // Rien de neuf : rien d'envoyé.
    tick::run_with(&v.config(), T0 + 60, &options, &mail).expect("tick");
    assert!(
        mail.take()
            .iter()
            .all(|e| !e.subject.contains("journal des commandes"))
    );
    // 24 h plus tard, la commande jamais retirée expire et la nouvelle tête part.
    tick::run_with(&v.config(), T0 + COMMAND_TTL, &options, &mail).expect("tick");
    assert_eq!(v.state(&id), State::Expired);
    let sent = mail.take();
    let new_head = v.store().audit_head("site-a").unwrap();
    assert_ne!(new_head, head);
    assert!(sent.iter().any(|e| e.body.contains(&new_head)));

    // Clé d'audit illisible : tick passe quand même, rien n'expire.
    let id = v.enqueue(CommandKind::Ping);
    std::fs::remove_file(v.dir.path().join("audit.key")).unwrap();
    tick::run_with(&v.config(), T0 + 3 * COMMAND_TTL, &options, &mail).expect("tick sans clé");
    assert_eq!(v.state(&id), State::Pending);
}

// --- htaccess-* (#13) -------------------------------------------------------

const PREV: &str = "33bf0cf98fa40b5f4c44e053816b75487245c5fc01e66dd65470e2e70cbee0d8";
const NEW: &str = "8978bc0aa6aece0fc74de901712dd160c804917cda1ade8afb59f29f526ff94a";
const OTHER: &str = "1111111111111111111111111111111111111111111111111111111111111111";

impl Veilleur {
    fn enqueue_params(&self, kind: CommandKind, params: &Value) -> String {
        let id = uuid_v7(self.clock.unix_ms()).unwrap();
        let typology = config::typology_fingerprint(&self.config());
        self.store()
            .enqueue_command(
                "site-a",
                kind,
                Runtime::Php,
                &params.to_string(),
                &typology,
                &id,
                self.clock.unix(),
                false,
                &self.audit_key(),
            )
            .unwrap()
            .expect("en file");
        id
    }

    /// Rapport de l'agent du site A portant cette empreinte du .htaccess.
    fn report(&self, htaccess: &str) {
        self.advance(60);
        let files = json!({".htaccess": htaccess}).to_string();
        let pubkey = agent().verifying_key().to_bytes();
        let report = vigie::store::AcceptedReport {
            site: "site-a",
            pubkey: &pubkey,
            seq: self.clock.unix(),
            agent: "vigie-agent-php/0.4.0",
            facts: "{}",
            files: &files,
            findings: &[],
            dropped: 0,
        };
        let outcome = self
            .store()
            .accept_report(&report, self.clock.unix(), &|_, _| true)
            .unwrap();
        assert_eq!(outcome, vigie::store::ReportOutcome::Accepted);
    }

    fn integrity(&self) -> Vec<String> {
        self.store()
            .open_incidents()
            .unwrap()
            .into_iter()
            .filter(|i| i.check_name == "agent:integrity")
            .map(|i| i.key)
            .collect()
    }

    fn baseline_htaccess(&self) -> Value {
        let (files, _) = self.store().baseline("site-a").unwrap().unwrap();
        serde_json::from_str::<Value>(&files).unwrap()[".htaccess"].clone()
    }

    async fn pull_from(&self, peer: &str, forwarded: Option<&str>) -> Reply {
        let body = serde_json::to_vec(&self.body("site-a", None)).unwrap();
        let signature = key::sign(&agent(), DOMAIN_PULL, &[&body]);
        let router = serve::router_with(
            self.config(),
            Arc::clone(&self.clock) as Arc<dyn Clock>,
            Some(self.config_path()),
        );
        let mut request = Request::post("/r/v1/commands")
            .header("x-vigie-site", "site-a")
            .header("x-vigie-signature", signature);
        if let Some(forwarded) = forwarded {
            request = request.header("x-forwarded-for", forwarded);
        }
        let mut request = request.body(Body::from(body)).unwrap();
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo::<std::net::SocketAddr>(
                peer.parse().unwrap(),
            ));
        let response = router.oneshot(request).await.unwrap();
        Reply {
            status: response.status(),
            timestamp: None,
            signature: None,
            body: response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        }
    }
}

fn htaccess_result(id: &str, status: &str, current: &str) -> Value {
    json!({"command_id": id, "status": status, "detail": "d", "data": {"current_sha256": current}})
}

#[tokio::test]
async fn an_applied_htaccess_does_not_open_the_integrity_incident() {
    let v = Veilleur::new();
    v.report(PREV);
    let id = v.enqueue_params(
        CommandKind::HtaccessApply,
        &json!({"block": "# BEGIN vigie\n", "previous_sha256": PREV, "new_sha256": NEW}),
    );
    let served = v.pull(None).await;
    assert_eq!(served.json()["command"]["name"], "htaccess-apply");
    assert_eq!(served.json()["command"]["params"]["new_sha256"], NEW);
    // Le rapport part avant le retrait qui porte le résultat.
    v.report(NEW);
    assert!(v.integrity().is_empty(), "{:?}", v.integrity());
    assert_eq!(
        v.baseline_htaccess(),
        PREV,
        "la référence attend le résultat"
    );
    // Une empreinte hors des attendues l'ouvre.
    v.report(OTHER);
    assert_eq!(v.integrity(), ["site-a/agent:integrity/modified:.htaccess"]);
    v.advance(30);
    let reply = v.pull(Some(htaccess_result(&id, "ok", NEW))).await;
    assert_eq!(reply.json()["accepted"], true);
    assert_eq!(v.state(&id), State::Done);
    assert_eq!(
        v.baseline_htaccess(),
        NEW,
        "la référence suit current_sha256"
    );
    v.report(NEW);
    assert!(v.integrity().is_empty());
}

#[tokio::test]
async fn the_baseline_follows_only_an_expected_hash_and_unknown_still_admits() {
    let v = Veilleur::new();
    v.report(PREV);
    let id = v.enqueue_params(
        CommandKind::HtaccessApply,
        &json!({"block": "# BEGIN vigie\n", "previous_sha256": PREV, "new_sha256": NEW}),
    );
    v.pull(None).await;
    // Sans résultat en 24 h : unknown, les empreintes restent admises
    // (reprise après interruption).
    v.advance(COMMAND_TTL);
    v.store()
        .expire_commands(v.clock.unix(), &v.audit_key())
        .unwrap();
    assert_eq!(v.state(&id), State::Unknown);
    v.report(NEW);
    assert!(v.integrity().is_empty());
    // Résultat tardif « modifié pendant l'application » : la référence ne
    // suit pas une empreinte tierce.
    v.advance(30);
    v.pull(Some(htaccess_result(&id, "failed", OTHER))).await;
    assert_eq!(v.state(&id), State::Failed);
    assert_eq!(v.baseline_htaccess(), PREV);
    v.report(NEW);
    assert_eq!(v.integrity(), ["site-a/agent:integrity/modified:.htaccess"]);
}

#[tokio::test]
async fn a_rollback_admits_the_previous_hash_and_a_compute_only_admits_nothing() {
    let v = Veilleur::new();
    v.report(NEW);
    // Calcul seul : rien n'est écrit, rien n'est admis.
    let compute = v.enqueue_params(
        CommandKind::HtaccessApply,
        &json!({"block": "# BEGIN vigie\n", "previous_sha256": NEW, "new_sha256": null}),
    );
    v.pull(None).await;
    v.report(OTHER);
    assert_eq!(v.integrity().len(), 1);
    v.report(NEW);
    assert!(v.integrity().is_empty());
    v.advance(30);
    let done = json!({"command_id": compute, "status": "ok", "detail": "calcul seul",
        "data": {"current_sha256": NEW, "new_sha256": OTHER}});
    v.pull(Some(done)).await;
    assert_eq!(v.state(&compute), State::Done);
    assert_eq!(v.baseline_htaccess(), NEW);

    let id = v.enqueue_params(
        CommandKind::HtaccessRollback,
        &json!({"expected_current_sha256": NEW, "prev_sha256": PREV}),
    );
    v.advance(30);
    v.pull(None).await;
    v.report(PREV);
    assert!(v.integrity().is_empty());
    v.advance(30);
    v.pull(Some(htaccess_result(&id, "ok", PREV))).await;
    assert_eq!(v.baseline_htaccess(), PREV);
}

#[tokio::test]
async fn a_result_with_a_malformed_hash_is_refused_by_the_schema() {
    let v = Veilleur::new();
    let id = v.enqueue_params(
        CommandKind::HtaccessRollback,
        &json!({"expected_current_sha256": NEW, "prev_sha256": PREV}),
    );
    v.pull(None).await;
    v.advance(30);
    let reply = v
        .pull(Some(htaccess_result(&id, "ok", &NEW.to_uppercase())))
        .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(v.state(&id), State::Served);
}

#[tokio::test]
async fn the_source_address_of_signed_pulls_is_recorded() {
    let v = Veilleur::new();
    // Pair distant : son adresse, jamais son X-Forwarded-For.
    let reply = v.pull_from("192.0.2.50:4000", Some("198.51.100.1")).await;
    assert_eq!(reply.status, StatusCode::OK);
    v.advance(30);
    // Proxy local (Caddy) : la dernière adresse de X-Forwarded-For.
    let reply = v
        .pull_from("127.0.0.1:5000", Some("198.51.100.9, 2001:db8::50"))
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    let sources: Vec<String> = v
        .store()
        .agent_sources("site-a", v.clock.unix())
        .unwrap()
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(sources, ["192.0.2.50", "2001:db8::50"]);
    // Oubliée 30 jours après le dernier retrait.
    assert!(
        v.store()
            .agent_sources("site-a", v.clock.unix() + 31 * 86_400)
            .unwrap()
            .is_empty()
    );
}
