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

    // Bonne preuve : bascule, séquences remises à zéro.
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
