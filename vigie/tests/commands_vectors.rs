//! Vecteurs d'interopérabilité du canal de commandes, figés en JSON dans
//! `tests/fixtures/commands-vectors.json` et consommés aussi par les tests de
//! l'agent PHP (#6), sans exécuter de PHP ici.
//!
//! Chaque vecteur porte son verdict attendu. Ce fichier en est le
//! vérificateur de référence : il applique, dans l'ordre, les règles qu'un
//! agent doit appliquer à une réponse (`docs/protocole-commandes.md`).
//!
//! `VIGIE_WRITE_VECTORS=1 cargo test --test commands_vectors` régénère le
//! fichier ; sans la variable, le fichier committé doit être identique à ce
//! que le générateur produit.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde_json::{Value, json};

use vigie::command::key::{self, DOMAIN_COMMANDS, DOMAIN_PULL, DOMAIN_ROTATE};

const AGENT_SEED: [u8; 32] = [0x11; 32];
const COMMANDS_SEED: [u8; 32] = [0x22; 32];
const NEW_AGENT_SEED: [u8; 32] = [0x33; 32];
const SITE: &str = "site-a";
const NONCE: &str = "Tm9uY2VEZVRlc3RBMTIzNDU2";
const NOW: i64 = 1_800_000_000;
const ID: &str = "01a1e2f3-0000-7000-8000-000000000001";

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn command(site: &str, expires_at: i64) -> Value {
    json!({
        "v": 1, "site": site, "id": ID, "seq": 3, "name": "ping", "runtime": "php",
        "params": {}, "issued_at": NOW - 60, "expires_at": expires_at
    })
}

fn response(site: &str, nonce: &str, acked: Value, accepted: Value, command: Value) -> String {
    serde_json::to_string(&json!({
        "v": 1, "site": site, "nonce": nonce, "server_time": NOW,
        "acked": acked, "accepted": accepted, "command": command
    }))
    .unwrap()
}

fn signed_response(
    name: &str,
    verdict: &str,
    body: String,
    ts: i64,
    sign_ts: i64,
    domain: &[u8],
) -> Value {
    let key = SigningKey::from_bytes(&COMMANDS_SEED);
    let sign_ts = sign_ts.to_string();
    let signature = key::sign(&key, domain, &[sign_ts.as_bytes(), b"\n", body.as_bytes()]);
    json!({"name": name, "verdict": verdict, "timestamp": ts.to_string(), "body": body, "signature": signature})
}

fn generate() -> Value {
    let agent = SigningKey::from_bytes(&AGENT_SEED);
    let commands = SigningKey::from_bytes(&COMMANDS_SEED);
    let new_agent = SigningKey::from_bytes(&NEW_AGENT_SEED);

    let pull_body = serde_json::to_string(&json!({
        "v": 1, "type": "pull", "site": SITE, "seq": 7, "sent_at": NOW, "nonce": NONCE,
        "agent": "agent-php/0.2.0",
        "result": {"command_id": ID, "status": "ok", "detail": "pong"}
    }))
    .unwrap();
    let pulls = json!([
        {"name": "retrait signé avec le préfixe", "verdict": "valid", "body": pull_body,
         "signature": key::sign(&agent, DOMAIN_PULL, &[pull_body.as_bytes()])},
        {"name": "retrait signé sans préfixe (comme un rapport)", "verdict": "bad-signature", "body": pull_body,
         "signature": b64(&agent.sign(pull_body.as_bytes()).to_bytes())},
    ]);

    let valid = response(
        SITE,
        NONCE,
        Value::Null,
        Value::Null,
        command(SITE, NOW + 86_340),
    );
    let responses = json!([
        signed_response(
            "réponse valide avec commande",
            "valid",
            valid.clone(),
            NOW,
            NOW,
            DOMAIN_COMMANDS
        ),
        signed_response(
            "préfixe de domaine faux",
            "bad-signature",
            valid.clone(),
            NOW,
            NOW,
            b"vigie-audit-v1\n"
        ),
        signed_response(
            "horodatage d'en-tête altéré",
            "bad-signature",
            valid.clone(),
            NOW + 1,
            NOW,
            DOMAIN_COMMANDS
        ),
        signed_response(
            "horodatage différent de server_time",
            "timestamp-mismatch",
            valid.clone(),
            NOW + 5,
            NOW + 5,
            DOMAIN_COMMANDS
        ),
        signed_response(
            "horodatage hors de ±300 s",
            "clock",
            response(SITE, NONCE, Value::Null, Value::Null, Value::Null)
                .replace(&NOW.to_string(), &(NOW - 400).to_string()),
            NOW - 400,
            NOW - 400,
            DOMAIN_COMMANDS
        ),
        signed_response(
            "réponse pour un autre site",
            "site",
            response(
                "site-b",
                NONCE,
                Value::Null,
                Value::Null,
                command("site-b", NOW + 86_340)
            ),
            NOW,
            NOW,
            DOMAIN_COMMANDS
        ),
        signed_response(
            "commande pour un autre site",
            "site",
            response(
                SITE,
                NONCE,
                Value::Null,
                Value::Null,
                command("site-b", NOW + 86_340)
            ),
            NOW,
            NOW,
            DOMAIN_COMMANDS
        ),
        signed_response(
            "commande expirée",
            "expired",
            response(
                SITE,
                NONCE,
                Value::Null,
                Value::Null,
                command(SITE, NOW - 1)
            ),
            NOW,
            NOW,
            DOMAIN_COMMANDS
        ),
        signed_response(
            "nonce différent de celui du retrait",
            "nonce",
            response(
                SITE,
                "QXV0cmVOb25jZUF1dHJlTm9uY2U",
                Value::Null,
                Value::Null,
                Value::Null
            ),
            NOW,
            NOW,
            DOMAIN_COMMANDS
        ),
        signed_response(
            "accusé accepté",
            "valid",
            response(SITE, NONCE, json!(ID), json!(true), Value::Null),
            NOW,
            NOW,
            DOMAIN_COMMANDS
        ),
        signed_response(
            "accusé refusé",
            "valid",
            response(SITE, NONCE, json!(ID), json!(false), Value::Null),
            NOW,
            NOW,
            DOMAIN_COMMANDS
        ),
    ]);

    let new_pub = b64(&new_agent.verifying_key().to_bytes());
    let proof = key::sign(
        &new_agent,
        DOMAIN_ROTATE,
        &[
            SITE.as_bytes(),
            b"\n",
            ID.as_bytes(),
            b"\n",
            new_pub.as_bytes(),
        ],
    );
    let rotation = json!({
        "site": SITE, "command_id": ID, "new_seed": b64(&NEW_AGENT_SEED), "new_pubkey": new_pub, "proof": proof
    });

    json!({
        "comment": "Vecteurs du canal de commandes (docs/protocole-commandes.md). Graines de test seulement, jamais en service.",
        "domains": {
            "pull": "vigie-pull-v1\n", "commands": "vigie-commands-v1\n", "rotate": "vigie-rotate-v1\n"
        },
        "now": NOW,
        "site": SITE,
        "request_nonce": NONCE,
        "agent_seed": b64(&AGENT_SEED),
        "agent_pubkey": b64(&agent.verifying_key().to_bytes()),
        "commands_seed": b64(&COMMANDS_SEED),
        "commands_pubkey": b64(&commands.verifying_key().to_bytes()),
        "pulls": pulls,
        "responses": responses,
        "rotation": rotation,
    })
}

/// Vérificateur de référence d'une réponse, côté agent, dans l'ordre.
fn check_response(v: &Value, public: &VerifyingKey) -> &'static str {
    let ts = v["timestamp"].as_str().unwrap();
    let body = v["body"].as_str().unwrap();
    if !key::verify(
        public,
        DOMAIN_COMMANDS,
        &[ts.as_bytes(), b"\n", body.as_bytes()],
        v["signature"].as_str().unwrap(),
    ) {
        return "bad-signature";
    }
    let json: Value = serde_json::from_str(body).unwrap();
    let ts: i64 = ts.parse().unwrap();
    if json["server_time"].as_i64() != Some(ts) {
        return "timestamp-mismatch";
    }
    if (ts - NOW).abs() > 300 {
        return "clock";
    }
    if json["site"] != SITE || (json["command"].is_object() && json["command"]["site"] != SITE) {
        return "site";
    }
    if json["nonce"] != NONCE {
        return "nonce";
    }
    if json["command"].is_object() && json["command"]["expires_at"].as_i64().unwrap() <= ts {
        return "expired";
    }
    "valid"
}

#[test]
fn the_committed_vectors_match_the_generator_and_their_verdicts() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/commands-vectors.json");
    let generated = serde_json::to_string_pretty(&generate()).unwrap() + "\n";
    if std::env::var_os("VIGIE_WRITE_VECTORS").is_some() {
        std::fs::write(&path, &generated).unwrap();
    }
    let committed = std::fs::read_to_string(&path).expect("commands-vectors.json");
    assert_eq!(
        committed, generated,
        "vecteurs à régénérer (VIGIE_WRITE_VECTORS=1)"
    );

    let vectors: Value = serde_json::from_str(&committed).unwrap();
    let decode = |field: &str| -> [u8; 32] {
        STANDARD
            .decode(vectors[field].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    };
    let commands_public = SigningKey::from_bytes(&decode("commands_seed")).verifying_key();
    assert_eq!(b64(&commands_public.to_bytes()), vectors["commands_pubkey"]);
    for v in vectors["responses"].as_array().unwrap() {
        assert_eq!(
            check_response(v, &commands_public),
            v["verdict"].as_str().unwrap(),
            "{}",
            v["name"]
        );
    }
    let agent_public = SigningKey::from_bytes(&decode("agent_seed")).verifying_key();
    for v in vectors["pulls"].as_array().unwrap() {
        let ok = key::verify(
            &agent_public,
            DOMAIN_PULL,
            &[v["body"].as_str().unwrap().as_bytes()],
            v["signature"].as_str().unwrap(),
        );
        assert_eq!(ok, v["verdict"] == "valid", "{}", v["name"]);
    }
    let r = &vectors["rotation"];
    let new_public: [u8; 32] = STANDARD
        .decode(r["new_pubkey"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let new_public = VerifyingKey::from_bytes(&new_public).unwrap();
    assert!(key::verify(
        &new_public,
        DOMAIN_ROTATE,
        &[
            SITE.as_bytes(),
            b"\n",
            r["command_id"].as_str().unwrap().as_bytes(),
            b"\n",
            r["new_pubkey"].as_str().unwrap().as_bytes()
        ],
        r["proof"].as_str().unwrap()
    ));
}
