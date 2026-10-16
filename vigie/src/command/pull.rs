//! `POST /r/v1/commands` : l'agent retire sa commande et rend le résultat de
//! la précédente (`docs/protocole-commandes.md`).
//!
//! Vérifications, dans l'ordre, arrêt au premier échec (404 commun, raison au
//! journal) : site connu de la configuration relue et doté d'une clé ;
//! signature de l'agent sur `vigie-pull-v1\n` + octets du corps ; schéma ;
//! horloge ±300 s ; `seq` de retrait strictement croissant ; débit.
//!
//! Puis, dans une seule transaction IMMEDIATE : le résultat éventuel est
//! enregistré et toujours accusé (`acked`, avec `accepted`), la commande à
//! servir est choisie et revérifiée contre la configuration relue, l'audit
//! est écrit. La réponse n'est signée qu'après la validation de la
//! transaction : rien n'est accusé sans être tracé.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use super::key::{self, DOMAIN_COMMANDS, DOMAIN_PULL, DOMAIN_ROTATE};
use super::store::{COLUMNS, Command, event, from_row, transition};
use super::{CommandResult, Envelope, MAX_DETAIL, State, Status, VERSION, audit, printable};
use crate::capability::{self, CommandKind};
use crate::config::{Config, is_valid_id};
use crate::ingest::{Reason, Refusal};
use crate::report::MAX_CLOCK_SKEW;
use crate::store::Store;

pub const ROUTE: &str = "/r/v1/commands";

/// Ce qu'un retrait a fait en base : résultat accusé (id, accepté) et
/// commande servie.
type Step = (Option<(String, bool)>, Option<Command>);
pub const HEADER_TIMESTAMP: &str = "x-vigie-timestamp";
/// Un retrait accepté par site et par 30 s au plus.
pub const PULL_MIN_GAP: i64 = 30;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PullRequest {
    v: u8,
    #[serde(rename = "type")]
    kind: String,
    site: String,
    seq: i64,
    sent_at: i64,
    nonce: String,
    agent: String,
    #[serde(default)]
    result: Option<CommandResult>,
}

#[derive(Debug, Serialize)]
struct PullResponse<'a> {
    v: u8,
    site: &'a str,
    nonce: &'a str,
    server_time: i64,
    acked: Option<&'a str>,
    accepted: Option<bool>,
    command: Option<Envelope>,
}

/// Réponse prête à envoyer : corps exact, horodatage et signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    pub body: Vec<u8>,
    pub timestamp: i64,
    pub signature: String,
}

/// Ce qu'un retrait accepté a fait, pour le journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Served {
    pub site: String,
    pub seq: i64,
    pub acked: Option<(String, bool)>,
    pub command: Option<String>,
}

/// Clés lues par `serve` pour ce retrait.
pub struct Keys<'a> {
    pub commands: &'a SigningKey,
    pub audit: &'a SigningKey,
}

fn nonce_ok(nonce: &str) -> bool {
    (22..=64).contains(&nonce.len())
        && nonce
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Traite un retrait. `config` est la configuration relue pour ce retrait.
pub fn pull(
    store: &mut Store,
    config: &Config,
    keys: &Keys<'_>,
    site_header: Option<&str>,
    signature_header: Option<&str>,
    body: &[u8],
    now: i64,
) -> Result<(Signed, Served), Refusal> {
    let refuse = |reason| Refusal::new(site_header, reason);
    let internal = |e: anyhow::Error| refuse(Reason::Internal(format!("{e:#}")));

    let site_id = site_header
        .filter(|s| is_valid_id(s))
        .ok_or_else(|| refuse(Reason::MissingSite))?;
    let site = config
        .sites
        .iter()
        .find(|s| s.id == site_id)
        .ok_or_else(|| refuse(Reason::UnknownSite))?;
    let agent = store
        .agent(site_id)
        .map_err(internal)?
        .ok_or_else(|| refuse(Reason::UnknownSite))?;
    let signature = signature_header.ok_or_else(|| refuse(Reason::MissingSignature))?;
    let agent_key = VerifyingKey::from_bytes(&agent.pubkey).map_err(|_| refuse(Reason::BadKey))?;
    if !key::verify(&agent_key, DOMAIN_PULL, &[body], signature) {
        return Err(refuse(Reason::BadSignature));
    }

    let request: PullRequest =
        serde_json::from_slice(body).map_err(|e| refuse(Reason::Schema(format!("JSON : {e}"))))?;
    let schema = |why: &str| Err(refuse(Reason::Schema(why.to_owned())));
    if request.v != VERSION {
        return schema("v doit valoir 1");
    }
    if request.kind != "pull" {
        return schema("type doit valoir pull");
    }
    if request.site != site_id {
        return schema("site différent de X-Vigie-Site");
    }
    if request.seq < 1 {
        return schema("seq doit être positif");
    }
    if !nonce_ok(&request.nonce) {
        return schema("nonce : 22 à 64 caractères base64url");
    }
    if !printable(&request.agent, 64) {
        return schema("agent : 1 à 64 caractères imprimables");
    }
    if let Some(result) = &request.result
        && (!printable(&result.detail, MAX_DETAIL) || result.command_id.len() > 64)
    {
        return schema("result : detail imprimable de 1000 caractères au plus");
    }
    let skew = request.sent_at.saturating_sub(now);
    if skew.saturating_abs() > MAX_CLOCK_SKEW {
        return Err(refuse(Reason::Clock { skew }));
    }

    let typology = crate::config::typology_fingerprint(config);
    let mut tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| internal(e.into()))?;
    let outcome = (|| -> anyhow::Result<Result<Step, Reason>> {
        tx.execute(
            "INSERT INTO command_sites (site) VALUES (?1) ON CONFLICT (site) DO NOTHING",
            [site_id],
        )?;
        let (enabled, last_seq, last_at): (bool, i64, Option<i64>) = tx.query_row(
            "SELECT enabled, last_pull_seq, last_pull_at FROM command_sites WHERE site = ?1",
            [site_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if request.seq <= last_seq {
            return Ok(Err(Reason::Replay {
                seq: request.seq,
                last_seq,
            }));
        }
        if let Some(at) = last_at
            && now - at < PULL_MIN_GAP
        {
            return Ok(Err(Reason::TooSoon { last_valid_at: at }));
        }
        tx.execute(
            "UPDATE command_sites SET last_pull_seq = ?2, last_pull_at = ?3 WHERE site = ?1",
            params![site_id, request.seq, now],
        )?;
        let acked = match &request.result {
            Some(result) => Some(record_result(
                &mut tx,
                keys.audit,
                site_id,
                &agent.pubkey,
                result,
                now,
            )?),
            None => None,
        };
        let command = if enabled {
            next_command(&tx, keys.audit, site, &typology, now)?
        } else {
            None
        };
        Ok(Ok((acked, command)))
    })();
    let (acked, command) = match outcome {
        Ok(Ok(done)) => done,
        Ok(Err(reason)) => return Err(refuse(reason)),
        Err(err) => return Err(internal(err)),
    };
    tx.commit().map_err(|e| internal(e.into()))?;

    let envelope = command.as_ref().map(|c| Envelope {
        v: VERSION,
        site: c.site.clone(),
        id: c.id.clone(),
        seq: c.seq,
        name: c.kind.name(),
        runtime: c.runtime.clone(),
        params: serde_json::from_str(&c.params).unwrap_or(serde_json::json!({})),
        issued_at: c.created_at,
        expires_at: c.expires_at,
    });
    let response = PullResponse {
        v: VERSION,
        site: site_id,
        nonce: &request.nonce,
        server_time: now,
        acked: acked.as_ref().map(|(id, _)| id.as_str()),
        accepted: acked.as_ref().map(|(_, accepted)| *accepted),
        command: envelope,
    };
    let body = serde_json::to_vec(&response).map_err(|e| internal(e.into()))?;
    let timestamp = now.to_string();
    let signature = key::sign(
        keys.commands,
        DOMAIN_COMMANDS,
        &[timestamp.as_bytes(), b"\n", &body],
    );
    Ok((
        Signed {
            body,
            timestamp: now,
            signature,
        },
        Served {
            site: site_id.to_owned(),
            seq: request.seq,
            acked,
            command: command.map(|c| c.id),
        },
    ))
}

/// Enregistre un résultat et rend `(id, accepté)` : il est toujours accusé.
fn record_result(
    tx: &mut Transaction<'_>,
    audit_key: &SigningKey,
    site: &str,
    agent_pubkey: &[u8; 32],
    result: &CommandResult,
    now: i64,
) -> anyhow::Result<(String, bool)> {
    let id = result.command_id.clone();
    let reject = |tx: &Transaction<'_>, label: &str, why: &str| -> anyhow::Result<(String, bool)> {
        audit::append(
            tx,
            audit_key,
            &event(site, now, label, Some(&id), why.to_owned(), None),
        )?;
        Ok((id.clone(), false))
    };
    let command: Option<Command> = tx
        .query_row(
            &format!("SELECT {COLUMNS} FROM commands WHERE id = ?1"),
            [&id],
            from_row,
        )
        .optional()?;
    let Some(command) = command.filter(|c| c.site == site) else {
        return reject(
            tx,
            "result-rejected",
            "commande inconnue ou d'un autre site",
        );
    };
    let declared = serde_json::to_string(result)?;
    // Accusé perdu : le même résultat revient, sans effet.
    if command.result.as_deref() == Some(declared.as_str()) {
        return Ok((id, true));
    }
    match command.state {
        State::Served | State::Unknown => {}
        State::Expired | State::Cancelled => {
            return reject(tx, "result-late", "résultat d'une commande close");
        }
        _ => {
            return reject(
                tx,
                "result-rejected",
                "commande déjà close par un autre résultat",
            );
        }
    }
    let late = command.state == State::Unknown;
    let mut next = match result.status {
        Status::Ok => State::Done,
        Status::Failed => State::Failed,
        Status::Refused if late => State::Failed,
        Status::Refused => State::Refused,
    };
    let mut accepted = true;
    let mut detail = format!(
        "{} : {}",
        command.kind.name(),
        super::neutralize(&result.detail)
    );
    if command.kind == CommandKind::RotateKey && result.status == Status::Ok {
        match rotation(tx, site, &command, agent_pubkey, result, late)? {
            Ok(()) => detail.push_str(" ; clé de l'agent remplacée"),
            Err(why) => {
                next = State::Failed;
                accepted = false;
                detail = format!("rotate-key refusée : {why}");
            }
        }
    }
    transition(tx, &command, next, now)?;
    tx.execute(
        "UPDATE commands SET result = ?2 WHERE id = ?1",
        params![id, declared],
    )?;
    audit::append(
        tx,
        audit_key,
        &event(
            site,
            now,
            if late { "result-late" } else { "result" },
            Some(&id),
            detail,
            None,
        ),
    )?;
    Ok((id, accepted))
}

/// `rotate-key` : preuve de possession par la nouvelle clé, bascule et remise
/// à zéro des séquences. `Err` : raison du refus, la clé reste.
fn rotation(
    tx: &Transaction<'_>,
    site: &str,
    command: &Command,
    current: &[u8; 32],
    result: &CommandResult,
    late: bool,
) -> anyhow::Result<Result<(), &'static str>> {
    if late {
        return Ok(Err("issue inconnue : rotation tardive refusée"));
    }
    let (Some(new_key), Some(proof)) = (&result.data.new_pubkey, &result.data.proof) else {
        return Ok(Err("nouvelle clé ou preuve absente"));
    };
    let Some(new_bytes) = STANDARD
        .decode(new_key)
        .ok()
        .and_then(|raw| <[u8; 32]>::try_from(raw).ok())
    else {
        return Ok(Err("nouvelle clé illisible"));
    };
    if &new_bytes == current {
        return Ok(Err("nouvelle clé égale à l'ancienne"));
    }
    let used: Option<String> = tx
        .query_row(
            "SELECT site FROM site_keys WHERE pubkey = ?1 AND site <> ?2",
            params![new_bytes.as_slice(), site],
            |row| row.get(0),
        )
        .optional()?;
    if used.is_some() {
        return Ok(Err("nouvelle clé déjà celle d'un autre site"));
    }
    let Ok(verifying) = VerifyingKey::from_bytes(&new_bytes) else {
        return Ok(Err("nouvelle clé invalide"));
    };
    if !key::verify(
        &verifying,
        DOMAIN_ROTATE,
        &[
            site.as_bytes(),
            b"\n",
            command.id.as_bytes(),
            b"\n",
            new_key.as_bytes(),
        ],
        proof,
    ) {
        return Ok(Err("preuve de possession fausse"));
    }
    tx.execute(
        "UPDATE site_keys SET pubkey = ?2, last_logs_seq = 0 WHERE site = ?1",
        params![site, new_bytes.as_slice()],
    )?;
    tx.execute("UPDATE reports SET last_seq = 0 WHERE site = ?1", [site])?;
    tx.execute(
        "UPDATE command_sites SET last_pull_seq = 0 WHERE site = ?1",
        [site],
    )?;
    Ok(Ok(()))
}

/// Commande à servir : la commande non close du site, si la configuration
/// relue l'admet encore et qu'elle n'a pas expiré.
fn next_command(
    tx: &Transaction<'_>,
    audit_key: &SigningKey,
    site: &crate::config::Site,
    typology: &str,
    now: i64,
) -> anyhow::Result<Option<Command>> {
    let command: Option<Command> = tx
        .query_row(
            &format!(
                "SELECT {COLUMNS} FROM commands WHERE site = ?1 AND state IN ('pending', 'served')"
            ),
            [&site.id],
            from_row,
        )
        .optional()?;
    let Some(command) = command else {
        return Ok(None);
    };
    if command.expires_at <= now {
        // `tick` la passera en expired ou unknown.
        return Ok(None);
    }
    let runtime_now = site.effective_runtime().map(|r| r.as_str());
    let refusal = match capability::permit(command.kind, site) {
        Err(refusal) => Some(refusal.to_string()),
        Ok(()) if runtime_now != Some(command.runtime.as_str()) => {
            Some("runtime changé depuis la création".to_owned())
        }
        Ok(()) => None,
    };
    if let Some(why) = refusal {
        if command.state == State::Pending {
            transition(tx, &command, State::Refused, now)?;
            audit::append(
                tx,
                audit_key,
                &event(
                    &site.id,
                    now,
                    "refused",
                    Some(&command.id),
                    why,
                    Some(typology),
                ),
            )?;
        }
        return Ok(None);
    }
    if command.state == State::Pending {
        transition(tx, &command, State::Served, now)?;
        audit::append(
            tx,
            audit_key,
            &event(
                &site.id,
                now,
                "served",
                Some(&command.id),
                command.kind.name(),
                Some(typology),
            ),
        )?;
    }
    Ok(Some(command))
}

/// Nonce aléatoire au format attendu (tests et agents de test).
pub fn new_nonce() -> String {
    let mut bytes = [0u8; 24];
    let _ = getrandom::fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
