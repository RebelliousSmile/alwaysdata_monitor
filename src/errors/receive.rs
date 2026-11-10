//! `POST /r/v1/errors` : lots d'erreurs de site poussés par l'agent PHP
//! (issue #52, `docs/protocole-agent.md`).
//!
//! Vérifications, dans l'ordre, arrêt au premier échec (404 commun, raison au
//! journal) : taille et délai (`serve`) ; site connu de la configuration, au
//! runtime effectif `php` (capacité `agent:errors`) et doté d'une clé ;
//! signature de l'agent sur `vigie-errors-v1\n` + octets du corps ; schéma ;
//! horloge ±300 s ; puis, sous verrou d'écriture (`Store::accept_errors`) :
//! `seq` strictement croissant et remplacement des groupes du (site, jour).
//!
//! Un message qui contient encore une adresse IP ou un caractère de contrôle
//! fait refuser le lot entier : le texte reçu n'est jamais écrit au journal,
//! la raison ne donne que le rang du groupe. Les messages gardés sont
//! renormalisés (nombres, UUID) avant l'empreinte ; deux groupes que cette
//! renormalisation confond sont fusionnés.

use std::collections::HashMap;

use ed25519_dalek::VerifyingKey;
use serde::Deserialize;

use super::{
    MAX_COUNT, MAX_GROUPS, MAX_MESSAGE_CHARS, RETENTION_DAYS, contains_address, fingerprint,
    first_kept_day, normalize, valid_day,
};
use crate::capability::{Control, Ctx};
use crate::command::key::{self, DOMAIN_ERRORS};
use crate::command::printable;
use crate::config::{Config, is_valid_id};
use crate::ingest::{Reason, Refusal};
use crate::report::MAX_CLOCK_SKEW;
use crate::store::{ErrorBatch, ErrorGroup, ErrorsOutcome, Store};

pub const ROUTE: &str = "/r/v1/errors";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchBody {
    v: u8,
    #[serde(rename = "type")]
    kind: String,
    site: String,
    seq: i64,
    sent_at: i64,
    agent: String,
    day: String,
    groups: Vec<GroupBody>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupBody {
    message: String,
    count: i64,
    first_seen: i64,
    last_seen: i64,
}

/// Ce qu'un lot accepté a fait, pour le journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    pub site: String,
    pub seq: i64,
    pub day: String,
    /// Groupes reçus.
    pub received: usize,
    /// Groupes écrits, après fusion des empreintes confondues.
    pub stored: usize,
}

/// Renormalise les groupes d'un lot et fusionne ceux dont l'empreinte
/// coïncide (somme des compteurs, première vue la plus ancienne, dernière vue
/// la plus récente), dans l'ordre de première apparition.
fn merge_groups(groups: &[GroupBody]) -> Vec<ErrorGroup> {
    let mut merged: Vec<ErrorGroup> = Vec::with_capacity(groups.len());
    let mut index: HashMap<String, usize> = HashMap::new();
    for group in groups {
        let message = normalize(&group.message);
        let print = fingerprint(&message);
        match index.get(&print) {
            Some(&at) => {
                let kept = &mut merged[at];
                kept.count = kept.count.saturating_add(group.count);
                kept.first_seen = kept.first_seen.min(group.first_seen);
                kept.last_seen = kept.last_seen.max(group.last_seen);
            }
            None => {
                index.insert(print.clone(), merged.len());
                merged.push(ErrorGroup {
                    fingerprint: print,
                    message,
                    count: group.count,
                    first_seen: group.first_seen,
                    last_seen: group.last_seen,
                });
            }
        }
    }
    merged
}

/// Vérifie, normalise et enregistre un lot. `store` est la connexion
/// d'écriture de `serve` ; `now` en secondes Unix.
pub fn receive(
    store: &mut Store,
    config: &Config,
    site_header: Option<&str>,
    signature_header: Option<&str>,
    body: &[u8],
    now: i64,
) -> Result<Received, Refusal> {
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
    let ctx = Ctx {
        agent: true,
        baseline: false,
    };
    if !Control::Errors.watched(site, &ctx) {
        return Err(refuse(Reason::ErrorsClosed));
    }
    let signature = signature_header.ok_or_else(|| refuse(Reason::MissingSignature))?;
    let agent_key = VerifyingKey::from_bytes(&agent.pubkey).map_err(|_| refuse(Reason::BadKey))?;
    if !key::verify(&agent_key, DOMAIN_ERRORS, &[body], signature) {
        return Err(refuse(Reason::BadSignature));
    }

    // Le message de serde peut citer la valeur reçue (« invalid type: string
    // "…" ») : seul son rang va au journal.
    let batch: BatchBody = serde_json::from_slice(body).map_err(|e| {
        refuse(Reason::Schema(format!(
            "JSON : {:?} ligne {} colonne {}",
            e.classify(),
            e.line(),
            e.column()
        )))
    })?;
    let schema = |why: String| Err(refuse(Reason::Schema(why)).with_seq(batch.seq));
    if batch.v != 1 {
        return schema("v doit valoir 1".to_owned());
    }
    if batch.kind != "errors" {
        return schema("type doit valoir errors".to_owned());
    }
    if batch.site != site_id {
        return schema("site différent de X-Vigie-Site".to_owned());
    }
    if batch.seq < 1 {
        return schema("seq doit être positif".to_owned());
    }
    if !printable(&batch.agent, 64) {
        return schema("agent : 1 à 64 caractères imprimables".to_owned());
    }
    if !valid_day(&batch.day) {
        return schema("day : jour AAAA-MM-JJ du calendrier attendu".to_owned());
    }
    if batch.groups.len() > MAX_GROUPS {
        return schema(format!("groups : {MAX_GROUPS} groupes au plus"));
    }
    for (rank, group) in batch.groups.iter().enumerate() {
        let n = rank + 1;
        let chars = group.message.chars().count();
        if chars == 0 || chars > MAX_MESSAGE_CHARS {
            return schema(format!(
                "groupe {n} : message de 1 à {MAX_MESSAGE_CHARS} caractères"
            ));
        }
        if group.message.chars().any(char::is_control) {
            return schema(format!(
                "groupe {n} : caractère de contrôle dans le message"
            ));
        }
        if contains_address(&group.message) {
            return schema(format!("groupe {n} : adresse IP restante dans le message"));
        }
        if !(1..=MAX_COUNT).contains(&group.count) {
            return schema(format!("groupe {n} : count de 1 à {MAX_COUNT}"));
        }
        if group.first_seen < 0 || group.first_seen > group.last_seen {
            return schema(format!(
                "groupe {n} : first_seen positif et inférieur ou égal à last_seen"
            ));
        }
    }
    let skew = batch.sent_at.saturating_sub(now);
    if skew.saturating_abs() > MAX_CLOCK_SKEW {
        return Err(refuse(Reason::Clock { skew }).with_seq(batch.seq));
    }
    // Un jour déjà purgé ou à venir n'a pas de place : il serait écrit pour
    // être effacé au tour suivant, ou jamais lu.
    if batch.day < first_kept_day(now)
        || batch.day > crate::utc_day(now.saturating_add(MAX_CLOCK_SKEW))
    {
        return schema(format!(
            "day hors des {RETENTION_DAYS} derniers jours conservés"
        ));
    }

    let groups = merge_groups(&batch.groups);
    let outcome = store
        .accept_errors(&ErrorBatch {
            site: site_id,
            pubkey: &agent.pubkey,
            seq: batch.seq,
            day: &batch.day,
            groups: &groups,
        })
        .map_err(|e| internal(e).with_seq(batch.seq))?;
    match outcome {
        ErrorsOutcome::Accepted => {}
        ErrorsOutcome::UnknownSite => {
            return Err(refuse(Reason::UnknownSite).with_seq(batch.seq));
        }
        ErrorsOutcome::Replay { last_seq } => {
            return Err(refuse(Reason::Replay {
                seq: batch.seq,
                last_seq,
            })
            .with_seq(batch.seq));
        }
    }
    Ok(Received {
        site: site_id.to_owned(),
        seq: batch.seq,
        day: batch.day,
        received: batch.groups.len(),
        stored: groups.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(message: &str, count: i64, first: i64, last: i64) -> GroupBody {
        GroupBody {
            message: message.to_owned(),
            count,
            first_seen: first,
            last_seen: last,
        }
    }

    #[test]
    fn groups_are_renormalized_and_merged_by_fingerprint() {
        let merged = merge_groups(&[
            group("Undefined array key 3", 2, 100, 200),
            group("Other 9", 1, 150, 150),
            group("Undefined array key 42", 5, 50, 120),
        ]);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].message, "Undefined array key #");
        assert_eq!(merged[0].count, 7);
        assert_eq!(merged[0].first_seen, 50);
        assert_eq!(merged[0].last_seen, 200);
        assert_eq!(merged[0].fingerprint, fingerprint("Undefined array key #"));
        assert_eq!(merged[1].message, "Other #");
    }
}
