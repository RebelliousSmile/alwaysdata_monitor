//! `POST /r/v1/logs` : lots de lignes de logs poussés par l'agent d'un site
//! (`docs/logs.md`, issue #1).
//!
//! Vérifications, dans l'ordre, arrêt au premier échec (404 commun, raison au
//! journal) : taille et délai (`serve`) ; site connu de la configuration,
//! avec `[sites.logs] source`, et doté d'une clé ; signature de l'agent sur
//! `vigie-logs-v1\n` + octets du corps ; schéma ; horloge ±300 s ; puis, sous
//! verrou d'écriture (`Store::accept_logs`) : `seq` strictement croissant,
//! limite haute de `(site, file, gen)`, plafond quotidien.
//!
//! Les octets reçus ne sont jamais écrits : chaque ligne est découpée et
//! normalisée ici, et seules des [`Entry`] vont en base. Une ligne rejetée est
//! comptée par motif, jamais bloquante.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;

use super::{Entry, combined, normalize};
use crate::command::key::{self, DOMAIN_LOGS};
use crate::command::printable;
use crate::config::{Config, is_valid_id};
use crate::ingest::{Reason, Refusal};
use crate::report::MAX_CLOCK_SKEW;
use crate::store::{LogBatch, LogsOutcome, Store};

pub const ROUTE: &str = "/r/v1/logs";
/// Plage lue par l'agent pour un lot, au plus (constante partagée avec
/// l'agent PHP, `MAX_LOG_RANGE`).
pub const MAX_RANGE: i64 = 4 * 1024 * 1024;
/// Octets de `chunk` acceptés par site et par jour UTC de réception ; au-delà,
/// les lots sont refusés et l'agent prend du retard.
pub const MAX_DAILY_BYTES: i64 = 50_000_000;
/// Conservation des entrées, des lots et des limites hautes (RGPD).
pub const RETENTION: i64 = 30 * 86_400;
/// Fichiers sautés déclarés par un lot, au plus.
pub const MAX_SKIPPED_FILES: i64 = 1000;
/// Motif de rejet d'une entrée datée d'avant la conservation.
pub const REJECT_TOO_OLD: &str = "too_old";
/// Motif de rejet d'une ligne sans hôte ou d'un hôte hors `[sites.logs] hosts`.
pub const REJECT_HOST: &str = "host";

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
    file: String,
    #[serde(rename = "gen")]
    generation: i64,
    start: i64,
    end: i64,
    skipped_files: i64,
    chunk: String,
}

/// Ce qu'un lot accepté a fait, pour le journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    pub site: String,
    pub seq: i64,
    pub file: String,
    pub generation: i64,
    pub start: i64,
    pub end: i64,
    pub skipped_files: i64,
    pub stored: Stored,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stored {
    /// Plage déjà couverte : un renvoi après une réponse perdue.
    Duplicate,
    Accepted {
        accepted: usize,
        rejected: BTreeMap<String, u64>,
        /// Octets sautés depuis la limite haute.
        gap: i64,
    },
}

/// `http-AAAA-MM-JJ.log`, chiffres seulement : jamais un chemin.
pub fn valid_file_name(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() == 19
        && name.starts_with("http-")
        && name.ends_with(".log")
        && b[9] == b'-'
        && b[12] == b'-'
        && [5, 6, 7, 8, 10, 11, 13, 14]
            .iter()
            .all(|&i| b[i].is_ascii_digit())
}

/// Découpe et normalise les lignes d'un `chunk` ; rend les entrées gardées et
/// les rejets par motif. `hosts` : hôtes admis du site.
pub fn parse_chunk(
    chunk: &[u8],
    hosts: &[String],
    tz: Option<&jiff::tz::TimeZone>,
    now_ms: i64,
) -> (Vec<Entry>, BTreeMap<String, u64>) {
    let oldest = now_ms.saturating_sub(RETENTION.saturating_mul(1000));
    let mut entries = Vec::new();
    let mut rejected: BTreeMap<String, u64> = BTreeMap::new();
    for line in chunk.split(|&b| b == b'\n') {
        if line.iter().all(|&b| b == b'\r') {
            continue;
        }
        let reason = match combined::split(line).and_then(|raw| normalize(&raw, tz, now_ms)) {
            Err(reason) => reason.as_str(),
            Ok(entry) if entry.timestamp_ms < oldest => REJECT_TOO_OLD,
            Ok(entry) if !entry.host.as_ref().is_some_and(|h| hosts.contains(h)) => REJECT_HOST,
            Ok(entry) => {
                entries.push(entry);
                continue;
            }
        };
        *rejected.entry(reason.to_owned()).or_insert(0) += 1;
    }
    (entries, rejected)
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
    let logs = site
        .logs
        .as_ref()
        .filter(|l| l.source.is_some())
        .ok_or_else(|| refuse(Reason::LogsClosed))?;
    let agent = store
        .agent(site_id)
        .map_err(internal)?
        .ok_or_else(|| refuse(Reason::UnknownSite))?;
    let signature = signature_header.ok_or_else(|| refuse(Reason::MissingSignature))?;
    let agent_key = VerifyingKey::from_bytes(&agent.pubkey).map_err(|_| refuse(Reason::BadKey))?;
    if !key::verify(&agent_key, DOMAIN_LOGS, &[body], signature) {
        return Err(refuse(Reason::BadSignature));
    }

    let batch: BatchBody =
        serde_json::from_slice(body).map_err(|e| refuse(Reason::Schema(format!("JSON : {e}"))))?;
    let schema = |why: &str| Err(refuse(Reason::Schema(why.to_owned())).with_seq(batch.seq));
    if batch.v != 1 {
        return schema("v doit valoir 1");
    }
    if batch.kind != "logs" {
        return schema("type doit valoir logs");
    }
    if batch.site != site_id {
        return schema("site différent de X-Vigie-Site");
    }
    if batch.seq < 1 {
        return schema("seq doit être positif");
    }
    if !printable(&batch.agent, 64) {
        return schema("agent : 1 à 64 caractères imprimables");
    }
    if !valid_file_name(&batch.file) {
        return schema("file : http-AAAA-MM-JJ.log attendu");
    }
    if batch.generation < 0 || batch.start < 0 || batch.start >= batch.end {
        return schema("gen et start positifs, start < end");
    }
    if batch.end - batch.start > MAX_RANGE {
        return schema("plage de plus de 4 Mio");
    }
    if !(0..=MAX_SKIPPED_FILES).contains(&batch.skipped_files) {
        return schema("skipped_files : 0 à 1000");
    }
    let Ok(chunk) = STANDARD.decode(&batch.chunk) else {
        return schema("chunk : base64 standard attendu");
    };
    let bytes = i64::try_from(chunk.len()).unwrap_or(i64::MAX);
    if bytes > batch.end - batch.start {
        return schema("chunk plus long que la plage lue");
    }
    let skew = batch.sent_at.saturating_sub(now);
    if skew.saturating_abs() > MAX_CLOCK_SKEW {
        return Err(refuse(Reason::Clock { skew }).with_seq(batch.seq));
    }

    let tz = logs.time_zone();
    let (entries, rejected) =
        parse_chunk(&chunk, &logs.hosts, tz.as_ref(), now.saturating_mul(1000));
    let rejected_json = serde_json::to_string(&rejected).map_err(|e| internal(e.into()))?;
    let outcome = store
        .accept_logs(
            &LogBatch {
                site: site_id,
                pubkey: &agent.pubkey,
                seq: batch.seq,
                file: &batch.file,
                generation: batch.generation,
                start: batch.start,
                end: batch.end,
                bytes,
                skipped_files: batch.skipped_files,
                entries: &entries,
                rejected: &rejected_json,
            },
            now,
        )
        .map_err(|e| internal(e).with_seq(batch.seq))?;
    let stored = match outcome {
        LogsOutcome::Accepted { gap } => Stored::Accepted {
            accepted: entries.len(),
            rejected,
            gap,
        },
        LogsOutcome::Duplicate => Stored::Duplicate,
        LogsOutcome::UnknownSite => return Err(refuse(Reason::UnknownSite).with_seq(batch.seq)),
        LogsOutcome::Replay { last_seq } => {
            return Err(refuse(Reason::Replay {
                seq: batch.seq,
                last_seq,
            })
            .with_seq(batch.seq));
        }
        LogsOutcome::Overlap { high } => {
            return Err(refuse(Reason::Overlap {
                start: batch.start,
                end: batch.end,
                high,
            })
            .with_seq(batch.seq));
        }
        LogsOutcome::Quota { used } => {
            return Err(refuse(Reason::Quota { used }).with_seq(batch.seq));
        }
    };
    Ok(Received {
        site: site_id.to_owned(),
        seq: batch.seq,
        file: batch.file,
        generation: batch.generation,
        start: batch.start,
        end: batch.end,
        skipped_files: batch.skipped_files,
        stored,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_dated_log_names_are_files() {
        assert!(valid_file_name("http-2026-10-16.log"));
        for bad in [
            "http-2026-10-16.log.gz",
            "../http-2026-10-16.log",
            "http-2026-1-16.log",
            "http-2026-10-1x.log",
            "error-2026-10-16.log",
            "http-2026_10_16.log",
            "",
        ] {
            assert!(!valid_file_name(bad), "{bad}");
        }
    }

    #[test]
    fn a_chunk_keeps_only_recent_lines_of_its_hosts() {
        let now_ms = 1_792_108_800_000; // 2026-10-16T00:00:00Z
        let chunk = b"site-a.example.org 192.0.2.1 - - [15/Oct/2026:10:00:00 +0000] \"GET /?token=secret HTTP/1.1\" 200 1 \"-\" \"ua\"\n\
site-b.example.org 192.0.2.2 - - [15/Oct/2026:10:00:00 +0000] \"GET / HTTP/1.1\" 200 1 \"-\" \"ua\"\n\
192.0.2.3 - - [15/Oct/2026:10:00:00 +0000] \"GET / HTTP/1.1\" 200 1 \"-\" \"ua\"\n\
site-a.example.org 192.0.2.4 - - [01/Sep/2026:10:00:00 +0000] \"GET / HTTP/1.1\" 200 1 \"-\" \"ua\"\n\
\r\n\
pas une ligne";
        let hosts = vec!["site-a.example.org".to_owned()];
        let (entries, rejected) = parse_chunk(chunk, &hosts, None, now_ms);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].query_keys, ["token"]);
        let expected: BTreeMap<String, u64> = [("host", 2), ("too_old", 1), ("malformed", 1)]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect();
        assert_eq!(rejected, expected);
    }
}
