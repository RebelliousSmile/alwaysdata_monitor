//! Acceptation d'un rapport d'agent, dans l'ordre fixé par
//! `docs/protocole-agent.md` : site connu, signature, schéma, horodatage,
//! séquence, débit. La taille et le délai de réception sont vérifiés avant,
//! par `serve`.
//!
//! Chaque refus porte sa raison, pour le journal, mais `serve` répond le même
//! 404 à tous. Une [`Refusal`] ne contient jamais le corps reçu.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, VerifyingKey};

use crate::config::is_valid_id;
use crate::report::{self, MAX_CLOCK_SKEW};
use crate::store::{AcceptedReport, ReportOutcome, Store};

pub const HEADER_SITE: &str = "x-vigie-site";
pub const HEADER_SIGNATURE: &str = "x-vigie-signature";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    pub site: String,
    pub seq: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    TooLarge,
    TooSlow,
    /// Lecture du corps interrompue par le client.
    Truncated,
    MissingSite,
    /// Site absent de la configuration, ou sans clé enregistrée.
    UnknownSite,
    MissingSignature,
    /// Signature illisible ou fausse.
    BadSignature,
    /// Clé enregistrée inutilisable (point invalide).
    BadKey,
    Schema(String),
    Clock {
        skew: i64,
    },
    Replay {
        seq: i64,
        last_seq: i64,
    },
    TooSoon {
        last_valid_at: i64,
    },
    /// Lot de logs pour un site sans `[sites.logs] source`.
    LogsClosed,
    /// Lot de logs qui commence sous la limite haute et finit au-delà.
    Overlap {
        start: i64,
        end: i64,
        high: i64,
    },
    /// Plafond quotidien des logs du site atteint.
    Quota {
        used: i64,
    },
    Internal(String),
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("corps de plus de 64 Ko"),
            Self::TooSlow => f.write_str("corps non reçu en 10 s"),
            Self::Truncated => f.write_str("corps interrompu"),
            Self::MissingSite => f.write_str("en-tête X-Vigie-Site absent ou invalide"),
            Self::UnknownSite => f.write_str("site inconnu ou sans clé"),
            Self::MissingSignature => f.write_str("en-tête X-Vigie-Signature absent"),
            Self::BadSignature => f.write_str("signature invalide"),
            Self::BadKey => f.write_str("clé enregistrée inutilisable"),
            Self::Schema(reason) => write!(f, "schéma : {reason}"),
            Self::Clock { skew } => write!(f, "horloge décalée de {skew} s"),
            Self::Replay { seq, last_seq } => {
                write!(f, "seq {seq} non croissant (dernier accepté : {last_seq})")
            }
            Self::TooSoon { last_valid_at } => write!(
                f,
                "débit : rapport accepté à {}",
                crate::iso_utc(*last_valid_at)
            ),
            Self::LogsClosed => {
                f.write_str("réception des logs fermée ([sites.logs] source absent)")
            }
            Self::Overlap { start, end, high } => write!(
                f,
                "plage {start}..{end} à cheval sur la limite haute {high}"
            ),
            Self::Quota { used } => write!(
                f,
                "plafond quotidien des logs atteint ({used} octets reçus aujourd'hui)"
            ),
            Self::Internal(reason) => write!(f, "erreur interne : {reason}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// Seulement s'il a la forme d'un identifiant de site.
    pub site: Option<String>,
    pub seq: Option<i64>,
    pub reason: Reason,
}

impl Refusal {
    pub fn new(site_header: Option<&str>, reason: Reason) -> Self {
        Self {
            site: site_header.filter(|s| is_valid_id(s)).map(str::to_owned),
            seq: None,
            reason,
        }
    }

    pub(crate) fn with_seq(mut self, seq: i64) -> Self {
        self.seq = Some(seq);
        self
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("rapport refusé (site ")?;
        match &self.site {
            Some(site) => f.write_str(site)?,
            None => f.write_str("?")?,
        }
        if let Some(seq) = self.seq {
            write!(f, ", seq {seq}")?;
        }
        write!(f, ") : {}", self.reason)
    }
}

/// Vérifie et enregistre un rapport. `sites` : identifiants de la configuration.
/// `store` est la connexion d'écriture de `serve` (`writer.rs`) : l'appelant
/// décide d'une base absente, qu'il refuse comme un site inconnu.
pub fn ingest(
    store: &mut Store,
    sites: &[String],
    site_header: Option<&str>,
    signature_header: Option<&str>,
    body: &[u8],
    now: i64,
) -> Result<Accepted, Refusal> {
    let refuse = |reason| Refusal::new(site_header, reason);

    // Site connu : dans la configuration, puis avec une clé en base.
    let site = site_header
        .filter(|s| is_valid_id(s))
        .ok_or_else(|| refuse(Reason::MissingSite))?;
    if !sites.iter().any(|s| s == site) {
        return Err(refuse(Reason::UnknownSite));
    }
    let internal = |e: anyhow::Error| refuse(Reason::Internal(format!("{e:#}")));
    let agent = store
        .agent(site)
        .map_err(internal)?
        .ok_or_else(|| refuse(Reason::UnknownSite))?;

    // Signature, sur les octets reçus.
    let signature = signature_header.ok_or_else(|| refuse(Reason::MissingSignature))?;
    let signature: [u8; 64] = STANDARD
        .decode(signature)
        .ok()
        .and_then(|raw| raw.try_into().ok())
        .ok_or_else(|| refuse(Reason::BadSignature))?;
    let key = VerifyingKey::from_bytes(&agent.pubkey).map_err(|_| refuse(Reason::BadKey))?;
    key.verify_strict(body, &Signature::from_bytes(&signature))
        .map_err(|_| refuse(Reason::BadSignature))?;

    // Schéma, puis horodatage.
    let valid = report::parse(body, site).map_err(|e| refuse(Reason::Schema(e.0)))?;
    let skew = valid.sent_at.saturating_sub(now);
    if skew.saturating_abs() > MAX_CLOCK_SKEW {
        return Err(refuse(Reason::Clock { skew }).with_seq(valid.seq));
    }

    // Séquence et débit, sous verrou d'écriture.
    let outcome = store
        .accept_report(
            &AcceptedReport {
                site,
                pubkey: &agent.pubkey,
                seq: valid.seq,
                agent: &valid.agent,
                facts: &valid.facts,
                files: &valid.files,
                findings: &valid.findings,
            },
            now,
        )
        .map_err(|e| internal(e).with_seq(valid.seq))?;
    let reason = match outcome {
        ReportOutcome::Accepted => {
            return Ok(Accepted {
                site: site.to_owned(),
                seq: valid.seq,
            });
        }
        ReportOutcome::UnknownSite => Reason::UnknownSite,
        ReportOutcome::Replay { last_seq } => Reason::Replay {
            seq: valid.seq,
            last_seq,
        },
        ReportOutcome::TooSoon { last_valid_at } => Reason::TooSoon { last_valid_at },
    };
    Err(refuse(reason).with_seq(valid.seq))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_names_only_a_well_formed_site() {
        let refusal = Refusal::new(Some("site-a"), Reason::BadSignature).with_seq(7);
        assert_eq!(
            refusal.to_string(),
            "rapport refusé (site site-a, seq 7) : signature invalide"
        );
        let refusal = Refusal::new(Some("<script>\n"), Reason::MissingSite);
        assert_eq!(refusal.site, None);
        assert_eq!(
            refusal.to_string(),
            "rapport refusé (site ?) : en-tête X-Vigie-Site absent ou invalide"
        );
    }
}
