//! Canal de commandes (`docs/protocole-commandes.md`, issue #10) : la seule
//! voie d'écriture du veilleur vers un site, fermée par défaut.
//!
//! - `key` : clés de commandes et d'audit, signatures par domaine ;
//! - `audit` : journal chaîné par site, signé, ancré hors de la base ;
//! - `store` : file des commandes, activation par site, états ;
//! - `pull` : point d'entrée `/r/v1/commands`.

pub mod audit;
pub mod key;
pub mod pull;
pub mod store;

use serde::{Deserialize, Serialize};

use crate::capability::CommandKind;

/// Une commande non retirée, ou retirée sans résultat, se clôt 24 h après sa
/// création (`expired` ou `unknown`).
pub const COMMAND_TTL: i64 = 86_400;
/// Version de l'enveloppe d'une commande et des corps du canal.
pub const VERSION: u8 = 1;
/// Longueur maximale du `detail` d'un résultat, en caractères.
pub const MAX_DETAIL: usize = 1000;

/// État d'une commande. Transitions permises : `pending → served → done |
/// failed | refused` ; `pending → expired | refused` (refusée à la
/// délivrance : la configuration ne l'admet plus) ; `pending | served → cancelled` ;
/// `served → unknown → done | failed` (résultat tardif).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Pending,
    Served,
    Done,
    Failed,
    Refused,
    Expired,
    Cancelled,
    Unknown,
}

impl State {
    pub const ALL: [Self; 8] = [
        Self::Pending,
        Self::Served,
        Self::Done,
        Self::Failed,
        Self::Refused,
        Self::Expired,
        Self::Cancelled,
        Self::Unknown,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Served => "served",
            Self::Done => "done",
            Self::Failed => "failed",
            Self::Refused => "refused",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Unknown => "unknown",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.as_str() == raw)
    }

    /// Non close : bloque toute nouvelle commande pour le site.
    pub fn is_open(self) -> bool {
        matches!(self, Self::Pending | Self::Served)
    }

    pub fn can_become(self, next: Self) -> bool {
        use State::*;
        matches!(
            (self, next),
            (Pending, Served | Expired | Cancelled | Refused)
                | (Served, Done | Failed | Refused | Cancelled | Unknown)
                | (Unknown, Done | Failed)
        )
    }
}

/// Paramètres d'une commande : un schéma strict par commande. `ping` et
/// `rotate-key` n'en ont pas (objet vide).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NoParams {}

/// Paramètres validés pour une commande sans paramètre, sérialisés tels
/// quels dans l'enveloppe. `htaccess-*` en ont : ils sont construits par
/// `site recommend` et `site command … htaccess-rollback` ([`HtaccessApply`],
/// [`HtaccessRollback`]).
pub fn params_json(kind: CommandKind) -> Option<String> {
    match kind {
        CommandKind::Ping | CommandKind::RotateKey => {
            Some(serde_json::to_string(&NoParams::default()).unwrap_or_else(|_| "{}".into()))
        }
        CommandKind::HtaccessApply | CommandKind::HtaccessRollback => None,
    }
}

/// Chemin du `.htaccess` dans les empreintes de l'agent (`critical`).
pub const HTACCESS: &str = ".htaccess";

/// `htaccess-apply` (#13). `previous_sha256` : empreinte du `.htaccess` lue
/// dans le dernier rapport (`null` : fichier absent) ; l'agent refuse si le
/// fichier ne l'a plus. `new_sha256` : empreinte du contenu que l'agent
/// calcule ; `null` demande ce calcul seulement, sans rien écrire (le
/// veilleur ne connaît que des empreintes et ne peut pas la calculer).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HtaccessApply {
    pub block: String,
    pub previous_sha256: Option<String>,
    pub new_sha256: Option<String>,
}

/// `htaccess-rollback` (#13) : remet la copie privée de l'agent si elle a
/// `prev_sha256` (`null` : le fichier n'existait pas, il est supprimé) et si
/// le `.htaccess` a encore `expected_current_sha256`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HtaccessRollback {
    pub expected_current_sha256: Option<String>,
    pub prev_sha256: Option<String>,
}

/// Empreintes du `.htaccess` qu'une commande `htaccess-*` peut laisser :
/// `htaccess-apply` le nouveau contenu ou, après un retour automatique,
/// l'ancien ; `htaccess-rollback` la copie remise ou, refusé, l'actuel. Un
/// calcul seul (`new_sha256` nul) n'écrit rien : aucune.
pub fn htaccess_expected(kind: CommandKind, params: &str) -> Vec<String> {
    match kind {
        CommandKind::HtaccessApply => match serde_json::from_str::<HtaccessApply>(params) {
            Ok(p) if p.new_sha256.is_some() => {
                p.new_sha256.into_iter().chain(p.previous_sha256).collect()
            }
            _ => Vec::new(),
        },
        CommandKind::HtaccessRollback => serde_json::from_str::<HtaccessRollback>(params)
            .map(|p| {
                p.prev_sha256
                    .into_iter()
                    .chain(p.expected_current_sha256)
                    .collect()
            })
            .unwrap_or_default(),
        CommandKind::Ping | CommandKind::RotateKey => Vec::new(),
    }
}

/// SHA-256 en hexadécimal minuscule.
pub fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Issue d'une commande, déclarée par l'agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    Failed,
    Refused,
}

/// Résultat renvoyé par l'agent dans un retrait.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandResult {
    pub command_id: String,
    pub status: Status,
    pub detail: String,
    /// Propre à la commande : vide pour `ping`, nouvelle clé et preuve pour
    /// `rotate-key`.
    #[serde(default)]
    pub data: ResultData,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ResultData {
    /// `rotate-key` : nouvelle clé publique de rapport, base64.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_pubkey: Option<String>,
    /// `rotate-key` : signature par la nouvelle clé de
    /// `vigie-rotate-v1\n<site>\n<id>\n<nouvelle clé>`, base64.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    /// `htaccess-*` : empreinte du `.htaccess` après la commande, quelle
    /// que soit son issue (absente : fichier absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_sha256: Option<String>,
    /// `htaccess-apply` en calcul seul : empreinte du contenu calculé.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_sha256: Option<String>,
}

/// « Imprimable » au sens du protocole : aucun caractère de contrôle.
pub fn printable(value: &str, max: usize) -> bool {
    !value.is_empty() && value.chars().count() <= max && !value.chars().any(char::is_control)
}

/// Texte venu d'un site, neutralisé pour un terminal : caractères de
/// contrôle remplacés.
pub fn neutralize(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { '�' } else { c })
        .collect()
}

/// UUIDv7 (RFC 9562) : 48 bits d'heure en ms, version, variante, 74 bits
/// aléatoires.
pub fn uuid_v7(unix_ms: i64) -> anyhow::Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes[6..])
        .map_err(|err| anyhow::anyhow!("tirage aléatoire impossible : {err}"))?;
    let ms = u64::try_from(unix_ms.max(0)).unwrap_or(0) & 0xffff_ffff_ffff;
    bytes[..6].copy_from_slice(&ms.to_be_bytes()[2..]);
    bytes[6] = 0x70 | (bytes[6] & 0x0f);
    bytes[8] = 0x80 | (bytes[8] & 0x3f);
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

/// UUIDv7 bien formé (minuscules, version 7, variante RFC 9562).
pub fn is_uuid_v7(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, &b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        })
        && bytes[14] == b'7'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
}

/// Enveloppe d'une commande servie (`protocole-commandes.md`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Envelope {
    pub v: u8,
    pub site: String,
    pub id: String,
    pub seq: i64,
    pub name: &'static str,
    pub runtime: String,
    pub params: serde_json::Value,
    pub issued_at: i64,
    pub expires_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_documented_transitions_are_allowed() {
        use State::*;
        let allowed = [
            (Pending, Served),
            (Pending, Expired),
            (Pending, Cancelled),
            (Pending, Refused),
            (Served, Done),
            (Served, Failed),
            (Served, Refused),
            (Served, Cancelled),
            (Served, Unknown),
            (Unknown, Done),
            (Unknown, Failed),
        ];
        for from in State::ALL {
            for to in State::ALL {
                assert_eq!(
                    from.can_become(to),
                    allowed.contains(&(from, to)),
                    "{from:?} → {to:?}"
                );
            }
        }
        for state in State::ALL {
            assert_eq!(State::parse(state.as_str()), Some(state));
        }
    }

    #[test]
    fn uuids_are_version_7_and_ordered_by_time() {
        let a = uuid_v7(1_792_108_800_000).unwrap();
        let b = uuid_v7(1_792_108_800_001).unwrap();
        assert!(is_uuid_v7(&a), "{a}");
        assert!(a < b);
        assert!(a.starts_with("01a1"), "{a}");
        assert_ne!(uuid_v7(0).unwrap(), uuid_v7(0).unwrap());
        assert!(!is_uuid_v7("0192f5a8-7c3e-4d41-9b2a-5c1e8f0a4b6d"));
        assert!(!is_uuid_v7("0192F5A8-7C3E-7D41-9B2A-5C1E8F0A4B6D"));
    }

    #[test]
    fn results_are_strict() {
        let ok: CommandResult =
            serde_json::from_str(r#"{"command_id":"x","status":"ok","detail":"pong"}"#).unwrap();
        assert_eq!(ok.data, ResultData::default());
        assert!(
            serde_json::from_str::<CommandResult>(
                r#"{"command_id":"x","status":"ok","detail":"d","shell":"id"}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<CommandResult>(
                r#"{"command_id":"x","status":"ok","detail":"d","data":{"cmd":"id"}}"#
            )
            .is_err()
        );
        assert_eq!(neutralize("a\u{1b}[2Jb"), "a�[2Jb");
        assert!(!printable("a\nb", 10));
    }
}
