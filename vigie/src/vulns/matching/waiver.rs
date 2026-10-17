//! Dérogations (`docs/failles.md`, « Dérogations ») : par site, source
//! d'inventaire, purl sans version, faille et version vue par cette source,
//! jamais globales ; motivées ; 90 jours au plus ; interdites pour une
//! faille dont un CVE est dans KEV.
//!
//! Une dérogation sort son groupe du calcul de gravité : le groupe reste
//! listé « sous dérogation jusqu'au … », et l'incident reste ouvert en
//! information s'il ne reste rien d'autre. Elle devient caduque à son
//! échéance, quand la version de la source change, quand un CVE du groupe
//! entre dans KEV, ou quand un identifiant ou un alias hors de
//! `covered_ids` rejoint le groupe (« groupe changé » : un simple alias
//! nouveau publié par une source suffit).

use std::collections::BTreeSet;

use crate::inventory::Source;
use crate::vulns::UsageError;

use super::assess::{GroupResult, State};

/// Échéance la plus lointaine, en jours.
pub const MAX_DAYS: i64 = 90;
/// Longueur maximale d'un motif, en caractères.
pub const MAX_REASON_CHARS: usize = 500;

/// Dérogation relue, motif compris (il ne sort que par la CLI).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Waiver {
    pub id: i64,
    pub source: Source,
    /// Clé du constat : purl canonique sans version.
    pub base: String,
    /// Identifiant ou alias saisi, normalisé.
    pub advisory_ref: String,
    /// Version vue par la source à la saisie.
    pub version: String,
    /// Identifiants et alias du groupe à la saisie.
    pub covered_ids: BTreeSet<String>,
    pub until: i64,
    pub reason: String,
}

/// Validité d'une dérogation pour un groupe et une version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applies {
    Ok,
    Expired,
    VersionChanged,
    GroupChanged,
    Kev,
}

impl Applies {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ok => "valide",
            Self::Expired => "expirée",
            Self::VersionChanged => "caduque : version changée",
            Self::GroupChanged => "caduque : groupe changé",
            Self::Kev => "caduque : faille exploitée (KEV)",
        }
    }

    /// Valeur de l'API (`waiver.state`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "valid",
            Self::Expired => "expired",
            Self::VersionChanged => "version_changed",
            Self::GroupChanged => "group_changed",
            Self::Kev => "kev",
        }
    }
}

/// Échéance et motif, vérifiés **avant** toute lecture de la base :
/// échéance future, à 90 jours au plus ; motif de 1 à 500 caractères.
pub fn validate(until: i64, reason: &str, now: i64) -> Result<(), UsageError> {
    if until <= now {
        return Err(UsageError("échéance dans le passé".into()));
    }
    if until > now + MAX_DAYS * 86_400 {
        return Err(UsageError(format!(
            "échéance au-delà de {MAX_DAYS} jours : une dérogation se renouvelle, elle ne dure pas"
        )));
    }
    let n = reason.trim().chars().count();
    if n == 0 || n > MAX_REASON_CHARS {
        return Err(UsageError(format!(
            "motif obligatoire, {MAX_REASON_CHARS} caractères au plus (reçu : {n})"
        )));
    }
    Ok(())
}

/// Le groupe et la version admettent-ils une dérogation ? Version connue,
/// groupe touché ou inconnu, aucun CVE dans KEV.
pub fn validate_against(group: &GroupResult, version: Option<&str>) -> Result<(), UsageError> {
    if group.kev.is_some() {
        return Err(UsageError(
            "faille exploitée (KEV) : dérogation interdite".into(),
        ));
    }
    if version.is_none() || group.state == State::VersionUnknown {
        return Err(UsageError(
            "version inconnue : une dérogation exige une version ; acquitter l'incident avec `vigie ack <incident>`".into(),
        ));
    }
    Ok(())
}

impl Waiver {
    /// La dérogation vise-t-elle ce groupe ? Son identifiant saisi en est
    /// un identifiant ou un alias.
    pub fn targets(&self, group: &GroupResult) -> bool {
        group.ids.contains(&self.advisory_ref)
    }

    /// Validité pour le groupe vu à `version` par la source de la
    /// dérogation.
    pub fn applies(&self, group: &GroupResult, version: Option<&str>, now: i64) -> Applies {
        if now >= self.until {
            Applies::Expired
        } else if group.kev.is_some() {
            Applies::Kev
        } else if version != Some(self.version.as_str()) {
            Applies::VersionChanged
        } else if group.ids.iter().any(|id| !self.covered_ids.contains(id)) {
            Applies::GroupChanged
        } else {
            Applies::Ok
        }
    }
}
