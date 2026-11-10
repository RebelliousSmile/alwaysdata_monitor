//! Gravité d'un groupe par la seule règle de F4 (`vulns/severity.rs`) :
//! `assess_group` pour un groupe touché, `assess_unknown(raison,
//! assess_group(..))` pour un groupe inconnu. Aucun seuil n'est comparé
//! ici.
//!
//! Les faits de chaque membre ([`MemberFacts`]) sont gardés en base avec le
//! résultat : une table KEV ou EPSS qui change fait réévaluer la gravité
//! ([`reassess`]) sans relire une plage. Un membre porte l'identifiant de
//! sa source, jamais une copie de l'attribution, relue à l'affichage.

use serde::{Deserialize, Serialize};

use crate::finding::Severity;
use crate::vulns::advisory::{Score, ScoreOrigin};
use crate::vulns::exploit::{Cve, Exploitation};
use crate::vulns::range::UnknownReason;
use crate::vulns::severity::{AdvisoryFacts, assess_group, assess_unknown};
use crate::vulns::sources::Redistribution;
use crate::vulns::sync::registry;

use super::group::{Group, GroupVerdict};

/// Faits d'un membre, sérialisés en base (`vuln_match_items.members`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberFacts {
    pub id: String,
    /// Source de failles : l'attribution se relit par elle.
    pub source: String,
    pub cves: Vec<String>,
    pub malicious: bool,
    /// Score en dixièmes.
    pub score: Option<u8>,
    pub score_origin: Option<String>,
    pub informational: bool,
    pub fix_available: bool,
    /// Plage corrigée par l'exploitant (F3).
    pub corrected: bool,
    /// Lien vers l'avis.
    pub link: String,
}

impl MemberFacts {
    fn from_member(m: &super::group::Member) -> Self {
        Self {
            id: m.id.clone(),
            source: m.source.clone(),
            cves: m.facts.cves.iter().map(|c| c.as_str().to_owned()).collect(),
            malicious: m.facts.malicious,
            score: m.facts.score.map(|s| s.tenths),
            score_origin: m.facts.score.map(|s| s.origin.as_str().to_owned()),
            informational: m.facts.informational,
            fix_available: m.facts.fix_available,
            corrected: m.corrected,
            link: m.link.clone(),
        }
    }

    /// Faits de la règle de gravité.
    pub fn facts(&self) -> AdvisoryFacts {
        let score = match (self.score, self.score_origin.as_deref()) {
            (Some(tenths), Some(origin)) => {
                ScoreOrigin::from_name(origin).map(|origin| Score { tenths, origin })
            }
            _ => None,
        };
        AdvisoryFacts {
            id: self.id.clone(),
            cves: self.cves.iter().filter_map(|c| Cve::parse(c)).collect(),
            malicious: self.malicious,
            score,
            informational: self.informational,
            fix_available: self.fix_available,
        }
    }
}

/// État d'un groupe gardé : un groupe non touché n'est pas gardé.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Affected,
    VersionUnknown,
    RangeUnknown,
}

impl State {
    /// Valeur de l'API (`verdict`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Affected => "affected",
            Self::VersionUnknown => "version_unknown",
            Self::RangeUnknown => "range_unknown",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "affected" => Some(Self::Affected),
            "version_unknown" => Some(Self::VersionUnknown),
            "range_unknown" => Some(Self::RangeUnknown),
            _ => None,
        }
    }

    /// Libellé de la CLI, des e-mails et du détail.
    pub fn label(self) -> &'static str {
        match self {
            Self::Affected => "touché",
            Self::VersionUnknown => "version inconnue",
            Self::RangeUnknown => "plage inconnue",
        }
    }
}

/// Fait KEV retenu pour un groupe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KevInfo {
    pub cve: String,
    /// `AAAA-MM-JJ`.
    pub date_added: String,
    pub ransomware: bool,
}

/// Fait EPSS retenu pour un groupe, en millionièmes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpssInfo {
    pub epss_ppm: u32,
    pub percentile_ppm: u32,
}

/// Groupe évalué pour un composant : ce qui est gardé en base et affiché.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupResult {
    pub key: String,
    /// Identifiants et alias de tous les membres (couverture d'une
    /// dérogation).
    pub ids: Vec<String>,
    pub members: Vec<MemberFacts>,
    pub state: State,
    pub divergence: bool,
    /// Correctif du groupe ; vide : aucun correctif.
    pub fixed: Vec<String>,
    pub severity: Severity,
    /// Règle de F4 (`Rule::as_str`), ou `version_unknown`, `range_unknown`.
    pub rule: String,
    pub kev: Option<KevInfo>,
    pub epss: Option<EpssInfo>,
    /// Score retenu, en dixièmes.
    pub score: Option<u8>,
    pub redistribution: Redistribution,
}

impl GroupResult {
    /// Une plage corrigée par l'exploitant porte un membre.
    pub fn corrected(&self) -> bool {
        self.members.iter().any(|m| m.corrected)
    }
}

/// Niveau de redistribution d'un groupe : le plus restrictif de ses
/// sources ; une source inconnue du binaire vaut « interne ».
pub fn redistribution<'a>(sources: impl IntoIterator<Item = &'a str>) -> Redistribution {
    sources
        .into_iter()
        .map(|s| registry::redistribution(s).unwrap_or(Redistribution::Internal))
        .fold(Redistribution::Free, Redistribution::most_restrictive)
}

/// Gravité, règle et faits d'exploitation de membres déjà connus.
fn evaluate(
    members: &[MemberFacts],
    state: State,
    tables: &impl Exploitation,
) -> (
    Severity,
    String,
    Option<KevInfo>,
    Option<EpssInfo>,
    Option<u8>,
) {
    let facts: Vec<AdvisoryFacts> = members.iter().map(MemberFacts::facts).collect();
    let Some(a) = assess_group(&facts, tables) else {
        return (Severity::Info, "default".into(), None, None, None);
    };
    let kev = a.kev.as_ref().map(|(cve, fact)| KevInfo {
        cve: cve.as_str().to_owned(),
        date_added: fact.date_added.to_string(),
        ransomware: fact.known_ransomware,
    });
    let epss = a.epss.as_ref().map(|(_, fact)| EpssInfo {
        epss_ppm: fact.epss_ppm,
        percentile_ppm: fact.percentile_ppm,
    });
    let score = a.score.map(|s| s.tenths);
    let (severity, rule) = match state {
        State::Affected => (a.severity, a.rule.as_str().to_owned()),
        State::VersionUnknown => (
            assess_unknown(UnknownReason::VersionUnknown, &a).severity,
            "version_unknown".to_owned(),
        ),
        State::RangeUnknown => (
            assess_unknown(UnknownReason::RangeUnknown, &a).severity,
            "range_unknown".to_owned(),
        ),
    };
    (severity, rule, kev, epss, score)
}

/// Groupe évalué ; `None` pour un groupe non touché.
pub fn assess(group: &Group, tables: &impl Exploitation) -> Option<GroupResult> {
    let (state, divergence, fixed) = match &group.verdict {
        GroupVerdict::NotAffected => return None,
        GroupVerdict::Affected { fixed, divergence } => {
            (State::Affected, *divergence, fixed.clone())
        }
        GroupVerdict::Unknown(UnknownReason::VersionUnknown) => {
            (State::VersionUnknown, false, Vec::new())
        }
        GroupVerdict::Unknown(UnknownReason::RangeUnknown) => {
            (State::RangeUnknown, false, Vec::new())
        }
    };
    let members: Vec<MemberFacts> = group.members.iter().map(MemberFacts::from_member).collect();
    let (severity, rule, kev, epss, score) = evaluate(&members, state, tables);
    Some(GroupResult {
        key: group.key.clone(),
        ids: group.ids.iter().cloned().collect(),
        redistribution: redistribution(members.iter().map(|m| m.source.as_str())),
        members,
        state,
        divergence,
        fixed,
        severity,
        rule,
        kev,
        epss,
        score,
    })
}

/// Même groupe, gravité recalculée sur ses faits gardés : KEV ou EPSS ont
/// changé, les plages ne sont pas relues.
pub fn reassess(previous: &GroupResult, tables: &impl Exploitation) -> GroupResult {
    let (severity, rule, kev, epss, score) = evaluate(&previous.members, previous.state, tables);
    GroupResult {
        severity,
        rule,
        kev,
        epss,
        score,
        ..previous.clone()
    }
}
