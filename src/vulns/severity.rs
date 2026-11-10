//! Règle de gravité des failles (issue #18, F4), seule de Vigie : F7 (#21)
//! l'appelle telle quelle pour chaque faille, chaque groupe fusionné et
//! chaque inconnue. Transcription littérale du tableau « Gravité » de
//! `docs/failles.md` (F0, révisé le 2026-10-17) ; les seuils sont des
//! décisions écrites dans `docs/decisions.md`, pas des réglages.
//!
//! Fonctions pures : aucune lecture de base, d'horloge ni de configuration.
//! Les tables KEV et EPSS arrivent par le trait [`Exploitation`]. Aucun
//! flottant : score en dixièmes entiers ([`Score::tenths`]), EPSS en
//! millionièmes entiers.

use crate::finding::Severity;
use crate::vulns::advisory::{Advisory, Score};
use crate::vulns::exploit::{Cve, EpssFact, Exploitation, KevFact, TablesState};
use crate::vulns::range::UnknownReason;

/// CVSS ≥ 9,0 : critique.
pub const CVSS_CRITICAL_TENTHS: u8 = 90;
/// CVSS ≥ 7,0 : avertissement.
pub const CVSS_WARNING_TENTHS: u8 = 70;
/// EPSS ≥ 0,1 : avertissement.
pub const EPSS_WARNING_PPM: u32 = 100_000;

/// Ce que la règle sait d'une faille.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryFacts {
    pub id: String,
    /// Identifiant s'il est un CVE, puis alias CVE, dédoublonnés.
    pub cves: Vec<Cve>,
    /// Entrée `MAL-` (paquet malveillant).
    pub malicious: bool,
    /// Score déjà choisi par `Score::select` de F1.
    pub score: Option<Score>,
    /// Wordfence `informational: true`.
    pub informational: bool,
    /// Correctif connu pour la version installée (verdict de F7) ; affiché,
    /// n'entre dans aucune règle.
    pub fix_available: bool,
}

impl AdvisoryFacts {
    pub fn from_advisory(advisory: &Advisory, fix_available: bool) -> Self {
        let mut cves: Vec<Cve> = Vec::new();
        for raw in std::iter::once(&advisory.id).chain(&advisory.aliases) {
            if let Some(cve) = Cve::parse(raw)
                && !cves.contains(&cve)
            {
                cves.push(cve);
            }
        }
        Self {
            id: advisory.id.clone(),
            cves,
            malicious: advisory.malicious,
            score: advisory.score,
            informational: advisory.informational,
            fix_available,
        }
    }
}

/// Règle qui a fixé la gravité, dans l'ordre où elles se lisent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rule {
    Kev,
    Malicious,
    CvssCritical,
    CvssHigh,
    Epss,
    UnknownSeverity,
    Informational,
    Default,
}

impl Rule {
    /// Nom stable (constats de F7).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Kev => "kev",
            Self::Malicious => "malicious",
            Self::CvssCritical => "cvss_critical",
            Self::CvssHigh => "cvss_high",
            Self::Epss => "epss",
            Self::UnknownSeverity => "unknown_severity",
            Self::Informational => "informational",
            Self::Default => "default",
        }
    }

    /// Libellé de la CLI et des e-mails.
    pub fn label(self) -> &'static str {
        match self {
            Self::Kev => "exploitée (CISA KEV)",
            Self::Malicious => "paquet malveillant",
            Self::CvssCritical => "CVSS ≥ 9,0",
            Self::CvssHigh => "CVSS ≥ 7,0",
            Self::Epss => "EPSS ≥ 0,1",
            Self::UnknownSeverity => "gravité inconnue",
            Self::Informational => "informational (Wordfence)",
            Self::Default => "aucune règle",
        }
    }
}

/// Gravité d'une faille ou d'un groupe, et ce qui l'explique.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    pub severity: Severity,
    pub rule: Rule,
    /// Identifiant du membre retenu (la faille elle-même hors groupe).
    pub member: String,
    /// Fait KEV retenu : `dateAdded` le plus ancien, `known_ransomware` vrai
    /// si l'un des CVE l'est.
    pub kev: Option<(Cve, KevFact)>,
    /// Plus haut score EPSS parmi les CVE, et son percentile.
    pub epss: Option<(Cve, EpssFact)>,
    pub score: Option<Score>,
    /// Aucun correctif connu : affiché, ne baisse jamais la gravité.
    pub no_fix: bool,
    pub tables: TablesState,
}

/// Règle d'une inconnue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownRule {
    VersionUnknown,
    RangeUnknown,
}

impl UnknownRule {
    pub fn label(self) -> &'static str {
        match self {
            Self::VersionUnknown => "version inconnue",
            Self::RangeUnknown => "plage inconnue",
        }
    }
}

/// Gravité d'une inconnue (« version inconnue », « plage inconnue »).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownAssessment {
    pub severity: Severity,
    pub rule: UnknownRule,
}

/// Les huit règles de F0, lues de haut en bas, la première tranche :
///
/// | Gravité | Condition |
/// | --- | --- |
/// | critique | un CVE dans KEV, ou entrée `MAL-`, ou CVSS ≥ 9,0 |
/// | avertissement | CVSS ≥ 7,0, ou EPSS ≥ 0,1, ou gravité inconnue (sauf `informational` sans score) |
/// | information | tout le reste |
///
/// `informational` ne déclasse qu'une faille qu'aucune règle critique ou
/// d'avertissement ne retient ; `fix_available` n'entre nulle part.
fn rules(facts: &AdvisoryFacts, in_kev: bool, epss_ppm: Option<u32>) -> (Severity, Rule) {
    let tenths = facts.score.map(|s| s.tenths);
    match (in_kev, facts.malicious, tenths, epss_ppm) {
        (true, ..) => (Severity::Critical, Rule::Kev),
        (_, true, ..) => (Severity::Critical, Rule::Malicious),
        (_, _, Some(t), _) if t >= CVSS_CRITICAL_TENTHS => (Severity::Critical, Rule::CvssCritical),
        (_, _, Some(t), _) if t >= CVSS_WARNING_TENTHS => (Severity::Warning, Rule::CvssHigh),
        (_, _, _, Some(p)) if p >= EPSS_WARNING_PPM => (Severity::Warning, Rule::Epss),
        (_, _, None, _) if !facts.informational => (Severity::Warning, Rule::UnknownSeverity),
        (_, _, None, _) => (Severity::Info, Rule::Informational),
        _ => (Severity::Info, Rule::Default),
    }
}

/// Faits KEV et EPSS retenus, avec leur CVE.
type Facts = (Option<(Cve, KevFact)>, Option<(Cve, EpssFact)>);

/// Faits KEV et EPSS d'un ensemble de CVE.
fn lookup(cves: &[Cve], tables: &impl Exploitation) -> Facts {
    let mut kev: Option<(Cve, KevFact)> = None;
    let mut epss: Option<(Cve, EpssFact)> = None;
    for cve in cves {
        if let Some(fact) = tables.kev(cve) {
            kev = Some(match kev.take() {
                None => (cve.clone(), fact),
                Some((kept, held)) => {
                    let ransomware = held.known_ransomware || fact.known_ransomware;
                    let (cve, mut fact) = if fact.date_added < held.date_added {
                        (cve.clone(), fact)
                    } else {
                        (kept, held)
                    };
                    fact.known_ransomware = ransomware;
                    (cve, fact)
                }
            });
        }
        if let Some(fact) = tables.epss(cve)
            && epss
                .as_ref()
                .is_none_or(|(_, e)| fact.epss_ppm > e.epss_ppm)
        {
            epss = Some((cve.clone(), fact));
        }
    }
    (kev, epss)
}

/// Gravité d'une faille seule.
pub fn assess(facts: &AdvisoryFacts, tables: &impl Exploitation) -> Assessment {
    let (kev, epss) = lookup(&facts.cves, tables);
    let (severity, rule) = rules(facts, kev.is_some(), epss.as_ref().map(|(_, e)| e.epss_ppm));
    Assessment {
        severity,
        rule,
        member: facts.id.clone(),
        kev,
        epss,
        score: facts.score,
        no_fix: !facts.fix_available,
        tables: tables.state(),
    }
}

/// Gravité d'un groupe de failles fusionnées par F7 (une même faille vue
/// par plusieurs sources) : KEV et EPSS cherchés sur l'union dédoublonnée
/// des CVE ; chaque membre évalué avec ses propres `malicious`, score et
/// `informational` et ces faits communs ; gravité = maximum ; règle, score
/// et membre = ceux du premier membre (ordre reçu) qui l'atteint. `None`
/// pour un groupe vide.
pub fn assess_group(members: &[AdvisoryFacts], tables: &impl Exploitation) -> Option<Assessment> {
    let mut cves: Vec<Cve> = Vec::new();
    for cve in members.iter().flat_map(|m| &m.cves) {
        if !cves.contains(cve) {
            cves.push(cve.clone());
        }
    }
    let (kev, epss) = lookup(&cves, tables);
    let epss_ppm = epss.as_ref().map(|(_, e)| e.epss_ppm);
    let mut best: Option<(Severity, Rule, &AdvisoryFacts)> = None;
    for m in members {
        let (severity, rule) = rules(m, kev.is_some(), epss_ppm);
        if best.is_none_or(|(s, ..)| severity > s) {
            best = Some((severity, rule, m));
        }
    }
    let (severity, rule, member) = best?;
    Some(Assessment {
        severity,
        rule,
        member: member.id.clone(),
        kev,
        epss,
        score: member.score,
        no_fix: members.iter().all(|m| !m.fix_available),
        tables: tables.state(),
    })
}

/// Gravité d'une inconnue sur une faille déjà évaluée : avertissement si
/// la faille est critique (KEV, `MAL-`, CVSS ≥ 9,0), information sinon.
/// F7 prend le maximum par composant.
pub fn assess_unknown(reason: UnknownReason, advisory: &Assessment) -> UnknownAssessment {
    let rule = match reason {
        UnknownReason::VersionUnknown => UnknownRule::VersionUnknown,
        UnknownReason::RangeUnknown => UnknownRule::RangeUnknown,
    };
    let severity = if advisory.severity == Severity::Critical {
        Severity::Warning
    } else {
        Severity::Info
    };
    UnknownAssessment { severity, rule }
}
