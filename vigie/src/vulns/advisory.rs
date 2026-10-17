//! Modèle interne d'une faille : sous-ensemble strict d'OSV 1.9.x, validé et
//! borné (`docs/failles.md`, « Modèle interne et versions »).
//!
//! Une seule porte d'entrée : [`Advisory::build`], appelée par
//! [`from_osv`] et par les convertisseurs de F3 (Wordfence,
//! Friends-Of-Presta), qui remplissent un [`Draft`] de champs bruts.
//!
//! **Aucune suppression silencieuse d'un paquet identifié.** Chaque écart
//! est compté dans un [`Tally`] par [`Reason`], sans texte de la source :
//!
//! - faille entière écartée : `too_large`, `bad_json`, `bad_id`, `bad_date`,
//!   `withdrawn`, `duplicate_id` (compté par le chargement), `no_affected` ;
//! - un `affected` écarté : `bad_purl` (nom hors grammaire),
//!   `out_of_scope` (autre écosystème) ;
//! - ligne gardée et marquée `unevaluable` (verdict « plage inconnue ») :
//!   plage malformée, plus de 256 plages, plus de 128 événements ;
//! - faille gardée, licence inconnue : `unknown_license` ;
//! - entrée ignorée seule : `bad_version_entry`, `bad_reference`,
//!   `bad_severity`, `bad_last_known`, `bad_alias`, `bad_cwe` ; écart entre
//!   `package.purl` d'OSV et le purl calculé : `purl_mismatch` (le purl
//!   calculé l'emporte).

use std::collections::BTreeMap;

use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};

use crate::api::log_text::LogText;
use crate::vulns::cvss::{self, CvssVersion};
use crate::vulns::purl::{self, FromOsvError, Purl};
use crate::vulns::version::{Scheme, SourceEcosystem, in_grammar, parse, parse_bound};

/// Taille maximale d'une entrée OSV (mesure : 1 148 610 o au plus).
pub const MAX_ENTRY_BYTES: usize = 4 * 1024 * 1024;
/// `affected` par faille (mesure : 406).
pub const MAX_AFFECTED: usize = 1024;
/// Plages par ligne `affected` (mesure : 6) ; au-delà, ligne `unevaluable`.
pub const MAX_RANGES: usize = 256;
/// Événements par plage (mesure : 46) ; au-delà, plage malformée.
pub const MAX_EVENTS: usize = 128;
/// Entrées de `versions[]` par ligne (mesure : 2 340).
pub const MAX_VERSIONS: usize = 10_000;
/// Alias par faille (mesure : 16).
pub const MAX_ALIASES: usize = 32;
/// Références gardées (toutes sont lues).
pub const MAX_REFERENCES: usize = 10;
/// Longueur maximale d'une URL de référence.
pub const MAX_URL_CHARS: usize = 2048;
/// Entrées de `severity[]` (mesure : 2).
pub const MAX_SEVERITIES: usize = 4;
/// CWE par faille (mesure : 6).
pub const MAX_CWES: usize = 8;
/// Longueur maximale d'un identifiant (mesure : 23).
pub const MAX_ID_CHARS: usize = 64;
/// Licence d'un préfixe absent de [`licence_for_id`].
pub const LICENSE_UNKNOWN: &str = "inconnue";

/// Raison d'un écart, compté sans texte de la source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    TooLarge,
    BadJson,
    BadId,
    BadDate,
    UnknownLicense,
    DuplicateId,
    NoAffected,
    /// Faille dont **chaque** `affected` est d'un autre écosystème (GHSA
    /// multi-écosystèmes dans le mauvais export) : attendu, compté à part
    /// et hors du taux d'écart de F2, comme `out_of_scope` et `withdrawn`.
    NoAffectedOutOfScope,
    /// Nom d'entrée de l'archive illisible (compté par F2, qui lit le ZIP).
    BadEntryName,
    Withdrawn,
    BadPurl,
    OutOfScope,
    Unevaluable,
    BadVersionEntry,
    BadReference,
    BadSeverity,
    BadLastKnown,
    PurlMismatch,
    BadAlias,
    BadCwe,
    /// Tables KEV et EPSS (F4) : identifiant hors de la grammaire CVE du
    /// schéma KEV.
    BadCve,
    /// Tables KEV et EPSS : nombre illisible ou hors de `[0, 1]`.
    BadValue,
    /// Tables KEV et EPSS : champ requis absent.
    MissingField,
    /// Tables KEV et EPSS : CVE déjà vu dans le même chargement.
    Duplicate,
    /// KEV : `knownRansomwareCampaignUse` ni `Known` ni `Unknown`, lu
    /// « non ».
    UnknownRansomware,
    /// KEV : `count` différent du nombre d'entrées.
    CountMismatch,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TooLarge => "too_large",
            Self::BadJson => "bad_json",
            Self::BadId => "bad_id",
            Self::BadDate => "bad_date",
            Self::UnknownLicense => "unknown_license",
            Self::DuplicateId => "duplicate_id",
            Self::NoAffected => "no_affected",
            Self::NoAffectedOutOfScope => "no_affected_out_of_scope",
            Self::BadEntryName => "bad_entry_name",
            Self::Withdrawn => "withdrawn",
            Self::BadPurl => "bad_purl",
            Self::OutOfScope => "out_of_scope",
            Self::Unevaluable => "unevaluable",
            Self::BadVersionEntry => "bad_version_entry",
            Self::BadReference => "bad_reference",
            Self::BadSeverity => "bad_severity",
            Self::BadLastKnown => "bad_last_known",
            Self::PurlMismatch => "purl_mismatch",
            Self::BadAlias => "bad_alias",
            Self::BadCwe => "bad_cwe",
            Self::BadCve => "bad_cve",
            Self::BadValue => "bad_value",
            Self::MissingField => "missing_field",
            Self::Duplicate => "duplicate",
            Self::UnknownRansomware => "unknown_ransomware",
            Self::CountMismatch => "count_mismatch",
        }
    }

    /// Perte de la faille entière pour une anomalie : le numérateur du taux
    /// d'écart de F2 est la somme de ces raisons. Sinon, simple note : ligne
    /// ou entrée écartée seule, ou exclusion normale (`withdrawn`, faille
    /// d'un autre écosystème `no_affected_out_of_scope`). Sans joker : une
    /// raison ajoutée (F3) ne compile pas sans son classement. Pour KEV et
    /// EPSS (F4), une ligne perdue est un écart (`bad_cve`, `bad_date`,
    /// `bad_value`, `missing_field`, `duplicate`) ; `unknown_ransomware` et
    /// `count_mismatch` ne sont que des notes.
    pub fn is_drop(self) -> bool {
        match self {
            Self::TooLarge
            | Self::BadJson
            | Self::BadId
            | Self::BadDate
            | Self::DuplicateId
            | Self::NoAffected
            | Self::BadEntryName
            | Self::BadCve
            | Self::BadValue
            | Self::MissingField
            | Self::Duplicate => true,
            Self::Withdrawn
            | Self::NoAffectedOutOfScope
            | Self::BadPurl
            | Self::OutOfScope
            | Self::UnknownLicense
            | Self::Unevaluable
            | Self::BadVersionEntry
            | Self::BadReference
            | Self::BadSeverity
            | Self::BadLastKnown
            | Self::PurlMismatch
            | Self::BadAlias
            | Self::BadCwe
            | Self::UnknownRansomware
            | Self::CountMismatch => false,
        }
    }

    /// Toutes les raisons, dans l'ordre d'affichage.
    pub const ALL: [Reason; 26] = [
        Self::TooLarge,
        Self::BadJson,
        Self::BadId,
        Self::BadDate,
        Self::UnknownLicense,
        Self::DuplicateId,
        Self::NoAffected,
        Self::NoAffectedOutOfScope,
        Self::BadEntryName,
        Self::Withdrawn,
        Self::BadPurl,
        Self::OutOfScope,
        Self::Unevaluable,
        Self::BadVersionEntry,
        Self::BadReference,
        Self::BadSeverity,
        Self::BadLastKnown,
        Self::PurlMismatch,
        Self::BadAlias,
        Self::BadCwe,
        Self::BadCve,
        Self::BadValue,
        Self::MissingField,
        Self::Duplicate,
        Self::UnknownRansomware,
        Self::CountMismatch,
    ];
}

/// Compteurs par raison.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Tally(BTreeMap<Reason, u64>);

impl Tally {
    pub fn add(&mut self, reason: Reason) {
        *self.0.entry(reason).or_default() += 1;
    }

    pub fn get(&self, reason: Reason) -> u64 {
        self.0.get(&reason).copied().unwrap_or(0)
    }

    pub fn merge(&mut self, other: &Tally) {
        for (r, n) in &other.0 {
            *self.0.entry(*r).or_default() += n;
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (Reason, u64)> + '_ {
        self.0.iter().map(|(r, n)| (*r, *n))
    }

    /// Failles entières perdues pour une anomalie ([`Reason::is_drop`]).
    pub fn dropped(&self) -> u64 {
        self.iter()
            .filter(|(r, _)| r.is_drop())
            .map(|(_, n)| n)
            .sum()
    }
}

/// Identifiants déjà vus dans un même chargement : un id en double écarte
/// la seconde faille, comptée `duplicate_id`.
#[derive(Debug, Default)]
pub struct Seen(std::collections::HashSet<String>);

impl Seen {
    /// `true` si la faille est nouvelle ; sinon compte `duplicate_id`.
    pub fn first(&mut self, advisory: &Advisory, tally: &mut Tally) -> bool {
        if self.0.insert(advisory.id.clone()) {
            true
        } else {
            tally.add(Reason::DuplicateId);
            false
        }
    }
}

/// Origine du score retenu (ordre de F0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScoreOrigin {
    Wordfence,
    FriendsOfPresta,
    CvssV31,
    GhsaSeverity,
}

impl ScoreOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wordfence => "wordfence",
            Self::FriendsOfPresta => "friends_of_presta",
            Self::CvssV31 => "cvss_v31",
            Self::GhsaSeverity => "ghsa_severity",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "wordfence" => Some(Self::Wordfence),
            "friends_of_presta" => Some(Self::FriendsOfPresta),
            "cvss_v31" => Some(Self::CvssV31),
            "ghsa_severity" => Some(Self::GhsaSeverity),
            _ => None,
        }
    }
}

/// Score CVSS retenu, en dixièmes entiers (98 pour 9,8), sur [0, 100] :
/// aucun flottant ne sort du modèle (les seuils de F7 comparent à 90 et 70).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Score {
    pub tenths: u8,
    pub origin: ScoreOrigin,
}

/// Score décimal écrit par une source (Wordfence `cvss.score`,
/// Friends-Of-Presta) en dixièmes : `9.8` → 98, `10` → 100. Refusés : plus
/// d'une décimale, plus de 10,0, signe, exposant, espaces.
pub fn parse_tenths(raw: &str) -> Option<u8> {
    let (int, frac) = match raw.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (raw, None),
    };
    let digits = |s: &str, max: usize| {
        !s.is_empty() && s.len() <= max && s.bytes().all(|b| b.is_ascii_digit())
    };
    if !digits(int, 2) || frac.is_some_and(|f| !digits(f, 1)) {
        return None;
    }
    let tenths = int.parse::<u16>().ok()? * 10 + frac.map_or(Some(0), |f| f.parse::<u16>().ok())?;
    u8::try_from(tenths).ok().filter(|t| *t <= 100)
}

impl Score {
    /// Score d'une source, depuis son texte décimal.
    pub fn from_text(raw: &str, origin: ScoreOrigin) -> Option<Score> {
        parse_tenths(raw).map(|tenths| Score { tenths, origin })
    }

    /// Ordre de F0 : score fourni par la source (Wordfence, puis
    /// Friends-Of-Presta), puis CVSS v3 calculé depuis le premier vecteur
    /// valide, puis `database_specific.severity` des GHSA (9, 7, 5, 3).
    pub fn select(
        provided: Option<Score>,
        severity: &[Severity],
        ghsa_severity: Option<&str>,
    ) -> Option<Score> {
        if provided.is_some() {
            return provided;
        }
        if let Some(tenths) = severity.iter().find_map(|s| s.score) {
            return Some(Score {
                tenths,
                origin: ScoreOrigin::CvssV31,
            });
        }
        let tenths = match ghsa_severity? {
            "CRITICAL" => 90,
            "HIGH" => 70,
            "MODERATE" => 50,
            "LOW" => 30,
            _ => return None,
        };
        Some(Score {
            tenths,
            origin: ScoreOrigin::GhsaSeverity,
        })
    }
}

/// Entrée validée de `severity[]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Severity {
    /// `CVSS_V3` ou `CVSS_V4`.
    #[serde(rename = "type")]
    pub kind: String,
    pub vector: String,
    /// Score de base calculé, en dixièmes (v3 seulement).
    pub score: Option<u8>,
}

/// Référence gardée.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reference {
    /// `ADVISORY`, `FIX` ou `WEB`.
    #[serde(rename = "type")]
    pub kind: String,
    pub url: String,
}

/// Événement d'une plage, au format OSV (`{"introduced": "0"}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    Introduced(String),
    Fixed(String),
    LastAffected(String),
    Limit(String),
}

impl Event {
    pub fn value(&self) -> &str {
        match self {
            Self::Introduced(v) | Self::Fixed(v) | Self::LastAffected(v) | Self::Limit(v) => v,
        }
    }
}

/// Plage évaluable : chaque borne s'analyse avec `scheme`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Range {
    /// Schéma de la ligne, ou `semver` pour une plage OSV `SEMVER`.
    pub scheme: Scheme,
    pub events: Vec<Event>,
}

/// `last_known_affected_version_range` : `< v` ou `<= v`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastKnown {
    pub inclusive: bool,
    pub version: String,
}

/// Ligne `affected` pour un purl.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Affected {
    /// purl sans version.
    pub purl: Purl,
    /// Comparateur de l'écosystème de la source.
    pub scheme: Scheme,
    /// Plages évaluables seulement.
    pub ranges: Vec<Range>,
    /// Versions énumérées analysables par `scheme`.
    pub versions: Vec<String>,
    pub last_known: Option<LastKnown>,
    /// Une plage au moins était malformée, ou aucune plage ni version n'est
    /// retenue : verdict « plage inconnue » à défaut d'être touché.
    pub unevaluable: bool,
}

/// Faille validée et bornée.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advisory {
    pub id: String,
    pub aliases: Vec<String>,
    /// Assaini, 500 caractères au plus ; vide si la source n'en donne pas.
    pub summary: String,
    pub severity: Vec<Severity>,
    pub score: Option<Score>,
    /// Wordfence `informational: true`.
    pub informational: bool,
    /// `MAL-` en identifiant ou en alias : paquet malveillant.
    pub malicious: bool,
    /// Identifiant SPDX, ou [`LICENSE_UNKNOWN`].
    pub license: String,
    /// Assainie, 2 000 caractères au plus.
    pub attribution: String,
    pub cwe: Vec<String>,
    /// Secondes Unix.
    pub published: Option<i64>,
    pub modified: i64,
    pub references: Vec<Reference>,
    pub source_url: String,
    pub affected: Vec<Affected>,
}

/// Événement brut.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DraftEvent {
    Introduced(String),
    Fixed(String),
    LastAffected(String),
    Limit(String),
    /// Zéro ou plusieurs clés, clé inconnue ou valeur non textuelle.
    Malformed,
}

/// Plage brute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftRange {
    /// `ECOSYSTEM`, `SEMVER` ou `GIT` (ignorée) ; tout autre type est une
    /// plage malformée.
    pub kind: String,
    pub events: Vec<DraftEvent>,
}

/// Ligne `affected` brute : un ou deux purl partagent les mêmes plages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftAffected {
    pub purls: Vec<Purl>,
    pub scheme: Scheme,
    pub ranges: Vec<DraftRange>,
    /// `None` : entrée non textuelle.
    pub versions: Vec<Option<String>>,
    pub last_known: Option<String>,
}

/// Faille brute, avant validation.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Draft {
    pub id: String,
    pub aliases: Vec<String>,
    pub summary: Option<String>,
    /// Lu pour le repli du résumé, jamais stocké.
    pub details: Option<String>,
    pub published: Option<String>,
    pub modified: Option<String>,
    pub affected: Vec<DraftAffected>,
    /// `(type, vecteur)` de `severity[]`.
    pub severity: Vec<(String, String)>,
    /// `database_specific.severity` des GHSA.
    pub ghsa_severity: Option<String>,
    /// Score de la source (F3) : Wordfence `cvss.score`, Friends-Of-Presta.
    pub provided_score: Option<Score>,
    pub cwe: Vec<String>,
    /// `(type, url)` de `references[]`.
    pub references: Vec<(String, String)>,
    pub informational: bool,
    /// Licence imposée par la source (F3) ; sinon d'après le préfixe.
    pub license: Option<String>,
    /// Attribution de la source (F3, `copyrights` de Wordfence) ; sinon
    /// d'après le préfixe.
    pub attribution: Option<String>,
    pub source_url: Option<String>,
}

/// Licence d'un enregistrement OSV d'après le préfixe de son identifiant
/// (`docs/data.md` de `google/osv.dev`). Table fermée.
pub fn licence_for_id(id: &str) -> Option<&'static str> {
    match id.split_once('-')?.0 {
        "GHSA" | "EEF" => Some("CC-BY-4.0"),
        "DRUPAL" => Some("MIT"),
        "MAL" => Some("Apache-2.0"),
        "RUSTSEC" => Some("CC0-1.0"),
        _ => None,
    }
}

/// Lien OSV.dev d'un enregistrement.
pub fn osv_url(id: &str) -> String {
    format!("https://osv.dev/vulnerability/{id}")
}

/// Attribution d'un enregistrement OSV d'après son préfixe.
fn default_attribution(id: &str) -> String {
    let osv = osv_url(id);
    match id.split_once('-').map(|(p, _)| p) {
        Some("GHSA") => {
            format!("GitHub Advisory Database, CC-BY 4.0 : https://github.com/advisories/{id}")
        }
        Some("RUSTSEC") => {
            format!("RustSec Advisory Database, CC0 1.0 : https://rustsec.org/advisories/{id}.html")
        }
        Some("DRUPAL") => format!("Drupal Advisory Database, MIT, via OSV.dev : {osv}"),
        Some("MAL") => format!("OpenSSF Malicious Packages, Apache-2.0, via OSV.dev : {osv}"),
        Some("EEF") => format!("EEF, CC-BY 4.0, via OSV.dev : {osv}"),
        _ => format!("OSV.dev (licence inconnue) : {osv}"),
    }
}

/// Identifiant ou alias : `[A-Za-z0-9][A-Za-z0-9._:-]{0,63}`.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_CHARS
        && id.starts_with(|c: char| c.is_ascii_alphanumeric())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

/// Préfixes connus mis en majuscules dans un alias (`cve-` → `CVE-`).
const KNOWN_PREFIXES: [&str; 9] = [
    "CVE", "GHSA", "RUSTSEC", "MAL", "DRUPAL", "EEF", "PYSEC", "GO", "OSV",
];

/// Alias normalisé, `None` s'il est hors grammaire. Sert aussi à chercher
/// une faille par alias.
pub fn normalize_alias(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if !valid_id(raw) {
        return None;
    }
    if let Some((prefix, rest)) = raw.split_once('-') {
        let upper = prefix.to_ascii_uppercase();
        if KNOWN_PREFIXES.contains(&upper.as_str()) {
            return Some(format!("{upper}-{rest}"));
        }
    }
    Some(raw.to_owned())
}

fn parse_time(raw: &str) -> Option<i64> {
    raw.parse::<jiff::Timestamp>().ok().map(|t| t.as_second())
}

/// URL http ou https, sans identifiants, 2 048 caractères au plus.
fn valid_url(raw: &str) -> bool {
    if raw.len() > MAX_URL_CHARS {
        return false;
    }
    let Ok(url) = url::Url::parse(raw) else {
        return false;
    };
    matches!(url.scheme(), "http" | "https")
        && url.username().is_empty()
        && url.password().is_none()
        && url.host().is_some()
        && !raw.chars().any(|c| c.is_control() || c.is_whitespace())
}

fn cwe(raw: &str) -> Option<String> {
    let digits = raw.strip_prefix("CWE-")?;
    (!digits.is_empty() && digits.len() <= 6 && digits.bytes().all(|b| b.is_ascii_digit()))
        .then(|| raw.to_owned())
}

/// `< v` ou `<= v`.
fn last_known(raw: &str, scheme: Scheme) -> Option<LastKnown> {
    let raw = raw.trim();
    let (inclusive, v) = if let Some(v) = raw.strip_prefix("<=") {
        (true, v)
    } else {
        (false, raw.strip_prefix('<')?)
    };
    let v = v.trim();
    parse(scheme, v).ok()?;
    Some(LastKnown {
        inclusive,
        version: v.to_owned(),
    })
}

/// Plage brute → plage évaluable, ou `None` si elle est malformée.
fn build_range(r: &DraftRange, line_scheme: Scheme) -> Option<Range> {
    let scheme = match r.kind.as_str() {
        "ECOSYSTEM" => line_scheme,
        "SEMVER" => Scheme::Semver,
        _ => return None,
    };
    if r.events.is_empty() || r.events.len() > MAX_EVENTS {
        return None;
    }
    let mut events = Vec::with_capacity(r.events.len() + 1);
    for e in &r.events {
        let event = match e {
            DraftEvent::Introduced(v) => {
                parse_bound(scheme, v).ok()?;
                Event::Introduced(v.clone())
            }
            DraftEvent::Fixed(v) => {
                parse(scheme, v).ok()?;
                Event::Fixed(v.clone())
            }
            DraftEvent::LastAffected(v) => {
                parse(scheme, v).ok()?;
                Event::LastAffected(v.clone())
            }
            // `limit: "*"` : aucune limite.
            DraftEvent::Limit(v) if v == "*" => continue,
            DraftEvent::Limit(v) => {
                parse(scheme, v).ok()?;
                Event::Limit(v.clone())
            }
            DraftEvent::Malformed => return None,
        };
        events.push(event);
    }
    // `fixed` sans `introduced` : plancher ajouté.
    if !events.iter().any(|e| matches!(e, Event::Introduced(_))) {
        events.insert(0, Event::Introduced("0".to_owned()));
    }
    Some(Range { scheme, events })
}

fn build_lines(a: &DraftAffected, tally: &mut Tally) -> Vec<Affected> {
    let mut unevaluable = a.ranges.len() > MAX_RANGES;
    let mut ranges = Vec::new();
    for r in a.ranges.iter().take(MAX_RANGES) {
        if r.kind == "GIT" {
            continue;
        }
        match build_range(r, a.scheme) {
            Some(range) => ranges.push(range),
            None => unevaluable = true,
        }
    }
    let mut versions = Vec::new();
    for (i, v) in a.versions.iter().enumerate() {
        match v {
            Some(v) if i < MAX_VERSIONS && parse(a.scheme, v).is_ok() => versions.push(v.clone()),
            _ => tally.add(Reason::BadVersionEntry),
        }
    }
    let last_known = a.last_known.as_deref().and_then(|raw| {
        let lk = last_known(raw, a.scheme);
        if lk.is_none() {
            tally.add(Reason::BadLastKnown);
        }
        lk
    });
    if ranges.is_empty() && versions.is_empty() {
        // Ni plage ni version : rien ne dit quelles versions sont touchées.
        unevaluable = true;
    }
    a.purls
        .iter()
        .map(|purl| {
            if unevaluable {
                tally.add(Reason::Unevaluable);
            }
            Affected {
                purl: purl.without_version(),
                scheme: a.scheme,
                ranges: ranges.clone(),
                versions: versions.clone(),
                last_known: last_known.clone(),
                unevaluable,
            }
        })
        .collect()
}

impl Advisory {
    /// Seule validation d'une faille. Rend la raison si la faille entière
    /// est écartée (déjà comptée dans `tally`).
    pub fn build(draft: Draft, tally: &mut Tally) -> Result<Advisory, Reason> {
        let result = Self::build_inner(draft, tally);
        if let Err(reason) = result {
            tally.add(reason);
        }
        result
    }

    fn build_inner(draft: Draft, tally: &mut Tally) -> Result<Advisory, Reason> {
        if !valid_id(&draft.id) {
            return Err(Reason::BadId);
        }
        let id = draft.id;
        let modified = draft
            .modified
            .as_deref()
            .and_then(parse_time)
            .ok_or(Reason::BadDate)?;
        let published = draft.published.as_deref().and_then(parse_time);
        if draft.affected.len() > MAX_AFFECTED {
            return Err(Reason::TooLarge);
        }

        let mut affected = Vec::new();
        for a in &draft.affected {
            affected.extend(build_lines(a, tally));
        }
        if affected.is_empty() {
            return Err(Reason::NoAffected);
        }

        let mut aliases: Vec<String> = Vec::new();
        for raw in &draft.aliases {
            match normalize_alias(raw) {
                Some(a) if a == id || aliases.contains(&a) => {}
                Some(a) if aliases.len() < MAX_ALIASES => aliases.push(a),
                _ => tally.add(Reason::BadAlias),
            }
        }
        let malicious = id.starts_with("MAL-") || aliases.iter().any(|a| a.starts_with("MAL-"));

        let summary = draft
            .summary
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or_else(|| {
                draft
                    .details
                    .as_deref()
                    .and_then(|d| d.lines().map(str::trim).find(|l| !l.is_empty()))
            })
            .map(|s| String::from(LogText::summary(s)))
            .unwrap_or_default();

        let license = match draft.license.as_deref() {
            Some(l) => String::from(LogText::new(l, 64)),
            None => match licence_for_id(&id) {
                Some(l) => l.to_owned(),
                None => {
                    tally.add(Reason::UnknownLicense);
                    LICENSE_UNKNOWN.to_owned()
                }
            },
        };
        let attribution = String::from(LogText::attribution(
            &draft
                .attribution
                .clone()
                .unwrap_or_else(|| default_attribution(&id)),
        ));
        let source_url = match draft.source_url {
            Some(u) if valid_url(&u) => u,
            Some(_) => {
                tally.add(Reason::BadReference);
                osv_url(&id)
            }
            None => osv_url(&id),
        };

        let mut severity = Vec::new();
        for (kind, vector) in &draft.severity {
            let want = match kind.as_str() {
                "CVSS_V3" => [CvssVersion::V30, CvssVersion::V31].as_slice(),
                "CVSS_V4" => [CvssVersion::V40].as_slice(),
                // CVSS_V2, Ubuntu… : hors du modèle.
                _ => continue,
            };
            match cvss::parse(vector) {
                Some(c) if want.contains(&c.version) && severity.len() < MAX_SEVERITIES => {
                    severity.push(Severity {
                        kind: kind.clone(),
                        vector: vector.clone(),
                        score: c.base_score,
                    });
                }
                _ => tally.add(Reason::BadSeverity),
            }
        }
        let provided = match draft.provided_score {
            Some(s) if s.tenths <= 100 => Some(s),
            Some(_) => {
                tally.add(Reason::BadSeverity);
                None
            }
            None => None,
        };
        let score = Score::select(provided, &severity, draft.ghsa_severity.as_deref());

        let mut cwes = Vec::new();
        for raw in &draft.cwe {
            match cwe(raw) {
                Some(c) if cwes.contains(&c) => {}
                Some(c) if cwes.len() < MAX_CWES => cwes.push(c),
                _ => tally.add(Reason::BadCwe),
            }
        }

        let mut refs: Vec<(usize, Reference)> = Vec::new();
        for (kind, url) in &draft.references {
            let rank = match kind.as_str() {
                "ADVISORY" => 0,
                "FIX" => 1,
                "WEB" => 2,
                _ => continue,
            };
            if valid_url(url) {
                refs.push((
                    rank,
                    Reference {
                        kind: kind.clone(),
                        url: url.clone(),
                    },
                ));
            } else {
                tally.add(Reason::BadReference);
            }
        }
        refs.sort_by_key(|(rank, _)| *rank);
        let references = refs
            .into_iter()
            .map(|(_, r)| r)
            .take(MAX_REFERENCES)
            .collect();

        Ok(Advisory {
            id,
            aliases,
            summary,
            severity,
            score,
            informational: draft.informational,
            malicious,
            license,
            attribution,
            cwe: cwes,
            published,
            modified,
            references,
            source_url,
            affected,
        })
    }

    /// Lignes de ce purl (sans version).
    pub fn lines_for<'a>(&'a self, purl: &Purl) -> Vec<&'a Affected> {
        let key = purl.without_version();
        self.affected.iter().filter(|a| a.purl == key).collect()
    }
}

/// Champ facultatif d'un type quelconque : la valeur si c'est le type
/// attendu, sinon ignorée sans casser l'enregistrement. Réservé aux petits
/// champs (une valeur `untagged` est mise en tampon) ; les gros objets
/// `database_specific` sont lus champ à champ, le reste ignoré sans copie.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Lenient<T> {
    Ok(T),
    Other(IgnoredAny),
}

impl<T> Lenient<T> {
    fn ok(self) -> Option<T> {
        match self {
            Self::Ok(v) => Some(v),
            Self::Other(_) => None,
        }
    }
}

#[derive(Deserialize)]
struct OsvRecord {
    id: Option<String>,
    modified: Option<String>,
    published: Option<String>,
    withdrawn: Option<IgnoredAny>,
    #[serde(default)]
    aliases: Vec<Lenient<String>>,
    summary: Option<String>,
    details: Option<String>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
    #[serde(default)]
    severity: Vec<OsvPair>,
    #[serde(default)]
    references: Vec<OsvReference>,
    database_specific: Option<OsvDatabaseSpecific>,
}

#[derive(Deserialize)]
struct OsvDatabaseSpecific {
    severity: Option<Lenient<String>>,
    cwe_ids: Option<Lenient<Vec<Lenient<String>>>>,
}

#[derive(Deserialize)]
struct OsvPair {
    #[serde(rename = "type")]
    kind: Option<Lenient<String>>,
    score: Option<Lenient<String>>,
}

#[derive(Deserialize)]
struct OsvReference {
    #[serde(rename = "type")]
    kind: Option<Lenient<String>>,
    url: Option<Lenient<String>>,
}

#[derive(Deserialize)]
struct OsvPackage {
    ecosystem: Option<String>,
    name: Option<String>,
    purl: Option<Lenient<String>>,
}

#[derive(Deserialize)]
struct OsvAffected {
    package: Option<OsvPackage>,
    #[serde(default)]
    ranges: Vec<OsvRange>,
    #[serde(default)]
    versions: Vec<Lenient<String>>,
    database_specific: Option<OsvAffectedSpecific>,
}

#[derive(Deserialize)]
struct OsvAffectedSpecific {
    last_known_affected_version_range: Option<Lenient<String>>,
}

#[derive(Deserialize)]
struct OsvRange {
    #[serde(rename = "type")]
    kind: Option<Lenient<String>>,
    #[serde(default)]
    events: Vec<BTreeMap<String, Lenient<String>>>,
}

fn draft_event(mut map: BTreeMap<String, Lenient<String>>) -> DraftEvent {
    if map.len() != 1 {
        return DraftEvent::Malformed;
    }
    let (key, value) = map.pop_first().expect("une clé");
    let Some(value) = value.ok() else {
        return DraftEvent::Malformed;
    };
    match key.as_str() {
        "introduced" => DraftEvent::Introduced(value),
        "fixed" => DraftEvent::Fixed(value),
        "last_affected" => DraftEvent::LastAffected(value),
        "limit" => DraftEvent::Limit(value),
        _ => DraftEvent::Malformed,
    }
}

/// Une entrée d'un export OSV (`dump` : écosystème de l'export). Rend la
/// faille validée, ou la raison de son écart ; chaque écart est compté dans
/// `tally`.
pub fn from_osv(
    bytes: &[u8],
    dump: SourceEcosystem,
    tally: &mut Tally,
) -> Result<Advisory, Reason> {
    let drop = |tally: &mut Tally, r: Reason| {
        tally.add(r);
        Err(r)
    };
    if bytes.len() > MAX_ENTRY_BYTES {
        return drop(tally, Reason::TooLarge);
    }
    let Ok(record) = serde_json::from_slice::<OsvRecord>(bytes) else {
        return drop(tally, Reason::BadJson);
    };
    if record.withdrawn.is_some() {
        return drop(tally, Reason::Withdrawn);
    }
    let Some(dump_name) = dump.osv_name() else {
        return drop(tally, Reason::OutOfScope);
    };
    if record.affected.len() > MAX_AFFECTED {
        return drop(tally, Reason::TooLarge);
    }
    let scheme = dump.scheme();
    let mut affected = Vec::new();
    let (mut foreign, mut unidentified) = (0usize, 0usize);
    for a in record.affected {
        let (Some(ecosystem), Some(name)) = a.package.as_ref().map_or((None, None), |p| {
            (p.ecosystem.as_deref(), p.name.as_deref())
        }) else {
            tally.add(Reason::BadPurl);
            unidentified += 1;
            continue;
        };
        if ecosystem != dump_name {
            tally.add(Reason::OutOfScope);
            foreign += 1;
            continue;
        }
        let purls = match purl::from_osv(ecosystem, name) {
            Ok(p) => p,
            Err(FromOsvError::OutOfScope) => {
                tally.add(Reason::OutOfScope);
                foreign += 1;
                continue;
            }
            Err(FromOsvError::BadName) => {
                tally.add(Reason::BadPurl);
                unidentified += 1;
                continue;
            }
        };
        if let Some(given) =
            a.package
                .as_ref()
                .and_then(|p| p.purl.as_ref())
                .and_then(|p| match p {
                    Lenient::Ok(s) => Some(s.clone()),
                    Lenient::Other(_) => None,
                })
        {
            let same = match (Purl::parse(&given), purl::osv_base(ecosystem, name)) {
                (Ok(g), Ok(base)) => g.without_version() == base,
                _ => false,
            };
            if !same {
                tally.add(Reason::PurlMismatch);
            }
        }
        let last_known = a
            .database_specific
            .and_then(|d| d.last_known_affected_version_range)
            .and_then(Lenient::ok);
        affected.push(DraftAffected {
            purls,
            scheme,
            ranges: a
                .ranges
                .into_iter()
                .map(|r| DraftRange {
                    kind: r.kind.and_then(Lenient::ok).unwrap_or_default(),
                    events: r.events.into_iter().map(draft_event).collect(),
                })
                .collect(),
            versions: a
                .versions
                .into_iter()
                .map(|v| v.ok().filter(|v| in_grammar(v)))
                .collect(),
            last_known,
        });
    }
    if affected.is_empty() && foreign > 0 && unidentified == 0 {
        return drop(tally, Reason::NoAffectedOutOfScope);
    }
    let db = record.database_specific;
    let (ghsa_severity, cwe) = match db {
        Some(db) => (
            db.severity.and_then(Lenient::ok),
            db.cwe_ids
                .and_then(Lenient::ok)
                .unwrap_or_default()
                .into_iter()
                .map(|c| c.ok().unwrap_or_default())
                .collect(),
        ),
        None => (None, Vec::new()),
    };
    let draft = Draft {
        id: record.id.unwrap_or_default(),
        aliases: record
            .aliases
            .into_iter()
            .map(|a| a.ok().unwrap_or_default())
            .collect(),
        summary: record.summary,
        details: record.details,
        published: record.published,
        modified: record.modified,
        affected,
        severity: record
            .severity
            .into_iter()
            .map(|s| {
                (
                    s.kind.and_then(Lenient::ok).unwrap_or_default(),
                    s.score.and_then(Lenient::ok).unwrap_or_default(),
                )
            })
            .collect(),
        ghsa_severity,
        provided_score: None,
        cwe,
        references: record
            .references
            .into_iter()
            .map(|r| {
                (
                    r.kind.and_then(Lenient::ok).unwrap_or_default(),
                    r.url.and_then(Lenient::ok).unwrap_or_default(),
                )
            })
            .collect(),
        informational: false,
        license: None,
        attribution: None,
        source_url: None,
    };
    Advisory::build(draft, tally)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn licences_by_prefix() {
        assert_eq!(licence_for_id("GHSA-aaaa-bbbb-cccc"), Some("CC-BY-4.0"));
        assert_eq!(licence_for_id("EEF-CVE-2026-1"), Some("CC-BY-4.0"));
        assert_eq!(licence_for_id("DRUPAL-CORE-2026-001"), Some("MIT"));
        assert_eq!(licence_for_id("MAL-2026-1"), Some("Apache-2.0"));
        assert_eq!(licence_for_id("RUSTSEC-2026-0001"), Some("CC0-1.0"));
        assert_eq!(licence_for_id("ZZZ-1"), None);
        assert_eq!(licence_for_id("ghsa-aaaa"), None);
        assert_eq!(licence_for_id("GHSA"), None);
    }

    #[test]
    fn reasons_are_classified() {
        let drops: Vec<&str> = Reason::ALL
            .iter()
            .filter(|r| r.is_drop())
            .map(|r| r.as_str())
            .collect();
        assert_eq!(
            drops,
            [
                "too_large",
                "bad_json",
                "bad_id",
                "bad_date",
                "duplicate_id",
                "no_affected",
                "bad_entry_name",
                "bad_cve",
                "bad_value",
                "missing_field",
                "duplicate"
            ]
        );
        for r in Reason::ALL {
            // Nom sérialisé identique à `as_str`.
            assert_eq!(serde_json::to_value(r).unwrap(), r.as_str());
        }
        let mut t = Tally::default();
        t.add(Reason::Withdrawn);
        t.add(Reason::NoAffectedOutOfScope);
        t.add(Reason::BadId);
        t.add(Reason::BadPurl);
        assert_eq!(t.dropped(), 1);
    }

    #[test]
    fn decimal_scores_become_tenths() {
        assert_eq!(parse_tenths("9.8"), Some(98));
        assert_eq!(parse_tenths("10.0"), Some(100));
        assert_eq!(parse_tenths("10"), Some(100));
        assert_eq!(parse_tenths("0"), Some(0));
        assert_eq!(parse_tenths("7.5"), Some(75));
        for bad in [
            "9.85", "10.1", "11", "-1", "+9.8", "9.8e0", "1e1", " 9.8", "9.", ".8", "", "100",
        ] {
            assert_eq!(parse_tenths(bad), None, "{bad:?}");
        }
        assert_eq!(
            Score::from_text("9.8", ScoreOrigin::Wordfence),
            Some(Score {
                tenths: 98,
                origin: ScoreOrigin::Wordfence
            })
        );
    }

    #[test]
    fn aliases_are_normalized() {
        assert_eq!(normalize_alias("cve-2026-1").as_deref(), Some("CVE-2026-1"));
        assert_eq!(normalize_alias("Ghsa-abcd").as_deref(), Some("GHSA-abcd"));
        assert_eq!(normalize_alias("autre-1").as_deref(), Some("autre-1"));
        assert_eq!(normalize_alias("cve 1"), None);
    }

    #[test]
    fn last_known_forms() {
        assert_eq!(
            last_known("< 2.0.0", Scheme::Semver),
            Some(LastKnown {
                inclusive: false,
                version: "2.0.0".into()
            })
        );
        assert_eq!(
            last_known("<= 1.2", Scheme::Composer).map(|l| l.inclusive),
            Some(true)
        );
        assert_eq!(last_known(">= 1.0", Scheme::Composer), None);
    }
}
