//! Wordfence Intelligence v3, flux `production` (WordPress : extensions,
//! thèmes, noyau). Fiche, conditions et limites : `docs/failles.md`,
//! « Wordfence Intelligence v3 ».
//!
//! **Lecture en flux.** ≈ 123 Mo de JSON : ni l'arbre entier ni le corps en
//! mémoire. Le flux est un objet dont chaque clé est l'UUID d'une faille ;
//! chaque valeur est lue en [`RawValue`] (4 Mio au plus, compteur d'octets en
//! couche externe remis à zéro avant chaque clé), puis décodée seule.
//!
//! **Trois périmètres d'erreur.**
//!
//! - flux : syntaxe JSON, valeur trop grosse, trop d'entrées → chargement
//!   abandonné (le cadre de F2 garde la génération active) ;
//! - faille : `id` et `software[].type` / `slug` seuls sont stricts, une
//!   forme inattendue écarte la faille (`bad_record`) ;
//! - champ : tout autre champ est décodé à part ; `null`, `[]` et `{}` valent
//!   « vide » (le `json_encode` de PHP écrit un tableau associatif vide en
//!   `[]`), un échec retire ce seul champ avec sa raison. Une plage illisible
//!   rend sa ligne `unevaluable`, jamais la faille écartée.
//!
//! **Verrou de relecture.** L'import reste refusé tant que
//! [`WORDFENCE_TERMS_REVIEWED`] vaut `None` : la constante ne change que dans
//! le commit qui consigne la relecture des conditions dans `failles.md`.

use std::collections::BTreeMap;
use std::io::Read;
use std::time::Instant;

use serde::Deserialize;
use serde::de::{DeserializeOwned, MapAccess, Visitor};
use serde_json::value::RawValue;

use super::Redistribution;
use crate::api::log_text::MAX_ATTRIBUTION_CHARS;
use crate::vulns::advisory::{
    Advisory, Draft, DraftAffected, DraftEvent, DraftRange, MAX_ENTRY_BYTES, Reason, Score,
    ScoreOrigin, Seen, Tally, parse_tenths,
};
use crate::vulns::purl::{Purl, PurlType};
use crate::vulns::sync::{Sink, SyncError};
use crate::vulns::version::{Scheme, parse};

/// Date de la relecture des conditions Wordfence depuis le VPS, consignée
/// dans `docs/failles.md` (« Relecture des conditions depuis le VPS ») ;
/// `None` tant qu'elle n'est pas faite. Change seulement dans le commit qui
/// la consigne (test `terms_review_matches_failles_md`).
pub const WORDFENCE_TERMS_REVIEWED: Option<&str> = None;
/// Usage interne à l'exploitant tant que les conditions n'ont pas tranché
/// l'affichage aux clients.
pub const REDISTRIBUTION: Redistribution = Redistribution::Internal;
/// Licence portée par chaque faille ; la licence exacte est dans
/// l'attribution (`copyrights`).
pub const LICENSE: &str = "Wordfence-Intelligence";
/// Mention fixe quand `copyrights` est vide, absent ou trop long.
pub const FIXED_ATTRIBUTION: &str = "Wordfence Intelligence, © Defiant Inc.";
/// Entrées du flux au plus (mesure : à relever sur le VPS).
pub const MAX_ENTRIES: u64 = 200_000;
/// Libellé repéré dans `failles.md` par le test de cohérence du verrou.
pub const REVIEW_LINE: &str = "Relecture des conditions depuis le VPS";

/// Lien de l'enregistrement, reproduit avec l'attribution.
pub fn record_url(uuid: &str) -> String {
    format!("https://www.wordfence.com/threat-intel/vulnerabilities/id/{uuid}")
}

/// UUID canonique en minuscules (`8-4-4-4-12` hexadécimaux), sinon `None`.
fn uuid(raw: &str) -> Option<String> {
    let lower = raw.to_ascii_lowercase();
    let ok = lower.len() == 36
        && lower.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        });
    ok.then_some(lower)
}

/// Présent, même à `null` : distingue « absent » de « vide ».
fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Box<RawValue>>, D::Error> {
    Box::<RawValue>::deserialize(d).map(Some)
}

/// Enregistrement : `id` et `software[]` stricts, le reste brut.
#[derive(Deserialize)]
struct WfRecord {
    id: String,
    software: Vec<WfSoftware>,
    #[serde(default, deserialize_with = "present")]
    title: Option<Box<RawValue>>,
    #[serde(default, deserialize_with = "present")]
    cve: Option<Box<RawValue>>,
    #[serde(default, deserialize_with = "present")]
    cvss: Option<Box<RawValue>>,
    #[serde(default, deserialize_with = "present")]
    cwe: Option<Box<RawValue>>,
    #[serde(default, deserialize_with = "present")]
    references: Option<Box<RawValue>>,
    #[serde(default, deserialize_with = "present")]
    copyrights: Option<Box<RawValue>>,
    #[serde(default, deserialize_with = "present")]
    informational: Option<Box<RawValue>>,
    #[serde(default, deserialize_with = "present")]
    published: Option<Box<RawValue>>,
    #[serde(default, deserialize_with = "present")]
    updated: Option<Box<RawValue>>,
}

#[derive(Deserialize)]
struct WfSoftware {
    #[serde(rename = "type")]
    kind: String,
    slug: String,
    #[serde(default, deserialize_with = "present")]
    affected_versions: Option<Box<RawValue>>,
    #[serde(default, deserialize_with = "present")]
    patched: Option<Box<RawValue>>,
    #[serde(default, deserialize_with = "present")]
    patched_versions: Option<Box<RawValue>>,
}

#[derive(Deserialize)]
struct WfRange {
    from_version: String,
    to_version: String,
    /// Lu pour mémoire : une borne basse exclusive est traduite en
    /// inclusive (signalement de trop plutôt qu'en moins).
    #[serde(default)]
    #[allow(dead_code)]
    from_inclusive: Option<bool>,
    #[serde(default)]
    to_inclusive: Option<bool>,
}

#[derive(Deserialize)]
struct WfCvss {
    #[serde(default, deserialize_with = "present")]
    vector: Option<Box<RawValue>>,
    #[serde(default, deserialize_with = "present")]
    score: Option<Box<RawValue>>,
}

#[derive(Deserialize)]
struct WfCwe {
    id: u32,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

/// Champ secondaire décodé.
enum Field<T> {
    Absent,
    /// `null`, `[]` ou `{}`.
    Empty,
    Value(T),
    Bad,
}

/// `null`, `[]`, `{}` (espaces compris).
fn is_empty_json(raw: &RawValue) -> bool {
    let text = raw.get();
    text.len() <= 16
        && matches!(
            text.chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
                .as_str(),
            "null" | "[]" | "{}"
        )
}

fn field<T: DeserializeOwned>(raw: Option<&RawValue>) -> Field<T> {
    let Some(raw) = raw else {
        return Field::Absent;
    };
    if is_empty_json(raw) {
        return Field::Empty;
    }
    serde_json::from_str(raw.get()).map_or(Field::Bad, Field::Value)
}

/// Date RFC 3339, ou `AAAA-MM-JJ hh:mm:ss` lue en UTC, réécrite en RFC 3339.
fn wf_date(raw: &str) -> Option<String> {
    if let Ok(t) = raw.parse::<jiff::Timestamp>() {
        return Some(t.to_string());
    }
    let (date, time) = raw.split_once(' ')?;
    if date.len() != 10 || time.len() != 8 {
        return None;
    }
    let civil: jiff::civil::DateTime = format!("{date}T{time}").parse().ok()?;
    let zoned = civil.to_zoned(jiff::tz::TimeZone::UTC).ok()?;
    Some(zoned.timestamp().to_string())
}

/// Date d'un champ : `Some(Ok)` lisible, `Some(Err)` présente et illisible.
fn date_field(raw: Option<&RawValue>) -> Option<Result<String, ()>> {
    match field::<String>(raw) {
        Field::Absent | Field::Empty => None,
        Field::Value(s) => Some(wf_date(s.trim()).ok_or(())),
        Field::Bad => Some(Err(())),
    }
}

/// Événements d'un libellé de `affected_versions` : `*` en bas → plancher,
/// en haut → plage ouverte ; `to_inclusive` → `last_affected`, sinon
/// `fixed`. Borne basse au-dessus de la haute → plage malformée.
fn range_events(r: &WfRange) -> Vec<DraftEvent> {
    let (from, to) = (r.from_version.trim(), r.to_version.trim());
    let inclusive = r.to_inclusive.unwrap_or(true);
    if from != "*"
        && to != "*"
        && let (Ok(a), Ok(b)) = (parse(Scheme::Php, from), parse(Scheme::Php, to))
        && (a > b || (a == b && !inclusive))
    {
        return vec![DraftEvent::Malformed];
    }
    let mut events = vec![DraftEvent::Introduced(if from == "*" {
        "0".to_owned()
    } else {
        from.to_owned()
    })];
    if to != "*" {
        events.push(if inclusive {
            DraftEvent::LastAffected(to.to_owned())
        } else {
            DraftEvent::Fixed(to.to_owned())
        });
    }
    events
}

/// Ligne `affected` d'un `software[]`, ou la raison de son écart.
fn software_line(s: &WfSoftware, tally: &mut Tally) -> Result<DraftAffected, Reason> {
    let purl = match s.kind.as_str() {
        "plugin" | "theme" => Purl::new(PurlType::Wordpress, Some(&s.kind), s.slug.trim(), None)
            .map_err(|_| Reason::BadPurl)?,
        "core" => Purl::new(PurlType::Wordpress, Some("core"), "core", None)
            .map_err(|_| Reason::BadPurl)?,
        _ => return Err(Reason::OutOfScope),
    };
    let mut ranges: Vec<DraftRange> =
        match field::<BTreeMap<String, Box<RawValue>>>(s.affected_versions.as_deref()) {
            Field::Value(map) => map
                .values()
                .map(|raw| DraftRange {
                    kind: "ECOSYSTEM".into(),
                    events: match serde_json::from_str::<WfRange>(raw.get()) {
                        Ok(r) => range_events(&r),
                        Err(_) => vec![DraftEvent::Malformed],
                    },
                })
                .collect(),
            // Vide ou illisible : ni plage ni version, ligne `unevaluable`.
            Field::Absent | Field::Empty | Field::Bad => Vec::new(),
        };
    let patched = matches!(field::<bool>(s.patched.as_deref()), Field::Value(true));
    if patched && let Field::Value(list) = field::<Vec<String>>(s.patched_versions.as_deref()) {
        let mut versions = Vec::new();
        for raw in &list {
            match parse(Scheme::Php, raw.trim()) {
                Ok(v) => versions.push(v),
                Err(_) => tally.add(Reason::BadVersionEntry),
            }
        }
        for range in &mut ranges {
            let Some(DraftEvent::LastAffected(last)) = range.events.last() else {
                continue;
            };
            let Ok(last) = parse(Scheme::Php, last) else {
                continue;
            };
            if let Some(fixed) = versions.iter().filter(|v| **v > last).min() {
                range.events.push(DraftEvent::Fixed(fixed.to_string()));
            }
        }
    }
    Ok(DraftAffected {
        purls: vec![purl],
        scheme: Scheme::Php,
        ranges,
        versions: Vec::new(),
        last_known: None,
    })
}

/// Attribution d'une faille depuis `copyrights` : `message`, puis les autres
/// clés **triées**, chacune `notice`, `license`, `license_url` (en texte,
/// jamais en lien), puis le lien de l'enregistrement. Vide, absente ou de
/// plus de 2 000 caractères : mention fixe et la raison comptée.
pub fn attribution(copyrights: Option<&RawValue>, url: &str) -> (String, Option<Reason>) {
    let fixed = |reason| (format!("{FIXED_ATTRIBUTION} — {url}"), Some(reason));
    let map = match field::<BTreeMap<String, serde_json::Value>>(copyrights) {
        Field::Absent | Field::Bad => return fixed(Reason::NoCopyrights),
        Field::Empty => return fixed(Reason::EmptyCopyrights),
        Field::Value(map) => map,
    };
    let text = |v: Option<&serde_json::Value>| {
        v.and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };
    let mut parts: Vec<String> = text(map.get("message")).into_iter().collect();
    for (key, value) in map.iter().filter(|(k, _)| k.as_str() != "message") {
        let Some(holder) = value.as_object() else {
            continue;
        };
        let notice = text(holder.get("notice"));
        let license = text(holder.get("license")).map(|l| format!("licence {l}"));
        let license_url = text(holder.get("license_url"));
        let one: Vec<String> = [notice, license, license_url]
            .into_iter()
            .flatten()
            .collect();
        if !one.is_empty() {
            parts.push(format!("{key} : {}", one.join(", ")));
        }
    }
    if parts.is_empty() {
        return fixed(Reason::EmptyCopyrights);
    }
    let assembled = format!("{} — {url}", parts.join(" ; "));
    if assembled.chars().count() > MAX_ATTRIBUTION_CHARS {
        return fixed(Reason::AttributionOverflow);
    }
    (assembled, None)
}

/// Une entrée du flux (`key` : clé de l'objet racine, `json` : sa valeur).
/// Rend la faille validée, ou la raison de son écart, comptée dans `tally`.
pub fn convert_record(key: &str, json: &str, tally: &mut Tally) -> Result<Advisory, Reason> {
    let drop = |tally: &mut Tally, r: Reason| {
        tally.add(r);
        Err(r)
    };
    if json.len() > MAX_ENTRY_BYTES {
        return drop(tally, Reason::TooLarge);
    }
    let Ok(record) = serde_json::from_str::<WfRecord>(json) else {
        return drop(tally, Reason::BadRecord);
    };
    let (Some(id), Some(key)) = (uuid(record.id.trim()), uuid(key.trim())) else {
        return drop(tally, Reason::BadId);
    };
    if id != key {
        return drop(tally, Reason::BadId);
    }
    let url = record_url(&id);

    let mut affected = Vec::new();
    for s in &record.software {
        match software_line(s, tally) {
            Ok(line) => affected.push(line),
            Err(reason) => tally.add(reason),
        }
    }

    let aliases = match field::<OneOrMany>(record.cve.as_deref()) {
        Field::Value(OneOrMany::One(c)) => vec![c],
        Field::Value(OneOrMany::Many(list)) => list,
        Field::Bad => {
            tally.add(Reason::BadAlias);
            Vec::new()
        }
        Field::Absent | Field::Empty => Vec::new(),
    };

    let (mut severity, mut provided_score) = (Vec::new(), None);
    match field::<WfCvss>(record.cvss.as_deref()) {
        Field::Value(cvss) => {
            match field::<String>(cvss.vector.as_deref()) {
                Field::Value(v) => {
                    let kind = if v.starts_with("CVSS:4.") {
                        "CVSS_V4"
                    } else {
                        "CVSS_V3"
                    };
                    severity.push((kind.to_owned(), v));
                }
                Field::Bad => tally.add(Reason::BadSeverity),
                Field::Absent | Field::Empty => {}
            }
            // Nombre JSON lu comme texte, jamais par un flottant.
            if let Some(raw) = cvss.score.as_deref().filter(|r| !is_empty_json(r)) {
                match parse_tenths(raw.get().trim()) {
                    Some(tenths) => {
                        provided_score = Some(Score {
                            tenths,
                            origin: ScoreOrigin::Wordfence,
                        });
                    }
                    None => tally.add(Reason::BadSeverity),
                }
            }
        }
        Field::Bad => tally.add(Reason::BadSeverity),
        Field::Absent | Field::Empty => {}
    }

    let cwe = match field::<WfCwe>(record.cwe.as_deref()) {
        Field::Value(c) => vec![format!("CWE-{}", c.id)],
        Field::Bad => {
            tally.add(Reason::BadCwe);
            Vec::new()
        }
        Field::Absent | Field::Empty => Vec::new(),
    };

    let references = match field::<Vec<String>>(record.references.as_deref()) {
        Field::Value(list) => list
            .into_iter()
            .map(|u| ("WEB".to_owned(), u.trim().to_owned()))
            .collect(),
        Field::Bad => {
            tally.add(Reason::BadReference);
            Vec::new()
        }
        Field::Absent | Field::Empty => Vec::new(),
    };

    let summary = match field::<String>(record.title.as_deref()) {
        Field::Value(t) => Some(t),
        _ => None,
    };
    let informational = matches!(
        field::<bool>(record.informational.as_deref()),
        Field::Value(true)
    );

    // `modified` = `updated`, sinon `published` ; aucune des deux : faille
    // écartée (`bad_date`, par `Advisory::build`).
    let published = date_field(record.published.as_deref());
    let updated = date_field(record.updated.as_deref());
    let modified = match (&updated, &published) {
        (Some(Ok(u)), _) => Some(u.clone()),
        (_, Some(Ok(p))) => Some(p.clone()),
        _ => None,
    };
    let unreadable_date = matches!(published, Some(Err(()))) || matches!(updated, Some(Err(())));

    let (attribution, note) = attribution(record.copyrights.as_deref(), &url);
    let draft = Draft {
        id: format!("WF-{id}"),
        aliases,
        summary,
        details: None,
        published: published.and_then(Result::ok),
        modified,
        affected,
        severity,
        ghsa_severity: None,
        provided_score,
        cwe,
        references,
        informational,
        license: Some(LICENSE.to_owned()),
        attribution: Some(attribution),
        source_url: Some(url),
    };
    let advisory = Advisory::build(draft, tally)?;
    if let Some(note) = note {
        tally.add(note);
    }
    if unreadable_date {
        tally.add(Reason::BadPublished);
    }
    Ok(advisory)
}

/// Plafonds de lecture du flux.
#[derive(Debug, Clone)]
pub struct FeedLimits {
    /// Entrées au plus ([`MAX_ENTRIES`] en production).
    pub entries: u64,
    /// Échéance de la source, vérifiée à chaque entrée.
    pub deadline: Option<Instant>,
}

impl Default for FeedLimits {
    fn default() -> Self {
        Self {
            entries: MAX_ENTRIES,
            deadline: None,
        }
    }
}

/// Compteur d'octets, couche externe du lecteur : au-delà de
/// [`MAX_ENTRY_BYTES`] depuis la dernière remise à zéro, la lecture échoue
/// et la valeur en cours n'est jamais gardée en entier.
struct Counted<R> {
    inner: R,
    count: std::rc::Rc<std::cell::Cell<u64>>,
    tripped: std::rc::Rc<std::cell::Cell<bool>>,
}

impl<R: Read> Read for Counted<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        let total = self.count.get() + n as u64;
        self.count.set(total);
        if total > MAX_ENTRY_BYTES as u64 {
            self.tripped.set(true);
            return Err(std::io::Error::other("entrée trop grosse"));
        }
        Ok(n)
    }
}

/// Lit l'objet racine clé par clé et pousse chaque faille retenue.
struct Root<'s> {
    count: std::rc::Rc<std::cell::Cell<u64>>,
    limits: &'s FeedLimits,
    sink: &'s mut dyn Sink,
    tally: &'s mut Tally,
    failure: &'s mut Option<SyncError>,
}

impl<'de> Visitor<'de> for Root<'_> {
    type Value = u64;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("un objet dont les clés sont les UUID des failles")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<u64, A::Error> {
        use serde::de::Error;
        let mut seen = Seen::default();
        let mut entries = 0u64;
        loop {
            self.count.set(0);
            let Some(key) = map.next_key::<String>()? else {
                break;
            };
            let raw: Box<RawValue> = map.next_value()?;
            entries += 1;
            if entries > self.limits.entries {
                *self.failure = Some(SyncError::TooLarge {
                    what: "entrées du flux Wordfence",
                });
                return Err(A::Error::custom("plafond"));
            }
            if self.limits.deadline.is_some_and(|d| Instant::now() >= d) {
                *self.failure = Some(SyncError::Deadline);
                return Err(A::Error::custom("échéance"));
            }
            if let Ok(advisory) = convert_record(&key, raw.get(), self.tally)
                && seen.first(&advisory, self.tally)
                && let Err(err) = self.sink.push(advisory)
            {
                *self.failure = Some(err);
                return Err(A::Error::custom("chargement"));
            }
        }
        Ok(entries)
    }
}

/// Lit le flux `production` en flux depuis `reader` (le fichier du dossier
/// de travail) et pousse chaque faille retenue dans `sink`, chaque écart
/// dans `tally`. Rend le nombre d'entrées lues ; toute erreur de flux
/// abandonne la lecture (le cadre ne valide aucun chargement partiel).
pub fn parse_feed<R: Read>(
    reader: R,
    limits: &FeedLimits,
    sink: &mut dyn Sink,
    tally: &mut Tally,
) -> Result<u64, SyncError> {
    use serde::Deserializer as _;
    let count = std::rc::Rc::new(std::cell::Cell::new(0));
    let tripped = std::rc::Rc::new(std::cell::Cell::new(false));
    let counted = Counted {
        inner: std::io::BufReader::new(reader),
        count: count.clone(),
        tripped: tripped.clone(),
    };
    let mut de = serde_json::Deserializer::from_reader(counted);
    let mut failure = None;
    let root = Root {
        count,
        limits,
        sink,
        tally,
        failure: &mut failure,
    };
    let result = (&mut de).deserialize_map(root).and_then(|n| {
        de.end()?;
        Ok(n)
    });
    match result {
        Ok(entries) => Ok(entries),
        Err(_) if failure.is_some() => Err(failure.expect("cause notée")),
        Err(_) if tripped.get() => Err(SyncError::TooLarge {
            what: "entrée du flux Wordfence (4 Mio)",
        }),
        Err(err) => Err(feed_error(&err)),
    }
}

/// Erreur de flux, sans texte de la source : la cause, la ligne, la colonne.
fn feed_error(err: &serde_json::Error) -> SyncError {
    use serde_json::error::Category;
    let at = format!("ligne {} colonne {}", err.line(), err.column());
    SyncError::Format(match err.classify() {
        Category::Io => format!("lecture du flux Wordfence interrompue ({at})"),
        Category::Eof => format!("flux Wordfence tronqué ({at})"),
        Category::Syntax => format!("JSON Wordfence illisible ({at})"),
        Category::Data => format!("racine du flux Wordfence : objet attendu ({at})"),
    })
}

/// État de la relecture lu dans `failles.md` : `Ok(None)` « non faite »,
/// `Ok(Some(date))` « faite le AAAA-MM-JJ ».
pub fn review_in_doc(doc: &str) -> Result<Option<String>, String> {
    let line = doc
        .lines()
        .find(|l| l.contains(REVIEW_LINE))
        .ok_or_else(|| format!("ligne « {REVIEW_LINE} » absente"))?;
    if line.contains("non faite") {
        return Ok(None);
    }
    let date = line
        .split_once("faite le ")
        .map(|(_, rest)| rest.chars().take(10).collect::<String>())
        .ok_or_else(|| "ni « non faite » ni « faite le AAAA-MM-JJ »".to_owned())?;
    date.parse::<jiff::civil::Date>()
        .map_err(|_| format!("date de relecture illisible : {date}"))?;
    Ok(Some(date))
}

/// La constante du binaire et `failles.md` disent la même chose.
pub fn check_review(doc: &str, constant: Option<&str>) -> Result<(), String> {
    let in_doc = review_in_doc(doc)?;
    if in_doc.as_deref() != constant {
        return Err(format!(
            "failles.md dit {in_doc:?}, WORDFENCE_TERMS_REVIEWED vaut {constant:?}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_are_rfc3339_or_utc_wall_clock() {
        assert_eq!(
            wf_date("2099-01-10 12:00:00").as_deref(),
            Some("2099-01-10T12:00:00Z")
        );
        assert_eq!(
            wf_date("2099-01-12T08:00:00+02:00").as_deref(),
            Some("2099-01-12T06:00:00Z")
        );
        for bad in ["2099-13-45 00:00:00", "2026-01-10", "", "hier"] {
            assert_eq!(wf_date(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn uuids_are_lowercased_and_checked() {
        assert_eq!(
            uuid("00000000-0000-4000-8000-0000000000AB").as_deref(),
            Some("00000000-0000-4000-8000-0000000000ab")
        );
        assert_eq!(uuid("00000000-0000-4000-8000-00000000000"), None);
        assert_eq!(uuid("0000000g-0000-4000-8000-000000000001"), None);
        assert_eq!(uuid("00000000_0000-4000-8000-000000000001"), None);
    }

    #[test]
    fn empty_json_values() {
        for (text, empty) in [("null", true), ("[ ]", true), ("{}", true), ("[1]", false)] {
            let raw: Box<RawValue> = serde_json::from_str(text).unwrap();
            assert_eq!(is_empty_json(&raw), empty, "{text}");
        }
    }
}
