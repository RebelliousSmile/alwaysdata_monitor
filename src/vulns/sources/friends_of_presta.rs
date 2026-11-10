//! Friends-Of-Presta (`friends-of-presta/security-advisories`) : modules
//! PrestaShop tiers et noyau. Fiche : `docs/failles.md`, « Friends-Of-Presta ».
//!
//! L'archive `main.tar.gz` du dépôt est lue en flux ([`super::tar`]) ; seuls
//! les fichiers ordinaires `<racine>/_posts/<nom>.md` sont convertis. Un avis
//! est un Markdown à en-tête YAML : l'en-tête est lu par un analyseur ligne à
//! ligne **fermé** (`title`, `categories`, `severity`), le corps par ses
//! puces `**Clé**: valeur` de la section `## Summary`. « Impacted release »
//! est du texte libre, lu par la grammaire fermée de [`super::release`] : une
//! formulation non reconnue donne une ligne `unevaluable`, jamais « non
//! vulnérable ».
//!
//! Aucun texte de l'avis n'est stocké hors du titre assaini.

use std::io::{BufRead, Read};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use super::Redistribution;
use super::release::parse_release;
use super::tar::{Kind, TarLimits, TarReader};
use crate::vulns::advisory::{
    Advisory, Draft, DraftAffected, DraftEvent, DraftRange, Event, Reason, Score, ScoreOrigin,
    Seen, Tally, parse_tenths,
};
use crate::vulns::cvss;
use crate::vulns::purl::{Purl, PurlType};
use crate::vulns::sync::download::{Download, Fetched, Request};
use crate::vulns::sync::{Dumped, FetchOutcome, Limits, Sink, SourceMeta, SyncError, VulnSource};
use crate::vulns::version::Scheme;

/// Seuls des faits (CVE, module, plage, vecteur, CWE, date) et le lien
/// sortent vers un client.
pub const REDISTRIBUTION: Redistribution = Redistribution::FactsOnly;
pub const LICENSE: &str = "CC-BY-SA-4.0";
/// Avis au plus, en octets ; au-delà, `too_large`.
pub const MAX_ADVISORY_BYTES: u64 = 1024 * 1024;
/// Lignes de l'en-tête YAML au plus, fermeture comprise.
pub const MAX_FRONT_LINES: usize = 64;
/// Octets de l'en-tête YAML au plus.
pub const MAX_FRONT_BYTES: usize = 8 * 1024;
/// Noms de modules par avis au plus.
pub const MAX_PRODUCTS: usize = 16;
/// Nom de fichier gardé tel quel dans l'identifiant (`FOP-<nom>`).
pub const MAX_SHORT_NAME: usize = 60;

/// Lien GitHub d'un avis (`<nom>.md`).
pub fn post_url(file: &str) -> String {
    format!("https://github.com/friends-of-presta/security-advisories/blob/main/_posts/{file}")
}

/// Identifiant d'un avis d'après son nom de fichier sans `.md` : `FOP-<nom>`
/// jusqu'à 60 caractères, sinon `FOPH-<47 premiers>-<8 hexadécimaux du
/// SHA-256 du nom>` (61 caractères, stable, préfixe distinct).
pub fn advisory_id(name: &str) -> String {
    if name.len() <= MAX_SHORT_NAME {
        return format!("FOP-{name}");
    }
    let digest = Sha256::digest(name.as_bytes());
    let hex: String = digest.iter().take(4).map(|b| format!("{b:02x}")).collect();
    format!("FOPH-{}-{hex}", &name[..47])
}

/// Nom de fichier admis : `[A-Za-z0-9._-]`, 1 à 255 caractères.
fn valid_name(name: &str) -> bool {
    (1..=255).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// En-tête YAML retenu.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FrontMatter {
    pub title: Option<String>,
    pub categories: Vec<String>,
    pub severity: Option<String>,
}

/// Clé en cours de lecture.
#[derive(PartialEq, Eq)]
enum Current {
    None,
    /// `categories:` sans valeur : puces attendues.
    CategoriesList,
    Retained,
    Ignored,
}

/// Scalaire : nu, `"…"` (échappements `\"` et `\\`) ou `'…'` ; ancre, alias,
/// étiquette, bloc ou suite d'une valeur après les guillemets refusés.
fn scalar(raw: &str) -> Option<String> {
    let raw = raw.trim();
    match raw.chars().next() {
        None => Some(String::new()),
        Some('&' | '*' | '|' | '>' | '!' | '[' | '{' | '%' | '@' | '`') => None,
        Some('"') => {
            let mut out = String::new();
            let mut chars = raw[1..].chars();
            loop {
                match chars.next()? {
                    '\\' => match chars.next()? {
                        c @ ('"' | '\\') => out.push(c),
                        _ => return None,
                    },
                    '"' => break,
                    c => out.push(c),
                }
            }
            chars.as_str().trim().is_empty().then_some(out)
        }
        Some('\'') => {
            let inner = raw[1..].strip_suffix('\'')?;
            (!inner.contains('\'')).then(|| inner.to_owned())
        }
        Some(_) => Some(raw.to_owned()),
    }
}

/// `[a, b]` → éléments.
fn flow_list(raw: &str) -> Option<Vec<String>> {
    let inner = raw.trim().strip_prefix('[')?.strip_suffix(']')?;
    if inner.contains(['[', ']', '{', '}']) {
        return None;
    }
    inner
        .split(',')
        .map(scalar)
        .filter(|s| s.as_ref().is_none_or(|s| !s.is_empty()))
        .collect()
}

/// En-tête YAML et corps, ou `None` (`bad_front_matter`).
pub fn front_matter(text: &str) -> Option<(FrontMatter, &str)> {
    let mut lines = text.split_inclusive('\n');
    if lines.next()?.trim_end() != "---" {
        return None;
    }
    let mut offset = text.find('\n')? + 1;
    let mut fm = FrontMatter::default();
    let mut seen: Vec<&str> = Vec::new();
    let mut current = Current::None;
    for (i, line) in lines.enumerate() {
        offset += line.len();
        if i + 2 > MAX_FRONT_LINES || offset > MAX_FRONT_BYTES {
            return None;
        }
        let body = line.trim_end_matches(['\n', '\r']);
        if body == "---" {
            return Some((fm, &text[offset..]));
        }
        let trimmed = body.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if body.starts_with([' ', '\t', '-']) {
            match current {
                Current::CategoriesList => {
                    let item = trimmed.strip_prefix("- ")?;
                    let item = scalar(item)?;
                    if !item.is_empty() {
                        fm.categories.push(item);
                    }
                }
                Current::Ignored => {}
                Current::None | Current::Retained => return None,
            }
            continue;
        }
        let (key, value) = body.split_once(':')?;
        let key = key.trim();
        if !matches!(key, "title" | "categories" | "severity") {
            current = Current::Ignored;
            continue;
        }
        if seen.contains(&key) {
            return None;
        }
        seen.push(key);
        current = Current::Retained;
        match key {
            "title" => fm.title = Some(scalar(value)?).filter(|t| !t.is_empty()),
            "severity" => fm.severity = Some(scalar(value)?).filter(|t| !t.is_empty()),
            _ => {
                let value = value.trim();
                if value.is_empty() {
                    current = Current::CategoriesList;
                } else if value.starts_with('[') {
                    fm.categories = flow_list(value)?;
                } else {
                    fm.categories = scalar(value)?
                        .split_whitespace()
                        .map(str::to_owned)
                        .collect();
                }
            }
        }
    }
    None
}

/// Puces lues dans la section `## Summary` et vecteur CVSS du corps.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    pub cve: Vec<String>,
    pub published: Option<String>,
    pub product: Option<String>,
    pub impacted: Option<String>,
    pub weakness: Vec<String>,
    pub severity: Option<String>,
    pub vector: Option<String>,
}

/// `[texte](url)` → `texte`.
fn strip_links(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(open) = rest.find('[') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        match after.find("](").and_then(|close| {
            let tail = &after[close + 2..];
            tail.find(')').map(|end| (close, close + 2 + end + 1))
        }) {
            Some((close, next)) => {
                out.push_str(&after[..close]);
                rest = &after[next..];
            }
            None => {
                out.push('[');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Identifiants `<préfixe>\d…` du texte (`CVE-2099-0001`, `CWE-89`).
fn ids(text: &str, prefix: &str, min_digits: usize, max: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (at, _) in text.match_indices(prefix) {
        let tail = &text[at + prefix.len()..];
        let id: String = if prefix == "CVE-" {
            // `AAAA-N…` : quatre chiffres, tiret, au moins quatre chiffres.
            let year: String = tail.chars().take_while(char::is_ascii_digit).collect();
            let rest = tail.get(year.len()..).unwrap_or("");
            let num: String = rest
                .strip_prefix('-')
                .map(|r| r.chars().take_while(char::is_ascii_digit).collect())
                .unwrap_or_default();
            if year.len() != 4 || num.len() < min_digits || num.len() > 19 {
                continue;
            }
            format!("CVE-{year}-{num}")
        } else {
            let num: String = tail.chars().take_while(char::is_ascii_digit).collect();
            if num.len() < min_digits || num.len() > 6 {
                continue;
            }
            format!("{prefix}{num}")
        };
        if !out.contains(&id) && out.len() < max {
            out.push(id);
        }
    }
    out
}

/// Corps de l'avis.
pub fn summary(body: &str) -> Summary {
    let mut s = Summary::default();
    let mut inside = false;
    for line in body.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            inside = t
                .trim_start_matches('#')
                .trim()
                .eq_ignore_ascii_case("summary");
            continue;
        }
        if !inside {
            continue;
        }
        let Some(item) = t.strip_prefix("* ").or_else(|| t.strip_prefix("- ")) else {
            continue;
        };
        let Some(rest) = item.trim().strip_prefix("**") else {
            continue;
        };
        let Some((key, value)) = rest.split_once("**") else {
            continue;
        };
        let key = key
            .trim()
            .trim_end_matches(':')
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase();
        let value = strip_links(value.trim_start().trim_start_matches(':').trim());
        match key.as_str() {
            "cve id" => s.cve = ids(&value, "CVE-", 4, 32),
            "published at" => s.published = Some(value),
            "product" => s.product = Some(value),
            "impacted release" => s.impacted = Some(value),
            "weakness" => s.weakness = ids(&value, "CWE-", 1, 8),
            "severity" => s.severity = Some(value),
            _ => {}
        }
    }
    s.vector = body
        .lines()
        .filter(|l| l.contains("**Vector string**"))
        .find_map(|l| {
            let at = l.find("CVSS:3.")?;
            let v: String = l[at..]
                .chars()
                .take_while(|c| !c.is_whitespace() && *c != '|')
                .collect();
            cvss::parse(&v).map(|_| v)
        });
    s
}

/// Score entre parenthèses (`critical (9.8)` → 98), lu en dixièmes exacts.
fn score_in(raw: &str) -> Option<u8> {
    let open = raw.find('(')?;
    let close = raw[open..].find(')')? + open;
    parse_tenths(raw[open + 1..close].trim())
}

/// `AAAA-MM-JJ` valide → `AAAA-MM-JJT00:00:00Z`.
fn day(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.len() != 10 {
        return None;
    }
    raw.parse::<jiff::civil::Date>().ok()?;
    Some(format!("{raw}T00:00:00Z"))
}

/// Un avis : nom de fichier sans `.md` et contenu. Rend la faille validée,
/// ou la raison de son écart, comptée dans `tally`.
pub fn convert_post(name: &str, bytes: &[u8], tally: &mut Tally) -> Result<Advisory, Reason> {
    let drop = |tally: &mut Tally, r: Reason| {
        tally.add(r);
        Err(r)
    };
    if !valid_name(name) {
        return drop(tally, Reason::BadId);
    }
    if bytes.len() as u64 > MAX_ADVISORY_BYTES {
        return drop(tally, Reason::TooLarge);
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return drop(tally, Reason::BadFrontMatter);
    };
    let Some((fm, body)) = front_matter(text) else {
        return drop(tally, Reason::BadFrontMatter);
    };
    let has = |c: &str| fm.categories.iter().any(|x| x.eq_ignore_ascii_case(c));
    let module = if has("modules") {
        true
    } else if has("core") {
        false
    } else if has("dependancies") {
        return drop(tally, Reason::OutOfScope);
    } else {
        return drop(tally, Reason::UnknownCategory);
    };
    let s = summary(body);

    let mut purls = Vec::new();
    if module {
        let products = s.product.as_deref().unwrap_or("");
        for raw in products
            .split([',', '/'])
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .take(MAX_PRODUCTS)
        {
            match Purl::new(PurlType::Prestashop, Some("module"), raw, None) {
                Ok(p) if !purls.contains(&p) => purls.push(p),
                Ok(_) => {}
                Err(_) => tally.add(Reason::BadPurl),
            }
        }
    } else if let Ok(p) = Purl::new(PurlType::Prestashop, Some("core"), "prestashop", None) {
        purls.push(p);
    }
    let events: Vec<DraftEvent> = match s.impacted.as_deref().and_then(|r| parse_release(r, true)) {
        Some(events) => events
            .into_iter()
            .map(|e| match e {
                Event::Introduced(v) => DraftEvent::Introduced(v),
                Event::Fixed(v) => DraftEvent::Fixed(v),
                Event::LastAffected(v) => DraftEvent::LastAffected(v),
                Event::Limit(v) => DraftEvent::Limit(v),
            })
            .collect(),
        None => vec![DraftEvent::Malformed],
    };
    let affected = if purls.is_empty() {
        Vec::new()
    } else {
        vec![DraftAffected {
            purls,
            scheme: Scheme::Php,
            ranges: vec![DraftRange {
                kind: "ECOSYSTEM".into(),
                events,
            }],
            versions: Vec::new(),
            last_known: None,
        }]
    };

    let from_name = name.get(..10).and_then(day);
    let (published, bad_published) = match s.published.as_deref() {
        Some(raw) => match day(raw) {
            Some(d) => (Some(d), false),
            None => (from_name, true),
        },
        None => (from_name, false),
    };

    let mut provided_score = None;
    let candidates = [fm.severity.as_deref(), s.severity.as_deref()];
    if let Some(tenths) = candidates.iter().flatten().find_map(|r| score_in(r)) {
        provided_score = Some(Score {
            tenths,
            origin: ScoreOrigin::FriendsOfPresta,
        });
    } else if candidates.iter().any(Option::is_some) {
        tally.add(Reason::BadSeverity);
    }

    let file = format!("{name}.md");
    let url = post_url(&file);
    let draft = Draft {
        id: advisory_id(name),
        aliases: s.cve,
        summary: fm.title,
        details: None,
        published: published.clone(),
        modified: published,
        affected,
        severity: s
            .vector
            .map(|v| vec![("CVSS_V3".to_owned(), v)])
            .unwrap_or_default(),
        ghsa_severity: None,
        provided_score,
        cwe: s.weakness,
        references: Vec::new(),
        informational: false,
        license: Some(LICENSE.to_owned()),
        attribution: Some(format!("Friends-Of-Presta, CC BY-SA 4.0 — {url}")),
        source_url: Some(url),
    };
    let advisory = Advisory::build(draft, tally)?;
    if bad_published {
        tally.add(Reason::BadPublished);
    }
    Ok(advisory)
}

/// Plafonds de lecture de l'archive.
#[derive(Debug, Clone)]
pub struct ArchiveLimits {
    pub tar: TarLimits,
    /// Avis au plus, en octets.
    pub advisory: u64,
    pub deadline: Option<Instant>,
}

/// Bilan de lecture de l'archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveRead {
    /// Avis lus (`_posts/*.md`) : dénominateur du taux d'écart.
    pub entries: u64,
    /// Octets décompressés.
    pub unpacked: u64,
    /// Commit de l'archive (commentaire pax global, 40 hexadécimaux).
    pub revision: Option<String>,
}

/// Lit l'archive en flux et pousse chaque faille retenue dans `sink`, chaque
/// écart dans `tally`. Toute erreur de structure ou de plafond abandonne la
/// lecture.
pub fn parse_archive<R: Read>(
    reader: R,
    limits: &ArchiveLimits,
    sink: &mut dyn Sink,
    tally: &mut Tally,
) -> Result<ArchiveRead, SyncError> {
    parse_buffered(std::io::BufReader::new(reader), limits, sink, tally)
}

fn parse_buffered<R: BufRead>(
    reader: R,
    limits: &ArchiveLimits,
    sink: &mut dyn Sink,
    tally: &mut Tally,
) -> Result<ArchiveRead, SyncError> {
    let mut tar = TarReader::new(reader, limits.tar);
    let mut root: Option<String> = None;
    let mut seen = Seen::default();
    let mut entries = 0u64;
    while let Some(member) = tar.next_member()? {
        if limits.deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(SyncError::Deadline);
        }
        let Some(path) = member.path else {
            tally.add(Reason::BadArchiveMember);
            continue;
        };
        let parts: Vec<&str> = path.split('/').collect();
        match &root {
            None => root = Some(parts[0].to_owned()),
            Some(r) if r != parts[0] => {
                return Err(SyncError::Format("archive : plusieurs racines".into()));
            }
            Some(_) => {}
        }
        match member.kind {
            Kind::Link | Kind::Device => {
                tally.add(Reason::BadArchiveMember);
                continue;
            }
            Kind::File => {}
            Kind::Dir | Kind::Other => continue,
        }
        let [_, "_posts", file] = parts.as_slice() else {
            continue;
        };
        let Some(name) = file.strip_suffix(".md") else {
            continue;
        };
        entries += 1;
        if !valid_name(name) {
            tally.add(Reason::BadId);
            continue;
        }
        let Some(bytes) = tar.read_data(limits.advisory)? else {
            tally.add(Reason::TooLarge);
            continue;
        };
        if let Ok(advisory) = convert_post(name, &bytes, tally)
            && seen.first(&advisory, tally)
        {
            sink.push(advisory)?;
        }
    }
    let revision = tar
        .comment()
        .map(str::trim)
        .filter(|c| c.len() == 40 && c.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_owned);
    Ok(ArchiveRead {
        entries,
        unpacked: tar.unpacked(),
        revision,
    })
}

/// Identifiant de la source (`[vulns] sources`).
pub const SOURCE_ID: &str = "friends-of-presta";
/// Archive de la branche `main` (redirigée vers `codeload.github.com`).
pub const URL: &str =
    "https://github.com/friends-of-presta/security-advisories/archive/refs/heads/main.tar.gz";
/// Origines admises, redirection comprise.
pub const ORIGINS: &[(&str, u16)] = &[("github.com", 443), ("codeload.github.com", 443)];
/// Version du lecteur : à incrémenter dans le commit de tout changement du
/// lecteur tar, de l'en-tête, de la grammaire ou de la conversion qui change
/// les failles produites à partir des mêmes octets.
pub const LOADER_VERSION: u32 = 1;

const MIB: u64 = 1024 * 1024;

/// Source Friends-Of-Presta.
#[derive(Debug, Clone, Copy, Default)]
pub struct FriendsOfPresta;

impl VulnSource for FriendsOfPresta {
    fn id(&self) -> &'static str {
        SOURCE_ID
    }

    fn meta(&self) -> SourceMeta {
        SourceMeta {
            url: URL,
            origins: ORIGINS,
            license: LICENSE,
            attribution: "Friends-Of-Presta, CC BY-SA 4.0, lien de chaque avis",
            limits: Limits {
                compressed: 64 * MIB,
                unpacked: 512 * MIB,
                entries: 50_000,
                entry: MAX_ADVISORY_BYTES,
                central_directory: 0,
                duration: Duration::from_secs(10 * 60),
                max_dropped_ratio: 0.01,
            },
            min_interval: Duration::ZERO,
            loader_version: LOADER_VERSION,
            redistribution: REDISTRIBUTION,
            raw_content_encodings: &[],
        }
    }

    fn fetch(
        &self,
        dl: &mut Download,
        sink: &mut dyn Sink,
        tally: &mut Tally,
    ) -> Result<FetchOutcome, SyncError> {
        let url = dl.url().cloned().ok_or(SyncError::OriginRefused)?;
        // URL qui sert les validateurs (F4 : requête conditionnelle vers elle
        // seule).
        let served = Some(url.to_string());
        let dump = match dl.get_to_file(&Request::get(url))? {
            Fetched::NotModified => {
                return Ok(FetchOutcome::Unchanged {
                    not_modified: true,
                    validators: None,
                    stale: false,
                    served: served.clone(),
                });
            }
            Fetched::SameDigest { validators, .. } => {
                return Ok(FetchOutcome::Unchanged {
                    not_modified: false,
                    validators: Some(validators),
                    stale: false,
                    served: served.clone(),
                });
            }
            Fetched::Dump(dump) => dump,
        };
        let file = std::fs::File::open(&dump.path)
            .map_err(|e| SyncError::io("lecture de l'archive", &e))?;
        let limits = ArchiveLimits {
            tar: TarLimits {
                members: dl.limits().entries,
                unpacked: dl.limits().unpacked,
            },
            advisory: dl.limits().entry,
            deadline: Some(dl.deadline()),
        };
        let read = parse_archive(file, &limits, sink, tally)?;
        Ok(FetchOutcome::Loaded(Dumped {
            sha256: dump.sha256,
            validators: dump.validators,
            bytes: dump.bytes,
            unpacked_bytes: read.unpacked,
            entries: read.entries,
            revision: read.revision,
            served,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_names_get_a_stable_hashed_id() {
        let short = "a".repeat(60);
        assert_eq!(advisory_id(&short), format!("FOP-{short}"));
        assert_eq!(advisory_id(&short).len(), 64);
        let long = format!("2099-01-15-{}", "b".repeat(50));
        let id = advisory_id(&long);
        assert_eq!(id.len(), 61);
        assert!(id.starts_with(&format!("FOPH-{}-", &long[..47])));
        assert_eq!(advisory_id(&long), id);
    }

    #[test]
    fn links_are_reduced_to_their_text() {
        assert_eq!(
            strip_links("[CVE-2099-0002](https://example.org/x) et [a](b)"),
            "CVE-2099-0002 et a"
        );
        assert_eq!(strip_links("[sans lien"), "[sans lien");
    }

    #[test]
    fn scores_in_parentheses() {
        assert_eq!(score_in("critical (9.8)"), Some(98));
        assert_eq!(score_in("critical (10)"), Some(100));
        for bad in [
            "critical (12)",
            "critical (9.85)",
            "critical (9,8)",
            "critical",
        ] {
            assert_eq!(score_in(bad), None, "{bad}");
        }
    }
}
