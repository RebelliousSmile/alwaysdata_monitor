//! Constats du contrôle `vulns` : **un** par (site, purl sans version),
//! agrégé sur toutes les sources d'inventaire, tous les chemins et toutes
//! les failles, jamais un par faille ; et un « inventaire périmé » par
//! source d'inventaire.
//!
//! Seuils : un constat de composant **s'ouvre** à l'avertissement ou
//! au-dessus, ou s'il est tenu ouvert par une dérogation ; un incident déjà
//! ouvert reste ouvert, en information s'il le faut, tant qu'un groupe
//! touché ou inconnu subsiste (pas de battement autour d'un seuil EPSS).
//!
//! Détail écrit par Vigie, assaini ([`LogText`]) champ par champ, borné à
//! [`MAX_VULNS_DETAIL_CHARS`] : première ligne de [`MAX_SUBJECT_CHARS`] au
//! plus (objet de l'e-mail), une ligne par groupe du plus grave au moins
//! grave, « + K autres », mention de redistribution, attributions
//! dédoublonnées et jamais tronquées : ce sont les groupes qui cèdent la
//! place. Aucun résumé ni titre venu d'une source.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use crate::api::log_text::LogText;
use crate::finding::{Finding, Severity};
use crate::inventory::Source;
use crate::vulns::exploit::ppm_text;
use crate::vulns::sources::Redistribution;
use crate::vulns::version::parse;

use super::assess::{GroupResult, MemberFacts, State};
use super::waiver::{Applies, Waiver};
use super::{Component, scheme_of};

/// Nom du contrôle.
pub const CHECK: &str = "vulns";
/// Clé du constat « inventaire périmé » de la source `agent`.
pub const KEY_STALE_AGENT: &str = "inventaire-perime-agent";
/// Clé du constat « inventaire périmé » de la source `ci`.
pub const KEY_STALE_CI: &str = "inventaire-perime-ci";
/// Longueur maximale du détail d'un constat, en caractères.
pub const MAX_VULNS_DETAIL_CHARS: usize = 4_096;
/// Longueur maximale de la première ligne (objet de l'e-mail).
pub const MAX_SUBJECT_CHARS: usize = 200;
/// Longueur maximale d'un identifiant ou d'une version affichés.
const MAX_FIELD_CHARS: usize = 128;
/// Longueur maximale d'un lien affiché.
const MAX_LINK_CHARS: usize = 2_048;
/// Mention d'un groupe d'une source qui n'autorise pas la redistribution.
pub const INTERNAL_NOTE: &str =
    "usage interne : failles d'une source non redistribuable, ne pas transmettre à un client";

/// Clé du constat « inventaire périmé » d'une source.
pub fn stale_key(source: Source) -> &'static str {
    match source {
        Source::Agent => KEY_STALE_AGENT,
        Source::Ci => KEY_STALE_CI,
    }
}

/// Un composant et ses groupes touchés ou inconnus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct View {
    pub component: Component,
    pub groups: Vec<GroupResult>,
}

/// Dérogation qui vise ce groupe de cette vue, et sa validité.
pub fn waiver_for<'w>(
    key: &str,
    view: &View,
    group: &GroupResult,
    waivers: &'w [Waiver],
    now: i64,
) -> Option<(&'w Waiver, Applies)> {
    let version = view.component.version.as_deref();
    let mut found: Option<(&Waiver, Applies)> = None;
    for w in waivers
        .iter()
        .filter(|w| w.source == view.component.source && w.base == key && w.targets(group))
    {
        let applies = w.applies(group, version, now);
        // Une dérogation valide l'emporte sur une caduque.
        if found.is_none() || applies == Applies::Ok {
            found = Some((w, applies));
        }
    }
    found
}

/// Libellé d'une règle gardée (`Rule::as_str` de F4, ou une inconnue).
pub fn rule_label(rule: &str) -> &'static str {
    match rule {
        "kev" => "exploitée (CISA KEV)",
        "malicious" => "paquet malveillant",
        "cvss_critical" => "CVSS ≥ 9,0",
        "cvss_high" => "CVSS ≥ 7,0",
        "epss" => "EPSS ≥ 0,1",
        "unknown_severity" => "gravité inconnue",
        "informational" => "informational (Wordfence)",
        "version_unknown" => "version inconnue",
        "range_unknown" => "plage inconnue",
        _ => "aucune règle",
    }
}

fn clean(raw: &str, max: usize) -> String {
    LogText::new(raw, max).into()
}

/// `AAAA-MM-JJ` d'une date Unix.
pub fn day(secs: i64) -> String {
    crate::iso_utc(secs).chars().take(10).collect()
}

/// Score en dixièmes, à la française : `9,8`.
pub fn tenths(t: u8) -> String {
    format!("{},{}", t / 10, t % 10)
}

/// Groupe agrégé sur les vues : la gravité retenue est la plus haute hors
/// dérogation.
struct Line<'a> {
    group: &'a GroupResult,
    severity: Severity,
    /// Toutes les vues qui le voient l'ont sous dérogation valide.
    waived_until: Option<i64>,
    sources: BTreeSet<Source>,
}

/// Versions de chaque source : « agent : 1.2.3 ; ci : 1.2.4 ».
fn versions(views: &[View]) -> String {
    let mut by_source: BTreeMap<Source, Vec<String>> = BTreeMap::new();
    for v in views {
        let mut text = match &v.component.version {
            Some(version) => clean(version, MAX_FIELD_CHARS),
            None => "version inconnue".to_owned(),
        };
        if v.component.carried {
            text.push_str(" (absent d'un relevé partiel)");
        }
        let list = by_source.entry(v.component.source).or_default();
        if !list.contains(&text) {
            list.push(text);
        }
    }
    by_source
        .iter()
        .map(|(source, list)| format!("{} : {}", source.as_str(), list.join(", ")))
        .collect::<Vec<_>>()
        .join(" ; ")
}

/// Le plus grand correctif des groupes, s'ils se comparent.
fn largest_fix(views: &[View], lines: &[Line<'_>]) -> Option<String> {
    let scheme = scheme_of(views.first()?.component.ecosystem);
    let mut best: Option<(crate::vulns::version::Version, &str)> = None;
    for f in lines
        .iter()
        .filter(|l| l.waived_until.is_none() && l.group.state == State::Affected)
        .flat_map(|l| &l.group.fixed)
    {
        let v = parse(scheme, f).ok()?;
        if best.as_ref().is_none_or(|(b, _)| v > *b) {
            best = Some((v, f));
        }
    }
    best.map(|(_, f)| clean(f, MAX_FIELD_CHARS))
}

fn first_line(key: &str, views: &[View], lines: &[Line<'_>]) -> String {
    let critical = lines
        .iter()
        .filter(|l| l.waived_until.is_none() && l.severity == Severity::Critical)
        .count();
    let mut text = format!(
        "{} ({}) : {} faille(s)",
        clean(key, MAX_FIELD_CHARS * 2),
        versions(views),
        lines.len()
    );
    if critical > 0 {
        text.push_str(&format!(", dont {critical} critique(s)"));
    }
    let open: Vec<&Line<'_>> = lines.iter().filter(|l| l.waived_until.is_none()).collect();
    let affected: Vec<&&Line<'_>> = open
        .iter()
        .filter(|l| l.group.state == State::Affected)
        .collect();
    if open.is_empty() {
        text.push_str(" ; toutes sous dérogation");
    } else if affected.is_empty() {
        text.push_str(" ; version ou plage inconnue");
    } else if affected.iter().any(|l| l.group.fixed.is_empty()) {
        text.push_str(" ; aucun correctif pour au moins une faille");
    } else {
        match largest_fix(views, lines) {
            Some(fix) => text.push_str(&format!(" ; corriger : ≥ {fix}")),
            None => text.push_str(" ; corriger : voir le détail"),
        }
    }
    LogText::new(&text, MAX_SUBJECT_CHARS).into()
}

fn group_line(line: &Line<'_>) -> String {
    let g = line.group;
    let others: Vec<String> = g
        .ids
        .iter()
        .filter(|id| **id != g.key)
        .map(|id| clean(id, MAX_FIELD_CHARS))
        .collect();
    let mut parts = vec![format!(
        "- {}{} : {}",
        clean(&g.key, MAX_FIELD_CHARS),
        if others.is_empty() {
            String::new()
        } else {
            format!(" ({})", others.join(", "))
        },
        g.state.label()
    )];
    parts.push(format!(
        "{} ({})",
        line.severity.label(),
        rule_label(&g.rule)
    ));
    if let Some(score) = g.score {
        parts.push(format!("CVSS {}", tenths(score)));
    }
    if let Some(kev) = &g.kev {
        parts.push(format!(
            "KEV depuis le {}{}",
            clean(&kev.date_added, 10),
            if kev.ransomware {
                ", rançongiciel"
            } else {
                ""
            }
        ));
    }
    if let Some(epss) = &g.epss {
        parts.push(format!("EPSS {}", ppm_text(epss.epss_ppm)));
    }
    if g.state == State::Affected {
        if g.fixed.is_empty() {
            parts.push("aucun correctif".into());
        } else {
            let fixed: Vec<String> = g.fixed.iter().map(|f| clean(f, MAX_FIELD_CHARS)).collect();
            parts.push(format!("corrigée en {}", fixed.join(" ou ")));
        }
    }
    if g.divergence {
        parts.push("version listée hors plage".into());
    }
    if g.corrected() {
        parts.push("plage corrigée".into());
    }
    if line.sources.len() > 1 || line.sources.contains(&Source::Ci) {
        let seen: Vec<&str> = line.sources.iter().map(|s| s.as_str()).collect();
        parts.push(format!("vue par {}", seen.join(" et ")));
    }
    if let Some(until) = line.waived_until {
        parts.push(format!("sous dérogation jusqu'au {}", day(until)));
    }
    let mut links: Vec<String> = Vec::new();
    for m in &g.members {
        let link = clean(&m.link, MAX_LINK_CHARS);
        if !link.is_empty() && !links.contains(&link) {
            links.push(link);
        }
    }
    parts.extend(links);
    parts.join(" ; ")
}

/// Ce qu'un constat de composant dit, et sa gravité, ou `None` s'il n'y a
/// rien à ouvrir ni à garder ouvert.
///
/// `attribution` rend l'attribution d'un membre (celle de la faille, sinon
/// celle de sa source) ; `already_open` : un incident de cette clé est
/// ouvert.
pub fn base_finding(
    site: &str,
    key: &str,
    views: &[View],
    waivers: &[Waiver],
    attribution: &dyn Fn(&MemberFacts) -> Option<String>,
    already_open: bool,
    now: i64,
) -> Option<Finding> {
    let mut by_key: BTreeMap<&str, Line<'_>> = BTreeMap::new();
    for view in views {
        for g in &view.groups {
            let waived = waiver_for(key, view, g, waivers, now)
                .filter(|(_, applies)| *applies == Applies::Ok)
                .map(|(w, _)| w.until);
            let entry = by_key.entry(g.key.as_str()).or_insert(Line {
                group: g,
                severity: Severity::Info,
                waived_until: waived,
                sources: BTreeSet::new(),
            });
            entry.sources.insert(view.component.source);
            match (waived, entry.waived_until) {
                // Vue hors dérogation : elle compte, et le groupe aussi.
                (None, _) => {
                    if entry.waived_until.is_some() || g.severity >= entry.severity {
                        entry.group = g;
                    }
                    entry.waived_until = None;
                    entry.severity = entry.severity.max(g.severity);
                }
                (Some(until), Some(held)) => entry.waived_until = Some(until.min(held)),
                (Some(_), None) => {}
            }
        }
    }
    if by_key.is_empty() {
        return None;
    }
    let mut lines: Vec<Line<'_>> = by_key.into_values().collect();
    for l in lines.iter_mut().filter(|l| l.waived_until.is_some()) {
        l.severity = l.group.severity;
    }
    lines.sort_by(|a, b| {
        let rank = |l: &Line<'_>| (l.waived_until.is_none(), l.severity);
        rank(b).cmp(&rank(a)).then(a.group.key.cmp(&b.group.key))
    });
    let severity = lines
        .iter()
        .filter(|l| l.waived_until.is_none())
        .map(|l| l.severity)
        .max();
    let any_waived = lines.iter().any(|l| l.waived_until.is_some());
    let severity = match severity {
        Some(s) if s >= Severity::Warning => s,
        // Information : seulement pour garder un incident ouvert, ou tenu
        // ouvert par une dérogation (relevé à son échéance).
        Some(_) if already_open || any_waived => Severity::Info,
        None if already_open || any_waived => Severity::Info,
        _ => return None,
    };
    Some(Finding::new(
        site,
        CHECK,
        severity,
        key,
        detail(site, key, views, &lines, attribution),
    ))
}

fn detail(
    site: &str,
    key: &str,
    views: &[View],
    lines: &[Line<'_>],
    attribution: &dyn Fn(&MemberFacts) -> Option<String>,
) -> String {
    let head = first_line(key, views, lines);
    let carried = views.iter().any(|v| v.component.carried);
    let mut shown: Vec<String> = Vec::new();
    let mut attributions: Vec<String> = Vec::new();
    let mut restricted = false;
    let tail_for = |hidden: usize, attributions: &[String], restricted: bool| -> String {
        let mut tail = String::new();
        if carried {
            tail.push_str(
                "\nabsent d'un relevé partiel de sa source : rapproché sur la dernière version vue",
            );
        }
        if hidden > 0 {
            tail.push_str(&format!("\n+ {hidden} autres : vigie site vulns {site}"));
        }
        if restricted {
            tail.push('\n');
            tail.push_str(INTERNAL_NOTE);
        }
        if !attributions.is_empty() {
            tail.push_str("\nattributions :");
            for a in attributions {
                tail.push('\n');
                tail.push_str(a);
            }
        }
        tail
    };
    for (i, line) in lines.iter().enumerate() {
        let text = group_line(line);
        let mut more = attributions.clone();
        for m in &line.group.members {
            if let Some(a) = attribution(m).map(|a| clean(&a, usize::MAX))
                && !a.is_empty()
                && !more.contains(&a)
            {
                more.push(a);
            }
        }
        let more_restricted = restricted || line.group.redistribution != Redistribution::Free;
        let body: String = shown.iter().map(|s| format!("\n{s}")).collect();
        let hidden = lines.len() - i - 1;
        let candidate = format!(
            "{head}{body}\n{text}{}",
            tail_for(hidden, &more, more_restricted)
        );
        if candidate.chars().count() > MAX_VULNS_DETAIL_CHARS {
            break;
        }
        shown.push(text);
        attributions = more;
        restricted = more_restricted;
    }
    let body: String = shown.iter().map(|s| format!("\n{s}")).collect();
    let hidden = lines.len() - shown.len();
    let out = format!(
        "{head}{body}{}",
        tail_for(hidden, &attributions, restricted)
    );
    // Garde : jamais au-delà, même si l'en-tête seul déborde.
    out.chars().take(MAX_VULNS_DETAIL_CHARS).collect()
}

/// Constat « inventaire périmé » d'une source : avertissement quand le
/// dernier inventaire reçu (renvoi inchangé compris), ou la déclaration de
/// la source s'il n'y en a aucun, a plus de `threshold`
/// (`inventory::stale_after`). Les constats de composants restent.
pub fn stale_finding(
    site: &str,
    source: Source,
    last_inventory: Option<i64>,
    declared_at: i64,
    threshold: Duration,
    now: i64,
) -> Option<Finding> {
    let threshold = i64::try_from(threshold.as_secs()).unwrap_or(i64::MAX);
    let since = last_inventory.map_or(declared_at, |seen| seen.max(declared_at));
    if now.saturating_sub(since) <= threshold {
        return None;
    }
    let days = threshold / 86_400;
    let detail = match last_inventory {
        Some(seen) => format!(
            "inventaire {} périmé : dernier reçu le {} (seuil {days} jours)",
            source.as_str(),
            day(seen)
        ),
        None => format!(
            "inventaire {} périmé : aucun reçu depuis la déclaration de la source le {} (seuil {days} jours)",
            source.as_str(),
            day(declared_at)
        ),
    };
    Some(Finding::new(
        site,
        CHECK,
        Severity::Warning,
        stale_key(source),
        detail,
    ))
}
