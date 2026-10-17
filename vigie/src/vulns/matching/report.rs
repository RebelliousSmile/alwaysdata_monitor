//! Rendu texte de `vigie site components`, `vigie site vulns` et `vigie
//! vulns report` (#21) : lecture des runs actifs seulement, tout texte venu
//! d'une base relu par `LogText` (aucun caractère de contrôle), attributions
//! entières relues depuis l'identifiant de la source, liens en texte, CVSS
//! en décimal, EPSS en pour cent.

use std::collections::{BTreeMap, BTreeSet};

use crate::api::log_text::LogText;
use crate::finding::Severity;
use crate::inventory::Source;
use crate::store::Store;
use crate::vulns::exploit::PPM;
use crate::vulns::sources::Redistribution;

use super::assess::{GroupResult, MemberFacts, State};
use super::finding::{day, rule_label, tenths};
use super::key;
use super::store::{ComponentResult, attribution, run_results, site_states};
use super::waiver::{Applies, Waiver};
use super::waiver_store::Row;

fn clean(raw: &str) -> String {
    LogText::new(raw, usize::MAX).into()
}

/// Runs actifs d'un site, par source.
pub fn active_runs(store: &Store, site: &str) -> anyhow::Result<Vec<(Source, i64)>> {
    Ok(site_states(&store.conn, site)?
        .into_iter()
        .filter_map(|s| Some((s.source?, s.active_run?)))
        .collect())
}

/// Composants des runs actifs d'un site, toutes sources.
pub fn site_results(store: &Store, site: &str) -> anyhow::Result<Vec<ComponentResult>> {
    let mut out = Vec::new();
    for (source, run) in active_runs(store, site)? {
        out.extend(run_results(&store.conn, site, source, run)?);
    }
    Ok(out)
}

/// Attribution d'un membre, lue en base (faille, sinon source).
pub fn attribution_of(store: &Store) -> impl Fn(&MemberFacts) -> Option<String> + '_ {
    move |m| attribution(&store.conn, &m.source, &m.id).ok().flatten()
}

fn severity_of(r: &ComponentResult) -> Option<Severity> {
    r.groups.iter().map(|g| g.severity).max()
}

/// `vigie site components` : une ligne par (source, composant), triée par
/// gravité puis purl.
pub fn components_lines(results: &[ComponentResult]) -> Vec<String> {
    let mut sorted: Vec<&ComponentResult> = results.iter().collect();
    sorted.sort_by(|a, b| {
        severity_of(b)
            .cmp(&severity_of(a))
            .then(
                a.component
                    .base
                    .canonical()
                    .cmp(&b.component.base.canonical()),
            )
            .then(a.component.source.cmp(&b.component.source))
    });
    sorted
        .iter()
        .map(|r| {
            let c = &r.component;
            format!(
                "{}  {}  {}  {}  {} faille(s)  {}{}",
                c.source.as_str(),
                clean(&c.base.canonical()),
                c.version
                    .as_deref()
                    .map_or("version inconnue".to_owned(), clean),
                c.scope.as_str(),
                r.groups.len(),
                severity_of(r).map_or("-", Severity::label),
                if c.carried {
                    "  (absent d'un relevé partiel)"
                } else {
                    ""
                }
            )
        })
        .collect()
}

/// Dérogation sous la forme de la règle pure.
fn as_waiver(row: &Row) -> Waiver {
    Waiver {
        id: row.id,
        source: row.source,
        base: row.base.clone(),
        advisory_ref: row.advisory_ref.clone(),
        version: row.version.clone(),
        covered_ids: row.covered_ids.clone(),
        until: row.until,
        reason: row.reason.clone(),
    }
}

/// État d'une dérogation lu contre les runs actifs.
pub fn waiver_state(row: &Row, results: &[ComponentResult], now: i64) -> String {
    if let Some(at) = row.revoked_at {
        return format!("retirée le {}", day(at));
    }
    let w = as_waiver(row);
    let found = results
        .iter()
        .filter(|r| r.component.source == row.source && key(&r.component.base) == row.base)
        .find_map(|r| {
            r.groups
                .iter()
                .find(|g| w.targets(g))
                .map(|g| (r.component.version.as_deref(), g))
        });
    match found {
        Some((version, g)) => w.applies(g, version, now).label().to_owned(),
        None if now >= row.until => Applies::Expired.label().to_owned(),
        None => "sans objet : faille ou composant absents du dernier inventaire".to_owned(),
    }
}

fn redistribution_label(level: Redistribution) -> &'static str {
    match level {
        Redistribution::Internal => "usage interne",
        Redistribution::FactsOnly => "faits seulement",
        Redistribution::Free => "libre",
    }
}

/// Groupe agrégé sur les sources et les chemins.
struct Line<'a> {
    base: String,
    group: &'a GroupResult,
    versions: BTreeMap<Source, BTreeSet<String>>,
    severity: Severity,
    /// Dérogation valide, et sa ligne, pour au moins une vue ; `open` : une
    /// vue au moins hors dérogation.
    waiver: Option<&'a Row>,
    open: bool,
}

fn lines<'a>(results: &'a [ComponentResult], rows: &'a [Row], now: i64) -> Vec<Line<'a>> {
    let mut by: BTreeMap<(String, String), Line<'a>> = BTreeMap::new();
    for r in results {
        let base = key(&r.component.base);
        for g in &r.groups {
            let waiver = rows
                .iter()
                .filter(|w| w.revoked_at.is_none())
                .filter(|w| w.source == r.component.source && w.base == base)
                .find(|w| {
                    let w = as_waiver(w);
                    w.targets(g) && w.applies(g, r.component.version.as_deref(), now) == Applies::Ok
                });
            let entry = by
                .entry((base.clone(), g.key.clone()))
                .or_insert_with(|| Line {
                    base: base.clone(),
                    group: g,
                    versions: BTreeMap::new(),
                    severity: g.severity,
                    waiver: None,
                    open: false,
                });
            entry
                .versions
                .entry(r.component.source)
                .or_default()
                .insert(
                    r.component
                        .version
                        .as_deref()
                        .map_or("version inconnue".to_owned(), clean),
                );
            match waiver {
                Some(w) => entry.waiver = entry.waiver.or(Some(w)),
                None => {
                    if !entry.open || g.severity > entry.severity {
                        entry.group = g;
                        entry.severity = g.severity;
                    }
                    entry.open = true;
                }
            }
        }
    }
    let mut out: Vec<Line<'a>> = by.into_values().collect();
    out.sort_by(|a, b| {
        b.open
            .cmp(&a.open)
            .then(b.severity.cmp(&a.severity))
            .then(a.base.cmp(&b.base))
            .then(a.group.key.cmp(&b.group.key))
    });
    out
}

/// Compte des groupes hors dérogation par gravité : (critiques,
/// avertissements, informations), et un groupe d'une source non libre.
pub fn counts(results: &[ComponentResult], rows: &[Row], now: i64) -> (usize, usize, usize, bool) {
    let all = lines(results, rows, now);
    let open = all.iter().filter(|l| l.open);
    let mut c = (0, 0, 0, false);
    for l in open {
        match l.severity {
            Severity::Critical => c.0 += 1,
            Severity::Warning => c.1 += 1,
            Severity::Info => c.2 += 1,
        }
    }
    c.3 = all
        .iter()
        .any(|l| l.group.redistribution != Redistribution::Free);
    c
}

fn group_text(
    line: &Line<'_>,
    attribution: &dyn Fn(&MemberFacts) -> Option<String>,
    all: bool,
) -> Vec<String> {
    let g = line.group;
    let others: Vec<String> = g
        .ids
        .iter()
        .filter(|id| **id != g.key)
        .map(|id| clean(id))
        .collect();
    let versions: Vec<String> = line
        .versions
        .iter()
        .map(|(s, v)| {
            format!(
                "{} : {}",
                s.as_str(),
                v.iter().cloned().collect::<Vec<_>>().join(", ")
            )
        })
        .collect();
    let mut out = vec![format!(
        "{}  {}{}  {}  ({})  {}",
        line.severity.label(),
        clean(&g.key),
        if others.is_empty() {
            String::new()
        } else {
            format!(" ({})", others.join(", "))
        },
        clean(&line.base),
        versions.join(" ; "),
        g.state.label()
    )];
    let mut facts = vec![format!("règle : {}", rule_label(&g.rule))];
    match g.state {
        State::Affected if g.fixed.is_empty() => facts.push("aucun correctif".into()),
        State::Affected => facts.push(format!(
            "corrigée en {}",
            g.fixed
                .iter()
                .map(|f| clean(f))
                .collect::<Vec<_>>()
                .join(" ou ")
        )),
        State::VersionUnknown | State::RangeUnknown => {}
    }
    if let Some(score) = g.score {
        facts.push(format!("CVSS {}", tenths(score)));
    }
    if let Some(kev) = &g.kev {
        facts.push(format!(
            "CISA KEV {} depuis le {}{}",
            clean(&kev.cve),
            clean(&kev.date_added),
            if kev.ransomware {
                ", rançongiciel"
            } else {
                ""
            }
        ));
    }
    if let Some(epss) = &g.epss {
        facts.push(format!(
            "EPSS {} % (percentile {} %)",
            percent(epss.epss_ppm),
            percent(epss.percentile_ppm)
        ));
    }
    if g.divergence {
        facts.push("version listée hors plage".into());
    }
    if g.corrected() {
        facts.push("plage corrigée".into());
    }
    out.push(format!("  {}", facts.join(" ; ")));
    out.push(format!(
        "  redistribution : {}",
        redistribution_label(g.redistribution)
    ));
    let mut seen = BTreeSet::new();
    for m in &g.members {
        out.push(format!(
            "  {} ({}) : {}",
            clean(&m.id),
            clean(&m.source),
            clean(&m.link)
        ));
        if let Some(a) = attribution(m).map(|a| clean(&a))
            && seen.insert(a.clone())
        {
            out.push(format!("  attribution : {a}"));
        }
    }
    if let Some(w) = line.waiver {
        let mut text = format!(
            "  sous dérogation n° {} ({}) jusqu'au {}",
            w.id,
            w.source.as_str(),
            day(w.until)
        );
        if all {
            text.push_str(&format!(" : {}", clean(&w.reason)));
        }
        out.push(text);
    }
    out
}

/// EPSS en pour cent, deux décimales tronquées : `12,34`.
fn percent(ppm: u32) -> String {
    let hundredths = u64::from(ppm) * 10_000 / u64::from(PPM);
    format!("{},{:02}", hundredths / 100, hundredths % 100)
}

/// `vigie site vulns` : groupes touchés et inconnus hors dérogation, de
/// l'avertissement au critique ; `all` ajoute les groupes d'information,
/// ceux sous dérogation (échéance, motif) et toutes les dérogations, leur
/// état compris.
pub fn vulns_lines(
    results: &[ComponentResult],
    rows: &[Row],
    attribution: &dyn Fn(&MemberFacts) -> Option<String>,
    all: bool,
    now: i64,
) -> Vec<String> {
    let mut out = Vec::new();
    for line in lines(results, rows, now) {
        let shown = all || (line.open && line.severity >= Severity::Warning);
        if shown {
            out.extend(group_text(&line, attribution, all));
        }
    }
    if all && !rows.is_empty() {
        out.push("dérogations :".into());
        for w in rows {
            out.push(format!(
                "  n° {}  {}  {}  {}  {}  jusqu'au {}  {}  par {} le {}",
                w.id,
                w.source.as_str(),
                clean(&w.base),
                clean(&w.advisory_ref),
                clean(&w.version),
                day(w.until),
                waiver_state(w, results, now),
                clean(&w.operator),
                day(w.created_at)
            ));
            out.push(format!("    motif : {}", clean(&w.reason)));
            if let Some(reason) = &w.revoke_reason {
                out.push(format!("    motif du retrait : {}", clean(reason)));
            }
        }
    }
    out
}
