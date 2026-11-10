//! Rapprochement d'une version avec les lignes `affected` d'une faille.
//!
//! Par plage, le pseudo-code « Evaluation » de la spécification OSV
//! (`docs/schema.md` de `ossf/osv-schema`), recopié ici :
//!
//! ```text
//! def IncludedInRange(v, range):
//!   sorted_events = sort(range.events)   # "0" (plancher) en tête
//!   if not BeforeLimits(v, sorted_events): return False
//!   vulnerable = False
//!   for evt in sorted_events:
//!     if evt.introduced and evt.introduced <= v: vulnerable = True
//!     elif evt.fixed and evt.fixed <= v: vulnerable = False
//!     elif evt.last_affected and evt.last_affected < v: vulnerable = False
//!   return vulnerable
//!
//! def BeforeLimits(v, sorted_events):
//!   if not any(evt.limit for evt in sorted_events): return True
//!   return any(evt.limit and v < evt.limit for evt in sorted_events)
//! ```
//!
//! Une ligne est touchée si l'une de ses plages l'est ; une faille l'est si
//! l'une de ses lignes l'est, ou si la version figure dans l'union des
//! `versions[]` de ses lignes (drapeau `divergence`). Une version ou une
//! plage illisible n'est jamais « non touchée » : [`Verdict::Unknown`].

use std::cmp::Ordering;

use crate::vulns::advisory::{Affected, Event, Range};
use crate::vulns::version::{Bound, Scheme, Version, parse, parse_bound};

/// Raison d'un verdict inconnu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownReason {
    /// Version d'inventaire absente ou illisible pour le comparateur.
    VersionUnknown,
    /// Plage ou borne illisible (ligne `unevaluable`).
    RangeUnknown,
}

/// Verdict d'une faille pour une version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Affected {
        /// Plus petite version `fixed` supérieure à la version, parmi les
        /// lignes qui la contiennent ; `None` : aucun correctif connu.
        fixed: Option<String>,
        /// Version listée dans `versions[]` mais hors de toute plage.
        divergence: bool,
        /// Plage ouverte, version au-delà de
        /// `last_known_affected_version_range`.
        beyond_last_known: bool,
    },
    NotAffected,
    Unknown(UnknownReason),
}

enum RangeOutcome {
    In(Option<Version>),
    Out,
    VersionUnknown,
}

fn event_bound(scheme: Scheme, e: &Event) -> Option<Bound> {
    match e {
        Event::Introduced(v) => parse_bound(scheme, v).ok(),
        Event::Fixed(v) | Event::LastAffected(v) | Event::Limit(v) => {
            parse(scheme, v).ok().map(Bound::At)
        }
    }
}

fn evaluate_range(range: &Range, raw: &str) -> RangeOutcome {
    let Ok(v) = parse(range.scheme, raw) else {
        return RangeOutcome::VersionUnknown;
    };
    let mut events: Vec<(Bound, &Event)> = Vec::with_capacity(range.events.len());
    for e in &range.events {
        // Bornes validées à l'import ; une borne relue illisible ne rend
        // jamais « non touché ».
        let Some(b) = event_bound(range.scheme, e) else {
            return RangeOutcome::VersionUnknown;
        };
        events.push((b, e));
    }
    events.sort_by(|a, b| a.0.cmp(&b.0));
    let at = Bound::At(v.clone());
    let limits: Vec<&Bound> = events
        .iter()
        .filter(|(_, e)| matches!(e, Event::Limit(_)))
        .map(|(b, _)| b)
        .collect();
    if !limits.is_empty() && !limits.iter().any(|l| at < **l) {
        return RangeOutcome::Out;
    }
    let mut vulnerable = false;
    for (b, e) in &events {
        match e {
            Event::Introduced(_) if *b <= at => vulnerable = true,
            Event::Fixed(_) if *b <= at => vulnerable = false,
            Event::LastAffected(_) if *b < at => vulnerable = false,
            _ => {}
        }
    }
    if !vulnerable {
        return RangeOutcome::Out;
    }
    let fixed = events
        .iter()
        .filter_map(|(b, e)| match (b, e) {
            (Bound::At(f), Event::Fixed(_)) if *f > v => Some(f.clone()),
            _ => None,
        })
        .min();
    RangeOutcome::In(fixed)
}

enum LineOutcome {
    Affected {
        fixed: Option<Version>,
        beyond: bool,
    },
    NotAffected,
    Unknown(UnknownReason),
}

fn evaluate_line(line: &Affected, raw: &str) -> LineOutcome {
    let mut version_unknown = false;
    let mut hit: Option<Option<Version>> = None;
    for range in &line.ranges {
        match evaluate_range(range, raw) {
            RangeOutcome::In(fixed) => {
                hit = Some(match (hit.take().flatten(), fixed) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                });
            }
            RangeOutcome::Out => {}
            RangeOutcome::VersionUnknown => version_unknown = true,
        }
    }
    if let Some(fixed) = hit {
        let beyond = fixed.is_none()
            && line.last_known.as_ref().is_some_and(|lk| {
                match (parse(line.scheme, &lk.version), parse(line.scheme, raw)) {
                    (Ok(lk_v), Ok(v)) => match v.cmp(&lk_v) {
                        Ordering::Greater => true,
                        Ordering::Equal => !lk.inclusive,
                        Ordering::Less => false,
                    },
                    _ => false,
                }
            });
        return LineOutcome::Affected { fixed, beyond };
    }
    if line.unevaluable {
        return LineOutcome::Unknown(UnknownReason::RangeUnknown);
    }
    if line.ranges.is_empty() && parse(line.scheme, raw).is_err() {
        version_unknown = true;
    }
    if version_unknown {
        return LineOutcome::Unknown(UnknownReason::VersionUnknown);
    }
    LineOutcome::NotAffected
}

/// Version listée dans `versions[]` d'une ligne, par égalité du comparateur.
fn listed(line: &Affected, raw: &str) -> bool {
    let Ok(v) = parse(line.scheme, raw) else {
        return false;
    };
    line.versions
        .iter()
        .any(|l| parse(line.scheme, l).is_ok_and(|l| l == v))
}

/// Verdict d'une faille pour un purl, d'après ses lignes `affected` (celles
/// de ce purl) et la version d'inventaire (`None` : inconnue).
///
/// Agrégation : touchée si l'une des lignes l'est (correctif le plus proche
/// parmi elles) ; sinon touchée avec `divergence` si la version figure dans
/// l'union des `versions[]` ; sinon inconnue si l'une des lignes l'est
/// (raison de la première ; « plage inconnue » avant « version inconnue »
/// dans une même ligne) ; sinon non touchée.
pub fn match_advisory(lines: &[&Affected], version: Option<&str>) -> Verdict {
    let Some(raw) = version else {
        let reason = if lines.iter().any(|l| l.unevaluable) {
            UnknownReason::RangeUnknown
        } else {
            UnknownReason::VersionUnknown
        };
        return Verdict::Unknown(reason);
    };
    let mut fixed: Option<Version> = None;
    let mut affected = false;
    let mut beyond = false;
    let mut unknown: Option<UnknownReason> = None;
    for line in lines {
        match evaluate_line(line, raw) {
            LineOutcome::Affected {
                fixed: f,
                beyond: b,
            } => {
                affected = true;
                beyond |= b;
                if let Some(f) = f {
                    fixed = Some(match fixed {
                        Some(cur) => cur.min(f),
                        None => f,
                    });
                }
            }
            LineOutcome::NotAffected => {}
            LineOutcome::Unknown(r) => {
                unknown.get_or_insert(r);
            }
        }
    }
    if affected {
        return Verdict::Affected {
            beyond_last_known: beyond && fixed.is_none(),
            fixed: fixed.map(|f| f.to_string()),
            divergence: false,
        };
    }
    if lines.iter().any(|l| listed(l, raw)) {
        return Verdict::Affected {
            fixed: None,
            divergence: true,
            beyond_last_known: false,
        };
    }
    match unknown {
        Some(r) => Verdict::Unknown(r),
        None => Verdict::NotAffected,
    }
}
