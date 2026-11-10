//! Constat `vulns-sync` : une base de failles sans synchronisation réussie
//! depuis plus de 3 jours ouvre un avertissement par source, sur le
//! pseudo-site du veilleur. Évalué par `tick` (un timer cassé ou jamais
//! installé ne lancerait jamais l'évaluation), à partir de l'état des
//! sources : fonction pure, sans base ni horloge.

use crate::api::log_text::LogText;
use crate::capability::{VULNS_SYNC, WATCHER_SITE};
use crate::finding::{Finding, Severity};
use crate::vulns::store::SyncState;

/// Âge au-delà duquel une base est périmée : 3 jours.
pub const STALE_AFTER: i64 = 259_200;
/// Préfixe des clés `meta` qui datent la première vue d'une source déclarée.
pub const META_DECLARED: &str = "vulns.declared.";
/// Longueur maximale de la dernière erreur reprise dans le constat.
const MAX_ERROR_CHARS: usize = 200;

fn days(seconds: i64) -> String {
    match seconds / 86_400 {
        1 => "1 jour".into(),
        n => format!("{n} jours"),
    }
}

/// Un constat par source déclarée dont la dernière réussite (ou, jamais
/// réussie, la première vue de sa déclaration, `declared_since`) date de
/// plus de [`STALE_AFTER`]. Le détail ne reprend de la source que l'issue
/// et la dernière erreur, assainie et bornée.
pub fn findings(
    declared: &[&str],
    states: &[(String, SyncState)],
    declared_since: impl Fn(&str) -> Option<i64>,
    now: i64,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for id in declared {
        let state = states.iter().find(|(s, _)| s == id).map(|(_, st)| st);
        let success = state.and_then(|s| s.last_success_at);
        let Some(since) = success.or_else(|| declared_since(id)) else {
            continue;
        };
        let age = now - since;
        if age <= STALE_AFTER {
            continue;
        }
        let mut detail = match success {
            Some(_) => format!("base {id} non synchronisée depuis {}", days(age)),
            None => format!(
                "base {id} jamais synchronisée, déclarée depuis {}",
                days(age)
            ),
        };
        if let Some(outcome) = state.and_then(|s| s.last_outcome) {
            detail.push_str(&format!(" ; dernière issue : {}", outcome.as_str()));
            if let Some(err) = state.and_then(|s| s.last_error.as_deref())
                && outcome == crate::vulns::store::Outcome::Failed
            {
                detail.push_str(&format!(
                    " ({})",
                    LogText::new(err, MAX_ERROR_CHARS).as_str()
                ));
            }
        }
        out.push(Finding::new(
            WATCHER_SITE,
            VULNS_SYNC,
            Severity::Warning,
            *id,
            detail,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vulns::store::Outcome;

    const NOW: i64 = 1_800_000_000;

    fn state(success: Option<i64>, outcome: Outcome, error: Option<&str>) -> SyncState {
        SyncState {
            last_success_at: success,
            last_outcome: Some(outcome),
            last_error: error.map(str::to_owned),
            ..SyncState::default()
        }
    }

    #[test]
    fn opens_after_three_days_and_not_before() {
        let fresh = [(
            "osv-npm".to_owned(),
            state(Some(NOW - STALE_AFTER), Outcome::Loaded, None),
        )];
        assert!(findings(&["osv-npm"], &fresh, |_| None, NOW).is_empty());
        let stale = [(
            "osv-npm".to_owned(),
            state(
                Some(NOW - STALE_AFTER - 86_400),
                Outcome::Failed,
                Some("délai\u{1b}[2J dépassé"),
            ),
        )];
        let found = findings(&["osv-npm"], &stale, |_| None, NOW);
        assert_eq!(found.len(), 1);
        let f = &found[0];
        assert_eq!(f.incident_key(), "_veilleur/vulns-sync/osv-npm");
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(
            f.detail,
            "base osv-npm non synchronisée depuis 4 jours ; dernière issue : failed (délai\u{fffd}[2J dépassé)"
        );
    }

    #[test]
    fn never_synchronized_counts_from_its_declaration() {
        let since = |_: &str| Some(NOW - STALE_AFTER - 1);
        let found = findings(&["osv-crates-io"], &[], since, NOW);
        assert_eq!(found.len(), 1);
        assert!(found[0].detail.contains("jamais synchronisée"));
        assert!(findings(&["osv-crates-io"], &[], |_| Some(NOW), NOW).is_empty());
        assert!(findings(&["osv-crates-io"], &[], |_| None, NOW).is_empty());
    }
}
