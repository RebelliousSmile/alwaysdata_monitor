//! Comparaison des empreintes rapportées par l'agent avec la référence du
//! site. L'agent ne garde aucun état : c'est le veilleur qui voit une dérive.
//!
//! La référence est posée par le premier rapport, puis changée seulement par
//! `vigie site accept` : un fichier modifié reste signalé tant qu'il diffère.

use std::collections::BTreeMap;

use crate::finding::{Finding, Severity};
use crate::store::AGENT_PREFIX;

/// Nom du contrôle, sous le préfixe des agents pour être clos avec eux. Un
/// agent ne peut pas l'envoyer lui-même (`report.rs`).
pub const INTEGRITY: &str = "integrity";

/// Empreinte SHA-256 par chemin, `None` pour un fichier absent.
pub type Files = BTreeMap<String, Option<String>>;

pub fn check_name() -> String {
    format!("{AGENT_PREFIX}{INTEGRITY}")
}

/// Constats d'intégrité et nouvelle référence.
///
/// - Empreinte différente de celle de la référence : avertissement.
/// - Chemin inconnu de la référence, ou absent quand elle a été posée : son
///   empreinte entre dans la référence sans constat.
/// - Fichier absent : aucun constat ici, l'agent le signale déjà
///   (`critical-file`). La référence garde l'ancienne empreinte, si bien qu'un
///   fichier restauré différent est signalé.
/// - Chemin de la référence que l'agent ne rapporte plus : conservé.
pub fn compare(site: &str, baseline: &Files, files: &Files) -> (Vec<Finding>, Files) {
    let mut findings = Vec::new();
    let mut next = baseline.clone();
    for (path, hash) in files {
        let Some(hash) = hash else {
            next.entry(path.clone()).or_insert(None);
            continue;
        };
        match baseline.get(path) {
            Some(Some(expected)) if expected != hash => findings.push(Finding::new(
                site,
                check_name(),
                Severity::Warning,
                format!("modified:{path}"),
                format!(
                    "{path} modifié depuis la référence (sha256 {}…) : `vigie site accept {site}` si c'est voulu",
                    &hash[..16.min(hash.len())]
                ),
            )),
            Some(Some(_)) => {}
            Some(None) | None => {
                next.insert(path.clone(), Some(hash.clone()));
            }
        }
    }
    (findings, next)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "33bf0cf98fa40b5f4c44e053816b75487245c5fc01e66dd65470e2e70cbee0d8";
    const B: &str = "8978bc0aa6aece0fc74de901712dd160c804917cda1ade8afb59f29f526ff94a";

    fn files(entries: &[(&str, Option<&str>)]) -> Files {
        entries
            .iter()
            .map(|(p, h)| ((*p).to_owned(), h.map(str::to_owned)))
            .collect()
    }

    #[test]
    fn identical_files_give_nothing() {
        let base = files(&[(".htaccess", Some(A)), ("index.php", Some(B))]);
        let (findings, next) = compare("site-a", &base, &base);
        assert!(findings.is_empty());
        assert_eq!(next, base);
    }

    #[test]
    fn a_changed_hash_is_a_warning_and_keeps_the_baseline() {
        let base = files(&[(".htaccess", Some(A))]);
        let (findings, next) = compare("site-a", &base, &files(&[(".htaccess", Some(B))]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert_eq!(
            findings[0].incident_key(),
            "site-a/agent:integrity/modified:.htaccess"
        );
        assert!(findings[0].detail.contains("8978bc0aa6aece0f"));
        assert_eq!(next, base, "la référence ne suit pas une modification");
    }

    #[test]
    fn a_new_path_joins_the_baseline_silently() {
        let base = files(&[(".htaccess", Some(A))]);
        let (findings, next) = compare(
            "site-a",
            &base,
            &files(&[(".htaccess", Some(A)), ("index.php", Some(B))]),
        );
        assert!(findings.is_empty());
        assert_eq!(
            next,
            files(&[(".htaccess", Some(A)), ("index.php", Some(B))])
        );
    }

    #[test]
    fn a_missing_file_is_left_to_the_agent_and_keeps_its_hash() {
        let base = files(&[("wp-config.php", Some(A))]);
        let (findings, next) = compare("site-a", &base, &files(&[("wp-config.php", None)]));
        assert!(findings.is_empty());
        assert_eq!(next, base);
        // Restauré avec un autre contenu : signalé.
        let (findings, _) = compare("site-a", &next, &files(&[("wp-config.php", Some(B))]));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn a_file_absent_at_baseline_is_adopted_when_it_appears() {
        let base = files(&[(".user.ini", None)]);
        let (findings, next) = compare("site-a", &base, &files(&[(".user.ini", Some(A))]));
        assert!(findings.is_empty());
        assert_eq!(next, files(&[(".user.ini", Some(A))]));
    }

    #[test]
    fn a_path_no_longer_reported_is_kept() {
        let base = files(&[(".htaccess", Some(A)), ("old.php", Some(B))]);
        let (findings, next) = compare("site-a", &base, &files(&[(".htaccess", Some(A))]));
        assert!(findings.is_empty());
        assert_eq!(next, base);
    }
}
