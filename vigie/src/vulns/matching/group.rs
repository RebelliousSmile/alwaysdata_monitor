//! Fusion des failles candidates d'un purl sans version : deux candidates
//! qui partagent un identifiant ou un alias normalisé sont une même faille
//! (union-find, fermeture transitive). Une faille connue de GHSA et de
//! Wordfence sous le même CVE forme un seul groupe.
//!
//! Verdict d'un groupe pour une version : `Affected` si un membre l'est,
//! sinon `Unknown` avec « plage inconnue » prioritaire sur « version
//! inconnue » (aucune version ne lève une plage illisible), sinon
//! `NotAffected`. Un groupe n'est jamais « non touché » quand un membre est
//! touché ou inconnu.

use std::collections::{BTreeMap, BTreeSet};

use crate::vulns::advisory::{Affected, normalize_alias};
use crate::vulns::range::{UnknownReason, Verdict, match_advisory};
use crate::vulns::severity::AdvisoryFacts;
use crate::vulns::store::Candidate;
use crate::vulns::version::{Scheme, parse};

/// Membre d'un groupe : une faille d'une source, et son verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// Source de failles (`osv-packagist`, `wordfence`…).
    pub source: String,
    pub id: String,
    pub verdict: Verdict,
    /// Plage corrigée par l'exploitant (F3).
    pub corrected: bool,
    /// Faits de la règle de gravité (F4), correctif connu compris.
    pub facts: AdvisoryFacts,
    /// Lien vers l'avis (`source_url`).
    pub link: String,
}

/// Verdict d'un groupe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupVerdict {
    Affected {
        /// Correctif du groupe : le plus grand des plus petits correctifs
        /// des membres touchés s'ils se comparent, sinon tous ; vide :
        /// aucun correctif connu.
        fixed: Vec<String>,
        /// Version listée dans `versions[]` hors de toute plage (Packagist).
        divergence: bool,
    },
    Unknown(UnknownReason),
    NotAffected,
}

/// Failles fusionnées d'un purl sans version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// Plus petit `CVE-…` du groupe, sinon son plus petit identifiant.
    pub key: String,
    /// Identifiants et alias normalisés de tous les membres.
    pub ids: BTreeSet<String>,
    /// Membres dans l'ordre (source, identifiant).
    pub members: Vec<Member>,
    pub verdict: GroupVerdict,
}

/// Identifiant ou alias normalisé ; tel quel s'il est hors grammaire
/// (identifiants déjà validés par F1).
fn norm(raw: &str) -> String {
    normalize_alias(raw).unwrap_or_else(|| raw.to_owned())
}

fn find(parent: &mut [usize], mut i: usize) -> usize {
    while parent[i] != i {
        parent[i] = parent[parent[i]];
        i = parent[i];
    }
    i
}

/// Clé d'un groupe : plus petit CVE, sinon plus petit identifiant.
pub fn group_key(ids: &BTreeSet<String>) -> String {
    ids.iter()
        .find(|id| id.starts_with("CVE-"))
        .or_else(|| ids.iter().next())
        .cloned()
        .unwrap_or_default()
}

/// Correctif d'un ensemble de versions `fixed` d'un même comparateur : la
/// plus grande ; illisibles ou de comparateurs différents : toutes, triées.
fn group_fix(fixes: &[(Option<Scheme>, String)]) -> Vec<String> {
    let mut all: Vec<String> = fixes.iter().map(|(_, f)| f.clone()).collect();
    all.sort();
    all.dedup();
    if all.len() <= 1 {
        return all;
    }
    let schemes: BTreeSet<Option<Scheme>> = fixes.iter().map(|(s, _)| *s).collect();
    let [Some(scheme)] = schemes.into_iter().collect::<Vec<_>>()[..] else {
        return all;
    };
    let parsed: Option<Vec<_>> = all
        .iter()
        .map(|f| parse(scheme, f).ok().map(|v| (v, f.clone())))
        .collect();
    match parsed.and_then(|p| p.into_iter().max_by(|a, b| a.0.cmp(&b.0))) {
        Some((_, max)) => vec![max],
        None => all,
    }
}

/// Verdict d'un groupe à partir de ses membres.
pub fn group_verdict(members: &[(Verdict, Option<Scheme>)]) -> GroupVerdict {
    let mut affected = false;
    let mut divergence = false;
    let mut fixes = Vec::new();
    let mut unknown: Option<UnknownReason> = None;
    for (verdict, scheme) in members {
        match verdict {
            Verdict::Affected {
                fixed,
                divergence: d,
                ..
            } => {
                affected = true;
                divergence |= d;
                if let Some(f) = fixed {
                    fixes.push((*scheme, f.clone()));
                }
            }
            Verdict::Unknown(reason) => {
                unknown = Some(match (unknown, reason) {
                    (Some(UnknownReason::RangeUnknown), _) | (_, UnknownReason::RangeUnknown) => {
                        UnknownReason::RangeUnknown
                    }
                    _ => UnknownReason::VersionUnknown,
                });
            }
            Verdict::NotAffected => {}
        }
    }
    if affected {
        GroupVerdict::Affected {
            fixed: group_fix(&fixes),
            divergence,
        }
    } else if let Some(reason) = unknown {
        GroupVerdict::Unknown(reason)
    } else {
        GroupVerdict::NotAffected
    }
}

/// Groupes des candidates d'un purl sans version, évalués pour `version`
/// (`None` : version inconnue). Triés par clé.
pub fn groups(candidates: &[Candidate], version: Option<&str>) -> Vec<Group> {
    let n = candidates.len();
    let mut parent: Vec<usize> = (0..n).collect();
    let mut owner: BTreeMap<String, usize> = BTreeMap::new();
    let ids: Vec<BTreeSet<String>> = candidates
        .iter()
        .map(|c| {
            std::iter::once(&c.advisory.id)
                .chain(&c.advisory.aliases)
                .map(|raw| norm(raw))
                .collect()
        })
        .collect();
    for (i, set) in ids.iter().enumerate() {
        for id in set {
            match owner.get(id) {
                Some(&j) => {
                    let (a, b) = (find(&mut parent, i), find(&mut parent, j));
                    if a != b {
                        parent[a.max(b)] = a.min(b);
                    }
                }
                None => {
                    owner.insert(id.clone(), i);
                }
            }
        }
    }
    let mut by_root: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for i in 0..n {
        let root = find(&mut parent, i);
        by_root.entry(root).or_default().push(i);
    }
    let mut out: Vec<Group> = by_root
        .into_values()
        .map(|indexes| {
            let mut group_ids = BTreeSet::new();
            let mut members = Vec::new();
            let mut verdicts = Vec::new();
            for i in indexes {
                let c = &candidates[i];
                group_ids.extend(ids[i].iter().cloned());
                let lines: Vec<&Affected> = c.lines.iter().collect();
                let verdict = match_advisory(&lines, version);
                let fix_available = matches!(&verdict, Verdict::Affected { fixed: Some(_), .. });
                verdicts.push((verdict.clone(), c.lines.first().map(|l| l.scheme)));
                members.push(Member {
                    source: c.source.clone(),
                    id: c.advisory.id.clone(),
                    verdict,
                    corrected: c.corrected,
                    facts: AdvisoryFacts::from_advisory(&c.advisory, fix_available),
                    link: c.advisory.source_url.clone(),
                });
            }
            members.sort_by(|a, b| (&a.source, &a.id).cmp(&(&b.source, &b.id)));
            Group {
                key: group_key(&group_ids),
                ids: group_ids,
                members,
                verdict: group_verdict(&verdicts),
            }
        })
        .collect();
    out.sort_by(|a, b| a.key.cmp(&b.key));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn affected(fixed: Option<&str>) -> Verdict {
        Verdict::Affected {
            fixed: fixed.map(str::to_owned),
            divergence: false,
            beyond_last_known: false,
        }
    }

    #[test]
    fn range_unknown_wins_over_version_unknown() {
        let v = group_verdict(&[
            (Verdict::Unknown(UnknownReason::VersionUnknown), None),
            (Verdict::Unknown(UnknownReason::RangeUnknown), None),
            (Verdict::NotAffected, None),
        ]);
        assert_eq!(v, GroupVerdict::Unknown(UnknownReason::RangeUnknown));
    }

    #[test]
    fn one_affected_member_makes_the_group_affected() {
        let v = group_verdict(&[
            (Verdict::NotAffected, Some(Scheme::Php)),
            (affected(Some("1.2.4")), Some(Scheme::Php)),
            (Verdict::Unknown(UnknownReason::RangeUnknown), None),
        ]);
        assert_eq!(
            v,
            GroupVerdict::Affected {
                fixed: vec!["1.2.4".into()],
                divergence: false
            }
        );
    }

    #[test]
    fn the_group_fix_is_the_largest_comparable_one() {
        let v = group_verdict(&[
            (affected(Some("1.2.10")), Some(Scheme::Php)),
            (affected(Some("1.2.5")), Some(Scheme::Php)),
            (affected(None), Some(Scheme::Php)),
        ]);
        assert_eq!(
            v,
            GroupVerdict::Affected {
                fixed: vec!["1.2.10".into()],
                divergence: false
            }
        );
        // Comparateurs différents : tous listés.
        let v = group_verdict(&[
            (affected(Some("1.2.4")), Some(Scheme::Php)),
            (affected(Some("1.2.5")), Some(Scheme::Composer)),
        ]);
        assert!(matches!(v, GroupVerdict::Affected { fixed, .. } if fixed.len() == 2));
    }

    #[test]
    fn the_key_is_the_smallest_cve_then_the_smallest_id() {
        let ids: BTreeSet<String> = ["WF-2", "GHSA-x", "CVE-2099-0002", "CVE-2099-0001"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        assert_eq!(group_key(&ids), "CVE-2099-0001");
        let ids: BTreeSet<String> = ["WF-2", "GHSA-x"].into_iter().map(str::to_owned).collect();
        assert_eq!(group_key(&ids), "GHSA-x");
    }
}
