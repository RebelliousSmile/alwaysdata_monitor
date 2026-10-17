//! Rapprochement pur (#21, phase 1) : fusion des doublons, verdicts,
//! gravité par F4, dérogations, constats et leur détail, péremption. Données
//! fictives seulement (`support/matching_data.rs`).

use std::collections::BTreeSet;
use std::time::Duration;

use vigie::config::SiteKind;
use vigie::finding::{Finding, Severity};
use vigie::inventory::{Scope, Source};
use vigie::vulns::exploit::MemoryTables;
use vigie::vulns::matching::assess::{GroupResult, MemberFacts, State, assess};
use vigie::vulns::matching::finding::{
    KEY_STALE_AGENT, KEY_STALE_CI, MAX_SUBJECT_CHARS, MAX_VULNS_DETAIL_CHARS, View, base_finding,
    stale_finding,
};
use vigie::vulns::matching::group::{GroupVerdict, groups};
use vigie::vulns::matching::waiver::{Applies, Waiver, validate, validate_against};
use vigie::vulns::matching::{Component, admitted, key};
use vigie::vulns::purl::{Purl, PurlType};
use vigie::vulns::range::UnknownReason;
use vigie::vulns::sources::Redistribution;
use vigie::vulns::store::Candidate;
use vigie::vulns::version::Scheme;

#[path = "support/matching_data.rs"]
mod matching_data;
use matching_data::*;

const NOW: i64 = 4_070_908_800; // 2099-01-01
const DAY: i64 = 86_400;

fn component(source: Source, base: &str, version: Option<&str>, path: &str) -> Component {
    let base = Purl::parse(base).unwrap();
    Component {
        source,
        ecosystem: base.ty(),
        base,
        version: version.map(str::to_owned),
        scope: Scope::Required,
        path: path.into(),
        carried: false,
    }
}

fn evaluate(cands: &[Candidate], version: Option<&str>, t: &MemoryTables) -> Vec<GroupResult> {
    groups(cands, version)
        .iter()
        .filter_map(|g| assess(g, t))
        .collect()
}

fn view(source: Source, base: &str, version: Option<&str>, cands: &[Candidate]) -> View {
    view_with(source, base, version, cands, &tables(&[], &[]))
}

fn view_with(
    source: Source,
    base: &str,
    version: Option<&str>,
    cands: &[Candidate],
    t: &MemoryTables,
) -> View {
    View {
        component: component(source, base, version, "wp-content/plugins/exemple-plugin"),
        groups: evaluate(cands, version, t),
    }
}

fn attribution(m: &MemberFacts) -> Option<String> {
    Some(match m.source.as_str() {
        "wordfence" => ATTRIBUTION_WF.into(),
        _ => ATTRIBUTION_FREE.into(),
    })
}

fn finding(base: &str, views: &[View], waivers: &[Waiver], open: bool) -> Option<Finding> {
    finding_at(base, views, waivers, open, NOW)
}

fn finding_at(
    base: &str,
    views: &[View],
    waivers: &[Waiver],
    open: bool,
    now: i64,
) -> Option<Finding> {
    let key = key(&Purl::parse(base).unwrap());
    base_finding("site-a", &key, views, waivers, &attribution, open, now)
}

/// Faille Wordfence fictive de l'extension, corrigée en 1.2.4.
fn wf(id: &str, aliases: &[&str], score: Option<u8>) -> Candidate {
    cand(
        "wordfence",
        &Fake {
            id,
            aliases,
            purl: PLUGIN,
            scheme: Scheme::Php,
            score,
            attribution: ATTRIBUTION_WF,
            ..Fake::default()
        },
    )
}

/// GHSA fictive de la même extension.
fn ghsa(id: &str, aliases: &[&str], fixed: &str) -> Candidate {
    cand(
        "osv-packagist",
        &Fake {
            id,
            aliases,
            purl: PLUGIN,
            scheme: Scheme::Php,
            ranges: &[("0", fixed)],
            ..Fake::default()
        },
    )
}

#[test]
fn an_affected_plugin_opens_one_finding_keyed_by_its_base() {
    let cands = [wf("WF-2099-0001", &["CVE-2099-0001"], Some(75))];
    let v = view(Source::Agent, PLUGIN, Some("1.2.3"), &cands);
    assert_eq!(v.groups.len(), 1);
    assert_eq!(v.groups[0].state, State::Affected);
    assert_eq!(v.groups[0].fixed, ["1.2.4"]);
    let f = finding(PLUGIN, &[v], &[], false).expect("constat");
    assert_eq!(f.incident_key(), format!("site-a/vulns/{PLUGIN}"));
    assert_eq!(f.severity, Severity::Warning);
    assert!(f.detail.contains("corriger : ≥ 1.2.4"), "{}", f.detail);
    assert!(f.detail.contains(ATTRIBUTION_WF), "{}", f.detail);
    assert!(f.detail.contains("usage interne"), "{}", f.detail);

    // Version corrigée : aucun groupe, l'incident ouvert se clôt.
    let fixed = view(Source::Agent, PLUGIN, Some("1.2.4"), &cands);
    assert!(fixed.groups.is_empty());
    assert_eq!(finding(PLUGIN, &[fixed], &[], true), None);
}

#[test]
fn a_four_component_module_and_prereleases_use_their_comparator() {
    let fop = cand(
        "friends-of-presta",
        &Fake {
            id: "FOP-2099-0001",
            aliases: &["CVE-2099-0101"],
            purl: MODULE,
            scheme: Scheme::Php,
            ranges: &[("0", "1.6.1.25")],
            ..Fake::default()
        },
    );
    let views: Vec<View> = (0..4)
        .map(|i| View {
            component: component(
                Source::Agent,
                MODULE,
                Some("1.6.1.24"),
                &format!("modules/exemplemodule{i}"),
            ),
            groups: evaluate(
                std::slice::from_ref(&fop),
                Some("1.6.1.24"),
                &tables(&[], &[]),
            ),
        })
        .collect();
    assert_eq!(views[0].groups[0].fixed, ["1.6.1.25"]);
    let f = finding(MODULE, &views, &[], false).expect("constat");
    assert!(f.detail.contains("faits seulement") || f.detail.contains("usage interne"));
    assert!(
        f.detail
            .starts_with(&format!("{MODULE} (agent : 1.6.1.24) : 1 faille(s)"))
    );

    let rc = cand(
        "osv-packagist",
        &Fake {
            ranges: &[("2.0.0-beta1", "2.0.0")],
            ..Fake::default()
        },
    );
    let g = evaluate(&[rc], Some("2.0.0-RC1"), &tables(&[], &[]));
    assert_eq!(g[0].state, State::Affected);
}

#[test]
fn packagist_enumeration_and_range_both_count() {
    let listed = cand(
        "osv-packagist",
        &Fake {
            ranges: &[("1.0.0", "1.2.0")],
            versions: &["1.0.0", "1.5.0"],
            ..Fake::default()
        },
    );
    let g = evaluate(
        std::slice::from_ref(&listed),
        Some("1.5.0"),
        &tables(&[], &[]),
    );
    assert!(g[0].divergence, "listée hors plage");
    let g = evaluate(&[listed], Some("1.1.0"), &tables(&[], &[]));
    assert_eq!(g[0].state, State::Affected, "la plage fait foi");
    assert!(!g[0].divergence);
}

#[test]
fn duplicates_merge_by_id_and_alias_transitively() {
    let cands = [
        wf("WF-2099-0001", &["CVE-2099-0001"], Some(75)),
        ghsa("GHSA-2099-aaaa-0001", &["CVE-2099-0001"], "1.2.4"),
    ];
    let g = groups(&cands, Some("1.2.3"));
    assert_eq!(g.len(), 1);
    assert_eq!(g[0].key, "CVE-2099-0001");
    assert_eq!(g[0].members.len(), 2);
    let sources: BTreeSet<&str> = g[0].members.iter().map(|m| m.source.as_str()).collect();
    assert_eq!(sources.len(), 2);

    // Sans CVE commun : deux groupes.
    let cands = [
        wf("WF-2099-0002", &[], Some(75)),
        ghsa("GHSA-2099-aaaa-0002", &["CVE-2099-0002"], "1.2.4"),
    ];
    assert_eq!(groups(&cands, Some("1.2.3")).len(), 2);

    // A~B par CVE, B~C par l'identifiant GHSA : un seul groupe.
    let cands = [
        wf("WF-2099-0003", &["CVE-2099-0003"], Some(75)),
        ghsa("GHSA-2099-aaaa-0003", &["CVE-2099-0003"], "1.2.4"),
        cand(
            "friends-of-presta",
            &Fake {
                id: "FOP-2099-0003",
                aliases: &["GHSA-2099-aaaa-0003"],
                purl: PLUGIN,
                scheme: Scheme::Php,
                ..Fake::default()
            },
        ),
    ];
    let g = groups(&cands, Some("1.2.3"));
    assert_eq!(g.len(), 1);
    assert_eq!(g[0].members.len(), 3);
}

#[test]
fn a_merged_group_takes_the_most_restrictive_level_and_keeps_no_attribution() {
    let cands = [
        wf("WF-2099-0001", &["CVE-2099-0001"], Some(75)),
        ghsa("GHSA-2099-aaaa-0001", &["CVE-2099-0001"], "1.2.5"),
    ];
    let g = evaluate(&cands, Some("1.2.3"), &tables(&[], &[]));
    assert_eq!(g[0].redistribution, Redistribution::Internal);
    assert_eq!(g[0].fixed, ["1.2.5"], "plus grand des correctifs");
    let json = serde_json::to_string(&g[0]).unwrap();
    assert!(!json.contains("attribution"), "{json}");
    assert!(!json.contains("Exemple Intelligence"), "{json}");

    let cands = [
        cand(
            "friends-of-presta",
            &Fake {
                id: "FOP-2099-0004",
                aliases: &["CVE-2099-0004"],
                purl: PLUGIN,
                scheme: Scheme::Php,
                ..Fake::default()
            },
        ),
        ghsa("GHSA-2099-aaaa-0004", &["CVE-2099-0004"], "1.2.4"),
    ];
    let g = evaluate(&cands, Some("1.2.3"), &tables(&[], &[]));
    assert_eq!(g[0].redistribution, Redistribution::FactsOnly);

    // Un membre touché suffit.
    let cands = [
        wf("WF-2099-0005", &["CVE-2099-0005"], Some(75)),
        ghsa("GHSA-2099-aaaa-0005", &["CVE-2099-0005"], "1.0.0"),
    ];
    let g = groups(&cands, Some("1.2.3"));
    assert!(matches!(g[0].verdict, GroupVerdict::Affected { .. }));
}

#[test]
fn unknown_version_or_range_is_never_silent() {
    let npm = |score| {
        cand(
            "osv-npm",
            &Fake {
                purl: NPM,
                scheme: Scheme::Semver,
                score,
                ..Fake::default()
            },
        )
    };
    let g = evaluate(&[npm(Some(75))], None, &tables(&[], &[]));
    assert_eq!(g[0].state, State::VersionUnknown);
    assert_eq!(g[0].severity, Severity::Info);
    let g = evaluate(&[npm(Some(98))], None, &tables(&[], &[]));
    assert_eq!(g[0].severity, Severity::Warning, "faille critique");
    let open = View {
        component: component(Source::Ci, NPM, None, "package-lock.json"),
        groups: g,
    };
    let f = finding(NPM, &[open], &[], false).expect("avertissement");
    assert!(f.detail.contains("version inconnue"), "{}", f.detail);

    // Un membre à plage illisible, l'autre à version inconnue.
    let unevaluable = cand(
        "friends-of-presta",
        &Fake {
            id: "FOP-2099-0006",
            aliases: &["CVE-2099-0006"],
            purl: PLUGIN,
            scheme: Scheme::Php,
            ranges: &[],
            ..Fake::default()
        },
    );
    let mut corrected = ghsa("GHSA-2099-aaaa-0006", &["CVE-2099-0006"], "1.2.4");
    corrected.corrected = true;
    let g = groups(&[unevaluable.clone(), corrected.clone()], None);
    assert_eq!(
        g[0].verdict,
        GroupVerdict::Unknown(UnknownReason::RangeUnknown)
    );
    let v = view(
        Source::Agent,
        PLUGIN,
        Some("1.2.3"),
        &[unevaluable, corrected],
    );
    let f = finding(PLUGIN, &[v], &[], false).expect("constat");
    assert!(f.detail.contains("plage corrigée"), "{}", f.detail);
}

#[test]
fn two_sources_and_two_paths_make_one_finding() {
    let cands = [wf("WF-2099-0001", &["CVE-2099-0001"], Some(95))];
    let agent = view(Source::Agent, PLUGIN, Some("1.2.3"), &cands);
    let ci = view(Source::Ci, PLUGIN, Some("1.2.4"), &cands);
    assert!(ci.groups.is_empty());
    let f = finding(PLUGIN, &[agent.clone(), ci], &[], false).expect("constat");
    assert_eq!(f.severity, Severity::Critical, "gravité de la vue agent");
    assert!(
        f.detail.contains("agent : 1.2.3 ; ci : 1.2.4"),
        "{}",
        f.detail
    );

    let other_path = View {
        component: component(Source::Agent, PLUGIN, Some("1.1.0"), "vendor/b"),
        groups: evaluate(&cands, Some("1.1.0"), &tables(&[], &[])),
    };
    let f = finding(PLUGIN, &[agent.clone(), other_path], &[], false).unwrap();
    assert!(f.detail.contains("agent : 1.2.3, 1.1.0"), "{}", f.detail);

    let mut carried = agent;
    carried.component.carried = true;
    let f = finding(PLUGIN, &[carried], &[], false).unwrap();
    assert!(
        f.detail.contains("absent d'un relevé partiel"),
        "{}",
        f.detail
    );
}

#[test]
fn thirty_vulns_make_one_finding_at_the_highest_severity() {
    let ids: Vec<String> = (0..30).map(|i| format!("WF-2099-1{i:03}")).collect();
    let cves: Vec<String> = (0..30).map(|i| format!("CVE-2099-1{i:03}")).collect();
    let cands: Vec<Candidate> = (0..30)
        .map(|i| {
            let alias = [cves[i].as_str()];
            wf(&ids[i], &alias, Some(if i == 7 { 95 } else { 50 }))
        })
        .collect();
    let v = view(Source::Agent, PLUGIN, Some("1.2.3"), &cands);
    assert_eq!(v.groups.len(), 30);
    let f = finding(PLUGIN, &[v], &[], false).unwrap();
    assert_eq!(f.severity, Severity::Critical);
    assert!(f.detail.starts_with(&format!(
        "{PLUGIN} (agent : 1.2.3) : 30 faille(s), dont 1 critique(s)"
    )));
}

#[test]
fn opening_needs_a_warning_and_closing_needs_no_group_left() {
    let info = [wf("WF-2099-0001", &["CVE-2099-0001"], Some(30))];
    let v = view(Source::Agent, PLUGIN, Some("1.2.3"), &info);
    assert_eq!(finding(PLUGIN, std::slice::from_ref(&v), &[], false), None);
    let f = finding(PLUGIN, &[v], &[], true).expect("gardé ouvert");
    assert_eq!(f.severity, Severity::Info);

    // EPSS 0,09 → 0,11 → 0,09 : jamais de battement.
    let low = tables(&[], &[("CVE-2099-0001", 90_000)]);
    let high = tables(&[], &[("CVE-2099-0001", 110_000)]);
    let at = |t: &MemoryTables, open| {
        let v = view_with(Source::Agent, PLUGIN, Some("1.2.3"), &info, t);
        finding(PLUGIN, &[v], &[], open).map(|f| f.severity)
    };
    assert_eq!(at(&low, false), None);
    assert_eq!(at(&high, false), Some(Severity::Warning));
    assert_eq!(at(&low, true), Some(Severity::Info));

    // Entrée dans KEV : même clé, critique.
    let kev = tables(&["CVE-2099-0001"], &[]);
    let v = view_with(Source::Agent, PLUGIN, Some("1.2.3"), &info, &kev);
    let f = finding(PLUGIN, &[v], &[], true).unwrap();
    assert_eq!(f.severity, Severity::Critical);
    assert_eq!(f.key, PLUGIN);
}

fn waiver(source: Source, advisory: &str, version: &str, covered: &[&str], until: i64) -> Waiver {
    Waiver {
        id: 1,
        source,
        base: PLUGIN.into(),
        advisory_ref: advisory.into(),
        version: version.into(),
        covered_ids: covered.iter().map(|s| (*s).into()).collect(),
        until,
        reason: "motif fictif".into(),
    }
}

#[test]
fn a_waiver_takes_its_group_out_of_the_severity() {
    let cands = [
        wf("WF-2099-0002", &["CVE-2099-0002"], Some(95)),
        wf("WF-2099-0003", &["CVE-2099-0003"], Some(75)),
    ];
    let v = view(Source::Agent, PLUGIN, Some("1.2.3"), &cands);
    let w = waiver(
        Source::Agent,
        "CVE-2099-0002",
        "1.2.3",
        &["CVE-2099-0002", "WF-2099-0002"],
        NOW + 30 * DAY,
    );
    let f = finding(
        PLUGIN,
        std::slice::from_ref(&v),
        std::slice::from_ref(&w),
        false,
    )
    .unwrap();
    assert_eq!(f.severity, Severity::Warning, "critique sous dérogation");
    assert!(
        f.detail.contains("sous dérogation jusqu'au"),
        "{}",
        f.detail
    );

    // Seul groupe touché sous dérogation : tenu ouvert en information.
    let only = view(Source::Agent, PLUGIN, Some("1.2.3"), &cands[..1]);
    let f = finding(
        PLUGIN,
        std::slice::from_ref(&only),
        std::slice::from_ref(&w),
        false,
    )
    .expect("tenu ouvert");
    assert_eq!(f.severity, Severity::Info);

    // À J+31 : expirée, la gravité revient.
    let later = NOW + 31 * DAY;
    assert_eq!(
        w.applies(&only.groups[0], Some("1.2.3"), later),
        Applies::Expired
    );
    let f = finding_at(
        PLUGIN,
        std::slice::from_ref(&only),
        std::slice::from_ref(&w),
        true,
        later,
    )
    .unwrap();
    assert_eq!(f.severity, Severity::Critical);

    // Autre version : caduque ; dérogation ci sans effet sur la vue agent.
    assert_eq!(
        w.applies(&only.groups[0], Some("1.2.3.1"), NOW),
        Applies::VersionChanged
    );
    let ci = Waiver {
        source: Source::Ci,
        ..w.clone()
    };
    let f = finding(PLUGIN, std::slice::from_ref(&only), &[ci], false).unwrap();
    assert_eq!(f.severity, Severity::Critical);
}

#[test]
fn a_waiver_covers_the_group_it_saw_and_lapses_when_it_grows() {
    let cands = [
        wf("WF-2099-0004", &["CVE-2099-0004"], Some(95)),
        ghsa("GHSA-2099-aaaa-0004", &["CVE-2099-0004"], "1.2.4"),
    ];
    let v = view(Source::Agent, PLUGIN, Some("1.2.3"), &cands);
    let g = &v.groups[0];
    let covered: Vec<&str> = g.ids.iter().map(String::as_str).collect();
    assert_eq!(
        covered,
        ["CVE-2099-0004", "GHSA-2099-aaaa-0004", "WF-2099-0004"]
    );
    let w = waiver(
        Source::Agent,
        "GHSA-2099-aaaa-0004",
        "1.2.3",
        &covered,
        NOW + DAY,
    );
    assert!(w.targets(g));
    assert_eq!(w.applies(g, Some("1.2.3"), NOW), Applies::Ok);

    let grown = [
        cands[0].clone(),
        cands[1].clone(),
        ghsa("GHSA-2099-bbbb-0004", &["CVE-2099-0004"], "1.2.4"),
    ];
    let v = view(Source::Agent, PLUGIN, Some("1.2.3"), &grown);
    assert_eq!(
        w.applies(&v.groups[0], Some("1.2.3"), NOW),
        Applies::GroupChanged
    );

    let kev = tables(&["CVE-2099-0004"], &[]);
    let v = view_with(Source::Agent, PLUGIN, Some("1.2.3"), &cands, &kev);
    assert_eq!(w.applies(&v.groups[0], Some("1.2.3"), NOW), Applies::Kev);
    assert!(validate_against(&v.groups[0], Some("1.2.3")).is_err());
    assert_eq!(
        finding(PLUGIN, &[v], &[w], false).unwrap().severity,
        Severity::Critical
    );
}

#[test]
fn validate_refuses_bad_deadlines_and_reasons() {
    assert!(validate(NOW + 90 * DAY, "motif", NOW).is_ok());
    assert!(validate(NOW + 90 * DAY + 1, "motif", NOW).is_err());
    assert!(validate(NOW - 1, "motif", NOW).is_err());
    assert!(validate(NOW, "motif", NOW).is_err());
    assert!(validate(NOW + DAY, "", NOW).is_err());
    assert!(validate(NOW + DAY, "   ", NOW).is_err());
    assert!(validate(NOW + DAY, &"x".repeat(500), NOW).is_ok());
    assert!(validate(NOW + DAY, &"x".repeat(501), NOW).is_err());
}

#[test]
fn the_key_never_carries_a_version_path_or_source() {
    let cands = [wf("WF-2099-0001", &["CVE-2099-0001"], Some(75))];
    let mut v = view(Source::Ci, PLUGIN, Some("1.2.3"), &cands);
    v.component.path = "chemin/propre-au-site".into();
    let f = finding(PLUGIN, &[v], &[], false).unwrap();
    assert_eq!(f.key, PLUGIN);
    assert!(!f.detail.contains("chemin/propre-au-site"));
}

#[test]
fn a_long_detail_keeps_attributions_whole_and_stays_bounded() {
    let ids: Vec<String> = (0..30).map(|i| format!("GHSA-2099-cccc-{i:04}")).collect();
    let cands: Vec<Candidate> = ids.iter().map(|id| ghsa(id, &[], "1.2.4")).collect();
    let v = view(Source::Agent, PLUGIN, Some("1.2.3"), &cands);
    let long = format!("Exemple Intelligence SARL {}", "x".repeat(1_974));
    assert_eq!(long.chars().count(), 2_000);
    let hostile = |m: &MemberFacts| -> Option<String> {
        Some(if m.id.ends_with("0000") {
            long.clone()
        } else {
            "Attribution\u{1b}[2J fictive\u{202e}".into()
        })
    };
    let f = base_finding("site-a", PLUGIN, &[v], &[], &hostile, false, NOW).unwrap();
    assert!(f.detail.chars().count() <= MAX_VULNS_DETAIL_CHARS);
    assert!(f.detail.contains(&long), "attribution entière");
    assert!(
        f.detail.contains("autres : vigie site vulns site-a"),
        "{}",
        f.detail
    );
    assert!(!f.detail.contains('\u{1b}') && !f.detail.contains('\u{202e}'));
    assert!(f.detail.contains("Attribution\u{fffd}[2J fictive\u{fffd}"));
    let first = f.detail.lines().next().unwrap();
    assert!(first.chars().count() <= MAX_SUBJECT_CHARS);
}

#[test]
fn an_inventory_goes_stale_per_source() {
    let agent = Duration::from_secs(7 * 86_400);
    let ci = Duration::from_secs(35 * 86_400);
    assert_eq!(vigie::inventory::stale_after(Source::Agent), agent);
    assert_eq!(vigie::inventory::stale_after(Source::Ci), ci);
    let seen = NOW - 7 * DAY - 1;
    let f = stale_finding("site-a", Source::Agent, Some(seen), 0, agent, NOW).unwrap();
    assert_eq!(f.key, KEY_STALE_AGENT);
    assert_eq!(f.severity, Severity::Warning);
    assert_eq!(
        stale_finding(
            "site-a",
            Source::Agent,
            Some(NOW - 7 * DAY + 1),
            0,
            agent,
            NOW
        ),
        None
    );
    assert_eq!(
        stale_finding("site-a", Source::Ci, Some(seen), 0, ci, NOW),
        None
    );
    let f = stale_finding("site-a", Source::Ci, Some(NOW - 35 * DAY - 1), 0, ci, NOW).unwrap();
    assert_eq!(f.key, KEY_STALE_CI);
    // Aucun inventaire : compté depuis la déclaration.
    let f = stale_finding("site-a", Source::Agent, None, NOW - 8 * DAY, agent, NOW).unwrap();
    assert!(f.detail.contains("déclaration"), "{}", f.detail);
}

#[test]
fn only_admitted_ecosystems_are_matched() {
    assert!(!admitted(SiteKind::Wordpress, PurlType::Prestashop));
    assert!(admitted(SiteKind::Wordpress, PurlType::Wordpress));
    for kind in [SiteKind::Generic, SiteKind::Wordpress, SiteKind::Prestashop] {
        assert!(admitted(kind, PurlType::Cargo), "{kind:?}");
    }
}

#[test]
fn fuzz_never_panics_and_keeps_details_bounded() {
    let started = std::time::Instant::now();
    let mut rng = XorShift(0x5eed_f7f7_2099_0021);
    let versions = [
        "1.0.0",
        "1.2.3",
        "1.2.4",
        "2.0.0-RC1",
        "0",
        "9.9.9.9",
        "1.2.3-beta",
        "",
    ];
    let pool: Vec<Candidate> = (0..12)
        .map(|i| {
            let id = format!("GHSA-2099-ffff-{i:04}");
            let a1 = format!("CVE-2099-9{:03}", i % 5);
            let a2 = format!("GHSA-2099-ffff-{:04}", (i + 3) % 12);
            let aliases = [a1.as_str(), a2.as_str()];
            let fix = versions[i % 4];
            cand(
                if i % 3 == 0 {
                    "wordfence"
                } else {
                    "osv-packagist"
                },
                &Fake {
                    id: &id,
                    aliases: &aliases[..i % 3],
                    purl: PLUGIN,
                    scheme: Scheme::Php,
                    ranges: if i % 5 == 4 { &[] } else { &[("0", "")] },
                    score: (i % 4 != 0).then_some((i * 9 % 101) as u8),
                    ..Fake::default()
                },
            )
            .tap_fix(fix)
        })
        .collect();
    let t = tables(&["CVE-2099-9001"], &[("CVE-2099-9002", 150_000)]);
    for _ in 0..20_000 {
        let n = 1 + rng.below(pool.len());
        let picked: Vec<Candidate> = (0..n)
            .map(|_| pool[rng.below(pool.len())].clone())
            .collect();
        let mut views = Vec::new();
        for source in [Source::Agent, Source::Ci] {
            if rng.below(2) == 0 {
                continue;
            }
            let raw = versions[rng.below(versions.len())];
            let version = (!raw.is_empty()).then_some(raw);
            views.push(view_with(source, PLUGIN, version, &picked, &t));
        }
        let open = rng.below(2) == 0;
        if let Some(f) = finding(PLUGIN, &views, &[], open) {
            assert!(f.detail.chars().count() <= MAX_VULNS_DETAIL_CHARS);
            assert!(f.detail.lines().next().unwrap().chars().count() <= MAX_SUBJECT_CHARS);
            assert_eq!(f.key, PLUGIN);
        }
    }
    assert!(started.elapsed() < Duration::from_secs(60));
}

trait TapFix {
    fn tap_fix(self, fix: &str) -> Self;
}

impl TapFix for Candidate {
    /// Plage `[0, fix)` sur la première ligne, ou ouverte si `fix` est vide.
    fn tap_fix(mut self, fix: &str) -> Self {
        use vigie::vulns::advisory::Event;
        if let Some(range) = self.lines.first_mut().and_then(|l| l.ranges.first_mut()) {
            range.events.retain(|e| matches!(e, Event::Introduced(_)));
            if !fix.is_empty() && fix != "0" {
                range.events.push(Event::Fixed(fix.into()));
            }
        }
        self
    }
}
