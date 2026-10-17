//! Modèle des failles (#15, phase 2) : purl, `Advisory::build` et
//! `from_osv`, gravité, licences, verdicts et agrégation, fixtures réelles
//! (`tests/fixtures/vulns/osv`, sous `NOTICE`), fictives et hostiles, fuzz.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use vigie::vulns::advisory::{
    Advisory, Draft, DraftAffected, DraftEvent, DraftRange, LICENSE_UNKNOWN, MAX_ALIASES, MAX_CWES,
    MAX_REFERENCES, Reason, Score, ScoreOrigin, Seen, Tally, from_osv,
};
use vigie::vulns::cvss;
use vigie::vulns::purl::{self, FromOsvError, Purl, PurlType};
use vigie::vulns::range::{UnknownReason, Verdict, match_advisory};
use vigie::vulns::version::{Scheme, SourceEcosystem};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vulns")
}

fn read(rel: &str) -> Vec<u8> {
    std::fs::read(fixtures().join(rel)).unwrap_or_else(|e| panic!("{rel} : {e}"))
}

fn load(rel: &str, dump: SourceEcosystem) -> (Advisory, Tally) {
    let mut tally = Tally::default();
    let a = from_osv(&read(rel), dump, &mut tally).unwrap_or_else(|r| panic!("{rel} : {r:?}"));
    (a, tally)
}

fn verdict(a: &Advisory, purl: &str, version: Option<&str>) -> Verdict {
    let purl = Purl::parse(purl).unwrap();
    let lines = a.lines_for(&purl);
    assert!(!lines.is_empty(), "{} : aucune ligne pour {purl}", a.id);
    match_advisory(&lines, version)
}

fn affected(fixed: Option<&str>) -> Verdict {
    Verdict::Affected {
        fixed: fixed.map(str::to_owned),
        divergence: false,
        beyond_last_known: false,
    }
}

const RANGE_UNKNOWN: Verdict = Verdict::Unknown(UnknownReason::RangeUnknown);
const VERSION_UNKNOWN: Verdict = Verdict::Unknown(UnknownReason::VersionUnknown);

// ---------------------------------------------------------------- purl

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PurlVector {
    #[serde(rename = "in")]
    input: String,
    out: Option<String>,
    why: String,
}

#[test]
fn purl_vectors() {
    let vectors: Vec<PurlVector> = serde_json::from_slice(&read("purl.json")).unwrap();
    assert!(vectors.len() > 50);
    for v in &vectors {
        let got = Purl::parse(&v.input).ok().map(|p| p.canonical());
        assert_eq!(got, v.out, "{:?} ({})", v.input, v.why);
        if let Some(out) = &v.out {
            // Forme canonique idempotente.
            assert_eq!(Purl::parse(out).unwrap().canonical(), *out, "{out}");
        }
    }
}

#[derive(Deserialize)]
struct OsvPurlVector {
    ecosystem: String,
    name: String,
    out: Option<Vec<String>>,
    why: String,
}

#[test]
fn osv_purl_vectors() {
    let vectors: Vec<OsvPurlVector> = serde_json::from_slice(&read("osv-purl.json")).unwrap();
    for v in &vectors {
        let got = purl::from_osv(&v.ecosystem, &v.name);
        match &v.out {
            Some(out) => {
                let got: Vec<String> = got
                    .unwrap_or_else(|e| panic!("{} {} : {e:?}", v.ecosystem, v.name))
                    .iter()
                    .map(Purl::canonical)
                    .collect();
                assert_eq!(&got, out, "{} {} ({})", v.ecosystem, v.name, v.why);
            }
            None => {
                let want = if v.why.starts_with("out_of_scope") {
                    FromOsvError::OutOfScope
                } else {
                    FromOsvError::BadName
                };
                assert_eq!(got, Err(want), "{} {} ({})", v.ecosystem, v.name, v.why);
            }
        }
    }
}

#[test]
fn purl_accessors() {
    let p = Purl::parse("pkg:npm/%40exemple/paquet@2.0.0-rc.1").unwrap();
    assert_eq!(p.ty(), PurlType::Npm);
    assert_eq!(p.namespace(), Some("@exemple"));
    assert_eq!(p.name(), "paquet");
    assert_eq!(p.version(), Some("2.0.0-rc.1"));
    assert_eq!(p.without_version().canonical(), "pkg:npm/%40exemple/paquet");
    assert_eq!(
        p.without_version()
            .with_version("3.0.0")
            .unwrap()
            .canonical(),
        "pkg:npm/%40exemple/paquet@3.0.0"
    );
    assert!(p.with_version("1 0").is_err());
    let c = Purl::parse("pkg:cargo/serde").unwrap();
    assert_eq!(c.namespace(), None);
}

// ---------------------------------------------------------------- CVSS

#[derive(Deserialize)]
struct CvssScored {
    vector: String,
    tenths: u8,
    why: String,
}

#[derive(Deserialize)]
struct CvssOther {
    vector: String,
    why: String,
}

#[derive(Deserialize)]
struct CvssVectors {
    v3: Vec<CvssScored>,
    v4_valid: Vec<CvssOther>,
    invalid: Vec<CvssOther>,
}

#[test]
fn cvss_vectors() {
    let v: CvssVectors = serde_json::from_slice(&read("cvss.json")).unwrap();
    for s in &v.v3 {
        let got = cvss::parse(&s.vector).unwrap_or_else(|| panic!("{} ({})", s.vector, s.why));
        assert_eq!(got.base_score, Some(s.tenths), "{} ({})", s.vector, s.why);
    }
    for s in &v.v4_valid {
        let got = cvss::parse(&s.vector).unwrap_or_else(|| panic!("{} ({})", s.vector, s.why));
        assert_eq!(got.base_score, None, "aucun calcul v4 : {}", s.vector);
    }
    for s in &v.invalid {
        assert_eq!(cvss::parse(&s.vector), None, "{} ({})", s.vector, s.why);
    }
}

// ---------------------------------------------------------------- fixtures réelles

#[test]
fn real_ghsa_composer() {
    let (a, tally) = load("osv/GHSA-2q52-x2ff-qgfr.json", SourceEcosystem::Packagist);
    assert_eq!(a.license, "CC-BY-4.0");
    assert!(
        a.attribution
            .contains("https://github.com/advisories/GHSA-2q52-x2ff-qgfr")
    );
    assert_eq!(a.aliases, ["CVE-2026-24425"]);
    assert_eq!(a.cwe, ["CWE-693"]);
    assert_eq!(
        a.score,
        Some(Score {
            tenths: 88,
            origin: ScoreOrigin::CvssV31
        })
    );
    assert_eq!(a.severity.len(), 2);
    assert_eq!(a.severity[1].score, None, "aucun calcul v4");
    assert_eq!(a.affected.len(), 2);
    assert!(
        a.affected
            .iter()
            .all(|l| l.scheme == Scheme::Composer && !l.unevaluable)
    );
    assert!(a.published.is_some() && a.modified > 0);
    // Références : ADVISORY d'abord, PACKAGE ignorée.
    assert_eq!(a.references[0].kind, "ADVISORY");
    assert!(a.references.iter().all(|r| r.kind != "PACKAGE"));
    assert_eq!(tally.dropped(), 0);
    let p = "pkg:composer/twig/twig";
    assert_eq!(verdict(&a, p, Some("3.10.0")), affected(Some("3.26.0")));
    assert_eq!(verdict(&a, p, Some("v3.25.0")), affected(Some("3.26.0")));
    // last_affected 2.16.1 : touchée, sans correctif sur cette branche.
    assert_eq!(verdict(&a, p, Some("2.16.1")), affected(None));
    assert_eq!(verdict(&a, p, Some("2.16.2")), Verdict::NotAffected);
    assert_eq!(verdict(&a, p, Some("3.26.0")), Verdict::NotAffected);
    assert_eq!(verdict(&a, p, Some("dev-main")), VERSION_UNKNOWN);
    assert_eq!(verdict(&a, p, None), VERSION_UNKNOWN);
}

#[test]
fn real_ghsa_npm_with_scope() {
    let (a, _) = load("osv/GHSA-67hx-6x53-jw92.json", SourceEcosystem::Npm);
    assert_eq!(a.license, "CC-BY-4.0");
    let scoped = a
        .affected
        .iter()
        .find(|l| l.purl.namespace() == Some("@babel"))
        .unwrap();
    assert_eq!(scoped.purl.canonical(), "pkg:npm/%40babel/traverse");
    assert_eq!(scoped.scheme, Scheme::Semver);
    let expected = cvss::parse("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        .unwrap()
        .base_score
        .unwrap();
    assert_eq!(a.score.map(|s| s.tenths), Some(expected));
    let p = "pkg:npm/%40babel/traverse";
    // Deux lignes pour un même paquet : verdict de la faille, correctif de
    // la branche qui contient la version.
    assert_eq!(verdict(&a, p, Some("7.23.1")), affected(Some("7.23.2")));
    assert_eq!(
        verdict(&a, p, Some("8.0.0-alpha.2")),
        affected(Some("8.0.0-alpha.4"))
    );
    assert_eq!(verdict(&a, p, Some("7.23.2")), Verdict::NotAffected);
    assert_eq!(verdict(&a, p, Some("8.0.0-alpha.4")), Verdict::NotAffected);
    assert_eq!(
        verdict(&a, "pkg:npm/babel-traverse", Some("6.26.0")),
        affected(None)
    );
}

#[test]
fn real_rustsec() {
    let (a, _) = load("osv/RUSTSEC-2017-0004.json", SourceEcosystem::CratesIo);
    assert_eq!(a.license, "CC0-1.0");
    assert!(a.aliases.contains(&"GHSA-x67x-vg9m-65c3".to_owned()));
    assert_eq!(a.affected[0].purl.canonical(), "pkg:cargo/base64");
    assert_eq!(a.affected[0].ranges[0].scheme, Scheme::Semver);
    assert_eq!(
        a.score.map(|s| (s.tenths, s.origin)),
        Some((98, ScoreOrigin::CvssV31))
    );
    assert_eq!(
        verdict(&a, "pkg:cargo/base64", Some("0.5.1")),
        affected(Some("0.5.2"))
    );
    assert_eq!(
        verdict(&a, "pkg:cargo/base64", Some("0.5.2")),
        Verdict::NotAffected
    );
    assert_eq!(
        verdict(&a, "pkg:cargo/base64", Some("0.5")),
        VERSION_UNKNOWN
    );
}

// ---------------------------------------------------------------- fictives

#[test]
fn fictitious_composer_branches_and_cleanup() {
    let (a, tally) = load("fictif/composer-branches.json", SourceEcosystem::Packagist);
    assert_eq!(a.aliases, ["CVE-2026-0001"]);
    assert_eq!(a.cwe, ["CWE-79"]);
    assert_eq!(tally.get(Reason::BadCwe), 1);
    assert_eq!(tally.get(Reason::OutOfScope), 1, "PyPI ignoré");
    assert_eq!(
        tally.get(Reason::BadReference),
        2,
        "javascript: et user:pass@"
    );
    assert_eq!(
        a.references
            .iter()
            .map(|r| r.kind.as_str())
            .collect::<Vec<_>>(),
        ["ADVISORY", "WEB"]
    );
    // Vecteur v3.1 et severity HIGH : score calculé.
    assert_eq!(
        a.score.map(|s| (s.tenths, s.origin)),
        Some((98, ScoreOrigin::CvssV31))
    );
    let p = "pkg:composer/exemple/paquet";
    assert_eq!(verdict(&a, p, Some("1.2.0")), affected(Some("1.2.1")));
    assert_eq!(verdict(&a, p, Some("2.0.1")), affected(Some("2.0.3")));
    assert_eq!(verdict(&a, p, Some("1.5.0")), Verdict::NotAffected);
    // Listée dans l'union des versions[] mais hors plages.
    assert_eq!(
        verdict(&a, p, Some("0.9.0")),
        Verdict::Affected {
            fixed: None,
            divergence: true,
            beyond_last_known: false
        }
    );
    assert_eq!(verdict(&a, p, Some("dev-main")), VERSION_UNKNOWN);
}

#[test]
fn fictitious_prestashop_and_wordpress_mappings() {
    let (a, _) = load("fictif/prestashop-module.json", SourceEcosystem::Packagist);
    assert_eq!(a.affected.len(), 2, "deux lignes, une par purl");
    for p in [
        "pkg:composer/prestashop/exemplemodule",
        "pkg:prestashop/module/exemplemodule",
    ] {
        assert_eq!(verdict(&a, p, Some("1.2.0")), affected(Some("1.2.1")));
    }
    // Plage Packagist : comparateur Composer même sur le purl prestashop.
    assert!(a.affected.iter().all(|l| l.scheme == Scheme::Composer));
    assert_eq!(
        a.score.map(|s| (s.tenths, s.origin)),
        Some((50, ScoreOrigin::GhsaSeverity))
    );
    let (core, _) = load("fictif/prestashop-core.json", SourceEcosystem::Packagist);
    assert_eq!(core.affected.len(), 1);
    assert_eq!(
        verdict(&core, "pkg:prestashop/core/prestashop", Some("8.1.1")),
        affected(Some("8.1.2"))
    );
    let (wp, _) = load("fictif/wpackagist.json", SourceEcosystem::Packagist);
    assert_eq!(wp.affected[0].scheme, Scheme::Composer);
    assert_eq!(
        verdict(&wp, "pkg:wordpress/plugin/exemple-plugin", Some("v2.9")),
        affected(Some("3.0.0"))
    );
}

#[test]
fn fictitious_malicious_open_and_mixed_ranges() {
    let (mal, _) = load("fictif/npm-malveillant.json", SourceEcosystem::Npm);
    assert!(mal.malicious);
    assert_eq!(mal.license, "Apache-2.0");
    assert_eq!(mal.score, None, "aucun score");
    assert_eq!(
        verdict(&mal, "pkg:npm/%40exemple/malveillant", Some("1.0.0")),
        affected(None)
    );

    let (open, tally) = load("fictif/npm-ouverte.json", SourceEcosystem::Npm);
    assert_eq!(
        tally.get(Reason::BadVersionEntry),
        0,
        "version npm de 74 caractères acceptée"
    );
    assert_eq!(open.affected[0].versions.len(), 3);
    let p = "pkg:npm/%40exemple/paquet";
    assert_eq!(verdict(&open, p, Some("2.0.0-rc.1")), affected(None));
    assert_eq!(
        verdict(&open, p, Some("2.1.0")),
        Verdict::Affected {
            fixed: None,
            divergence: false,
            beyond_last_known: true
        }
    );
    assert_eq!(verdict(&open, p, Some("2.0.5")), affected(None));
    assert_eq!(verdict(&open, p, Some("1.9.0")), Verdict::NotAffected);
    assert_eq!(open.score.map(|s| s.tenths), Some(30));

    let (mixed, _) = load("fictif/cargo-mixte.json", SourceEcosystem::CratesIo);
    assert_eq!(mixed.license, "CC0-1.0");
    let p = "pkg:cargo/exemple";
    assert_eq!(verdict(&mixed, p, Some("0.9.0")), affected(Some("1.0.0")));
    assert_eq!(verdict(&mixed, p, Some("1.0.5")), Verdict::NotAffected);
    assert_eq!(verdict(&mixed, p, Some("1.2.0")), affected(None));
    assert_eq!(verdict(&mixed, p, Some("1.2.1")), Verdict::NotAffected);
}

#[test]
fn an_unevaluable_line_never_hides_a_vulnerability() {
    let (a, tally) = load(
        "fictif/composer-unevaluable.json",
        SourceEcosystem::Packagist,
    );
    assert_eq!(tally.get(Reason::Unevaluable), 1);
    let p = "pkg:composer/exemple/autre";
    // Une ligne touchée et une ligne unevaluable : touchée.
    assert_eq!(verdict(&a, p, Some("2.0.5")), affected(Some("2.1.0")));
    // Une ligne non touchée et une ligne unevaluable : plage inconnue.
    assert_eq!(verdict(&a, p, Some("1.0.5")), RANGE_UNKNOWN);
    assert_eq!(verdict(&a, p, None), RANGE_UNKNOWN);
    // Version illisible et ligne unevaluable : la plage d'abord.
    assert_eq!(verdict(&a, p, Some("dev-main")), RANGE_UNKNOWN);
}

#[test]
fn summary_falls_back_on_the_first_line_of_details() {
    let (a, tally) = load("fictif/sans-summary.json", SourceEcosystem::Packagist);
    assert_eq!(a.summary, "Première ligne du détail.");
    assert_eq!(a.license, "MIT");
    assert_eq!(tally.get(Reason::UnknownLicense), 0);
}

// ---------------------------------------------------------------- Draft (F3)

fn draft_line(purl: &str, scheme: Scheme, events: Vec<DraftEvent>) -> DraftAffected {
    DraftAffected {
        purls: vec![Purl::parse(purl).unwrap()],
        scheme,
        ranges: vec![DraftRange {
            kind: "ECOSYSTEM".into(),
            events,
        }],
        versions: Vec::new(),
        last_known: None,
    }
}

#[test]
fn a_wordfence_like_draft_goes_through_the_same_validation() {
    let mut tally = Tally::default();
    let draft = Draft {
        id: "00000000-0000-4000-8000-000000000001".into(),
        aliases: vec!["cve-2026-0003".into()],
        summary: Some("Faille fictive du noyau\u{1b}[31m".into()),
        modified: Some("2026-10-01T00:00:00+02:00".into()),
        affected: vec![draft_line(
            "pkg:wordpress/core/core",
            Scheme::Php,
            vec![
                // from_inclusive: false traduit en introduced inclusif (F3).
                DraftEvent::Introduced("6.0".into()),
                DraftEvent::Fixed("6.4.2".into()),
            ],
        )],
        severity: vec![(
            "CVSS_V3".into(),
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into(),
        )],
        provided_score: Score::from_text("6.1", ScoreOrigin::Wordfence),
        informational: true,
        license: Some("licence fictive".into()),
        attribution: Some("Copyright fictif\u{202e}, https://example.org/".into()),
        source_url: Some("https://example.org/avis/1".into()),
        ..Draft::default()
    };
    let a = Advisory::build(draft, &mut tally).unwrap();
    assert!(a.informational);
    // Score fourni par Wordfence avant le vecteur v3.1.
    assert_eq!(
        a.score.map(|s| (s.tenths, s.origin)),
        Some((61, ScoreOrigin::Wordfence))
    );
    assert_eq!(
        a.attribution,
        "Copyright fictif\u{fffd}, https://example.org/"
    );
    assert_eq!(a.summary, "Faille fictive du noyau\u{fffd}[31m");
    assert_eq!(a.source_url, "https://example.org/avis/1");
    assert_eq!(a.affected[0].scheme, Scheme::Php);
    let p = "pkg:wordpress/core/core";
    assert_eq!(verdict(&a, p, Some("6.4.1")), affected(Some("6.4.2")));
    assert_eq!(verdict(&a, p, Some("6.4-RC1")), affected(Some("6.4.2")));
    assert_eq!(verdict(&a, p, Some("6.4.2")), Verdict::NotAffected);
    assert_eq!(verdict(&a, p, Some("6.4-bogus")), VERSION_UNKNOWN);
}

#[test]
fn a_friends_of_presta_like_draft_uses_php_on_four_components() {
    let mut tally = Tally::default();
    let draft = Draft {
        id: "FOP-2026-0001".into(),
        modified: Some("2026-10-01T00:00:00Z".into()),
        affected: vec![draft_line(
            "pkg:prestashop/module/exemplemodule",
            Scheme::Php,
            vec![
                DraftEvent::Introduced("0".into()),
                DraftEvent::LastAffected("1.6.1.24".into()),
            ],
        )],
        provided_score: Score::from_text("9.8", ScoreOrigin::FriendsOfPresta),
        license: Some("CC-BY-SA-4.0".into()),
        attribution: Some("Friends-Of-Presta, https://example.org/".into()),
        ..Draft::default()
    };
    let a = Advisory::build(draft, &mut tally).unwrap();
    assert_eq!(tally.get(Reason::UnknownLicense), 0);
    assert_eq!(
        a.score.map(|s| (s.tenths, s.origin)),
        Some((98, ScoreOrigin::FriendsOfPresta))
    );
    let p = "pkg:prestashop/module/exemplemodule";
    assert_eq!(verdict(&a, p, Some("1.6.1.24")), affected(None));
    assert_eq!(verdict(&a, p, Some("1.6.1.3")), affected(None));
    assert_eq!(verdict(&a, p, Some("1.7.0.0")), Verdict::NotAffected);
}

#[test]
fn php_last_affected_does_not_include_a_longer_equal_version() {
    // version_compare("1.0.0", "1.0") vaut 1 : last_affected 1.0 n'inclut pas
    // 1.0.0 (limite de la sémantique PHP, écrite dans failles.md).
    let mut tally = Tally::default();
    let draft = Draft {
        id: "FOP-2026-0002".into(),
        modified: Some("2026-10-01T00:00:00Z".into()),
        affected: vec![draft_line(
            "pkg:wordpress/plugin/exemple-plugin",
            Scheme::Php,
            vec![
                DraftEvent::Introduced("0".into()),
                DraftEvent::LastAffected("1.0".into()),
            ],
        )],
        ..Draft::default()
    };
    let a = Advisory::build(draft, &mut tally).unwrap();
    let p = "pkg:wordpress/plugin/exemple-plugin";
    assert_eq!(verdict(&a, p, Some("1.0")), affected(None));
    assert_eq!(verdict(&a, p, Some("1.0.0")), Verdict::NotAffected);
}

#[test]
fn severity_order() {
    let mut tally = Tally::default();
    let base = || Draft {
        id: "GHSA-ex40-ex40-ex40".into(),
        modified: Some("2026-10-01T00:00:00Z".into()),
        affected: vec![draft_line(
            "pkg:composer/exemple/paquet",
            Scheme::Composer,
            vec![DraftEvent::Introduced("0".into())],
        )],
        ..Draft::default()
    };
    // Vecteur v4 seul et MODERATE : 50, origine ghsa_severity.
    let a = Advisory::build(
        Draft {
            severity: vec![(
                "CVSS_V4".into(),
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N".into(),
            )],
            ghsa_severity: Some("MODERATE".into()),
            ..base()
        },
        &mut tally,
    )
    .unwrap();
    assert_eq!(
        a.score.map(|s| (s.tenths, s.origin)),
        Some((50, ScoreOrigin::GhsaSeverity))
    );
    // Aucun score.
    let a = Advisory::build(base(), &mut tally).unwrap();
    assert_eq!(a.score, None);
    assert!(!a.malicious);
    // MAL- en alias : malveillant.
    let a = Advisory::build(
        Draft {
            aliases: vec!["MAL-2026-0002".into()],
            ..base()
        },
        &mut tally,
    )
    .unwrap();
    assert!(a.malicious);
    // provided_score hors de [0, 100] : retiré seul, compté.
    let before = tally.get(Reason::BadSeverity);
    let a = Advisory::build(
        Draft {
            provided_score: Some(Score {
                tenths: 110,
                origin: ScoreOrigin::Wordfence,
            }),
            ghsa_severity: Some("CRITICAL".into()),
            ..base()
        },
        &mut tally,
    )
    .unwrap();
    assert_eq!(tally.get(Reason::BadSeverity), before + 1);
    assert_eq!(
        a.score.map(|s| (s.tenths, s.origin)),
        Some((90, ScoreOrigin::GhsaSeverity))
    );
    assert_eq!(Score::from_text("11", ScoreOrigin::Wordfence), None);
}

// ---------------------------------------------------------------- hostiles

#[test]
fn hostile_fixtures_give_exactly_the_expected_outcome() {
    let dir = fixtures().join("hostile");
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        let Some(stem) = name.strip_suffix(".json") else {
            continue;
        };
        let (outcome, rest) = stem.split_once('-').unwrap();
        if outcome == "texte" {
            // Texte hostile assaini, sans écart : `hostile_details`.
            let mut tally = Tally::default();
            let a = from_osv(
                &std::fs::read(&path).unwrap(),
                SourceEcosystem::Packagist,
                &mut tally,
            );
            assert_bounded(&a.unwrap());
            continue;
        }
        let reason = Reason::ALL
            .into_iter()
            .filter(|r| rest.starts_with(r.as_str()))
            .max_by_key(|r| r.as_str().len())
            .unwrap_or_else(|| panic!("{name} : raison absente du nom"));
        let mut tally = Tally::default();
        let result = from_osv(
            &std::fs::read(&path).unwrap(),
            SourceEcosystem::Packagist,
            &mut tally,
        );
        let result = if result.is_err() && rest.contains("129") {
            // Les fixtures npm sont lues dans l'export npm.
            let mut t = Tally::default();
            let r = from_osv(&std::fs::read(&path).unwrap(), SourceEcosystem::Npm, &mut t);
            tally = t;
            r
        } else {
            result
        };
        match outcome {
            "drop" => {
                // Faille non gardée : perte (is_drop) ou exclusion normale
                // (withdrawn, no_affected_out_of_scope).
                assert_eq!(result.as_ref().err(), Some(&reason), "{name}");
                assert_eq!(
                    reason.is_drop(),
                    !matches!(reason, Reason::Withdrawn | Reason::NoAffectedOutOfScope),
                    "{name}"
                );
            }
            "keep" => {
                let a = result.unwrap_or_else(|r| panic!("{name} : écartée ({r:?})"));
                assert!(!reason.is_drop(), "{name}");
                assert_bounded(&a);
            }
            other => panic!("{name} : issue {other}"),
        }
        assert!(tally.get(reason) >= 1, "{name} : {:?}", tally);
        seen += 1;
    }
    assert!(seen >= 25, "{seen}");
}

fn hostile(name: &str) -> (Result<Advisory, Reason>, Tally) {
    let mut tally = Tally::default();
    let r = from_osv(
        &read(&format!("hostile/{name}")),
        SourceEcosystem::Packagist,
        &mut tally,
    );
    (r, tally)
}

#[test]
fn hostile_details() {
    // Préfixe inconnu : gardée, licence inconnue, attribution OSV.dev.
    let (a, tally) = hostile("keep-unknown_license-ZZZ.json");
    let a = a.unwrap();
    assert_eq!(a.license, LICENSE_UNKNOWN);
    assert!(
        a.attribution
            .contains("https://osv.dev/vulnerability/ZZZ-2026-0001")
    );
    assert_eq!(tally.get(Reason::UnknownLicense), 1);

    // Nom hors grammaire : affected écarté seul.
    let (a, tally) = hostile("keep-bad_purl.json");
    assert_eq!(a.unwrap().affected.len(), 1);
    assert_eq!(tally.get(Reason::BadPurl), 1);

    // PyPI et Drupal dans l'export Packagist : ignorés, comptés.
    let (a, tally) = hostile("keep-out_of_scope-pypi-drupal.json");
    assert_eq!(a.unwrap().affected.len(), 1);
    assert_eq!(tally.get(Reason::OutOfScope), 2);
    let (_, tally) = hostile("drop-no_affected_out_of_scope.json");
    assert_eq!(tally.get(Reason::NoAffected), 0);
    assert_eq!(
        tally.dropped(),
        0,
        "exclusion normale, hors du taux d'écart"
    );

    // Ligne gardée unevaluable : plage inconnue.
    for name in [
        "keep-unevaluable-deux-cles.json",
        "keep-unevaluable-zero-cle.json",
        "keep-unevaluable-borne-129.json",
        "keep-unevaluable-borne-vide.json",
        "keep-unevaluable-129-evenements.json",
        "keep-unevaluable-257-plages.json",
        "keep-unevaluable-ni-plage-ni-version.json",
        "keep-unevaluable-type-inconnu.json",
    ] {
        let (a, tally) = hostile(name);
        let a = a.unwrap();
        assert!(a.affected[0].unevaluable, "{name}");
        assert_eq!(tally.get(Reason::Unevaluable), 1, "{name}");
        let v = verdict(&a, "pkg:composer/exemple/paquet", Some("500.0.0"));
        assert_eq!(v, RANGE_UNKNOWN, "{name}");
    }
    // 257 plages : les 256 premières restent évaluées.
    let (a, _) = hostile("keep-unevaluable-257-plages.json");
    let a = a.unwrap();
    assert_eq!(a.affected[0].ranges.len(), 256);
    assert_eq!(
        verdict(&a, "pkg:composer/exemple/paquet", Some("3.0.5")),
        affected(Some("3.1"))
    );

    // versions[] : entrée de 129 caractères et entrée non textuelle
    // ignorées seules ; version npm de 74 caractères gardée.
    let mut tally = Tally::default();
    let a = from_osv(
        &read("hostile/keep-bad_version_entry-129.json"),
        SourceEcosystem::Npm,
        &mut tally,
    )
    .unwrap();
    assert_eq!(tally.get(Reason::BadVersionEntry), 2);
    assert_eq!(a.affected[0].versions.len(), 2);
    assert_eq!(a.affected[0].ranges.len(), 1);

    let (a, tally) = hostile("keep-bad_reference.json");
    let a = a.unwrap();
    assert_eq!(tally.get(Reason::BadReference), 3);
    assert_eq!(a.references.len(), 1);

    let (a, tally) = hostile("keep-bad_severity-metrique-repetee.json");
    let a = a.unwrap();
    assert_eq!(tally.get(Reason::BadSeverity), 1);
    assert!(a.severity.is_empty());
    assert_eq!(a.score.map(|s| s.origin), Some(ScoreOrigin::GhsaSeverity));

    let (a, tally) = hostile("keep-bad_last_known.json");
    assert_eq!(a.unwrap().affected[0].last_known, None);
    assert_eq!(tally.get(Reason::BadLastKnown), 1);

    let (a, tally) = hostile("keep-bad_alias.json");
    let a = a.unwrap();
    assert_eq!(a.aliases.len(), MAX_ALIASES);
    assert_eq!(a.aliases[0], "CVE-2026-0002");
    assert!(tally.get(Reason::BadAlias) >= 1);

    let (a, _) = hostile("keep-bad_cwe.json");
    assert_eq!(a.unwrap().cwe.len(), MAX_CWES);

    let (a, _) = hostile("texte-resume-hostile.json");
    let a = a.unwrap();
    assert_eq!(a.summary.chars().count(), 500);
    assert!(a.summary.starts_with("\u{fffd}[31mrouge\u{fffd}é"));
    assert_eq!(a.aliases, ["CVE-2026-1"]);
}

#[test]
fn an_entry_of_5_mib_is_dropped() {
    let mut big = String::from(
        r#"{"id":"GHSA-ex50-ex50-ex50","modified":"2026-10-01T00:00:00Z","details":""#,
    );
    big.push_str(&"a".repeat(5 * 1024 * 1024));
    big.push_str(r#"","affected":[]}"#);
    let mut tally = Tally::default();
    assert_eq!(
        from_osv(big.as_bytes(), SourceEcosystem::Packagist, &mut tally),
        Err(Reason::TooLarge)
    );
    assert_eq!(tally.get(Reason::TooLarge), 1);
}

#[test]
fn a_duplicate_id_drops_the_second() {
    let mut tally = Tally::default();
    let mut seen = Seen::default();
    let (a, _) = load("osv/RUSTSEC-2017-0004.json", SourceEcosystem::CratesIo);
    assert!(seen.first(&a, &mut tally));
    assert!(!seen.first(&a, &mut tally));
    assert_eq!(tally.get(Reason::DuplicateId), 1);
    assert_eq!(tally.dropped(), 1);
}

// ---------------------------------------------------------------- fuzz

fn assert_bounded(a: &Advisory) {
    assert!(a.id.len() <= 64);
    assert!(a.aliases.len() <= MAX_ALIASES && a.aliases.iter().all(|x| x.len() <= 64));
    assert!(a.summary.chars().count() <= 500);
    assert!(a.attribution.chars().count() <= 2000);
    assert!(a.summary.chars().all(|c| !c.is_control()));
    assert!(a.references.len() <= MAX_REFERENCES);
    assert!(a.references.iter().all(|r| r.url.len() <= 2048));
    assert!(a.cwe.len() <= MAX_CWES);
    assert!(a.severity.len() <= 4);
    assert!(a.score.is_none_or(|s| s.tenths <= 100));
    assert!(!a.affected.is_empty() && a.affected.len() <= 2 * 1024);
    for l in &a.affected {
        assert!(l.ranges.len() <= 256);
        assert!(l.ranges.iter().all(|r| r.events.len() <= 129));
        assert!(l.versions.len() <= 10_000 && l.versions.iter().all(|v| v.len() <= 128));
        assert!(l.purl.version().is_none());
    }
}

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

#[test]
fn fuzz_mutations_never_panic_and_stay_bounded() {
    let seeds: Vec<(Vec<u8>, SourceEcosystem)> = vec![
        (
            read("osv/GHSA-2q52-x2ff-qgfr.json"),
            SourceEcosystem::Packagist,
        ),
        (read("osv/GHSA-67hx-6x53-jw92.json"), SourceEcosystem::Npm),
        (
            read("osv/RUSTSEC-2017-0004.json"),
            SourceEcosystem::CratesIo,
        ),
        (
            read("fictif/composer-branches.json"),
            SourceEcosystem::Packagist,
        ),
        (read("fictif/npm-ouverte.json"), SourceEcosystem::Npm),
        (read("fictif/cargo-mixte.json"), SourceEcosystem::CratesIo),
    ];
    let alphabet: &[u8] = b"{}[]\":,0123456789.-+_aZ \\\x00\xff\xc3\x1b";
    let mut rng = XorShift(0x5eed_15f1_0002_0001);
    let mut kept = 0;
    for _ in 0..50_000 {
        let (base, dump) = &seeds[rng.below(seeds.len())];
        let mut m = base.clone();
        for _ in 0..1 + rng.below(4) {
            let at = rng.below(m.len());
            match rng.below(3) {
                0 => m[at] = alphabet[rng.below(alphabet.len())],
                1 => {
                    m.remove(at);
                }
                _ => m.insert(at, alphabet[rng.below(alphabet.len())]),
            }
        }
        let mut tally = Tally::default();
        if let Ok(a) = from_osv(&m, *dump, &mut tally) {
            assert_bounded(&a);
            for l in &a.affected {
                let _ = match_advisory(&[l], Some("1.0.0"));
                let _ = match_advisory(&[l], None);
            }
            kept += 1;
        }
    }
    assert!(kept > 1_000, "{kept}");
}
