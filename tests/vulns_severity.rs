//! Règle de gravité (#18, phase 1) : table de vérité, bornes exactes,
//! plusieurs CVE, groupes fusionnés, inconnues, propriétés sur une grille
//! exhaustive, bout à bout depuis un `Draft`, et lecture des scores EPSS en
//! millionièmes. CVE fictifs `CVE-2099-…` seulement.

use std::cell::Cell;

use jiff::civil::{Date, date};

use vigie::finding::Severity;
use vigie::vulns::advisory::{
    Advisory, Draft, DraftAffected, DraftEvent, DraftRange, Score, ScoreOrigin, Tally,
};
use vigie::vulns::exploit::{
    Cve, DatasetInfo, EpssFact, Exploitation, KevFact, MemoryTables, TablesState, parse_ppm,
};
use vigie::vulns::purl::Purl;
use vigie::vulns::range::UnknownReason;
use vigie::vulns::severity::{
    AdvisoryFacts, Assessment, CVSS_CRITICAL_TENTHS, CVSS_WARNING_TENTHS, EPSS_WARNING_PPM, Rule,
    UnknownRule, assess, assess_group, assess_unknown,
};
use vigie::vulns::version::Scheme;

const CVE_A: &str = "CVE-2099-90001";
const CVE_B: &str = "CVE-2099-90002";

fn cve(raw: &str) -> Cve {
    Cve::parse(raw).unwrap()
}

fn kev_fact(added: Date, ransomware: bool) -> KevFact {
    KevFact {
        date_added: added,
        due_date: date(2099, 2, 1),
        known_ransomware: ransomware,
        name: "Faille fictive".into(),
    }
}

fn epss_fact(ppm: u32) -> EpssFact {
    EpssFact {
        generation: 1,
        epss_ppm: ppm,
        percentile_ppm: ppm / 2,
    }
}

fn loaded() -> TablesState {
    let info = |version: &str| DatasetInfo {
        generation: 1,
        version: version.into(),
        released: "2099-01-15T12:00:00Z".parse().unwrap(),
    };
    TablesState {
        kev: Some(info("2099.01.15")),
        epss: Some(info("v2099.01.01")),
    }
}

/// Tables chargées : `kev` les CVE du catalogue, `epss` leurs scores.
fn tables(kev: &[&str], epss: &[(&str, u32)]) -> MemoryTables {
    MemoryTables::new(
        kev.iter()
            .map(|c| (cve(c), kev_fact(date(2099, 1, 10), false))),
        epss.iter().map(|(c, p)| (cve(c), epss_fact(*p))),
        loaded(),
    )
}

fn facts(id: &str, cves: &[&str], score: Option<u8>) -> AdvisoryFacts {
    AdvisoryFacts {
        id: id.into(),
        cves: cves.iter().map(|c| cve(c)).collect(),
        malicious: false,
        score: score.map(|tenths| Score {
            tenths,
            origin: ScoreOrigin::CvssV31,
        }),
        informational: false,
        fix_available: true,
    }
}

/// Tables qui refusent toute lecture : une faille sans CVE ne les consulte
/// pas.
struct Untouchable;

impl Exploitation for Untouchable {
    fn kev(&self, _: &Cve) -> Option<KevFact> {
        panic!("KEV consulté")
    }
    fn epss(&self, _: &Cve) -> Option<EpssFact> {
        panic!("EPSS consulté")
    }
    fn state(&self) -> TablesState {
        TablesState::default()
    }
}

/// Compte les lectures par CVE.
struct Counting<'a> {
    inner: &'a MemoryTables,
    kev: Cell<usize>,
    epss: Cell<usize>,
}

impl Exploitation for Counting<'_> {
    fn kev(&self, cve: &Cve) -> Option<KevFact> {
        self.kev.set(self.kev.get() + 1);
        self.inner.kev(cve)
    }
    fn epss(&self, cve: &Cve) -> Option<EpssFact> {
        self.epss.set(self.epss.get() + 1);
        self.inner.epss(cve)
    }
    fn state(&self) -> TablesState {
        self.inner.state()
    }
}

// --- Table de vérité ---

struct Case {
    name: &'static str,
    malicious: bool,
    score: Option<u8>,
    informational: bool,
    fix: bool,
    kev: bool,
    epss: Option<u32>,
    want: Severity,
    rule: Rule,
}

const fn case(name: &'static str, score: Option<u8>, want: Severity, rule: Rule) -> Case {
    Case {
        name,
        malicious: false,
        score,
        informational: false,
        fix: true,
        kev: false,
        epss: None,
        want,
        rule,
    }
}

#[test]
fn truth_table() {
    use Severity::{Critical, Info, Warning};
    let cases = [
        Case {
            kev: true,
            ..case("KEV, score 5,0", Some(50), Critical, Rule::Kev)
        },
        Case {
            malicious: true,
            ..case("MAL- sans score", None, Critical, Rule::Malicious)
        },
        case("score 9,0", Some(90), Critical, Rule::CvssCritical),
        case("score 10,0", Some(100), Critical, Rule::CvssCritical),
        case("score 8,9", Some(89), Warning, Rule::CvssHigh),
        case("score 7,0", Some(70), Warning, Rule::CvssHigh),
        case("score 6,9 sans EPSS", Some(69), Info, Rule::Default),
        case("score 0,0", Some(0), Info, Rule::Default),
        Case {
            epss: Some(100_000),
            ..case("score 4,0, EPSS 0,1 exact", Some(40), Warning, Rule::Epss)
        },
        Case {
            epss: Some(99_999),
            ..case("score 4,0, EPSS 0,099999", Some(40), Info, Rule::Default)
        },
        Case {
            epss: Some(100_001),
            ..case("score 4,0, EPSS 0,100001", Some(40), Warning, Rule::Epss)
        },
        Case {
            epss: Some(0),
            ..case("score 6,9, EPSS 0", Some(69), Info, Rule::Default)
        },
        case(
            "aucun score, non informational",
            None,
            Warning,
            Rule::UnknownSeverity,
        ),
        Case {
            informational: true,
            ..case(
                "aucun score, informational",
                None,
                Info,
                Rule::Informational,
            )
        },
        Case {
            informational: true,
            ..case(
                "informational, score 9,8",
                Some(98),
                Critical,
                Rule::CvssCritical,
            )
        },
        Case {
            informational: true,
            kev: true,
            ..case("informational, KEV", None, Critical, Rule::Kev)
        },
        Case {
            informational: true,
            epss: Some(500_000),
            ..case(
                "aucun score, informational, EPSS 0,5",
                None,
                Warning,
                Rule::Epss,
            )
        },
        Case {
            informational: true,
            ..case("informational, score 6,1", Some(61), Info, Rule::Default)
        },
        Case {
            fix: false,
            ..case(
                "score 9,8 sans correctif",
                Some(98),
                Critical,
                Rule::CvssCritical,
            )
        },
        case(
            "score 9,8 avec correctif",
            Some(98),
            Critical,
            Rule::CvssCritical,
        ),
    ];
    for c in cases {
        let t = tables(
            if c.kev { &[CVE_A] } else { &[] },
            &c.epss.map(|p| (CVE_A, p)).into_iter().collect::<Vec<_>>(),
        );
        let f = AdvisoryFacts {
            malicious: c.malicious,
            informational: c.informational,
            fix_available: c.fix,
            ..facts("GHSA-ex18-ex18-ex18", &[CVE_A], c.score)
        };
        let a = assess(&f, &t);
        assert_eq!((a.severity, a.rule), (c.want, c.rule), "{}", c.name);
        assert_eq!(a.no_fix, !c.fix, "{}", c.name);
        assert_eq!(a.member, "GHSA-ex18-ex18-ex18", "{}", c.name);
        assert_eq!(a.kev.is_some(), c.kev, "{}", c.name);
        assert_eq!(a.epss.map(|(_, e)| e.epss_ppm), c.epss, "{}", c.name);
        assert_eq!(a.score, f.score, "{}", c.name);
        assert_eq!(a.tables, loaded(), "{}", c.name);
    }
    // Seuils nommés, comparés en entiers.
    assert_eq!(
        (CVSS_CRITICAL_TENTHS, CVSS_WARNING_TENTHS, EPSS_WARNING_PPM),
        (90, 70, 100_000)
    );
}

#[test]
fn labels_are_stable() {
    assert_eq!(Rule::Kev.as_str(), "kev");
    assert_eq!(Rule::UnknownSeverity.as_str(), "unknown_severity");
    assert_eq!(Rule::Epss.label(), "EPSS ≥ 0,1");
    assert_eq!(UnknownRule::RangeUnknown.label(), "plage inconnue");
}

// --- Sans CVE ---

#[test]
fn an_advisory_without_cve_reads_no_table() {
    // Wordfence ou Friends-Of-Presta sans CVE, score 6,1.
    let f = facts("00000000-0000-4000-8000-000000000018", &[], Some(61));
    let a = assess(&f, &Untouchable);
    assert_eq!((a.severity, a.rule), (Severity::Info, Rule::Default));
    assert_eq!((a.kev, a.epss), (None, None));
}

fn draft(id: &str, aliases: &[&str]) -> Draft {
    Draft {
        id: id.into(),
        aliases: aliases.iter().map(|a| (*a).to_owned()).collect(),
        modified: Some("2099-01-01T00:00:00Z".into()),
        affected: vec![DraftAffected {
            purls: vec![Purl::parse("pkg:composer/exemple/paquet").unwrap()],
            scheme: Scheme::Composer,
            ranges: vec![DraftRange {
                kind: "ECOSYSTEM".into(),
                events: vec![DraftEvent::Introduced("0".into())],
            }],
            versions: Vec::new(),
            last_known: None,
        }],
        ..Draft::default()
    }
}

fn build(d: Draft) -> Advisory {
    Advisory::build(d, &mut Tally::default()).unwrap()
}

#[test]
fn aliases_normalized_by_f1_join_kev() {
    let a = build(draft("GHSA-ex18-ex18-ex18", &["cve-2099-90001"]));
    let f = AdvisoryFacts::from_advisory(&a, true);
    assert_eq!(f.cves, [cve(CVE_A)]);
    let r = assess(&f, &tables(&[CVE_A], &[]));
    assert_eq!((r.severity, r.rule), (Severity::Critical, Rule::Kev));
    // Identifiant CVE compté une fois, même répété en alias.
    let a = build(draft(CVE_A, &[CVE_A, CVE_B]));
    assert_eq!(
        AdvisoryFacts::from_advisory(&a, false).cves,
        [cve(CVE_A), cve(CVE_B)]
    );
}

#[test]
fn aliases_outside_the_kev_grammar_are_ignored() {
    let a = build(draft("GHSA-ex18-ex18-ex18", &["CVE-99-1", "CVE-2099-123"]));
    assert_eq!(a.aliases.len(), 2);
    let f = AdvisoryFacts::from_advisory(&a, true);
    assert!(f.cves.is_empty());
    let r = assess(&f, &Untouchable);
    assert_eq!(r.rule, Rule::UnknownSeverity);
}

// --- Plusieurs CVE ---

#[test]
fn several_cves_one_in_kev() {
    let f = facts("GHSA-ex18-ex18-ex18", &[CVE_A, CVE_B], Some(30));
    let r = assess(&f, &tables(&[CVE_B], &[]));
    assert_eq!((r.severity, r.rule), (Severity::Critical, Rule::Kev));
    assert_eq!(r.kev.map(|(c, _)| c), Some(cve(CVE_B)));
}

#[test]
fn several_cves_in_kev_keep_the_oldest_date_and_any_ransomware() {
    let t = MemoryTables::new(
        [
            (cve(CVE_A), kev_fact(date(2099, 1, 20), true)),
            (cve(CVE_B), kev_fact(date(2099, 1, 5), false)),
        ],
        [],
        loaded(),
    );
    let r = assess(&facts("GHSA-ex18-ex18-ex18", &[CVE_A, CVE_B], None), &t);
    let (c, fact) = r.kev.unwrap();
    assert_eq!(c, cve(CVE_B));
    assert_eq!(fact.date_added, date(2099, 1, 5));
    assert!(fact.known_ransomware);
}

#[test]
fn several_cves_keep_the_highest_epss() {
    let f = facts("GHSA-ex18-ex18-ex18", &[CVE_A, CVE_B], Some(40));
    let r = assess(&f, &tables(&[], &[(CVE_A, 20_000), (CVE_B, 300_000)]));
    assert_eq!((r.severity, r.rule), (Severity::Warning, Rule::Epss));
    let (c, e) = r.epss.unwrap();
    assert_eq!(
        (c, e.epss_ppm, e.percentile_ppm),
        (cve(CVE_B), 300_000, 150_000)
    );
}

// --- Groupes fusionnés ---

fn wordfence(score: Option<u8>, informational: bool) -> AdvisoryFacts {
    AdvisoryFacts {
        informational,
        score: score.map(|tenths| Score {
            tenths,
            origin: ScoreOrigin::Wordfence,
        }),
        ..facts("00000000-0000-4000-8000-000000000018", &[], None)
    }
}

#[test]
fn a_group_sees_kev_through_the_union_of_its_cves() {
    let ghsa = facts("GHSA-ex18-ex18-ex18", &[CVE_A], None);
    let t = tables(&[CVE_A], &[]);
    let r = assess_group(&[ghsa.clone(), wordfence(Some(50), false)], &t).unwrap();
    assert_eq!((r.severity, r.rule), (Severity::Critical, Rule::Kev));
    assert_eq!(r.member, "GHSA-ex18-ex18-ex18");
    assert_eq!(r.kev.map(|(c, _)| c), Some(cve(CVE_A)));
    // Le premier membre reçu qui atteint le maximum est retenu.
    let r = assess_group(&[wordfence(Some(50), false), ghsa], &t).unwrap();
    assert_eq!(r.severity, Severity::Critical);
    assert_eq!(r.member, "00000000-0000-4000-8000-000000000018");
    assert_eq!(r.score.map(|s| s.tenths), Some(50));
}

#[test]
fn informational_wordfence_does_not_downgrade_a_ghsa_without_score() {
    let r = assess_group(
        &[
            wordfence(None, true),
            facts("GHSA-ex18-ex18-ex18", &[CVE_A], None),
        ],
        &tables(&[], &[]),
    )
    .unwrap();
    assert_eq!(
        (r.severity, r.rule, r.member.as_str()),
        (
            Severity::Warning,
            Rule::UnknownSeverity,
            "GHSA-ex18-ex18-ex18"
        )
    );
}

#[test]
fn every_member_sees_the_epss_of_the_union() {
    let t = tables(&[], &[(CVE_A, 400_000)]);
    let r = assess_group(
        &[
            wordfence(Some(50), false),
            facts("GHSA-ex18-ex18-ex18", &[CVE_A], Some(50)),
        ],
        &t,
    )
    .unwrap();
    assert_eq!((r.severity, r.rule), (Severity::Warning, Rule::Epss));
    assert_eq!(r.member, "00000000-0000-4000-8000-000000000018");
}

#[test]
fn a_cve_shared_by_two_members_is_read_once() {
    let inner = tables(&[CVE_A], &[(CVE_A, 10)]);
    let t = Counting {
        inner: &inner,
        kev: Cell::new(0),
        epss: Cell::new(0),
    };
    let members = [
        facts("GHSA-ex18-ex18-ex18", &[CVE_A], None),
        facts("RUSTSEC-2099-0018", &[CVE_A, CVE_B], None),
    ];
    let r = assess_group(&members, &t).unwrap();
    assert_eq!((t.kev.get(), t.epss.get()), (2, 2));
    assert_eq!(r.rule, Rule::Kev);
}

#[test]
fn a_group_of_one_is_assess_and_an_empty_group_is_none() {
    let t = tables(&[], &[(CVE_A, 200_000)]);
    let f = AdvisoryFacts {
        fix_available: false,
        ..facts("GHSA-ex18-ex18-ex18", &[CVE_A], Some(40))
    };
    assert_eq!(
        assess_group(std::slice::from_ref(&f), &t),
        Some(assess(&f, &t))
    );
    assert_eq!(assess_group(&[], &t), None);
}

#[test]
fn a_group_has_no_fix_only_if_no_member_has_one() {
    let t = tables(&[], &[]);
    let with = facts("GHSA-ex18-ex18-ex18", &[], Some(40));
    let without = AdvisoryFacts {
        fix_available: false,
        ..with.clone()
    };
    assert!(!assess_group(&[without.clone(), with], &t).unwrap().no_fix);
    assert!(
        assess_group(&[without.clone(), without], &t)
            .unwrap()
            .no_fix
    );
}

// --- Inconnues ---

fn assessed(score: Option<u8>, informational: bool) -> Assessment {
    let f = AdvisoryFacts {
        informational,
        ..facts("GHSA-ex18-ex18-ex18", &[], score)
    };
    assess(&f, &tables(&[], &[]))
}

#[test]
fn unknowns_are_warnings_on_critical_advisories_only() {
    let critical = assessed(Some(98), false);
    let v = assess_unknown(UnknownReason::VersionUnknown, &critical);
    assert_eq!(
        (v.severity, v.rule),
        (Severity::Warning, UnknownRule::VersionUnknown)
    );
    let r = assess_unknown(UnknownReason::RangeUnknown, &critical);
    assert_eq!(
        (r.severity, r.rule),
        (Severity::Warning, UnknownRule::RangeUnknown)
    );
    for a in [
        assessed(Some(75), false),
        assessed(None, false),
        assessed(Some(30), false),
        assessed(None, true),
    ] {
        for reason in [UnknownReason::VersionUnknown, UnknownReason::RangeUnknown] {
            assert_eq!(assess_unknown(reason, &a).severity, Severity::Info, "{a:?}");
        }
    }
}

// --- Ordre du score, bout à bout ---

const V31_98: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";

#[test]
fn end_to_end_from_draft_follows_the_f0_score_order() {
    let none = tables(&[], &[]);
    // Score Wordfence 5,3 avant le vecteur v3.1 à 9,8.
    let a = build(Draft {
        severity: vec![("CVSS_V3".into(), V31_98.into())],
        provided_score: Score::from_text("5.3", ScoreOrigin::Wordfence),
        license: Some("licence fictive".into()),
        attribution: Some("Fictif, https://example.org/".into()),
        ..draft("00000000-0000-4000-8000-000000000018", &[])
    });
    let r = assess(&AdvisoryFacts::from_advisory(&a, true), &none);
    assert_eq!(
        r.score.map(|s| (s.tenths, s.origin)),
        Some((53, ScoreOrigin::Wordfence))
    );
    assert_eq!(r.severity, Severity::Info);
    // Vecteur v3.1 à 9,8 avant MODERATE.
    let a = build(Draft {
        severity: vec![("CVSS_V3".into(), V31_98.into())],
        ghsa_severity: Some("MODERATE".into()),
        ..draft("GHSA-ex18-ex18-ex18", &[])
    });
    let r = assess(&AdvisoryFacts::from_advisory(&a, true), &none);
    assert_eq!(
        (r.severity, r.score.map(|s| s.origin)),
        (Severity::Critical, Some(ScoreOrigin::CvssV31))
    );
    // Vecteur v4 seul : HIGH, 70 dixièmes.
    let a = build(Draft {
        severity: vec![(
            "CVSS_V4".into(),
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N".into(),
        )],
        ghsa_severity: Some("HIGH".into()),
        ..draft("GHSA-ex18-ex18-ex18", &[])
    });
    let r = assess(&AdvisoryFacts::from_advisory(&a, true), &none);
    assert_eq!(
        (r.severity, r.score.map(|s| (s.tenths, s.origin))),
        (Severity::Warning, Some((70, ScoreOrigin::GhsaSeverity)))
    );
    // MAL- : malveillant.
    let a = build(draft("MAL-2099-0018", &[]));
    let r = assess(&AdvisoryFacts::from_advisory(&a, true), &none);
    assert_eq!(r.rule, Rule::Malicious);
}

// --- Propriétés ---

const SCORES: [Option<u8>; 7] = [
    None,
    Some(0),
    Some(69),
    Some(70),
    Some(89),
    Some(90),
    Some(100),
];
const EPSS: [Option<u32>; 5] = [None, Some(0), Some(99_999), Some(100_000), Some(1_000_000)];

#[derive(Debug, Clone, Copy)]
struct Point {
    kev: bool,
    malicious: bool,
    score: Option<u8>,
    epss: Option<u32>,
    informational: bool,
    fix: bool,
}

fn grid() -> Vec<Point> {
    let mut out = Vec::new();
    for kev in [false, true] {
        for malicious in [false, true] {
            for score in SCORES {
                for epss in EPSS {
                    for informational in [false, true] {
                        for fix in [false, true] {
                            out.push(Point {
                                kev,
                                malicious,
                                score,
                                epss,
                                informational,
                                fix,
                            });
                        }
                    }
                }
            }
        }
    }
    out
}

fn eval(p: Point) -> (Severity, Rule) {
    let t = tables(
        if p.kev { &[CVE_A] } else { &[] },
        &p.epss.map(|e| (CVE_A, e)).into_iter().collect::<Vec<_>>(),
    );
    let f = AdvisoryFacts {
        malicious: p.malicious,
        informational: p.informational,
        fix_available: p.fix,
        ..facts("GHSA-ex18-ex18-ex18", &[CVE_A], p.score)
    };
    let a = assess(&f, &t);
    (a.severity, a.rule)
}

#[test]
fn properties_hold_on_the_whole_grid() {
    let points = grid();
    assert_eq!(points.len(), 2 * 2 * 7 * 5 * 2 * 2);
    let sev: Vec<(Point, Severity, Rule)> = points
        .iter()
        .map(|p| {
            let (s, r) = eval(*p);
            (*p, s, r)
        })
        .collect();
    let find = |q: Point| {
        sev.iter()
            .find(|(p, ..)| {
                p.kev == q.kev
                    && p.malicious == q.malicious
                    && p.score == q.score
                    && p.epss == q.epss
                    && p.informational == q.informational
                    && p.fix == q.fix
            })
            .map(|(_, s, r)| (*s, *r))
            .unwrap()
    };
    for &(p, s, r) in &sev {
        // fix_available ne change jamais la gravité ni la règle.
        assert_eq!(find(Point { fix: !p.fix, ..p }), (s, r), "{p:?}");
        // informational ne fait jamais monter.
        if p.informational {
            assert!(
                s <= find(Point {
                    informational: false,
                    ..p
                })
                .0,
                "{p:?}"
            );
        }
        // Score absent et non informational : au moins avertissement.
        if p.score.is_none() && !p.informational {
            assert!(s >= Severity::Warning, "{p:?}");
        }
        // EPSS absent et EPSS 0 : même gravité.
        if p.epss.is_none() {
            assert_eq!(find(Point { epss: Some(0), ..p }).0, s, "{p:?}");
        }
    }
    // Monotonie entre scores présents, à informational et fix fixés.
    let rank = |e: Option<u32>| e.map_or(0, |v| v);
    for &(p, s, _) in sev.iter().filter(|(p, ..)| p.score.is_some()) {
        for &(q, t, _) in sev.iter().filter(|(q, ..)| q.score.is_some()) {
            let above = q.informational == p.informational
                && q.fix == p.fix
                && q.kev >= p.kev
                && q.malicious >= p.malicious
                && q.score >= p.score
                && rank(q.epss) >= rank(p.epss);
            if above {
                assert!(t >= s, "{p:?} → {s:?}, {q:?} → {t:?}");
            }
        }
    }
}

#[test]
fn a_group_is_never_below_its_members() {
    let mut specs = Vec::new();
    for kev in [false, true] {
        for malicious in [false, true] {
            for score in [None, Some(69), Some(90)] {
                for epss in [None, Some(100_000)] {
                    for informational in [false, true] {
                        specs.push((kev, malicious, score, epss, informational));
                    }
                }
            }
        }
    }
    type Rows = (Vec<(Cve, KevFact)>, Vec<(Cve, EpssFact)>);
    let member = |i: usize, spec: (bool, bool, Option<u8>, Option<u32>, bool)| {
        let c = format!("CVE-2099-1{i:04}");
        let rows: Rows = (
            spec.0
                .then(|| (cve(&c), kev_fact(date(2099, 1, 10), false)))
                .into_iter()
                .collect(),
            spec.3
                .map(|e| (cve(&c), epss_fact(e)))
                .into_iter()
                .collect(),
        );
        let f = AdvisoryFacts {
            malicious: spec.1,
            informational: spec.4,
            ..facts(&format!("GHSA-ex18-{i:04}-ex18"), &[c.as_str()], spec.2)
        };
        (f, rows)
    };
    let alone = |rows: &Rows| MemoryTables::new(rows.0.clone(), rows.1.clone(), loaded());
    for a in &specs {
        for b in &specs {
            let (fa, ra) = member(0, *a);
            let (fb, rb) = member(1, *b);
            let both = MemoryTables::new(
                ra.0.iter().chain(&rb.0).cloned(),
                ra.1.iter().chain(&rb.1).cloned(),
                loaded(),
            );
            let group = assess_group(&[fa.clone(), fb.clone()], &both).unwrap();
            let max = assess(&fa, &alone(&ra))
                .severity
                .max(assess(&fb, &alone(&rb)).severity);
            assert!(group.severity >= max, "{a:?} {b:?}");
        }
    }
}

#[test]
fn tables_never_loaded_raise_nothing() {
    let empty = MemoryTables::default();
    let r = assess(&facts("GHSA-ex18-ex18-ex18", &[CVE_A], Some(40)), &empty);
    assert_eq!((r.severity, r.rule), (Severity::Info, Rule::Default));
    assert_eq!(r.tables, TablesState::default());
    assert!(r.tables.kev.is_none() && r.tables.epss.is_none());
}

// --- parse_ppm ---

#[test]
fn epss_scores_are_read_in_truncated_millionths() {
    for (raw, want) in [
        ("0", 0),
        ("1", 1_000_000),
        ("0.1", 100_000),
        ("0.0999999", 99_999),
        ("0.100000999", 100_000),
        ("1.0", 1_000_000),
        ("1.000000000", 1_000_000),
        ("0.000001", 1),
        ("0.0000009", 0),
        ("1.0e-05", 10),
        ("1e-5", 10),
        ("9.99e-01", 999_000),
        ("1.23e-05", 12),
        ("1e-0", 1_000_000),
        ("0e-99", 0),
    ] {
        assert_eq!(parse_ppm(raw), Some(want), "{raw}");
    }
    for raw in [
        "-0.1",
        "1.1",
        "1.e-5",
        ".5",
        "0.1234567890",
        "2.0e+01",
        "1e-123",
        "",
        "2",
        "10e-2",
        "0,1",
        " 0.1",
        "0.1 ",
        "1e5",
        "1e-",
        "1.0000001",
        "5e-0",
        "NaN",
        "+0.1",
    ] {
        assert_eq!(parse_ppm(raw), None, "{raw}");
    }
}
