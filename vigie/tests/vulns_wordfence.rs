//! Convertisseur Wordfence Intelligence v3 (#17, phase 1) : lecture en flux,
//! conversion champ par champ, verdicts, entrées hostiles, fuzz, et
//! cohérence du verrou de relecture avec `docs/failles.md`. Fixtures
//! **fictives** (`tests/fixtures/vulns/wordfence/README`). Aucun réseau.

use std::path::{Path, PathBuf};

use serde_json::value::RawValue;
use vigie::vulns::advisory::{Advisory, MAX_CWES, MAX_REFERENCES, Reason, ScoreOrigin, Tally};
use vigie::vulns::purl::Purl;
use vigie::vulns::range::{UnknownReason, Verdict, match_advisory};
use vigie::vulns::sources::wordfence::{
    FIXED_ATTRIBUTION, FeedLimits, LICENSE, WORDFENCE_TERMS_REVIEWED, attribution, check_review,
    convert_record, parse_feed, record_url, review_in_doc,
};
use vigie::vulns::sync::{Sink, SyncError};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vulns/wordfence")
}

fn read(rel: &str) -> Vec<u8> {
    std::fs::read(fixtures().join(rel)).unwrap_or_else(|e| panic!("{rel} : {e}"))
}

#[derive(Default)]
struct Collect(Vec<Advisory>);

impl Sink for Collect {
    fn push(&mut self, advisory: Advisory) -> Result<(), SyncError> {
        self.0.push(advisory);
        Ok(())
    }
}

/// Lit un flux : failles retenues, compteurs, ou l'erreur de flux.
fn feed(bytes: &[u8]) -> Result<(Vec<Advisory>, Tally, u64), SyncError> {
    feed_with(bytes, &FeedLimits::default())
}

fn feed_with(bytes: &[u8], limits: &FeedLimits) -> Result<(Vec<Advisory>, Tally, u64), SyncError> {
    let mut sink = Collect::default();
    let mut tally = Tally::default();
    let entries = parse_feed(bytes, limits, &mut sink, &mut tally)?;
    Ok((sink.0, tally, entries))
}

fn production() -> (Vec<Advisory>, Tally) {
    let (all, tally, entries) = feed(&read("production.json")).expect("flux fictif");
    assert_eq!(entries, 15);
    (all, tally)
}

fn by_id<'a>(all: &'a [Advisory], n: &str) -> &'a Advisory {
    let id = format!("WF-00000000-0000-4000-8000-{n}");
    all.iter()
        .find(|a| a.id == id)
        .unwrap_or_else(|| panic!("{id} absente"))
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

// ---------------------------------------------------------------- happy path

#[test]
fn the_fictive_feed_converts_field_by_field() {
    let (all, tally) = production();
    assert_eq!(all.len(), 15, "{tally:?}");
    let a = by_id(&all, "000000000001");
    assert_eq!(a.aliases, ["CVE-2099-0001"]);
    assert_eq!(a.summary, "Exemple 1 - faille fictive");
    assert_eq!(a.cwe, ["CWE-79"]);
    assert_eq!(a.license, LICENSE);
    assert_eq!(a.references.len(), 1);
    assert_eq!(a.references[0].kind, "WEB");
    assert_eq!(a.references[0].url, "https://example.org/wf/1");
    // `published` lu en UTC, `modified` = `updated`.
    let at = |s: &str| s.parse::<jiff::Timestamp>().unwrap().as_second();
    assert_eq!(a.published, Some(at("2099-01-10T12:00:00Z")));
    assert_eq!(a.modified, at("2099-01-12T08:00:00Z"));
    let url = record_url("00000000-0000-4000-8000-000000000001");
    assert_eq!(
        url,
        "https://www.wordfence.com/threat-intel/vulnerabilities/id/00000000-0000-4000-8000-000000000001"
    );
    assert_eq!(a.source_url, url);
    let score = a.score.expect("score");
    assert_eq!((score.tenths, score.origin), (61, ScoreOrigin::Wordfence));
    assert_eq!(a.severity.len(), 1);
    assert_eq!(a.severity[0].kind, "CVSS_V3");
    assert!(a.severity[0].vector.starts_with("CVSS:3.1/"));
    assert!(!a.informational);
    let line = &a.affected[0];
    assert_eq!(line.purl.to_string(), "pkg:wordpress/plugin/exemple-plugin");
    assert_eq!(line.scheme.as_str(), "php");
    assert_eq!(
        serde_json::to_value(&line.ranges).unwrap(),
        serde_json::json!([{"scheme": "php", "events": [
            {"introduced": "0"}, {"last_affected": "1.2.3"}, {"fixed": "1.2.4"}
        ]}])
    );
    assert!(!line.unevaluable);
    // Champs non stockés.
    assert!(!format!("{a:?}").contains("jamais stocké"));
    assert!(!format!("{a:?}").contains("Chercheuse"));

    let theme = by_id(&all, "000000000002");
    assert_eq!(
        theme.affected[0].purl.to_string(),
        "pkg:wordpress/theme/exemple-theme"
    );
    assert_eq!(
        serde_json::to_value(&theme.affected[0].ranges).unwrap(),
        serde_json::json!([{"scheme": "php", "events": [
            {"introduced": "2.0"}, {"fixed": "2.1"}
        ]}])
    );
    assert_eq!(theme.cwe, ["CWE-352"]);

    // UUID en majuscules dans la source : id en minuscules.
    by_id(&all, "0000000000ab");

    // Score 10.0 → 100 dixièmes.
    assert_eq!(by_id(&all, "000000000008").score.unwrap().tenths, 100);
    // Plusieurs CVE.
    assert_eq!(
        by_id(&all, "00000000000e").aliases,
        ["CVE-2099-0014", "CVE-2099-1014"]
    );
    // Écarts du flux fictif : chacun attendu.
    assert_eq!(tally.get(Reason::EmptyCopyrights), 1);
    assert_eq!(tally.get(Reason::NoCopyrights), 1);
    assert_eq!(tally.get(Reason::OutOfScope), 1);
    assert_eq!(tally.dropped(), 0, "{tally:?}");
}

#[test]
fn the_core_has_one_evaluable_range_per_branch() {
    let (all, _) = production();
    let core = by_id(&all, "000000000003");
    assert_eq!(core.affected.len(), 1);
    let line = &core.affected[0];
    assert_eq!(line.purl.to_string(), "pkg:wordpress/core/core");
    assert_eq!(line.ranges.len(), 40);
    assert!(!line.unevaluable);
    let p = "pkg:wordpress/core/core";
    assert_eq!(verdict(core, p, Some("6.4.1")), affected(Some("6.4.2")));
    assert_eq!(verdict(core, p, Some("6.4.2")), Verdict::NotAffected);
    assert_eq!(verdict(core, p, Some("3.7.39")), affected(Some("3.7.40")));
    assert_eq!(verdict(core, p, Some("3.7.40")), Verdict::NotAffected);
    assert_eq!(verdict(core, p, Some("4.5.20")), affected(Some("4.5.21")));
}

#[test]
fn copyrights_are_assembled_in_a_stable_order() {
    let (all, _) = production();
    let a = by_id(&all, "000000000001");
    let url = record_url("00000000-0000-4000-8000-000000000001");
    assert_eq!(
        a.attribution,
        format!(
            "Ces données fictives sont fournies par Exemple Intelligence SARL. ; exemple : Copyright 2099 Exemple Intelligence SARL, licence Licence fictive d'exemple, https://example.org/licence-exemple ; mitre-fictif : Copyright 2099 Registre fictif de CVE, licence Conditions fictives du registre, https://example.org/conditions-registre — {url}"
        )
    );
    // Aucune URL de licence en lien actif (pas de Markdown ni de HTML).
    assert!(!a.attribution.contains("]("));
    assert!(!a.attribution.contains("<a"));
    // Mention vide et absente : mention fixe.
    let empty = by_id(&all, "000000000009");
    assert!(empty.attribution.starts_with(FIXED_ATTRIBUTION));
    let none = by_id(&all, "00000000000a");
    assert!(none.attribution.starts_with(FIXED_ATTRIBUTION));
    assert!(
        none.attribution
            .ends_with("00000000-0000-4000-8000-00000000000a")
    );

    // L'ordre des clés dans la source ne change rien.
    let swapped: Box<RawValue> = serde_json::from_str(
        r#"{"zeta": {"notice": "Z"}, "alpha": {"license": "A"}, "message": "M"}"#,
    )
    .unwrap();
    assert_eq!(
        attribution(Some(&swapped), "https://example.org/x"),
        (
            "M ; alpha : licence A ; zeta : Z — https://example.org/x".to_owned(),
            None
        )
    );
    // Au-delà de 2 000 caractères : mention fixe, `attribution_overflow`.
    let long: Box<RawValue> =
        serde_json::from_str(&format!(r#"{{"message": "{}"}}"#, "m".repeat(2001))).unwrap();
    let (text, reason) = attribution(Some(&long), "https://example.org/x");
    assert_eq!(text, format!("{FIXED_ATTRIBUTION} — https://example.org/x"));
    assert_eq!(reason, Some(Reason::AttributionOverflow));
    for (raw, reason) in [
        ("{}", Reason::EmptyCopyrights),
        ("[]", Reason::EmptyCopyrights),
        ("null", Reason::EmptyCopyrights),
        (r#"{"exemple": 3}"#, Reason::EmptyCopyrights),
        ("\"texte\"", Reason::NoCopyrights),
    ] {
        let raw: Box<RawValue> = serde_json::from_str(raw).unwrap();
        assert_eq!(attribution(Some(&raw), "u").1, Some(reason), "{raw}");
    }
    assert_eq!(attribution(None, "u").1, Some(Reason::NoCopyrights));
}

#[test]
fn an_overlong_attribution_keeps_the_advisory() {
    let record = format!(
        r#"{{"id": "00000000-0000-4000-8000-000000000060", "published": "2099-01-01 00:00:00",
            "software": [{{"type": "plugin", "slug": "exemple-long",
              "affected_versions": {{"* - 1.0": {{"from_version": "*", "to_version": "1.0", "to_inclusive": true}}}}}}],
            "copyrights": {{"message": "{}"}}}}"#,
        "m".repeat(2001)
    );
    let mut tally = Tally::default();
    let a = convert_record("00000000-0000-4000-8000-000000000060", &record, &mut tally)
        .expect("gardée");
    assert!(a.attribution.starts_with(FIXED_ATTRIBUTION));
    assert_eq!(tally.get(Reason::AttributionOverflow), 1);
    assert_eq!(tally.dropped(), 0);
}

// ---------------------------------------------------------------- verdicts

#[test]
fn verdicts_on_the_fictive_feed() {
    let (all, _) = production();
    let p = "pkg:wordpress/plugin/exemple-plugin";
    let plugin = by_id(&all, "000000000001");
    assert_eq!(verdict(plugin, p, Some("1.2.3")), affected(Some("1.2.4")));
    assert_eq!(verdict(plugin, p, Some("1.2.4")), Verdict::NotAffected);
    // Quatre composants, sémantique de version_compare.
    assert_eq!(verdict(plugin, p, Some("1.2.3.1")), Verdict::NotAffected);
    assert_eq!(verdict(plugin, p, Some("0.1")), affected(Some("1.2.4")));

    // Plage ouverte, aucun correctif.
    let open = by_id(&all, "000000000005");
    let po = "pkg:wordpress/plugin/exemple-sans-correctif";
    assert_eq!(verdict(open, po, Some("9.9")), affected(None));
    assert_eq!(verdict(open, po, Some("0.9")), Verdict::NotAffected);

    // Borne basse exclusive traduite en inclusive : 2.0 touchée.
    let exclusive = by_id(&all, "000000000006");
    assert_eq!(
        verdict(
            exclusive,
            "pkg:wordpress/plugin/exemple-exclusif",
            Some("2.0")
        ),
        affected(Some("2.6"))
    );

    // informational sans score.
    let info = by_id(&all, "000000000004");
    assert!(info.informational);
    assert!(info.score.is_none());

    // Champs `null`, `[]`, `{}` : vides, faille gardée.
    let blank = by_id(&all, "00000000000c");
    assert!(blank.aliases.is_empty() && blank.cwe.is_empty() && blank.references.is_empty());
    assert!(blank.score.is_none());
    assert_eq!(
        verdict(
            blank,
            "pkg:wordpress/plugin/exemple-champs-vides",
            Some("1.0")
        ),
        affected(None)
    );

    // Titre piégé : assaini, 500 caractères.
    let title = by_id(&all, "00000000000d");
    assert_eq!(title.summary.chars().count(), 500);
    assert!(!title.summary.contains('\u{1b}') && !title.summary.contains('\u{202e}'));

    // Une ligne d'un autre type écartée seule.
    let mixed = by_id(&all, "00000000000b");
    assert_eq!(mixed.affected.len(), 1);
    assert_eq!(
        mixed.affected[0].purl.to_string(),
        "pkg:wordpress/plugin/exemple-gratuit"
    );
}

// ---------------------------------------------------------------- hostile

#[test]
fn hostile_feeds_end_as_named() {
    let mut names: Vec<String> = std::fs::read_dir(fixtures().join("hostile"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert!(names.len() >= 30, "{names:?}");
    for name in names {
        let bytes = read(&format!("hostile/{name}"));
        let stem = name.trim_end_matches(".json");
        if stem.starts_with("stream-") {
            let err = feed(&bytes).err().unwrap_or_else(|| panic!("{name} : lu"));
            assert!(matches!(err, SyncError::Format(_)), "{name} : {err:?}");
            continue;
        }
        let (kind, rest) = stem.split_once('-').unwrap();
        let reason = rest.split('-').next().unwrap();
        let (all, tally, _) = feed(&bytes).unwrap_or_else(|e| panic!("{name} : {e}"));
        let counted: Vec<&str> = tally
            .iter()
            .filter(|(_, n)| *n > 0)
            .map(|(r, _)| r.as_str())
            .collect();
        assert!(counted.contains(&reason), "{name} : {counted:?}");
        match kind {
            "drop" => {
                let expected = usize::from(reason == "duplicate_id");
                assert_eq!(all.len(), expected, "{name}");
                assert!(tally.dropped() >= 1, "{name}");
            }
            "keep" => {
                assert_eq!(all.len(), 1, "{name}");
                assert_eq!(tally.dropped(), 0, "{name} : {counted:?}");
                // Aucune plage illisible ne rend « non touchée ».
                for line in &all[0].affected {
                    if line.unevaluable {
                        assert_eq!(match_advisory(&[line], Some("1.0")), RANGE_UNKNOWN);
                        assert_eq!(match_advisory(&[line], Some("0.1")), RANGE_UNKNOWN);
                    }
                }
            }
            other => panic!("{name} : préfixe {other}"),
        }
    }
}

#[test]
fn a_bad_record_drops_only_itself() {
    let good = r#"{"id": "00000000-0000-4000-8000-000000000071", "published": "2099-01-01 00:00:00",
        "software": [{"type": "plugin", "slug": "exemple-suite",
          "affected_versions": {"* - 1.0": {"from_version": "*", "to_version": "1.0", "to_inclusive": true}}}]}"#;
    let text = format!(
        r#"{{"00000000-0000-4000-8000-000000000070": {{"id": 70, "software": []}},
            "00000000-0000-4000-8000-000000000072": {{"id": "00000000-0000-4000-8000-000000000072", "software": "x"}},
            "00000000-0000-4000-8000-000000000071": {good}}}"#
    );
    let (all, tally, entries) = feed(text.as_bytes()).unwrap();
    assert_eq!(entries, 3);
    assert_eq!(all.len(), 1);
    assert_eq!(tally.get(Reason::BadRecord), 2);
}

#[test]
fn unreadable_dates_and_bounds() {
    // published sans heure, updated lisible : gardée, `bad_published`.
    let (all, tally, _) = feed(&read("hostile/keep-bad_published-sans-heure.json")).unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].published, None);
    assert_eq!(tally.get(Reason::BadPublished), 1);
    assert!(!Reason::BadPublished.is_drop());
    // Scores refusés, vecteur gardé.
    let (all, tally, _) = feed(&read("hostile/keep-bad_severity-score-10-1.json")).unwrap();
    assert!(
        all[0]
            .score
            .is_some_and(|s| s.origin != ScoreOrigin::Wordfence)
    );
    assert_eq!(all[0].severity.len(), 1);
    assert_eq!(tally.get(Reason::BadSeverity), 1);
}

#[test]
fn more_than_256_labels_make_the_line_unevaluable() {
    let labels: Vec<String> = (0..257)
        .map(|i| {
            format!(
                r#""{i}.0 - {i}.1": {{"from_version": "{i}.0", "to_version": "{i}.1", "to_inclusive": true}}"#
            )
        })
        .collect();
    let record = format!(
        r#"{{"id": "00000000-0000-4000-8000-000000000080", "published": "2099-01-01 00:00:00",
            "software": [{{"type": "core", "slug": "wordpress", "affected_versions": {{{}}}}}]}}"#,
        labels.join(",")
    );
    let mut tally = Tally::default();
    let a = convert_record("00000000-0000-4000-8000-000000000080", &record, &mut tally).unwrap();
    assert!(a.affected[0].unevaluable);
    assert_eq!(tally.get(Reason::Unevaluable), 1);
    assert_eq!(
        match_advisory(&[&a.affected[0]], Some("1.0")),
        affected(None)
    );
    assert_eq!(
        match_advisory(&[&a.affected[0]], Some("999.0")),
        RANGE_UNKNOWN
    );
}

#[test]
fn patched_without_a_higher_version_adds_no_fix() {
    let record = r#"{"id": "00000000-0000-4000-8000-000000000081", "published": "2099-01-01 00:00:00",
        "software": [{"type": "plugin", "slug": "exemple-patch",
          "affected_versions": {"* - 2.0": {"from_version": "*", "to_version": "2.0", "to_inclusive": true}},
          "patched": true, "patched_versions": ["1.0", "2.0", "pas une version!"]}]}"#;
    let mut tally = Tally::default();
    let a = convert_record("00000000-0000-4000-8000-000000000081", record, &mut tally).unwrap();
    assert_eq!(
        match_advisory(&[&a.affected[0]], Some("2.0")),
        affected(None)
    );
    assert_eq!(tally.get(Reason::BadVersionEntry), 1);
}

// ---------------------------------------------------------------- flux

#[test]
fn a_huge_value_aborts_the_stream_but_many_small_ones_do_not() {
    let big = format!(
        r#"{{"00000000-0000-4000-8000-000000000090": {{"id": "x", "title": "{}"}}}}"#,
        "a".repeat(5 * 1024 * 1024)
    );
    let err = feed(big.as_bytes()).unwrap_err();
    assert!(matches!(err, SyncError::TooLarge { .. }), "{err:?}");

    // 2 000 entrées de 3 Kio : 6 Mo au total, le compteur est remis à zéro.
    let one = |n: usize| {
        format!(
            r#""00000000-0000-4000-8000-{n:012x}": {{"id": "00000000-0000-4000-8000-{n:012x}", "title": "{}",
              "published": "2099-01-01 00:00:00",
              "software": [{{"type": "plugin", "slug": "exemple-{n}",
                "affected_versions": {{"* - 1.0": {{"from_version": "*", "to_version": "1.0", "to_inclusive": true}}}}}}]}}"#,
            "t".repeat(3000)
        )
    };
    let text = format!("{{{}}}", (0..2000).map(one).collect::<Vec<_>>().join(","));
    assert!(text.len() > 6_000_000);
    let (all, _, entries) = feed(text.as_bytes()).unwrap();
    assert_eq!((all.len(), entries), (2000, 2000));

    // Plafond d'entrées.
    let limits = FeedLimits {
        entries: 3,
        deadline: None,
    };
    let err = feed_with(&read("production.json"), &limits).unwrap_err();
    assert!(matches!(err, SyncError::TooLarge { .. }), "{err:?}");
    // Échéance passée.
    let limits = FeedLimits {
        entries: 10,
        deadline: Some(std::time::Instant::now()),
    };
    assert_eq!(
        feed_with(&read("production.json"), &limits).unwrap_err(),
        SyncError::Deadline
    );
    // Messages sans texte de la source.
    let err = feed(b"{\"secret-de-la-source\": [}").unwrap_err();
    assert!(!err.to_string().contains("secret"), "{err}");
}

// ---------------------------------------------------------------- fuzz

fn assert_bounded(a: &Advisory) {
    assert!(a.id.len() <= 64);
    assert!(a.aliases.len() <= 32 && a.aliases.iter().all(|x| x.len() <= 64));
    assert!(a.summary.chars().count() <= 500);
    assert!(a.attribution.chars().count() <= 2000);
    assert!(a.summary.chars().all(|c| !c.is_control()));
    assert!(a.attribution.chars().all(|c| !c.is_control()));
    assert!(a.references.len() <= MAX_REFERENCES);
    assert!(a.cwe.len() <= MAX_CWES);
    assert!(a.score.is_none_or(|s| s.tenths <= 100));
    assert!(!a.affected.is_empty());
    for l in &a.affected {
        assert!(l.ranges.len() <= 256);
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
    let all: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(&read("production.json")).unwrap();
    let seeds: Vec<Vec<u8>> = all
        .iter()
        .map(|(k, v)| format!("{{{}: {v}}}", serde_json::to_string(k).unwrap()).into_bytes())
        .collect();
    let alphabet: &[u8] = b"{}[]\":,0123456789.-+*_aZ \\\x00\xff\xc3\x1btrue";
    let mut rng = XorShift(0x5eed_17f1_0003_0001);
    let mut kept = 0;
    for _ in 0..50_000 {
        let mut m = seeds[rng.below(seeds.len())].clone();
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
        if let Ok((advisories, _, _)) = feed(&m) {
            for a in &advisories {
                assert_bounded(a);
                for l in &a.affected {
                    let _ = match_advisory(&[l], Some("1.0"));
                }
                kept += 1;
            }
        }
    }
    assert!(kept > 1_000, "{kept}");
}

// ---------------------------------------------------------------- verrou

fn failles_md() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/failles.md")).unwrap()
}

#[test]
fn terms_review_matches_failles_md() {
    let doc = failles_md();
    check_review(&doc, WORDFENCE_TERMS_REVIEWED).unwrap();
    if let Some(date) = WORDFENCE_TERMS_REVIEWED {
        let date: jiff::civil::Date = date.parse().expect("date valide");
        assert!(
            date <= jiff::Zoned::now().date(),
            "relecture datée du futur"
        );
    }
}

#[test]
fn the_review_check_fails_when_one_side_changes_alone() {
    let doc = "Relecture des conditions depuis le VPS : **non faite au 2026-10-17**. À";
    assert_eq!(review_in_doc(doc), Ok(None));
    assert!(check_review(doc, None).is_ok());
    assert!(check_review(doc, Some("2099-01-01")).is_err());
    let done = "Relecture des conditions depuis le VPS : **faite le 2026-11-02** depuis le VPS.";
    assert_eq!(review_in_doc(done), Ok(Some("2026-11-02".into())));
    assert!(check_review(done, Some("2026-11-02")).is_ok());
    assert!(check_review(done, None).is_err());
    assert!(check_review(done, Some("2026-11-03")).is_err());
    assert!(review_in_doc("Relecture des conditions depuis le VPS : faite le 2026-13-45").is_err());
    assert!(review_in_doc("rien").is_err());
    // Le vrai document, modifié en mémoire, ne passe plus.
    let real = failles_md().replace("**non faite au", "**faite le 2026-10-17, au");
    assert!(check_review(&real, WORDFENCE_TERMS_REVIEWED).is_err());
}
