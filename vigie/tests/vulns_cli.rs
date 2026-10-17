//! `vigie vulns sources | show | match` sur une base remplie par la
//! bibliothèque (#15, phase 3).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use vigie::clock::FakeClock;
use vigie::store::Store;
use vigie::vulns::advisory::{
    Advisory, Draft, DraftAffected, DraftEvent, DraftRange, Score, ScoreOrigin, Tally,
};
use vigie::vulns::purl::Purl;
use vigie::vulns::store::Load;
use vigie::vulns::version::{Scheme, SourceEcosystem};

#[path = "support/vulns_data.rs"]
mod vulns_data;
use vulns_data::{fixture, source};

fn vigie(config: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vigie"))
        .arg("--config")
        .arg(config)
        .args(args)
        .env_remove("VIGIE_CONFIG")
        .output()
        .expect("lancement de vigie")
}

fn write_config(dir: &Path) -> PathBuf {
    let raw = format!(
        "database = '{}'\n[alerts]\nto = \"alertes@example.org\"\nfrom = \"vigie@example.org\"\nsmtp_host = \"smtp.example.org\"\npassword_file = '{}'\n",
        dir.join("vigie.db").display(),
        dir.join("smtp-password").display()
    );
    let path = dir.join("config.toml");
    std::fs::write(&path, raw).unwrap();
    path
}

fn stdout(out: &Output) -> String {
    let text = String::from_utf8(out.stdout.clone()).unwrap();
    // Aucune sortie ne porte de caractère de contrôle hors saut de ligne.
    assert!(
        text.chars().all(|c| c == '\n' || !c.is_control()),
        "{text:?}"
    );
    text
}

/// Faille Wordfence fictive, informational.
fn wordfence_like() -> Advisory {
    let draft = Draft {
        id: "00000000-0000-4000-8000-000000000009".into(),
        summary: Some("Faille fictive\u{1b}[2J du noyau".into()),
        modified: Some("2026-10-01T00:00:00Z".into()),
        affected: vec![DraftAffected {
            purls: vec![Purl::parse("pkg:wordpress/core/core").unwrap()],
            scheme: Scheme::Php,
            ranges: vec![DraftRange {
                kind: "ECOSYSTEM".into(),
                events: vec![
                    DraftEvent::Introduced("6.0".into()),
                    DraftEvent::Fixed("6.4.2".into()),
                ],
            }],
            versions: Vec::new(),
            last_known: None,
        }],
        provided_score: Score::from_text("4.3", ScoreOrigin::Wordfence),
        informational: true,
        license: Some("licence fictive".into()),
        attribution: Some("Copyright fictif\u{202e} de démonstration".into()),
        ..Draft::default()
    };
    Advisory::build(draft, &mut Tally::default()).unwrap()
}

fn filled() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path());
    let mut store = Store::open(&dir.path().join("vigie.db")).unwrap();
    let clock = FakeClock::new(vigie::now() - 3_600);
    for (id, files, dump) in [
        (
            "osv-packagist",
            vec![
                "osv/GHSA-2q52-x2ff-qgfr.json",
                "fictif/composer-branches.json",
                "fictif/prestashop-module.json",
                "fictif/composer-unevaluable.json",
                "hostile/keep-unknown_license-ZZZ.json",
            ],
            SourceEcosystem::Packagist,
        ),
        (
            "osv-npm",
            vec!["fictif/npm-ouverte.json", "fictif/npm-malveillant.json"],
            SourceEcosystem::Npm,
        ),
    ] {
        source(&mut store, id);
        let mut tally = Tally::default();
        let advisories: Vec<_> = files.iter().map(|f| fixture(f, dump, &mut tally)).collect();
        let mut load = Load::begin(&mut store, id, &clock).unwrap();
        load.tally_mut().merge(&tally);
        load.push(&advisories).unwrap();
        load.commit(None).unwrap();
    }
    source(&mut store, "wordfence");
    let mut load = Load::begin(&mut store, "wordfence", &clock).unwrap();
    load.push(&[wordfence_like()]).unwrap();
    load.commit(None).unwrap();
    (dir, config)
}

#[test]
fn sources_lists_licence_age_entries_and_dropped_by_reason() {
    let (_dir, config) = filled();
    let out = vigie(&config, &["vulns", "sources"]);
    assert!(out.status.success(), "{out:?}");
    let text = stdout(&out);
    assert!(
        text.contains("osv-packagist  licence par enregistrement  chargée il y a 1 h  entrées 5"),
        "{text}"
    );
    assert!(text.contains("hors périmètre 1"), "{text}");
    assert!(text.contains("out_of_scope 1"), "{text}");
    assert!(text.contains("licence inconnue : 1 faille(s)"), "{text}");
    assert!(text.contains("osv-npm"), "{text}");
}

#[test]
fn show_prints_every_field_sanitized() {
    let (_dir, config) = filled();
    let out = vigie(&config, &["vulns", "show", "GHSA-2q52-x2ff-qgfr"]);
    assert!(out.status.success(), "{out:?}");
    let text = stdout(&out);
    for want in [
        "GHSA-2q52-x2ff-qgfr  (source osv-packagist)",
        "alias : CVE-2026-24425",
        "résumé : Twig: Possible sandbox bypass",
        "score : 8,8 (cvss_v31)",
        "CVSS_V4 : CVSS:4.0/",
        "CWE : CWE-693",
        "composant : pkg:composer/twig/twig (composer)",
        "ADVISORY : https://",
        "licence : CC-BY-4.0",
        "attribution : GitHub Advisory Database, CC-BY 4.0",
        "lien : https://osv.dev/vulnerability/GHSA-2q52-x2ff-qgfr",
    ] {
        assert!(text.contains(want), "{want} : {text}");
    }
    // Par alias, casse normalisée.
    let out = vigie(&config, &["vulns", "show", "cve-2026-24425"]);
    assert!(stdout(&out).contains("GHSA-2q52-x2ff-qgfr"));
    // Licence inconnue visible ; texte hostile assaini.
    let text = stdout(&vigie(&config, &["vulns", "show", "ZZZ-2026-0001"]));
    assert!(text.contains("licence : inconnue"), "{text}");
    let text = stdout(&vigie(
        &config,
        &["vulns", "show", "00000000-0000-4000-8000-000000000009"],
    ));
    assert!(text.contains("informational"), "{text}");
    assert!(
        text.contains("Copyright fictif\u{fffd} de démonstration"),
        "{text}"
    );
    assert!(
        text.contains("résumé : Faille fictive\u{fffd}[2J du noyau"),
        "{text}"
    );
    let out = vigie(&config, &["vulns", "show", "GHSA-absente"]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn match_prints_one_line_per_vulnerability() {
    let (_dir, config) = filled();
    let text = stdout(&vigie(
        &config,
        &["vulns", "match", "pkg:composer/exemple/paquet@1.2.0"],
    ));
    assert!(
        text.contains("GHSA-ex01-ex01-ex01  touché  corrigée en 1.2.1  score 9,8 (cvss_v31)"),
        "{text}"
    );
    let text = stdout(&vigie(
        &config,
        &["vulns", "match", "pkg:composer/exemple/paquet@0.5.0"],
    ));
    assert!(
        text.contains("ZZZ-2026-0001  touché  corrigée en 1.0.0"),
        "{text}"
    );
    let text = stdout(&vigie(
        &config,
        &["vulns", "match", "pkg:composer/exemple/paquet@0.9.0"],
    ));
    assert!(text.contains("[divergence : listée hors plages]"), "{text}");
    let text = stdout(&vigie(
        &config,
        &[
            "vulns",
            "match",
            "pkg:prestashop/module/exemplemodule@1.2.0",
        ],
    ));
    assert!(
        text.contains("GHSA-ex02-ex02-ex02  touché  corrigée en 1.2.1  score 5,0 (ghsa_severity)"),
        "{text}"
    );
    let text = stdout(&vigie(
        &config,
        &["vulns", "match", "pkg:npm/%40exemple/paquet@2.0.0-rc.1"],
    ));
    assert!(
        text.contains("GHSA-ex05-ex05-ex05  touché  aucun correctif connu"),
        "{text}"
    );
    let text = stdout(&vigie(
        &config,
        &["vulns", "match", "pkg:npm/%40exemple/malveillant@1.0.0"],
    ));
    assert!(text.contains("[paquet malveillant]"), "{text}");
    let text = stdout(&vigie(
        &config,
        &["vulns", "match", "pkg:wordpress/core/core@6.3"],
    ));
    assert!(
        text.contains("score 4,3 (wordfence)  [informational]"),
        "{text}"
    );
    let text = stdout(&vigie(
        &config,
        &["vulns", "match", "pkg:composer/exemple/paquet@1.5.0"],
    ));
    assert!(text.contains("aucune faille connue"), "{text}");
}

#[test]
fn unknown_versions_and_ranges_are_never_no_vulnerability() {
    let (_dir, config) = filled();
    for purl in [
        "pkg:composer/exemple/paquet@dev-main",
        "pkg:composer/exemple/paquet",
    ] {
        let text = stdout(&vigie(&config, &["vulns", "match", purl]));
        assert!(
            text.contains("GHSA-ex01-ex01-ex01  version inconnue"),
            "{text}"
        );
        assert!(!text.contains("aucune faille"), "{text}");
    }
    let text = stdout(&vigie(
        &config,
        &["vulns", "match", "pkg:composer/exemple/autre@1.0.5"],
    ));
    assert!(
        text.contains("GHSA-ex07-ex07-ex07  plage inconnue"),
        "{text}"
    );
}

#[test]
fn malformed_input_exits_with_code_2() {
    let (_dir, config) = filled();
    for args in [
        ["vulns", "match", "pkg:pypi/exemple@1.0"],
        ["vulns", "match", "pas un purl"],
        ["vulns", "show", "GHSA ex"],
    ] {
        let out = vigie(&config, &args);
        assert_eq!(out.status.code(), Some(2), "{args:?} {out:?}");
        assert!(!String::from_utf8_lossy(&out.stderr).is_empty());
    }
}

#[test]
fn no_database_or_an_older_one_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path());
    let out = vigie(&config, &["vulns", "sources"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("aucune base de failles"));
    {
        let conn = rusqlite::Connection::open(dir.path().join("vigie.db")).unwrap();
        conn.pragma_update(None, "user_version", 14).unwrap();
    }
    let out = vigie(
        &config,
        &["vulns", "match", "pkg:composer/exemple/paquet@1.0.0"],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("aucune base de failles"));
}
