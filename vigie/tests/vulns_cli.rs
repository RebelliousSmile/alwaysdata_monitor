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
use vigie::vulns::store::{LEASE, Load, SyncMeta};
use vigie::vulns::version::{Scheme, SourceEcosystem};

#[path = "support/dump_server.rs"]
mod dump_server;
#[path = "support/vulns_data.rs"]
mod vulns_data;
#[path = "support/zipgen.rs"]
mod zipgen;
use dump_server::{DumpServer, Reply};
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
        let mut load = Load::begin(&mut store, id, &clock, LEASE).unwrap();
        load.tally_mut().merge(&tally);
        load.push(&advisories).unwrap();
        load.commit(&Tally::default(), &SyncMeta::default())
            .unwrap();
    }
    source(&mut store, "wordfence");
    let mut load = Load::begin(&mut store, "wordfence", &clock, LEASE).unwrap();
    load.push(&[wordfence_like()]).unwrap();
    load.commit(&Tally::default(), &SyncMeta::default())
        .unwrap();
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

// --- vigie vulns sync (#16) ---

/// Configuration avec `[vulns] sources`.
fn config_with_sources(dir: &Path, sources: &str) -> PathBuf {
    let path = write_config(dir);
    let mut raw = std::fs::read_to_string(&path).unwrap();
    raw.push_str(&format!("[vulns]\nsources = [{sources}]\n"));
    std::fs::write(&path, raw).unwrap();
    path
}

#[test]
fn sync_without_declared_sources_says_so_and_exits_0() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path());
    let out = vigie(&config, &["vulns", "sync"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert_eq!(stdout(&out), "aucune source de failles déclarée\n");
    assert!(!dir.path().join("vigie.db").exists(), "aucune base créée");
    let config = config_with_sources(dir.path(), "");
    let out = vigie(&config, &["vulns", "sync"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
}

#[test]
fn sync_usage_and_configuration_errors_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_with_sources(dir.path(), "\"osv-npm\"");
    for args in [
        vec!["vulns", "sync", "--source", "osv-crates-io"],
        vec!["vulns", "sync", "--source", "osv-pypi"],
        vec!["vulns", "sync", "--accept-shrink"],
    ] {
        let out = vigie(&config, &args);
        assert_eq!(out.status.code(), Some(2), "{args:?} {out:?}");
    }
    for sources in ["\"osv-pypi\"", "\"osv-npm\", \"osv-npm\""] {
        let config = config_with_sources(dir.path(), sources);
        let out = vigie(&config, &["vulns", "sync"]);
        assert_eq!(out.status.code(), Some(2), "{sources} {out:?}");
    }
}

#[test]
fn rate_limited_sources_exit_0_and_sources_shows_why() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_with_sources(
        dir.path(),
        "\"osv-crates-io\", \"osv-packagist\", \"osv-npm\"",
    );
    {
        let mut store = Store::open(&dir.path().join("vigie.db")).unwrap();
        // KEV et EPSS, déclarés d'office (#18), aussi : aucun réseau.
        for id in ["osv-crates-io", "osv-packagist", "osv-npm", "kev", "epss"] {
            source(&mut store, id);
        }
    }
    // Retry-After en cours (reçu d'OSV) : aucune requête ne part.
    let conn = rusqlite::Connection::open(dir.path().join("vigie.db")).unwrap();
    conn.execute(
        "UPDATE vuln_sources SET retry_after_until = ?1",
        [vigie::now() + 3_600],
    )
    .unwrap();
    let out = vigie(&config, &["vulns", "sync"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let text = stdout(&out);
    for id in ["osv-crates-io", "osv-packagist", "osv-npm", "kev", "epss"] {
        assert!(text.contains(&format!("{id} : rate_limited")), "{text}");
    }
    let out = vigie(&config, &["vulns", "sources"]);
    assert!(out.status.success(), "{out:?}");
    let text = stdout(&out);
    assert!(text.contains(": rate_limited"), "{text}");
    assert!(
        text.contains("Retry-After : pas de requête avant"),
        "{text}"
    );
    assert!(text.contains("dernière réussite : jamais"), "{text}");
    assert!(!dir.path().join("vulns-work").join("osv-npm").exists());
}

#[test]
fn sources_prints_the_sync_state_after_a_load() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = config_with_sources(dir.path(), "\"osv-crates-io\"");
    let config = vigie::config::load(&config_path).unwrap();
    let server = DumpServer::start();
    let rustsec = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/vulns/osv/RUSTSEC-2017-0004.json"),
    )
    .unwrap();
    server.route(
        "/crates.io/all.zip",
        Reply::ok_etag(
            zipgen::zip_of(vec![zipgen::ZEntry::new(
                "RUSTSEC-2017-0004.json",
                &rustsec,
            )]),
            "\"c1\"",
            "Sat, 17 Oct 2026 03:00:00 GMT",
        ),
    );
    // KEV et EPSS, déclarés d'office (#18), sur le même serveur.
    server.route(
        KEV_MIRROR,
        Reply::ok_etag(vulns_fixture("kev/catalogue-n1.json"), "\"k1\"", LM),
    );
    server.route(
        EPSS_PATH,
        Reply::ok(gzip(&vulns_fixture("epss/scores.csv"))),
    );
    let options = vigie::vulns::sync::SyncOptions {
        trust: vigie::http::Trust::Custom(vec![server.ca.clone()]),
        endpoint_override: Some(server.base()),
        ..Default::default()
    };
    let clock = FakeClock::new(vigie::now() - 3_600);
    let report = vigie::vulns::sync::run(&config, &options, &clock, None, false).unwrap();
    assert_eq!(report.failures(), 0, "{report:?}");
    assert!(report.loaded());
    let ids: Vec<&str> = report.sources.iter().map(|s| s.id).collect();
    assert_eq!(ids, ["osv-crates-io", "kev", "epss"]);
    let out = vigie(&config_path, &["vulns", "sources"]);
    assert!(out.status.success(), "{out:?}");
    let text = stdout(&out);
    for want in [
        "osv-crates-io  licence par enregistrement  chargée il y a 1 h  entrées 1",
        "dernière réussite : il y a 1 h",
        "dernière tentative : il y a 1 h : loaded",
        "ETag oui  lecteur 1",
        "attribution : OSV.dev, licence de chaque enregistrement selon son préfixe",
        "kev  licence CC0-1.0  chargée il y a 1 h  entrées 4",
        "jeu : version 2099.01.15  publié le 2099-01-15T17:15:48Z  lignes 4  inchangé (périmé) : 0",
        "âge du catalogue KEV : ",
        "attribution : CISA KEV (Known Exploited Vulnerabilities Catalog), CC0 1.0",
        "epss  licence FIRST EPSS Usage Agreement  chargée il y a 1 h  entrées 4",
        "jeu : version v2099.01.01  publié le 2099-01-15T00:00:00Z  lignes 4",
        "attribution : FIRST EPSS, See EPSS at https://www.first.org/epss",
    ] {
        assert!(text.contains(want), "{want}\n{text}");
    }
    assert!(
        text.contains(&format!(
            "validateurs servis par {}",
            server.url(KEV_MIRROR)
        )),
        "{text}"
    );
    assert!(!text.contains("avertissement : catalogue KEV"), "{text}");
    let out = vigie(&config_path, &["vulns", "match", "pkg:cargo/base64@0.5.0"]);
    assert!(
        stdout(&out).contains("RUSTSEC-2017-0004  touché"),
        "{out:?}"
    );
}

// --- KEV et EPSS (#18) ---

const LM: &str = "Sat, 17 Oct 2026 03:00:00 GMT";
const KEV_MIRROR: &str = "/cisagov/kev-data/main/known_exploited_vulnerabilities.json";
const EPSS_PATH: &str = "/epss_scores-current.csv.gz";

fn vulns_fixture(rel: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/vulns")
            .join(rel),
    )
    .unwrap()
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(bytes).unwrap();
    gz.finish().unwrap()
}

/// Base : une faille fictive à alias `CVE-2099-90001`, sans score, puis
/// KEV (publié `released`) et EPSS chargés par la bibliothèque.
fn with_tables(released: &str) -> (tempfile::TempDir, PathBuf) {
    use vigie::vulns::enrich_store::{DatasetHeader, EnrichLoad, EnrichSource, EpssRow, KevRow};
    use vigie::vulns::exploit::{Cve, KevFact};
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path());
    let mut store = Store::open(&dir.path().join("vigie.db")).unwrap();
    let clock = FakeClock::new(vigie::now() - 3_600);
    let draft = Draft {
        id: "GHSA-ex18-ex18-ex18".into(),
        aliases: vec!["cve-2099-90001".into()],
        summary: Some("Faille fictive".into()),
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
    };
    source(&mut store, "osv-packagist");
    let mut load = Load::begin(&mut store, "osv-packagist", &clock, LEASE).unwrap();
    load.push(&[Advisory::build(draft, &mut Tally::default()).unwrap()])
        .unwrap();
    load.commit(&Tally::default(), &SyncMeta::default())
        .unwrap();
    let cve = |raw: &str| Cve::parse(raw).unwrap();
    for id in ["kev", "epss"] {
        source(&mut store, id);
    }
    let header = |version: &str, released: &str| DatasetHeader {
        version: version.into(),
        released: released.parse().unwrap(),
    };
    let mut kev = EnrichLoad::begin(&mut store, EnrichSource::Kev, &clock, LEASE).unwrap();
    kev.push_kev(&[KevRow {
        cve: cve("CVE-2099-90001"),
        fact: KevFact {
            date_added: "2099-01-10".parse().unwrap(),
            due_date: "2099-01-31".parse().unwrap(),
            known_ransomware: false,
            name: "Exemple Produit fictif : faille inventée".into(),
        },
    }])
    .unwrap();
    kev.commit(
        &header("2099.01.15", released),
        &Tally::default(),
        &SyncMeta::default(),
    )
    .unwrap();
    let mut epss = EnrichLoad::begin(&mut store, EnrichSource::Epss, &clock, LEASE).unwrap();
    epss.push_epss(&[
        (
            cve("CVE-2099-90001"),
            EpssRow {
                epss_ppm: 12,
                percentile_ppm: 1_000,
            },
        ),
        (
            cve("CVE-2099-90002"),
            EpssRow {
                epss_ppm: 100_000,
                percentile_ppm: 800_000,
            },
        ),
    ])
    .unwrap();
    epss.commit(
        &header("v2099.01.01", "2099-01-15T00:00:00Z"),
        &Tally::default(),
        &SyncMeta::default(),
    )
    .unwrap();
    (dir, config)
}

#[test]
fn show_explains_kev_epss_and_the_severity() {
    let (_dir, config) = with_tables("2099-01-15T17:15:48Z");
    let out = vigie(&config, &["vulns", "show", "CVE-2099-90001"]);
    assert!(out.status.success(), "{out:?}");
    let text = stdout(&out);
    for want in [
        "GHSA-ex18-ex18-ex18  (source osv-packagist)",
        "CISA KEV CVE-2099-90001 : ajoutée le 2099-01-10, échéance 2099-01-31, usage par rançongiciel connu : non",
        "FIRST EPSS CVE-2099-90001 : score 0.000012  percentile 0.001000 (modèle v2099.01.01 du 2099-01-15T00:00:00Z)",
        "gravité : critique (exploitée (CISA KEV))",
    ] {
        assert!(text.contains(want), "{want}\n{text}");
    }
    // Présent dans EPSS seulement : montré, sans faille.
    let out = vigie(&config, &["vulns", "show", "cve-2099-90002"]);
    assert!(out.status.success(), "{out:?}");
    let text = stdout(&out);
    assert!(
        text.contains("CVE-2099-90002  (aucune faille connue ; tables d'enrichissement seulement)"),
        "{text}"
    );
    assert!(
        text.contains("CISA KEV CVE-2099-90002 : absente du catalogue"),
        "{text}"
    );
    assert!(text.contains("score 0.100000"), "{text}");
    let out = vigie(&config, &["vulns", "show", "CVE-2099-99999"]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
}

#[test]
fn sources_warns_about_a_kev_catalogue_older_than_14_days() {
    let old = vigie::iso_utc(vigie::now() - 15 * 86_400);
    let (_dir, config) = with_tables(&old);
    let out = vigie(&config, &["vulns", "sources"]);
    assert!(out.status.success(), "{out:?}");
    let text = stdout(&out);
    assert!(text.contains("âge du catalogue KEV : 15 j"), "{text}");
    assert!(
        text.contains("avertissement : catalogue KEV de plus de 14 jours"),
        "{text}"
    );
}
