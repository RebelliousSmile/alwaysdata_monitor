//! Dérogations (#21, phase 3) : aperçu puis `--apply`, audit par empreinte
//! du motif, retrait, refus en code 2, prise en compte par le `tick`
//! suivant. Le motif semé `motif-secret-xyz` n'apparaît jamais dans la
//! chaîne d'audit, ni nulle part en base après `site remove`. Données
//! fictives seulement.

use sha2::{Digest, Sha256};

use vigie::finding::Severity;
use vigie::inventory::Source;
use vigie::vulns::advisory::Advisory;
use vigie::vulns::version::Scheme;

#[path = "support/match_cli.rs"]
mod match_cli;
#[path = "support/match_harness.rs"]
mod match_harness;
#[path = "support/matching_data.rs"]
mod matching_data;
use match_cli::*;
use matching_data::*;

const SECRET: &str = "motif-secret-xyz";
const PATH: &str = "wp-content/plugins/exemple-plugin";

fn wf(id: &str, aliases: &[&str], score: u8) -> Advisory {
    let ranges = [("0", "1.2.4")];
    build(&Fake {
        id,
        aliases,
        purl: PLUGIN,
        scheme: Scheme::Php,
        ranges: &ranges,
        score: Some(score),
        attribution: ATTRIBUTION_WF,
        ..Fake::default()
    })
}

/// Site A WordPress, extension 1.2.3 touchée par une faille critique,
/// rapprochée par un `tick`.
fn matched(inventory: &str) -> (Cli, i64) {
    let cli = setup("wordpress", inventory, true);
    let t = now() - 3_000;
    let h = &cli.harness;
    h.load(
        "wordfence",
        &[wf("WF-2099-0002", &["CVE-2099-0002"], 95)],
        t,
    );
    let version = format!("{PLUGIN}@1.2.3");
    h.inventory("site-a", Source::Agent, true, &[(&version, PATH)], t);
    h.tick(t + 60);
    assert_eq!(h.open("site-a")[0].severity, Severity::Critical);
    (cli, t)
}

fn until(days: i64) -> String {
    day(now() + days * 86_400)
}

/// Toute valeur texte de toutes les tables de la base.
fn all_text(cli: &Cli) -> String {
    let conn = cli.harness.raw();
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let mut out = String::new();
    for table in tables {
        let mut stmt = conn.prepare(&format!("SELECT * FROM \"{table}\"")).unwrap();
        let n = stmt.column_count();
        let mut rows = stmt.query([]).unwrap();
        while let Some(r) = rows.next().unwrap() {
            for i in 0..n {
                if let Ok(rusqlite::types::ValueRef::Text(t)) = r.get_ref(i) {
                    out.push_str(&String::from_utf8_lossy(t));
                    out.push('\n');
                }
            }
        }
    }
    out
}

#[test]
fn a_preview_writes_nothing_and_apply_audits_by_fingerprint() {
    let (cli, t) = matched("source = \"agent-php\"");
    let args = [
        "site",
        "vulns-ack",
        "site-a",
        PLUGIN,
        "cve-2099-0002",
        "--reason",
        SECRET,
        "--until",
    ];
    let date = until(30);
    let mut preview: Vec<&str> = args.to_vec();
    preview.push(&date);
    let out = cli.run(&preview);
    assert!(out.status.success(), "{out:?}");
    let text = stdout(&out);
    assert!(text.contains("source agent"), "{text}");
    assert!(text.contains("version 1.2.3"), "{text}");
    assert!(text.contains("CVE-2099-0002, WF-2099-0002"), "{text}");
    assert!(text.contains("empreinte du motif"), "{text}");
    assert!(text.contains("rien n'est écrit"), "{text}");
    assert_eq!(cli.harness.count("SELECT count(*) FROM vuln_waivers"), 0);
    assert_eq!(cli.harness.count("SELECT count(*) FROM command_audit"), 0);

    let mut apply = preview.clone();
    apply.push("--apply");
    let out = cli.run(&apply);
    assert!(out.status.success(), "{out:?}");
    let conn = cli.harness.raw();
    let (covered, hash, advisory): (String, String, String) = conn
        .query_row(
            "SELECT covered_ids, audit_hash, advisory_ref FROM vuln_waivers",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(covered, r#"["CVE-2099-0002","WF-2099-0002"]"#);
    assert_eq!(advisory, "CVE-2099-0002", "alias normalisé");
    let (entry, chain_hash): (String, String) = conn
        .query_row(
            "SELECT entry, hash FROM command_audit WHERE site = 'site-a'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(hash, chain_hash, "correspondance par audit_hash");
    let entry: serde_json::Value = serde_json::from_str(&entry).unwrap();
    assert_eq!(entry["event"], "vuln-waived");
    let detail: serde_json::Value =
        serde_json::from_str(entry["detail"].as_str().unwrap()).unwrap();
    let keys: Vec<&str> = detail
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        ["advisory", "operator", "purl", "reason_sha256", "until"]
    );
    let digest: String = Sha256::digest(SECRET.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(detail["reason_sha256"], digest);
    assert_eq!(detail["purl"], PLUGIN);
    let audit = cli.run(&["site", "audit", "site-a"]);
    assert!(
        !stdout(&audit).contains(SECRET),
        "motif absent de la chaîne"
    );
    let verify = cli.run(&["site", "audit", "site-a", "--verify"]);
    assert!(verify.status.success(), "{verify:?}");

    // Tick suivant : groupe sous dérogation, information.
    cli.harness.tick(t + 120);
    let open = cli.harness.open("site-a");
    assert_eq!(open[0].severity, Severity::Info);
    let shown = stdout(&cli.run(&["site", "vulns", "site-a"]));
    assert!(
        !shown.contains("CVE-2099-0002"),
        "hors dérogation seulement : {shown}"
    );
    let all = stdout(&cli.run(&["site", "vulns", "site-a", "--all"]));
    assert!(all.contains("sous dérogation n° 1 (agent)"), "{all}");
    assert!(all.contains(SECRET), "motif affiché par --all : {all}");

    // Retrait, motivé, audité par empreinte ; gravité rendue.
    let out = cli.run(&[
        "site",
        "vulns-ack",
        "site-a",
        "--revoke",
        "1",
        "--reason",
        "retrait-secret-abc",
        "--apply",
    ]);
    assert!(out.status.success(), "{out:?}");
    let entries = stdout(&cli.run(&["site", "audit", "site-a"]));
    assert!(entries.contains("vuln-waiver-revoked"), "{entries}");
    assert!(!entries.contains("retrait-secret-abc"));
    assert!(
        cli.run(&["site", "audit", "site-a", "--verify"])
            .status
            .success()
    );
    cli.harness.tick(t + 180);
    assert_eq!(cli.harness.open("site-a")[0].severity, Severity::Critical);

    // site remove : plus aucun motif en clair, nulle part.
    let out = cli.run(&["site", "remove", "site-a", "--yes"]);
    assert!(out.status.success(), "{out:?}");
    let everything = all_text(&cli);
    assert!(!everything.contains(SECRET));
    assert!(!everything.contains("retrait-secret-abc"));
    assert!(
        everything.contains(&digest),
        "l'empreinte reste dans la chaîne"
    );
}

#[test]
fn bad_deadlines_and_reasons_are_refused_before_opening_the_base() {
    let cli = setup("wordpress", "source = \"agent-php\"", true);
    let db = cli.dir().join("vigie.db");
    std::fs::remove_file(&db).unwrap();
    for (reason, until) in [
        ("motif", day(now() + 91 * 86_400)),
        ("motif", day(now() - 86_400)),
        ("motif", "2099-13-45".to_owned()),
        ("", until(30)),
        (&"x".repeat(501), until(30)),
    ] {
        let out = cli.run(&[
            "site",
            "vulns-ack",
            "site-a",
            PLUGIN,
            "CVE-2099-0002",
            "--reason",
            reason,
            "--until",
            &until,
        ]);
        assert_eq!(out.status.code(), Some(2), "{until} : {out:?}");
        assert!(!db.exists(), "base ouverte pour {until}");
    }
}

fn ack(cli: &Cli, extra: &[&str]) -> std::process::Output {
    let date = until(30);
    let mut args = vec![
        "site",
        "vulns-ack",
        "site-a",
        PLUGIN,
        "CVE-2099-0002",
        "--reason",
        "motif",
        "--until",
        &date,
    ];
    args.extend_from_slice(extra);
    cli.run(&args)
}

#[test]
fn kev_unknown_version_and_untouched_components_are_refused() {
    let (cli, t) = matched("source = \"agent-php\"");
    cli.harness.kev(&["CVE-2099-0002"], t + 100);
    let out = ack(&cli, &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("faille exploitée (KEV) : dérogation interdite"),
        "{out:?}"
    );

    let (cli, t) = matched("source = \"agent-php\"");
    // Faille qui ne touche pas le composant.
    let out = cli.run(&[
        "site",
        "vulns-ack",
        "site-a",
        PLUGIN,
        "CVE-2099-9999",
        "--reason",
        "motif",
        "--until",
        &until(30),
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("ne touche pas"), "{out:?}");
    // Composant absent du dernier inventaire.
    cli.harness
        .inventory("site-a", Source::Agent, true, &[], t + 600);
    cli.harness.tick(t + 660);
    let out = ack(&cli, &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("absent du dernier inventaire"),
        "{out:?}"
    );
    // Version inconnue : acquitter.
    cli.harness
        .inventory("site-a", Source::Agent, true, &[(PLUGIN, PATH)], t + 1_200);
    cli.harness.tick(t + 1_260);
    let out = ack(&cli, &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("vigie ack"), "{out:?}");
}

#[test]
fn sources_must_be_declared_and_named_when_there_are_two() {
    let (cli, _) = matched("source = \"agent-php\"");
    let out = ack(&cli, &["--source", "ci"]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");

    let (cli, t) = matched("sources = [\"agent-php\", \"ci\"]");
    let version = format!("{PLUGIN}@1.2.3");
    cli.harness.inventory(
        "site-a",
        Source::Ci,
        true,
        &[(&version, "composer.lock")],
        t + 300,
    );
    cli.harness.tick(t + 360);
    let out = ack(&cli, &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("--source"), "{out:?}");
    let out = ack(&cli, &["--source", "agent", "--source", "ci"]);
    assert!(out.status.success(), "{out:?}");
    let text = stdout(&out);
    assert!(
        text.contains("source agent") && text.contains("source ci"),
        "{text}"
    );
    let out = ack(&cli, &["--source", "agent", "--source", "ci", "--apply"]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(cli.harness.count("SELECT count(*) FROM vuln_waivers"), 2);
    assert_eq!(
        cli.harness
            .count("SELECT count(*) FROM command_audit WHERE site = 'site-a'"),
        2
    );
}

#[test]
fn a_new_alias_makes_the_waiver_lapse_as_group_changed() {
    let (cli, t) = matched("source = \"agent-php\"");
    assert!(ack(&cli, &["--apply"]).status.success());
    cli.harness.tick(t + 120);
    assert_eq!(cli.harness.open("site-a")[0].severity, Severity::Info);
    cli.harness.load(
        "wordfence",
        &[wf(
            "WF-2099-0002",
            &["CVE-2099-0002", "GHSA-2099-nouv-0002"],
            95,
        )],
        t + 180,
    );
    cli.harness.tick(t + 240);
    assert_eq!(cli.harness.open("site-a")[0].severity, Severity::Critical);
    let all = stdout(&cli.run(&["site", "vulns", "site-a", "--all"]));
    assert!(all.contains("caduque : groupe changé"), "{all}");
}

#[test]
fn malformed_input_unknown_sites_and_missing_commands_are_refused() {
    let (cli, _) = matched("source = \"agent-php\"");
    for args in [
        vec![
            "site",
            "vulns-ack",
            "site-a",
            "pkg:inconnu/x",
            "CVE-2099-0002",
        ],
        vec!["site", "vulns-ack", "site-a", PLUGIN, "id mal formé"],
        vec!["site", "vulns-ack", "site-z", PLUGIN, "CVE-2099-0002"],
        vec!["site", "vulns-ack", "site-b", PLUGIN, "CVE-2099-0002"],
        vec![
            "site",
            "vulns-ack",
            "site-a",
            "pkg:wordpress/plugin/exemple-plugin@1.2.3",
            "CVE-2099-0002",
        ],
    ] {
        let date = until(30);
        let mut args = args.clone();
        args.extend(["--reason", "motif", "--until", &date]);
        let out = cli.run(&args);
        assert_eq!(out.status.code(), Some(2), "{args:?} : {out:?}");
    }
    let cli = setup("wordpress", "source = \"agent-php\"", false);
    let out = ack(&cli, &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("[commands]"), "{out:?}");
}
