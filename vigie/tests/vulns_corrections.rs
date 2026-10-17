//! Corrections de plage auditées (#17, phase 4) : saisie et retrait par la
//! CLI, application à la lecture, chaîne `_veilleur` vérifiée dans les deux
//! sens, états « sans objet », « orpheline », « illisible », refus. Base
//! remplie par une synchronisation Friends-Of-Presta contre le serveur HTTPS
//! local (avis fictifs). Aucun réseau.

#[path = "support/dump_server.rs"]
mod dump_server;
#[path = "support/targen.rs"]
mod targen;
#[path = "support/veilleur.rs"]
mod veilleur;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use rusqlite::TransactionBehavior;
use vigie::clock::FakeClock;
use vigie::config::Config;
use vigie::http::Trust;
use vigie::store::Store;
use vigie::vulns::advisory::Tally;
use vigie::vulns::corrections::{self, State, latest_range_correction_id};
use vigie::vulns::purl::Purl;
use vigie::vulns::sources::friends_of_presta::FriendsOfPresta;
use vigie::vulns::store::{LEASE, Load, Outcome, SourceMeta, SyncMeta, candidates, upsert_source};
use vigie::vulns::sync::SyncOptions;
use vigie::vulns::sync::engine::sync_source;
use vigie::vulns::version::SourceEcosystem;

use dump_server::{DumpServer, Reply};

const T0: i64 = 1_800_000_000;
const FOP_PATH: &str = "/friends-of-presta/security-advisories/archive/refs/heads/main.tar.gz";
const FREE_ID: &str = "FOP-2099-01-20-modulelibre";
const FREE_PURL: &str = "pkg:prestashop/module/modulelibre";
const FREE_FILE: &str = "2099-01-20-modulelibre.md";
const REASON: &str = "Plage relue sur le dépôt fictif de l'éditeur";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vulns")
}

fn posts() -> Vec<(String, Vec<u8>)> {
    targen::posts(&fixtures().join("friends-of-presta/_posts"))
}

struct Env {
    dir: tempfile::TempDir,
    server: DumpServer,
    config: Config,
    clock: FakeClock,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        vigie::command::key::create(&dir.path().join("commands.key")).unwrap();
        vigie::command::key::create(&dir.path().join("audit.key")).unwrap();
        let config = veilleur::config(dir.path().join("vigie.db"));
        let env = Self {
            dir,
            server: DumpServer::start(),
            config,
            clock: FakeClock::new(T0),
        };
        env.sync(&posts());
        env
    }

    /// Synchronise Friends-Of-Presta sur l'archive de ces avis.
    fn sync(&self, posts: &[(String, Vec<u8>)]) {
        self.server
            .route(FOP_PATH, Reply::ok(targen::archive(posts)));
        let mut store = Store::open(&self.config.database).unwrap();
        let report = sync_source(
            &mut store,
            self.dir.path(),
            &FriendsOfPresta,
            &SyncOptions {
                trust: Trust::Custom(vec![self.server.ca.clone()]),
                endpoint_override: Some(self.server.base()),
                limits_override: None,
                free_space_override: None,
            },
            &self.clock,
            false,
        );
        assert_eq!(report.outcome, Outcome::Loaded, "{}", report.line);
        self.clock.advance(60);
    }

    fn config_file(&self, commands: bool) -> PathBuf {
        let mut raw = format!(
            "database = '{}'\n[alerts]\nto = \"alertes@example.org\"\nfrom = \"vigie@example.org\"\nsmtp_host = \"smtp.example.org\"\npassword_file = '{}'\n",
            self.config.database.display(),
            self.dir.path().join("smtp-password").display()
        );
        if commands {
            raw.push_str(&format!(
                "[commands]\nkey_file = '{}'\naudit_key_file = '{}'\n",
                self.dir.path().join("commands.key").display(),
                self.dir.path().join("audit.key").display()
            ));
        }
        let path = self.dir.path().join(if commands {
            "config.toml"
        } else {
            "sans-commandes.toml"
        });
        std::fs::write(&path, raw).unwrap();
        path
    }

    fn vigie_with(&self, commands: bool, args: &[&str], user: Option<&str>) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_vigie"));
        cmd.arg("--config")
            .arg(self.config_file(commands))
            .args(args)
            .env_remove("VIGIE_CONFIG");
        if let Some(u) = user {
            cmd.env("USER", u).env("LOGNAME", u);
        }
        cmd.output().expect("lancement de vigie")
    }

    fn vigie(&self, args: &[&str]) -> Output {
        self.vigie_with(true, args, None)
    }

    fn correct(&self, range: &str) -> Output {
        self.vigie(&[
            "vulns", "correct", FREE_ID, FREE_PURL, "--range", range, "--reason", REASON,
        ])
    }

    fn store(&self) -> Store {
        Store::open(&self.config.database).unwrap()
    }

    fn sql(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(&self.config.database).unwrap()
    }

    fn corrected(&self) -> bool {
        let found = candidates(&self.store(), &Purl::parse(FREE_PURL).unwrap()).unwrap();
        found
            .iter()
            .find(|c| c.advisory.id == FREE_ID)
            .is_some_and(|c| c.corrected)
    }
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8(out.stderr.clone()).unwrap()
}

fn code(out: &Output) -> i32 {
    out.status.code().unwrap()
}

#[test]
fn a_correction_is_applied_audited_and_cleared() {
    let env = Env::new();
    assert_eq!(latest_range_correction_id(&env.store()).unwrap(), None);
    let before = stdout(&env.vigie(&["vulns", "match", &format!("{FREE_PURL}@3.0.0")]));
    assert!(before.contains("plage inconnue"), "{before}");
    assert!(!env.corrected());

    let out = env.correct("<= 3.1.0");
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        stdout(&out).contains("correction 1 enregistrée"),
        "{}",
        stdout(&out)
    );
    assert_eq!(latest_range_correction_id(&env.store()).unwrap(), Some(1));
    let read = Store::open_read(&env.config.database).unwrap().unwrap();
    assert_eq!(latest_range_correction_id(&read).unwrap(), Some(1));
    assert!(env.corrected());

    let hit = stdout(&env.vigie(&["vulns", "match", &format!("{FREE_PURL}@3.0.0")]));
    assert!(hit.contains(&format!("{FREE_ID}  touché")), "{hit}");
    assert!(
        hit.contains(&format!("[plage corrigée : {REASON}]")),
        "{hit}"
    );
    let above = stdout(&env.vigie(&["vulns", "match", &format!("{FREE_PURL}@3.2.0")]));
    assert!(above.contains("aucune faille connue"), "{above}");
    let show = stdout(&env.vigie(&["vulns", "show", FREE_ID]));
    assert!(
        show.contains("plage corrigée pour pkg:prestashop/module/modulelibre"),
        "{show}"
    );

    let list = stdout(&env.vigie(&["vulns", "corrections"]));
    assert!(
        list.contains("active  introduced 0, last_affected 3.1.0"),
        "{list}"
    );
    let verify = env.vigie(&["vulns", "corrections", "--audit", "--verify"]);
    assert_eq!(code(&verify), 0, "{}", stderr(&verify));
    assert!(
        stdout(&verify).contains("1 ligne(s), 1 entrée(s)"),
        "{}",
        stdout(&verify)
    );
    let audit = stdout(&env.vigie(&["vulns", "corrections", "--audit"]));
    assert_eq!(audit.lines().count(), 1);
    assert!(audit.contains("range-corrected"), "{audit}");

    // Resynchronisation (nouvelle génération) : toujours appliquée.
    let mut changed = posts();
    changed.push(("2099-03-01-nouveau.md".into(), changed[0].1.clone()));
    env.sync(&changed);
    assert!(env.corrected());

    let out = env.vigie(&[
        "vulns",
        "correct",
        FREE_ID,
        FREE_PURL,
        "--clear",
        "--reason",
        "Retrait fictif",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(latest_range_correction_id(&env.store()).unwrap(), Some(2));
    assert!(!env.corrected());
    let after = stdout(&env.vigie(&["vulns", "match", &format!("{FREE_PURL}@3.0.0")]));
    assert!(after.contains("plage inconnue"), "{after}");
    assert!(stdout(&env.vigie(&["vulns", "corrections"])).contains("retirée"));
    let verify = env.vigie(&["vulns", "corrections", "--audit", "--verify"]);
    assert_eq!(code(&verify), 0, "{}", stderr(&verify));
    assert!(stdout(&verify).contains("2 ligne(s), 2 entrée(s)"));
}

#[test]
fn the_operator_is_the_account_not_user() {
    let env = Env::new();
    let out = env.vigie_with(
        true,
        &[
            "vulns", "correct", FREE_ID, FREE_PURL, "--range", "< 3.0", "--reason", REASON,
        ],
        Some("quelquun-dautre"),
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let rows = corrections::rows(&env.store()).unwrap();
    assert_eq!(rows[0].operator, corrections::operator());
    assert_ne!(rows[0].operator, "quelquun-dautre");
}

#[test]
fn refusals_exit_with_code_2() {
    let env = Env::new();
    // Une faille d'une autre source.
    {
        let mut store = env.store();
        upsert_source(
            &mut store,
            &SourceMeta {
                id: "osv-packagist".into(),
                url: "https://example.org/all.zip".into(),
                license: String::new(),
                attribution: String::new(),
            },
        )
        .unwrap();
        let mut tally = Tally::default();
        let a = vigie::vulns::advisory::from_osv(
            &std::fs::read(fixtures().join("osv/GHSA-2q52-x2ff-qgfr.json")).unwrap(),
            SourceEcosystem::Packagist,
            &mut tally,
        )
        .unwrap();
        let mut load = Load::begin(&mut store, "osv-packagist", &env.clock, LEASE).unwrap();
        load.push(&[a]).unwrap();
        load.commit(&Tally::default(), &SyncMeta::default())
            .unwrap();
    }
    let cases: Vec<(bool, Vec<&str>, &str)> = vec![
        (
            false,
            vec![
                "vulns", "correct", FREE_ID, FREE_PURL, "--range", "< 3.0", "--reason", REASON,
            ],
            "[commands]",
        ),
        (
            true,
            vec![
                "vulns",
                "correct",
                "GHSA-2q52-x2ff-qgfr",
                "pkg:composer/a/b",
                "--range",
                "< 3.0",
                "--reason",
                REASON,
            ],
            "osv-packagist",
        ),
        (
            true,
            vec![
                "vulns",
                "correct",
                FREE_ID,
                FREE_PURL,
                "--range",
                "all versions",
                "--reason",
                REASON,
            ],
            "grammaire",
        ),
        (
            true,
            vec![
                "vulns",
                "correct",
                FREE_ID,
                FREE_PURL,
                "--range",
                "<= 1.0 (fixed in 1.1)",
                "--reason",
                REASON,
            ],
            "grammaire",
        ),
        (
            true,
            vec![
                "vulns", "correct", FREE_ID, FREE_PURL, "--range", "< 3.0", "--reason", " ",
            ],
            "motif",
        ),
        (
            true,
            vec![
                "vulns",
                "correct",
                "FOP-2099-01-15-exemplemodule",
                "pkg:prestashop/module/exemplemodule",
                "--range",
                "< 3.0",
                "--reason",
                REASON,
            ],
            "rien à corriger",
        ),
        (
            true,
            vec![
                "vulns",
                "correct",
                FREE_ID,
                "pkg:prestashop/module/autre",
                "--range",
                "< 3.0",
                "--reason",
                REASON,
            ],
            "absent",
        ),
        (
            true,
            vec![
                "vulns", "correct", FREE_ID, FREE_PURL, "--clear", "--reason", REASON,
            ],
            "aucune correction",
        ),
    ];
    let long = "m".repeat(501);
    let mut cases = cases;
    cases.push((
        true,
        vec![
            "vulns", "correct", FREE_ID, FREE_PURL, "--range", "< 3.0", "--reason", &long,
        ],
        "motif",
    ));
    for (commands, args, want) in cases {
        let out = env.vigie_with(commands, &args, None);
        assert_eq!(code(&out), 2, "{args:?} : {}", stderr(&out));
        assert!(stderr(&out).contains(want), "{args:?} : {}", stderr(&out));
    }
    assert_eq!(latest_range_correction_id(&env.store()).unwrap(), None);
}

#[test]
fn the_table_is_append_only() {
    let env = Env::new();
    assert_eq!(code(&env.correct("< 3.0")), 0);
    let sql = env.sql();
    assert!(
        sql.execute("UPDATE vuln_range_corrections SET reason = 'x'", [])
            .is_err()
    );
    assert!(
        sql.execute("DELETE FROM vuln_range_corrections", [])
            .is_err()
    );
}

#[test]
fn tampering_is_caught_both_ways() {
    // Correction insérée hors outil.
    let env = Env::new();
    assert_eq!(code(&env.correct("< 3.0")), 0);
    env.sql()
        .execute(
            "INSERT INTO vuln_range_corrections
                 (source, advisory_id, purl, ranges, reason, operator, at, audit_hash)
             VALUES ('friends-of-presta', ?1, ?2, NULL, 'hors outil', 'x', 1, ?3)",
            rusqlite::params![FREE_ID, FREE_PURL, "a".repeat(64)],
        )
        .unwrap();
    let out = env.vigie(&["vulns", "corrections", "--audit", "--verify"]);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("sans entrée d'audit"),
        "{}",
        stderr(&out)
    );

    // Entrée `range-*` signée sans correction.
    let env = Env::new();
    let key = vigie::command::key::load(&env.dir.path().join("audit.key")).unwrap();
    {
        let mut sql = env.sql();
        let tx = sql
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        vigie::command::audit::append(
            &tx,
            &key,
            &vigie::command::audit::Entry {
                site: "_veilleur".into(),
                at: 1,
                event: "range-corrected".into(),
                command_id: None,
                detail: "{}".into(),
                typology: None,
            },
        )
        .unwrap();
        tx.commit().unwrap();
    }
    let out = env.vigie(&["vulns", "corrections", "--audit", "--verify"]);
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("sans correction"), "{}", stderr(&out));

    // Ligne d'audit altérée (déclencheur retiré pour le test).
    let env = Env::new();
    assert_eq!(code(&env.correct("< 3.0")), 0);
    let sql = env.sql();
    sql.execute_batch("DROP TRIGGER command_audit_no_update")
        .unwrap();
    sql.execute(
        "UPDATE command_audit SET entry = replace(entry, 'Plage', 'Page') WHERE site = '_veilleur'",
        [],
    )
    .unwrap();
    let out = env.vigie(&["vulns", "corrections", "--audit", "--verify"]);
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("altérée"), "{}", stderr(&out));
}

#[test]
fn unreadable_moot_and_orphan_corrections() {
    // Illisible : la ligne reste « plage inconnue ».
    let env = Env::new();
    env.sql()
        .execute(
            "INSERT INTO vuln_range_corrections
                 (source, advisory_id, purl, ranges, reason, operator, at, audit_hash)
             VALUES ('friends-of-presta', ?1, ?2, '{cassé', 'x', 'x', 1, ?3)",
            rusqlite::params![FREE_ID, FREE_PURL, "b".repeat(64)],
        )
        .unwrap();
    assert!(!env.corrected());
    let list = corrections::list(&env.store()).unwrap();
    assert_eq!(list[0].1, State::Unreadable);
    let m = stdout(&env.vigie(&["vulns", "match", &format!("{FREE_PURL}@3.0.0")]));
    assert!(m.contains("plage inconnue"), "{m}");

    // Sans objet : l'avis devient lisible, la plage de la source prime.
    let env = Env::new();
    assert_eq!(code(&env.correct("<= 3.1.0")), 0);
    let readable: Vec<(String, Vec<u8>)> = posts()
        .into_iter()
        .map(|(name, data)| {
            if name == FREE_FILE {
                let text = String::from_utf8(data)
                    .unwrap()
                    .replace("all versions before the fictive fix", "< 2.0.0");
                (name, text.into_bytes())
            } else {
                (name, data)
            }
        })
        .collect();
    env.sync(&readable);
    assert!(!env.corrected());
    assert_eq!(corrections::list(&env.store()).unwrap()[0].1, State::Moot);
    assert!(stdout(&env.vigie(&["vulns", "corrections"])).contains("sans objet"));
    let m = stdout(&env.vigie(&["vulns", "match", &format!("{FREE_PURL}@3.0.0")]));
    assert!(m.contains("aucune faille connue"), "{m}");

    // Orpheline : l'avis disparaît de la source.
    let without: Vec<(String, Vec<u8>)> = posts()
        .into_iter()
        .filter(|(n, _)| n != FREE_FILE)
        .collect();
    env.sync(&without);
    assert_eq!(corrections::list(&env.store()).unwrap()[0].1, State::Orphan);
    assert!(stdout(&env.vigie(&["vulns", "corrections"])).contains("orpheline"));
    // Une orpheline se retire.
    let out = env.vigie(&[
        "vulns",
        "correct",
        FREE_ID,
        FREE_PURL,
        "--clear",
        "--reason",
        "Avis retiré",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
}
