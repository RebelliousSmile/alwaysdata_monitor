//! Synchronisation complète (#16, phase 2) contre le serveur HTTPS local :
//! trois exports OSV construits par `zipgen` depuis les fixtures de F1,
//! idempotence (304, même empreinte), échecs et dumps hostiles qui laissent
//! la base précédente intacte, taux d'écart, garde contre le
//! rétrécissement, bail, débit et `LOADER_VERSION`. Aucun réseau.

#[path = "support/dump_server.rs"]
mod dump_server;
#[path = "support/veilleur.rs"]
mod veilleur;
#[path = "support/zipgen.rs"]
mod zipgen;

use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};
use url::Url;

use vigie::clock::{Clock, FakeClock};
use vigie::config::{Config, Vulns};
use vigie::http::Trust;
use vigie::store::Store;
use vigie::vulns::advisory::{Reason, Tally};
use vigie::vulns::purl::Purl;
use vigie::vulns::range::Verdict;
use vigie::vulns::sources::osv::OsvSource;
use vigie::vulns::store::{
    LEASE, Load, Outcome, SyncState, active_count, generations, match_purl, sync_state,
};
use vigie::vulns::sync::download::Download;
use vigie::vulns::sync::engine::sync_source;
use vigie::vulns::sync::{
    FetchOutcome, Limits, NotReady, Sink, SourceMeta, SourceReport, SyncContext, SyncError,
    SyncOptions, SyncReport, VulnSource,
};
use vigie::vulns::version::SourceEcosystem;

use dump_server::{DumpServer, Reply};
use zipgen::{Spec, ZEntry, build, crc32, zip_of};

const T0: i64 = 1_800_000_000;
const LM: &str = "Sat, 17 Oct 2026 03:00:00 GMT";
const CRATES: &str = "/crates.io/all.zip";
const PACKAGIST: &str = "/Packagist/all.zip";
const NPM: &str = "/npm/all.zip";

fn fixture(rel: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/vulns")
            .join(rel),
    )
    .unwrap()
}

fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Faille crates.io fictive `n` (`exemple-<n>`, touchée avant 1.0.0).
fn crate_record(n: usize) -> String {
    format!(
        r#"{{"id":"RUSTSEC-2099-{n:04}","modified":"2026-10-01T00:00:00Z","affected":[{{"package":{{"ecosystem":"crates.io","name":"exemple-{n}"}},"ranges":[{{"type":"SEMVER","events":[{{"introduced":"0"}},{{"fixed":"1.0.0"}}]}}]}}]}}"#
    )
}

fn crate_entry(n: usize, body: String) -> ZEntry {
    ZEntry::new(&format!("RUSTSEC-2099-{n:04}.json"), body.as_bytes())
}

/// Export crates.io de `n` failles fictives.
fn crates_zip(n: usize) -> Vec<u8> {
    zip_of((0..n).map(|i| crate_entry(i, crate_record(i))).collect())
}

fn real_crates() -> Vec<u8> {
    zip_of(vec![ZEntry::new(
        "RUSTSEC-2017-0004.json",
        &fixture("osv/RUSTSEC-2017-0004.json"),
    )])
}

fn real_packagist() -> Vec<u8> {
    zip_of(vec![
        ZEntry::new(
            "GHSA-2q52-x2ff-qgfr.json",
            &fixture("osv/GHSA-2q52-x2ff-qgfr.json"),
        ),
        ZEntry::new(
            "GHSA-exdv-exdv-exdv.json",
            &fixture("fictif/packagist-divergence.json"),
        ),
    ])
}

fn real_npm() -> Vec<u8> {
    zip_of(vec![ZEntry::new(
        "GHSA-67hx-6x53-jw92.json",
        &fixture("osv/GHSA-67hx-6x53-jw92.json"),
    )])
}

struct Env {
    _dir: tempfile::TempDir,
    server: DumpServer,
    config: Config,
    clock: FakeClock,
    limits: Option<Limits>,
}

impl Env {
    fn new(sources: &[&str]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut config = veilleur::config(dir.path().join("data").join("vigie.db"));
        config.vulns = Some(Vulns {
            sources: sources.iter().map(|s| (*s).to_owned()).collect(),
        });
        Self {
            _dir: dir,
            server: DumpServer::start(),
            config,
            clock: FakeClock::new(T0),
            limits: None,
        }
    }

    fn all() -> Self {
        let env = Self::new(&["osv-npm", "osv-packagist", "osv-crates-io"]);
        env.server
            .route(CRATES, Reply::ok_etag(real_crates(), "\"c1\"", LM));
        env.server
            .route(PACKAGIST, Reply::ok_etag(real_packagist(), "\"p1\"", LM));
        env.server
            .route(NPM, Reply::ok_etag(real_npm(), "\"n1\"", LM));
        env
    }

    fn options(&self) -> SyncOptions {
        SyncOptions {
            trust: Trust::Custom(vec![self.server.ca.clone()]),
            endpoint_override: Some(self.server.base()),
            limits_override: self.limits.clone(),
            free_space_override: None,
            // KEV et EPSS, déclarés d'office (#18) : `vulns_enrich_sync.rs`.
            skip_enrichment: true,
        }
    }

    fn run(&self, only: Option<&str>, accept_shrink: bool) -> SyncReport {
        vigie::vulns::sync::run(
            &self.config,
            &self.options(),
            &self.clock,
            only,
            accept_shrink,
        )
        .unwrap()
    }

    /// Une source hors du registre (tests de débit, de bail, de course).
    fn run_source(&self, source: &dyn VulnSource) -> SourceReport {
        let mut store = self.store();
        sync_source(
            &mut store,
            &self.base_dir(),
            source,
            &self.options(),
            &self.clock,
            false,
        )
    }

    fn base_dir(&self) -> PathBuf {
        self.config.database.parent().unwrap().to_path_buf()
    }

    fn store(&self) -> Store {
        Store::open(&self.config.database).unwrap()
    }

    fn state(&self, id: &str) -> SyncState {
        sync_state(&self.store(), id).unwrap().expect("source")
    }

    fn sql(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(&self.config.database).unwrap()
    }

    /// Lignes de failles, toutes générations confondues.
    fn rows(&self) -> i64 {
        self.sql()
            .query_row("SELECT count(*) FROM vuln_advisories", [], |r| r.get(0))
            .unwrap()
    }

    /// Identifiants de la génération active d'une source.
    fn active_ids(&self, id: &str) -> Vec<String> {
        let conn = self.sql();
        let mut stmt = conn
            .prepare(
                "SELECT a.id FROM vuln_advisories a JOIN vuln_sources s
                 ON s.id = a.source AND s.active_generation = a.generation
                 WHERE a.source = ?1 ORDER BY a.id",
            )
            .unwrap();
        stmt.query_map([id], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn work_is_empty(&self) -> bool {
        let root = self.base_dir().join("vulns-work");
        std::fs::read_dir(&root).map_or(true, |dirs| {
            dirs.flatten()
                .all(|d| std::fs::read_dir(d.path()).unwrap().count() == 0)
        })
    }

    fn crates_only(&self) -> OsvSource {
        OsvSource {
            ecosystem: SourceEcosystem::CratesIo,
        }
    }
}

fn outcomes(report: &SyncReport) -> Vec<(&str, Outcome)> {
    report.sources.iter().map(|s| (s.id, s.outcome)).collect()
}

fn affected(store: &Store, purl: &str) -> Option<Verdict> {
    match_purl(store, &Purl::parse(purl).unwrap())
        .unwrap()
        .into_iter()
        .map(|(_, v)| v)
        .find(|v| matches!(v, Verdict::Affected { .. }))
}

// --- Happy path ---

#[test]
fn three_sources_are_loaded_with_their_state() {
    let env = Env::all();
    let report = env.run(None, false);
    assert_eq!(
        outcomes(&report),
        [
            ("osv-crates-io", Outcome::Loaded),
            ("osv-packagist", Outcome::Loaded),
            ("osv-npm", Outcome::Loaded)
        ],
        "{report:?}"
    );
    assert_eq!(report.failures(), 0);
    let crates = env.state("osv-crates-io");
    assert_eq!(crates.last_outcome, Some(Outcome::Loaded));
    assert_eq!(crates.etag.as_deref(), Some("\"c1\""));
    assert_eq!(crates.http_last_modified.as_deref(), Some(LM));
    assert_eq!(crates.dump_sha256, Some(sha(&real_crates())));
    assert_eq!(crates.loader_version, Some(1));
    assert_eq!(crates.dump_bytes, Some(real_crates().len() as i64));
    assert_eq!(
        crates.unpacked_bytes,
        Some(fixture("osv/RUSTSEC-2017-0004.json").len() as i64)
    );
    assert!(crates.last_duration_ms.is_some());
    assert_eq!(crates.last_success_at, Some(T0));
    assert_eq!(crates.last_request_at, Some(T0));
    assert_eq!(crates.recent_entries, [1]);
    assert_eq!(crates.loading_since, None);
    let store = env.store();
    assert!(affected(&store, "pkg:cargo/base64@0.5.0").is_some());
    assert!(affected(&store, "pkg:npm/%40babel/traverse@7.23.1").is_some());
    assert!(affected(&store, "pkg:composer/twig/twig@3.10.0").is_some());
    assert_eq!(env.server.requests(), 3);
    assert!(env.work_is_empty());
}

#[test]
fn one_source_only_requests_that_source() {
    let env = Env::all();
    let report = env.run(Some("osv-npm"), false);
    assert_eq!(outcomes(&report), [("osv-npm", Outcome::Loaded)]);
    let paths: Vec<String> = env.server.seen().into_iter().map(|s| s.path).collect();
    assert_eq!(paths, [NPM]);
}

#[test]
fn an_undeclared_source_is_a_usage_error() {
    let env = Env::new(&["osv-npm"]);
    let err = vigie::vulns::sync::run(
        &env.config,
        &env.options(),
        &env.clock,
        Some("osv-crates-io"),
        false,
    )
    .unwrap_err();
    assert!(err.downcast_ref::<vigie::vulns::UsageError>().is_some());
    assert_eq!(env.server.requests(), 0);
}

// --- Idempotence ---

#[test]
fn a_304_writes_no_advisory_and_dates_the_success() {
    let env = Env::all();
    env.run(None, false);
    let (rows, gen_before) = (env.rows(), env.state("osv-npm").active_generation);
    env.clock.advance(3600);
    let report = env.run(None, false);
    assert!(
        report
            .sources
            .iter()
            .all(|s| s.outcome == Outcome::NotModified),
        "{report:?}"
    );
    let npm = env.state("osv-npm");
    assert_eq!(npm.active_generation, gen_before);
    assert_eq!(npm.last_success_at, Some(T0 + 3600));
    assert_eq!(npm.last_outcome, Some(Outcome::NotModified));
    assert_eq!(npm.loading_since, None, "bail rendu");
    assert_eq!(npm.etag.as_deref(), Some("\"n1\""));
    assert_eq!(env.rows(), rows);
    let second: Vec<_> = env.server.seen().into_iter().skip(3).collect();
    assert!(
        second
            .iter()
            .all(|s| s.header("if-none-match").is_some()
                && s.header("if-modified-since") == Some(LM))
    );
}

#[test]
fn the_same_dump_without_etag_is_unchanged() {
    let env = Env::new(&["osv-crates-io"]);
    env.server.route(CRATES, Reply::ok(real_crates()));
    env.run(None, false);
    let rows = env.rows();
    env.clock.advance(60);
    let report = env.run(None, false);
    assert_eq!(outcomes(&report), [("osv-crates-io", Outcome::Unchanged)]);
    assert_eq!(env.rows(), rows);
    assert_eq!(env.state("osv-crates-io").last_success_at, Some(T0 + 60));
    assert!(env.work_is_empty());
}

/// Source qui bascule la génération active par une autre connexion entre
/// le 304 et `finish_unchanged`.
struct Racing {
    inner: OsvSource,
    db: PathBuf,
}

impl VulnSource for Racing {
    fn id(&self) -> &'static str {
        self.inner.id()
    }
    fn meta(&self) -> SourceMeta {
        self.inner.meta()
    }
    fn fetch(
        &self,
        dl: &mut Download,
        sink: &mut dyn Sink,
        tally: &mut Tally,
    ) -> Result<FetchOutcome, SyncError> {
        let outcome = self.inner.fetch(dl, sink, tally)?;
        rusqlite::Connection::open(&self.db)
            .unwrap()
            .execute(
                "UPDATE vuln_sources SET active_generation = active_generation + 1
                 WHERE id = ?1",
                [self.id()],
            )
            .unwrap();
        Ok(outcome)
    }
}

#[test]
fn a_concurrent_switch_before_finish_unchanged_writes_nothing() {
    let env = Env::new(&["osv-crates-io"]);
    env.server
        .route(CRATES, Reply::ok_etag(real_crates(), "\"c1\"", LM));
    env.run(None, false);
    env.clock.advance(60);
    let report = env.run_source(&Racing {
        inner: env.crates_only(),
        db: env.config.database.clone(),
    });
    assert_eq!(report.outcome, Outcome::Busy, "{report:?}");
    let state = env.state("osv-crates-io");
    assert_eq!(state.last_success_at, Some(T0), "rien écrit");
    assert_eq!(state.last_outcome, Some(Outcome::Loaded));
}

#[test]
fn a_modified_dump_becomes_the_new_generation_and_the_old_is_purged() {
    let env = Env::new(&["osv-crates-io"]);
    env.server
        .route(CRATES, Reply::ok_etag(crates_zip(3), "\"a\"", LM));
    env.run(None, false);
    env.server
        .route(CRATES, Reply::ok_etag(crates_zip(5), "\"b\"", LM));
    env.clock.advance(60);
    let report = env.run(None, false);
    assert_eq!(outcomes(&report), [("osv-crates-io", Outcome::Loaded)]);
    let state = env.state("osv-crates-io");
    assert_eq!(state.etag.as_deref(), Some("\"b\""));
    assert_eq!(active_count(&env.store(), "osv-crates-io").unwrap(), 5);
    assert_eq!(
        generations(&env.store(), "osv-crates-io").unwrap(),
        [state.active_generation]
    );
    assert_eq!(state.recent_entries, [3, 5]);
}

/// Source au lecteur incrémenté.
struct Bumped(OsvSource);

impl VulnSource for Bumped {
    fn id(&self) -> &'static str {
        self.0.id()
    }
    fn meta(&self) -> SourceMeta {
        SourceMeta {
            loader_version: 2,
            ..self.0.meta()
        }
    }
    fn fetch(
        &self,
        dl: &mut Download,
        sink: &mut dyn Sink,
        tally: &mut Tally,
    ) -> Result<FetchOutcome, SyncError> {
        self.0.fetch(dl, sink, tally)
    }
}

#[test]
fn a_new_loader_version_reloads_without_conditionals() {
    let env = Env::new(&["osv-crates-io"]);
    env.server
        .route(CRATES, Reply::ok_etag(real_crates(), "\"c1\"", LM));
    env.run(None, false);
    let before = env.state("osv-crates-io").active_generation;
    env.clock.advance(60);
    let report = env.run_source(&Bumped(env.crates_only()));
    assert_eq!(report.outcome, Outcome::Loaded, "{report:?}");
    let last = env.server.seen().pop().unwrap();
    assert_eq!(last.header("if-none-match"), None);
    assert_eq!(last.header("if-modified-since"), None);
    let state = env.state("osv-crates-io");
    assert!(state.active_generation > before);
    assert_eq!(state.loader_version, Some(2));
}

// --- Packagist ---

#[test]
fn a_version_listed_outside_the_ranges_is_a_divergence() {
    let env = Env::all();
    env.run(Some("osv-packagist"), false);
    let store = env.store();
    assert_eq!(
        affected(&store, "pkg:composer/exemple/paquet@1.5.0"),
        Some(Verdict::Affected {
            fixed: None,
            divergence: true,
            beyond_last_known: false
        })
    );
    assert_eq!(
        affected(&store, "pkg:composer/exemple/paquet@1.1.0"),
        Some(Verdict::Affected {
            fixed: Some("1.2.0".into()),
            divergence: false,
            beyond_last_known: false
        })
    );
}

// --- Échec, base précédente intacte ---

/// Charge crates.io une fois, puis rend la ligne d'état et les failles.
fn loaded_crates() -> (Env, SyncState, Vec<String>) {
    let env = Env::new(&["osv-crates-io"]);
    env.server
        .route(CRATES, Reply::ok_etag(crates_zip(4), "\"c1\"", LM));
    env.run(None, false);
    env.clock.advance(60);
    let state = env.state("osv-crates-io");
    let ids = env.active_ids("osv-crates-io");
    (env, state, ids)
}

fn assert_intact(env: &Env, before: &SyncState, ids: &[String]) {
    let after = env.state("osv-crates-io");
    assert_eq!(after.active_generation, before.active_generation);
    assert_eq!(after.dump_sha256, before.dump_sha256);
    assert_eq!(after.etag, before.etag);
    assert_eq!(after.http_last_modified, before.http_last_modified);
    assert_eq!(after.last_success_at, before.last_success_at);
    assert_eq!(env.active_ids("osv-crates-io"), ids);
    assert!(env.work_is_empty());
}

fn failed_with(env: &Env, want: &str) {
    let report = env.run(None, false);
    assert_eq!(report.failures(), 1, "{report:?}");
    let state = env.state("osv-crates-io");
    assert_eq!(state.last_outcome, Some(Outcome::Failed));
    let err = state.last_error.unwrap_or_default();
    assert!(err.contains(want), "{err}");
    assert!(err.chars().count() <= 500);
}

#[test]
fn server_errors_network_and_deadline_keep_the_previous_base() {
    let (mut env, before, ids) = loaded_crates();
    env.server.route(
        CRATES,
        Reply::Status {
            code: 500,
            retry_after: None,
        },
    );
    failed_with(&env, "statut HTTP 500");
    assert_intact(&env, &before, &ids);

    env.server.route(CRATES, Reply::Hang);
    env.limits = Some(Limits {
        duration: Duration::from_secs(2),
        ..Limits::osv(SourceEcosystem::CratesIo)
    });
    failed_with(&env, "délai");
    assert_intact(&env, &before, &ids);
    env.limits = None;

    // Réseau coupé : port fermé.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let mut options = env.options();
    options.endpoint_override = Some(Url::parse(&format!("https://127.0.0.1:{port}/")).unwrap());
    let report = vigie::vulns::sync::run(&env.config, &options, &env.clock, None, false).unwrap();
    assert_eq!(report.failures(), 1);
    assert!(
        env.state("osv-crates-io")
            .last_error
            .unwrap()
            .contains("réseau")
    );
    assert_intact(&env, &before, &ids);
}

#[test]
fn hostile_zips_are_refused_whole() {
    let (mut env, before, ids) = loaded_crates();
    let mut bad_crc = crate_entry(1, crate_record(1));
    bad_crc.crc = Some(crc32(b"x"));
    let mut bomb = crate_entry(2, crate_record(2));
    bomb.unpacked = Some(10);
    let overlap = build(&Spec {
        entries: vec![
            crate_entry(1, crate_record(1)),
            crate_entry(2, crate_record(2)),
        ],
        duplicate_central: vec![0],
        ..Spec::default()
    })
    .bytes;
    for (zip, want) in [
        (zip_of(vec![bad_crc]), "CRC faux"),
        (zip_of(vec![bomb]), "longueur réelle"),
        (overlap, "recouvrent"),
    ] {
        env.server.route(CRATES, Reply::ok(zip));
        failed_with(&env, want);
        assert_intact(&env, &before, &ids);
    }
    env.limits = Some(Limits {
        entries: 3,
        ..Limits::osv(SourceEcosystem::CratesIo)
    });
    env.server.route(CRATES, Reply::ok(crates_zip(5)));
    failed_with(&env, "nombre d'entrées");
    assert_intact(&env, &before, &ids);
}

#[test]
fn giant_or_endless_bodies_fail() {
    let (env, before, ids) = loaded_crates();
    env.server.route(CRATES, Reply::HugeLength);
    failed_with(&env, "plafond dépassé");
    assert_intact(&env, &before, &ids);
    env.server.route(CRATES, Reply::Endless);
    failed_with(&env, "plafond dépassé");
    assert_intact(&env, &before, &ids);
}

#[test]
fn one_failing_source_does_not_stop_the_others() {
    let env = Env::all();
    env.server.route(
        PACKAGIST,
        Reply::Status {
            code: 500,
            retry_after: None,
        },
    );
    let report = env.run(None, false);
    assert_eq!(
        outcomes(&report),
        [
            ("osv-crates-io", Outcome::Loaded),
            ("osv-packagist", Outcome::Failed),
            ("osv-npm", Outcome::Loaded)
        ]
    );
    assert_eq!(report.failures(), 1);
}

/// Source pas prête.
struct Waiting(OsvSource);

impl VulnSource for Waiting {
    fn id(&self) -> &'static str {
        self.0.id()
    }
    fn meta(&self) -> SourceMeta {
        self.0.meta()
    }
    fn ready(&self, _ctx: &SyncContext) -> Result<(), NotReady> {
        Err(NotReady("conditions non relues".into()))
    }
    fn fetch(
        &self,
        dl: &mut Download,
        sink: &mut dyn Sink,
        tally: &mut Tally,
    ) -> Result<FetchOutcome, SyncError> {
        self.0.fetch(dl, sink, tally)
    }
}

/// Source qui échoue après avoir poussé toutes ses failles.
struct FailsBeforeCommit(OsvSource);

impl VulnSource for FailsBeforeCommit {
    fn id(&self) -> &'static str {
        self.0.id()
    }
    fn meta(&self) -> SourceMeta {
        self.0.meta()
    }
    fn fetch(
        &self,
        dl: &mut Download,
        sink: &mut dyn Sink,
        tally: &mut Tally,
    ) -> Result<FetchOutcome, SyncError> {
        self.0.fetch(dl, sink, tally)?;
        Err(SyncError::Io("échec simulé".into()))
    }
}

#[test]
fn an_etag_is_never_written_without_its_generation() {
    let env = Env::new(&["osv-crates-io"]);
    env.server
        .route(CRATES, Reply::ok_etag(crates_zip(600), "\"c1\"", LM));
    let report = env.run_source(&FailsBeforeCommit(env.crates_only()));
    assert_eq!(report.outcome, Outcome::Failed);
    let state = env.state("osv-crates-io");
    assert_eq!(state.etag, None);
    assert_eq!(state.http_last_modified, None);
    assert_eq!(state.dump_sha256, None);
    assert_eq!(state.active_generation, 0);
    assert_eq!(state.loading_since, None, "bail rendu");
    assert_eq!(active_count(&env.store(), "osv-crates-io").unwrap(), 0);
    // La génération orpheline est purgée au chargement suivant.
    env.clock.advance(60);
    env.run(None, false);
    let state = env.state("osv-crates-io");
    assert_eq!(
        generations(&env.store(), "osv-crates-io").unwrap(),
        [state.active_generation]
    );
}

// --- Seuil d'écart ---

fn with_bad(n: usize, bad: usize, body: impl Fn(usize) -> String) -> Vec<u8> {
    zip_of(
        (0..n)
            .map(|i| crate_entry(i, if i < bad { body(i) } else { crate_record(i) }))
            .collect(),
    )
}

#[test]
fn half_a_percent_of_bad_json_is_loaded_and_counted() {
    let env = Env::new(&["osv-crates-io"]);
    env.server.route(
        CRATES,
        Reply::ok(with_bad(1000, 5, |_| "{pas du json".into())),
    );
    let report = env.run(None, false);
    assert_eq!(outcomes(&report), [("osv-crates-io", Outcome::Loaded)]);
    let source = &vigie::vulns::store::sources(&env.store()).unwrap()[0];
    assert_eq!(source.dropped_detail.get("bad_json"), Some(&5));
    assert_eq!(source.entries, 995);
}

#[test]
fn two_percent_of_bad_json_fails_with_the_counters() {
    let env = Env::new(&["osv-crates-io"]);
    env.server.route(
        CRATES,
        Reply::ok(with_bad(1000, 20, |_| "{pas du json".into())),
    );
    let report = env.run(None, false);
    assert_eq!(report.failures(), 1);
    let state = env.state("osv-crates-io");
    assert_eq!(state.active_generation, 0);
    let err = state.last_error.unwrap();
    assert!(err.contains("bad_json 20"), "{err}");
    assert!(err.contains("taux d'écart 2.00 %"), "{err}");
}

#[test]
fn notes_and_normal_exclusions_never_count() {
    let env = Env::new(&["osv-crates-io"]);
    // 5 % de références refusées, 10 % de retraits, 5 % d'autres écosystèmes.
    let zip = zip_of(
        (0..1000)
            .map(|i| {
                let body = match i {
                    0..50 => crate_record(i).replace(
                        r#""modified""#,
                        r#""references":[{"type":"WEB","url":"javascript:alert(1)"}],"modified""#,
                    ),
                    50..150 => crate_record(i).replace(
                        r#""modified""#,
                        r#""withdrawn":"2026-10-02T00:00:00Z","modified""#,
                    ),
                    150..200 => crate_record(i).replace(r#""crates.io""#, r#""PyPI""#),
                    _ => crate_record(i),
                };
                crate_entry(i, body)
            })
            .collect(),
    );
    env.server.route(CRATES, Reply::ok(zip));
    let report = env.run(None, false);
    assert_eq!(
        outcomes(&report),
        [("osv-crates-io", Outcome::Loaded)],
        "{report:?}"
    );
    let source = &vigie::vulns::store::sources(&env.store()).unwrap()[0];
    assert_eq!(source.dropped_detail.get("bad_reference"), Some(&50));
    assert_eq!(source.dropped_detail.get("withdrawn"), Some(&100));
    assert_eq!(
        source.dropped_detail.get("no_affected_out_of_scope"),
        Some(&50)
    );
    assert_eq!(source.dropped, 0);
    assert!(!Reason::BadReference.is_drop() && !Reason::Withdrawn.is_drop());
}

// --- Rétrécissement ---

fn serve_crates(env: &Env, n: usize) -> SyncReport {
    env.server.route(CRATES, Reply::ok(crates_zip(n)));
    env.clock.advance(86_400);
    env.run(None, false)
}

#[test]
fn a_shrunk_dump_is_refused_and_the_active_set_kept() {
    let env = Env::new(&["osv-crates-io"]);
    serve_crates(&env, 1000);
    let report = serve_crates(&env, 10);
    assert_eq!(
        outcomes(&report),
        [("osv-crates-io", Outcome::RefusedShrink)]
    );
    assert_eq!(report.failures(), 1);
    let state = env.state("osv-crates-io");
    assert_eq!(state.last_outcome, Some(Outcome::RefusedShrink));
    assert_eq!(active_count(&env.store(), "osv-crates-io").unwrap(), 1000);
    assert!(state.last_error.unwrap().contains("--accept-shrink"));
}

#[test]
fn shrinking_by_steps_is_refused_against_the_recent_maximum() {
    let env = Env::new(&["osv-crates-io"]);
    serve_crates(&env, 1000);
    assert_eq!(serve_crates(&env, 850).sources[0].outcome, Outcome::Loaded);
    assert_eq!(
        serve_crates(&env, 700).sources[0].outcome,
        Outcome::RefusedShrink
    );
}

#[test]
fn accept_shrink_resets_the_reference() {
    let env = Env::new(&["osv-crates-io"]);
    serve_crates(&env, 1000);
    env.server.route(CRATES, Reply::ok(crates_zip(500)));
    env.clock.advance(86_400);
    let report = env.run(Some("osv-crates-io"), true);
    assert_eq!(outcomes(&report), [("osv-crates-io", Outcome::Loaded)]);
    assert_eq!(env.state("osv-crates-io").recent_entries, [500]);
    // Le lendemain, sans option : 500 est la référence.
    env.server.route(CRATES, Reply::ok(crates_zip(499)));
    env.clock.advance(86_400);
    assert_eq!(env.run(None, false).sources[0].outcome, Outcome::Loaded);
}

// --- Débit et concurrence ---

#[test]
fn a_lease_held_elsewhere_gives_busy_without_any_request() {
    let env = Env::all();
    let mut other = env.store();
    vigie::vulns::store::upsert_source(
        &mut other,
        &vigie::vulns::store::SourceMeta {
            id: "osv-npm".into(),
            url: String::new(),
            license: String::new(),
            attribution: String::new(),
        },
    )
    .unwrap();
    let held = Load::begin(&mut other, "osv-npm", &env.clock, LEASE).unwrap();
    let report = env.run(Some("osv-npm"), false);
    assert_eq!(outcomes(&report), [("osv-npm", Outcome::Busy)]);
    assert_eq!(report.failures(), 0);
    assert_eq!(env.server.requests(), 0);
    drop(held);
}

/// Source qui avance l'horloge au-delà du bail avant de pousser.
struct Slowpoke<'c> {
    inner: OsvSource,
    clock: &'c FakeClock,
}

impl VulnSource for Slowpoke<'_> {
    fn id(&self) -> &'static str {
        self.inner.id()
    }
    fn meta(&self) -> SourceMeta {
        self.inner.meta()
    }
    fn fetch(
        &self,
        dl: &mut Download,
        sink: &mut dyn Sink,
        tally: &mut Tally,
    ) -> Result<FetchOutcome, SyncError> {
        self.clock.advance(2 * 3600);
        self.inner.fetch(dl, sink, tally)
    }
}

#[test]
fn a_lease_lost_during_the_load_fails_without_mixing() {
    let (env, before, ids) = loaded_crates();
    env.server.route(CRATES, Reply::ok(crates_zip(7)));
    let report = env.run_source(&Slowpoke {
        inner: env.crates_only(),
        clock: &env.clock,
    });
    assert_eq!(report.outcome, Outcome::Failed, "{report:?}");
    assert!(
        report.line.contains("bail du chargement perdu"),
        "{}",
        report.line
    );
    assert_intact(&env, &before, &ids);
}

/// Source à débit propre (30 min entre deux requêtes).
struct Throttled(OsvSource);

impl VulnSource for Throttled {
    fn id(&self) -> &'static str {
        self.0.id()
    }
    fn meta(&self) -> SourceMeta {
        SourceMeta {
            min_interval: Duration::from_secs(1800),
            ..self.0.meta()
        }
    }
    fn fetch(
        &self,
        dl: &mut Download,
        sink: &mut dyn Sink,
        tally: &mut Tally,
    ) -> Result<FetchOutcome, SyncError> {
        self.0.fetch(dl, sink, tally)
    }
}

#[test]
fn the_rate_window_refuses_without_any_request() {
    let env = Env::new(&["osv-crates-io"]);
    env.server.route(CRATES, Reply::ok(real_crates()));
    let source = Throttled(env.crates_only());
    assert_eq!(env.run_source(&source).outcome, Outcome::Loaded);
    env.clock.advance(600);
    let report = env.run_source(&source);
    assert_eq!(report.outcome, Outcome::RateLimited);
    assert_eq!(env.server.requests(), 1);
    let state = env.state("osv-crates-io");
    assert_eq!(state.last_request_at, Some(T0), "jamais repoussée");
    assert_eq!(state.last_outcome, Some(Outcome::RateLimited));
    env.clock.advance(1200);
    assert_ne!(env.run_source(&source).outcome, Outcome::RateLimited);
    assert_eq!(env.server.requests(), 2);
}

#[test]
fn retry_after_is_honoured_and_not_a_failure() {
    let env = Env::new(&["osv-crates-io"]);
    env.server.route(
        CRATES,
        Reply::Status {
            code: 429,
            retry_after: Some("3600".into()),
        },
    );
    let report = env.run(None, false);
    assert_eq!(outcomes(&report), [("osv-crates-io", Outcome::RateLimited)]);
    assert_eq!(report.failures(), 0);
    assert_eq!(
        env.state("osv-crates-io").retry_after_until,
        Some(T0 + 3600)
    );
    env.server.route(CRATES, Reply::ok(real_crates()));
    env.clock.advance(600);
    let report = env.run(None, false);
    assert_eq!(outcomes(&report), [("osv-crates-io", Outcome::RateLimited)]);
    assert_eq!(env.server.requests(), 1);
    env.clock.advance(3000);
    assert_eq!(env.run(None, false).sources[0].outcome, Outcome::Loaded);
}

#[test]
fn a_source_not_ready_is_never_requested() {
    let env = Env::new(&["osv-crates-io"]);
    env.server.route(CRATES, Reply::ok(real_crates()));
    let report = env.run_source(&Waiting(env.crates_only()));
    assert_eq!(report.outcome, Outcome::Failed);
    assert_eq!(env.server.requests(), 0);
    let state = env.state("osv-crates-io");
    assert_eq!(state.last_request_at, None);
    assert_eq!(state.last_attempt_at, Some(T0));
    assert!(state.last_error.unwrap().contains("conditions non relues"));
}

#[test]
fn the_clock_is_the_only_time_source_of_the_state() {
    // Les dates écrites viennent de l'horloge injectée, pas du système.
    let env = Env::all();
    env.run(Some("osv-npm"), false);
    assert_eq!(env.state("osv-npm").last_attempt_at, Some(env.clock.unix()));
}
