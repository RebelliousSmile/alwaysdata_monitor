//! Sources KEV et EPSS dans le cadre F2 (#18, phase 3), contre le serveur
//! HTTPS local : les deux hôtes KEV sont distingués par leur chemin sous
//! la même origine épinglée. Succès, 304, même empreinte, `LOADER_VERSION`,
//! bail et débit, secours KEV (échec, 429, rétrécissement, régression de
//! `dateReleased`, `--accept-shrink`), fichiers hostiles, `Content-Encoding`
//! d'EPSS, constat `vulns-sync` à 3 jours. Fixtures fictives
//! (`CVE-2099-…`) ; gros fichiers et bombe gzip générés par le test. Aucun
//! réseau.

#[path = "support/dump_server.rs"]
mod dump_server;
#[path = "support/veilleur.rs"]
mod veilleur;

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use vigie::alert::MemoryNotifier;
use vigie::clock::FakeClock;
use vigie::config::{Config, Vulns};
use vigie::http::Trust;
use vigie::store::Store;
use vigie::tick::{self, Options};
use vigie::vulns::advisory::{Reason, Tally};
use vigie::vulns::enrich_store::{EnrichSource, StoreTables, active};
use vigie::vulns::exploit::{Cve, Exploitation};
use vigie::vulns::sources::epss::{self, EpssSource};
use vigie::vulns::sources::kev::{self, KevSource};
use vigie::vulns::store::{Outcome, SyncState, sync_state};
use vigie::vulns::sync::download::Download;
use vigie::vulns::sync::engine::sync_enrichment;
use vigie::vulns::sync::enrichment::{EnrichSink, EnrichmentSource};
use vigie::vulns::sync::{
    FetchOutcome, Limits, SourceMeta, SourceReport, SyncError, SyncOptions, SyncReport,
};

use dump_server::{DumpServer, Reply, Seen};

const T0: i64 = 1_800_000_000;
const LM: &str = "Sat, 17 Oct 2026 03:00:00 GMT";
const MIRROR: &str = "/cisagov/kev-data/main/known_exploited_vulnerabilities.json";
const CISA: &str = "/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS: &str = "/epss_scores-current.csv.gz";

fn fixture(rel: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/vulns")
            .join(rel),
    )
    .unwrap()
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(bytes).unwrap();
    gz.finish().unwrap()
}

/// Entrée KEV fictive `n`.
fn kev_entry(n: usize) -> serde_json::Value {
    serde_json::json!({
        "cveID": format!("CVE-2099-{:05}", 20_000 + n),
        "vendorProject": "Exemple",
        "product": format!("Produit fictif {n}"),
        "vulnerabilityName": format!("Exemple Produit fictif {n} : faille inventée"),
        "dateAdded": "2099-01-02",
        "shortDescription": "Description inventée.",
        "requiredAction": "Action inventée.",
        "dueDate": "2099-01-23",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": ""
    })
}

/// Catalogue KEV fictif de `entries`.
fn kev_doc(released: &str, entries: Vec<serde_json::Value>) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "title": "Catalogue fictif",
        "catalogVersion": &released[..10].replace('-', "."),
        "dateReleased": released,
        "count": entries.len(),
        "vulnerabilities": entries,
    }))
    .unwrap()
}

/// Catalogue de `n` entrées valides.
fn kev_n(released: &str, n: usize) -> Vec<u8> {
    kev_doc(released, (0..n).map(kev_entry).collect())
}

/// CSV EPSS fictif de `n` lignes.
fn epss_csv(n: usize) -> Vec<u8> {
    let mut out = String::from(
        "#model_version:v2099.01.01,score_date:2099-01-15T00:00:00+0000\ncve,epss,percentile\n",
    );
    for i in 0..n {
        out.push_str(&format!("CVE-2099-{:05},0.00{i:03},0.5\n", 30_000 + i));
    }
    out.into_bytes()
}

struct Env {
    _dir: tempfile::TempDir,
    server: DumpServer,
    config: Config,
    clock: FakeClock,
    limits: Option<Limits>,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut config = veilleur::config(dir.path().join("data").join("vigie.db"));
        config.sites.clear();
        config.vulns = Some(Vulns {
            sources: vec!["osv-crates-io".into()],
        });
        Self {
            _dir: dir,
            server: DumpServer::start(),
            config,
            clock: FakeClock::new(T0),
            limits: None,
        }
    }

    fn options(&self) -> SyncOptions {
        SyncOptions {
            trust: Trust::Custom(vec![self.server.ca.clone()]),
            endpoint_override: Some(self.server.base()),
            limits_override: self.limits.clone(),
            ..SyncOptions::default()
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

    fn kev(&self) -> Outcome {
        self.run(Some("kev"), false).sources[0].outcome
    }

    fn epss(&self) -> Outcome {
        self.run(Some("epss"), false).sources[0].outcome
    }

    fn run_source(&self, source: &dyn EnrichmentSource) -> SourceReport {
        let mut store = self.store();
        sync_enrichment(
            &mut store,
            self.config.database.parent().unwrap(),
            source,
            &self.options(),
            &self.clock,
            false,
        )
    }

    fn store(&self) -> Store {
        Store::open(&self.config.database).unwrap()
    }

    fn state(&self, id: &str) -> SyncState {
        sync_state(&self.store(), id).unwrap().expect("source")
    }

    fn url(&self, path: &str) -> String {
        self.server.url(path)
    }

    fn requests(&self, path: &str) -> Vec<Seen> {
        self.server
            .seen()
            .into_iter()
            .filter(|s| s.path == path)
            .collect()
    }

    fn kev_released(&self) -> Option<String> {
        active(&self.store(), EnrichSource::Kev)
            .unwrap()
            .map(|d| d.released.to_string())
    }

    fn kev_has(&self, cve: &str) -> bool {
        let store = self.store();
        StoreTables::open(&store)
            .unwrap()
            .kev(&Cve::parse(cve).unwrap())
            .is_some()
    }

    fn rows(&self, table: &str) -> i64 {
        rusqlite::Connection::open(&self.config.database)
            .unwrap()
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    /// Fixe `recent_entries` (garde contre le rétrécissement).
    fn set_recent(&self, id: &str, recent: &str) {
        rusqlite::Connection::open(&self.config.database)
            .unwrap()
            .execute(
                "UPDATE vuln_sources SET recent_entries = ?2 WHERE id = ?1",
                [id, recent],
            )
            .unwrap();
    }
}

fn failed_with(report: &SyncReport, want: &str) {
    let s = &report.sources[0];
    assert_eq!(s.outcome, Outcome::Failed, "{s:?}");
    assert!(s.line.contains(want), "{want} : {}", s.line);
}

// --- Configuration et ordre ---

#[test]
fn kev_and_epss_run_after_the_vulnerability_sources() {
    let env = Env::new();
    env.server
        .route(MIRROR, Reply::ok(fixture("kev/catalogue-n1.json")));
    env.server
        .route(EPSS, Reply::ok(gzip(&fixture("epss/scores.csv"))));
    let report = env.run(None, false);
    let ids: Vec<(&str, Outcome)> = report.sources.iter().map(|s| (s.id, s.outcome)).collect();
    // osv-crates-io sans route : 404, les suivantes continuent.
    assert_eq!(
        ids,
        [
            ("osv-crates-io", Outcome::Failed),
            ("kev", Outcome::Loaded),
            ("epss", Outcome::Loaded)
        ]
    );
    assert!(report.loaded(), "rapprochement F7 à refaire");
    assert_eq!(report.failures(), 1);
    for s in &report.sources {
        assert_eq!(s.line.lines().count(), 1, "{}", s.line);
    }
}

// --- Happy path ---

#[test]
fn kev_is_loaded_from_the_mirror_with_its_state() {
    let env = Env::new();
    env.server.route(
        MIRROR,
        Reply::ok_etag(fixture("kev/catalogue-n1.json"), "\"m1\"", LM),
    );
    assert_eq!(env.kev(), Outcome::Loaded);
    let st = env.state("kev");
    assert_eq!(st.entries, 4);
    assert_eq!(st.etag.as_deref(), Some("\"m1\""));
    assert_eq!(st.validator_url.as_deref(), Some(env.url(MIRROR).as_str()));
    assert_eq!(st.loader_version, Some(kev::LOADER_VERSION));
    let store = env.store();
    let set = active(&store, EnrichSource::Kev).unwrap().unwrap();
    assert_eq!(set.version, "2099.01.15");
    assert_eq!(set.released.to_string(), "2099-01-15T17:15:48.8752Z");
    let tables = StoreTables::open(&store).unwrap();
    let fact = tables.kev(&Cve::parse("CVE-2099-10001").unwrap()).unwrap();
    assert!(fact.known_ransomware);
    assert_eq!(fact.date_added.to_string(), "2099-01-02");
    let src = vigie::vulns::store::sources(&store).unwrap();
    let row = src.iter().find(|s| s.id == "kev").unwrap();
    assert_eq!(row.license, "CC0-1.0");
    assert!(row.attribution.contains("CISA KEV"));
    assert!(env.requests(CISA).is_empty());
}

#[test]
fn epss_is_loaded_in_millionths() {
    let env = Env::new();
    env.server.route(
        EPSS,
        Reply::ok_etag(gzip(&fixture("epss/scores.csv")), "\"e1\"", LM),
    );
    assert_eq!(env.epss(), Outcome::Loaded);
    let store = env.store();
    let tables = StoreTables::open(&store).unwrap();
    let e = tables.epss(&Cve::parse("CVE-2099-90001").unwrap()).unwrap();
    assert_eq!((e.epss_ppm, e.percentile_ppm), (12, 1_000));
    let state = tables.state().epss.unwrap();
    assert_eq!(state.version, "v2099.01.01");
    assert_eq!(state.released.to_string(), "2099-01-15T00:00:00Z");
    let src = vigie::vulns::store::sources(&store).unwrap();
    let row = src.iter().find(|s| s.id == "epss").unwrap();
    assert_eq!(row.entries, 4);
    assert_eq!(
        row.attribution,
        "FIRST EPSS, See EPSS at https://www.first.org/epss"
    );
}

// --- Idempotence et bail ---

#[test]
fn a_304_and_the_same_digest_write_nothing() {
    let env = Env::new();
    env.server.route(
        MIRROR,
        Reply::ok_etag(fixture("kev/catalogue-n1.json"), "\"m1\"", LM),
    );
    env.kev();
    let rows = env.rows("vuln_kev");
    env.clock.advance(60);
    assert_eq!(env.kev(), Outcome::NotModified);
    assert_eq!(
        env.requests(MIRROR)[1].header("if-none-match"),
        Some("\"m1\"")
    );
    assert_eq!(env.rows("vuln_kev"), rows);
    assert_eq!(env.state("kev").last_success_at, Some(T0 + 60));
    // Corps identique sans ETag : même empreinte.
    env.server
        .route(MIRROR, Reply::ok(fixture("kev/catalogue-n1.json")));
    env.clock.advance(60);
    assert_eq!(env.kev(), Outcome::Unchanged);
    let st = env.state("kev");
    assert_eq!((st.last_success_at, st.etag), (Some(T0 + 120), None));
    assert_eq!(env.rows("vuln_kev"), rows);
}

/// KEV sous un autre `LOADER_VERSION`.
struct Bumped;

impl EnrichmentSource for Bumped {
    fn id(&self) -> &'static str {
        "kev"
    }
    fn meta(&self) -> SourceMeta {
        SourceMeta {
            loader_version: 2,
            ..KevSource.meta()
        }
    }
    fn fetch(
        &self,
        dl: &mut Download,
        sink: &mut dyn EnrichSink,
        tally: &mut Tally,
    ) -> Result<FetchOutcome, SyncError> {
        KevSource.fetch(dl, sink, tally)
    }
}

#[test]
fn a_new_loader_version_reloads_without_conditionals() {
    let env = Env::new();
    env.server.route(
        MIRROR,
        Reply::ok_etag(fixture("kev/catalogue-n1.json"), "\"m1\"", LM),
    );
    env.kev();
    let report = env.run_source(&Bumped);
    assert_eq!(report.outcome, Outcome::Loaded, "{report:?}");
    assert_eq!(env.requests(MIRROR)[1].header("if-none-match"), None);
    assert_eq!(env.state("kev").loader_version, Some(2));
}

#[test]
fn a_held_lease_or_a_retry_after_sends_no_request() {
    let env = Env::new();
    env.server
        .route(MIRROR, Reply::ok(fixture("kev/catalogue-n1.json")));
    env.kev();
    env.server.reset();
    let conn = rusqlite::Connection::open(&env.config.database).unwrap();
    conn.execute(
        "UPDATE vuln_sources SET loading_generation = next_generation - 1,
             loading_since = ?1 WHERE id = 'kev'",
        [T0],
    )
    .unwrap();
    assert_eq!(env.kev(), Outcome::Busy);
    conn.execute(
        "UPDATE vuln_sources SET loading_generation = NULL, loading_since = NULL,
             retry_after_until = ?1 WHERE id = 'kev'",
        [T0 + 3_600],
    )
    .unwrap();
    assert_eq!(env.kev(), Outcome::RateLimited);
    assert_eq!(env.server.requests(), 0);
}

// --- Secours KEV ---

#[test]
fn a_failing_mirror_falls_back_to_cisa_without_its_validators() {
    let env = Env::new();
    env.server.route(
        MIRROR,
        Reply::ok_etag(fixture("kev/catalogue-n.json"), "\"m1\"", LM),
    );
    env.kev();
    env.server.route(
        MIRROR,
        Reply::Status {
            code: 500,
            retry_after: None,
        },
    );
    env.server.route(
        CISA,
        Reply::ok_etag(fixture("kev/catalogue-n1.json"), "\"c1\"", LM),
    );
    env.clock.advance(60);
    assert_eq!(env.kev(), Outcome::Loaded);
    let cisa = env.requests(CISA);
    assert_eq!(cisa[0].header("if-none-match"), None, "ETag du miroir");
    assert_eq!(
        env.state("kev").validator_url.as_deref(),
        Some(env.url(CISA).as_str())
    );
    assert!(env.kev_has("CVE-2099-90001"));
    // Miroir rétabli : requête inconditionnelle (autre URL que les
    // validateurs), N+1 à jour.
    env.server.route(
        MIRROR,
        Reply::ok_etag(fixture("kev/catalogue-n1.json"), "\"m2\"", LM),
    );
    env.clock.advance(60);
    env.server.reset();
    assert_eq!(env.kev(), Outcome::Unchanged, "même empreinte");
    assert_eq!(env.requests(MIRROR)[0].header("if-none-match"), None);
    assert_eq!(
        env.state("kev").validator_url.as_deref(),
        Some(env.url(MIRROR).as_str())
    );
}

#[test]
fn a_429_on_the_mirror_does_not_deprive_of_the_fallback() {
    let env = Env::new();
    env.server.route(
        MIRROR,
        Reply::Status {
            code: 429,
            retry_after: Some("3600".into()),
        },
    );
    env.server
        .route(CISA, Reply::ok(fixture("kev/catalogue-n1.json")));
    assert_eq!(env.kev(), Outcome::Loaded);
    assert_eq!(env.state("kev").retry_after_until, None);
    // Les deux en 429 : Retry-After écrit par le moteur.
    env.server.route(
        CISA,
        Reply::Status {
            code: 429,
            retry_after: Some("3600".into()),
        },
    );
    env.clock.advance(60);
    assert_eq!(env.kev(), Outcome::RateLimited);
    assert_eq!(env.state("kev").retry_after_until, Some(T0 + 60 + 3_600));
    assert!(env.kev_has("CVE-2099-90001"), "actif intact");
}

#[test]
fn a_shrunk_mirror_falls_back_and_both_shrunk_are_refused_once() {
    let env = Env::new();
    env.server
        .route(MIRROR, Reply::ok(kev_n("2099-01-15T00:00:00Z", 200)));
    env.kev();
    env.set_recent("kev", "[200]");
    // 70 % du maximum sur le miroir, cisa.gov complet.
    env.server
        .route(MIRROR, Reply::ok(kev_n("2099-01-16T00:00:00Z", 140)));
    env.server
        .route(CISA, Reply::ok(kev_n("2099-01-16T00:00:00Z", 210)));
    env.clock.advance(60);
    assert_eq!(env.kev(), Outcome::Loaded);
    assert_eq!(env.state("kev").entries, 210);
    // Les deux rétrécis.
    env.server
        .route(CISA, Reply::ok(kev_n("2099-01-17T00:00:00Z", 150)));
    env.server
        .route(MIRROR, Reply::ok(kev_n("2099-01-17T00:00:00Z", 140)));
    env.clock.advance(60);
    let before = env.state("kev");
    assert_eq!(env.kev(), Outcome::RefusedShrink);
    let st = env.state("kev");
    assert_eq!(st.recent_entries, before.recent_entries, "pas réécrit");
    assert_eq!(st.entries, 210);
    assert!(st.last_error.unwrap().contains("--accept-shrink"));
    // --accept-shrink : cisa.gov demandé d'abord, jeu accepté.
    env.server.reset();
    env.clock.advance(60);
    let report = env.run(Some("kev"), true);
    assert_eq!(report.sources[0].outcome, Outcome::Loaded, "{report:?}");
    assert_eq!(env.server.seen()[0].path, CISA);
    assert_eq!(env.state("kev").recent_entries, [150]);
}

#[test]
fn an_older_mirror_is_refused_and_counted_stale() {
    let env = Env::new();
    // N+1 actif, servi par cisa.gov.
    env.server.route(
        MIRROR,
        Reply::Status {
            code: 500,
            retry_after: None,
        },
    );
    env.server.route(
        CISA,
        Reply::ok_etag(fixture("kev/catalogue-n1.json"), "\"c1\"", LM),
    );
    env.kev();
    // Miroir en retard (N), cisa.gov N+1 sans ETag : même empreinte.
    env.server
        .route(MIRROR, Reply::ok(fixture("kev/catalogue-n.json")));
    env.server
        .route(CISA, Reply::ok(fixture("kev/catalogue-n1.json")));
    env.clock.advance(60);
    assert_eq!(env.kev(), Outcome::Unchanged);
    assert_eq!(env.state("kev").stale_count, 0);
    // Les deux en N : inchangé (périmé), validateurs de l'actif intacts.
    env.server.route(
        CISA,
        Reply::ok_etag(fixture("kev/catalogue-n.json"), "\"c0\"", LM),
    );
    let before = env.state("kev");
    env.clock.advance(60);
    let report = env.run(Some("kev"), false);
    assert_eq!(report.sources[0].outcome, Outcome::Unchanged, "{report:?}");
    assert!(report.sources[0].line.contains("plus ancien"));
    let st = env.state("kev");
    assert_eq!(st.stale_count, 1);
    assert_eq!(st.etag, before.etag);
    assert_eq!(st.validator_url, before.validator_url);
    assert_eq!(st.last_success_at, Some(T0 + 120));
    assert_eq!(
        env.kev_released().as_deref(),
        Some("2099-01-15T17:15:48.8752Z")
    );
    assert!(env.kev_has("CVE-2099-90001"));
    // Avec --accept-shrink : cisa.gov d'abord, N chargé.
    env.clock.advance(60);
    env.server.reset();
    let report = env.run(Some("kev"), true);
    assert_eq!(report.sources[0].outcome, Outcome::Loaded, "{report:?}");
    assert_eq!(env.server.seen()[0].path, CISA);
    assert!(!env.kev_has("CVE-2099-90001"));
}

#[test]
fn the_same_second_with_another_fraction_is_not_a_regression() {
    let env = Env::new();
    env.server
        .route(MIRROR, Reply::ok(kev_n("2099-01-15T10:00:00.900Z", 3)));
    env.kev();
    env.server
        .route(MIRROR, Reply::ok(kev_n("2099-01-15T10:00:00.100Z", 4)));
    env.clock.advance(60);
    assert_eq!(env.kev(), Outcome::Loaded);
    assert_eq!(env.state("kev").entries, 4);
}

#[test]
fn both_hosts_failing_keep_the_active_set() {
    let env = Env::new();
    env.server
        .route(MIRROR, Reply::ok(fixture("kev/catalogue-n1.json")));
    env.kev();
    for path in [MIRROR, CISA] {
        env.server.route(
            path,
            Reply::Status {
                code: 500,
                retry_after: None,
            },
        );
    }
    env.clock.advance(60);
    let report = env.run(Some("kev"), false);
    failed_with(&report, "statut HTTP 500");
    assert_eq!(report.failures(), 1);
    assert!(env.kev_has("CVE-2099-90001"));
}

#[test]
fn a_redirect_outside_the_pinned_origin_is_refused() {
    let env = Env::new();
    for path in [MIRROR, CISA] {
        env.server.route(
            path,
            Reply::Redirect("https://kev.example.org/kev.json".into()),
        );
    }
    failed_with(&env.run(Some("kev"), false), "origine non admise");
}

// --- KEV hostile ---

#[test]
fn hostile_entries_are_dropped_and_counted() {
    let catalog = kev::parse(&fixture("kev/hostile.json")).unwrap();
    let t = &catalog.tally;
    for (reason, n) in [
        (Reason::BadCve, 1),
        (Reason::BadDate, 1),
        (Reason::MissingField, 1),
        (Reason::Duplicate, 1),
        (Reason::UnknownRansomware, 1),
        (Reason::CountMismatch, 1),
    ] {
        assert_eq!(t.get(reason), n, "{reason:?}");
    }
    // Champ inconnu ignoré, rançongiciel inattendu lu « non ».
    assert_eq!(catalog.rows.len(), 3);
    assert_eq!(catalog.entries, 7);
    // 4 écartées sur 7 : bien au-delà du seuil, sur les deux hôtes.
    let env = Env::new();
    env.server
        .route(MIRROR, Reply::ok(fixture("kev/hostile.json")));
    env.server
        .route(CISA, Reply::ok(fixture("kev/hostile.json")));
    failed_with(&env.run(Some("kev"), false), "écartées");
}

#[test]
fn notes_and_a_few_drops_are_loaded_and_counted() {
    let env = Env::new();
    let mut entries: Vec<_> = (0..1_000).map(kev_entry).collect();
    // 5 écarts sur 1 000 (0,5 %), un rançongiciel inattendu, count faux.
    for e in entries.iter_mut().take(5) {
        e["cveID"] = "CVE-99-1".into();
    }
    entries[10]["knownRansomwareCampaignUse"] = "Peut-être".into();
    let mut doc: serde_json::Value =
        serde_json::from_slice(&kev_doc("2099-01-15T00:00:00Z", entries)).unwrap();
    doc["count"] = 1_001.into();
    env.server
        .route(MIRROR, Reply::ok(serde_json::to_vec(&doc).unwrap()));
    let report = env.run(Some("kev"), false);
    assert_eq!(report.sources[0].outcome, Outcome::Loaded, "{report:?}");
    let src = vigie::vulns::store::sources(&env.store()).unwrap();
    let row = src.iter().find(|s| s.id == "kev").unwrap();
    assert_eq!(row.entries, 995);
    assert_eq!(row.dropped, 5);
    assert_eq!(row.dropped_detail.get("unknown_ransomware"), Some(&1));
    assert_eq!(row.dropped_detail.get("count_mismatch"), Some(&1));
}

#[test]
fn two_percent_of_drops_fail() {
    let env = Env::new();
    let mut entries: Vec<_> = (0..1_000).map(kev_entry).collect();
    for e in entries.iter_mut().take(20) {
        e["dateAdded"] = "hier".into();
    }
    let doc = kev_doc("2099-01-15T00:00:00Z", entries);
    env.server.route(MIRROR, Reply::ok(doc.clone()));
    env.server.route(CISA, Reply::ok(doc));
    failed_with(&env.run(Some("kev"), false), "écartées");
}

#[test]
fn truncated_or_oversized_documents_fail_on_both_hosts() {
    let env = Env::new();
    let mut doc = fixture("kev/catalogue-n1.json");
    doc.truncate(doc.len() / 2);
    env.server.route(MIRROR, Reply::ok(doc.clone()));
    env.server.route(CISA, Reply::ok(doc));
    failed_with(&env.run(Some("kev"), false), "JSON KEV illisible");
    let big = vec![b' '; 17 * 1024 * 1024];
    env.server.route(MIRROR, Reply::ok(big.clone()));
    env.server.route(CISA, Reply::ok(big));
    env.clock.advance(60);
    failed_with(&env.run(Some("kev"), false), "plafond dépassé");
}

// --- EPSS hostile ---

#[test]
fn a_broken_comment_or_header_fails() {
    let env = Env::new();
    env.server.route(
        EPSS,
        Reply::ok(gzip(b"cve,epss,percentile\nCVE-2099-30000,0.1,0.1\n")),
    );
    failed_with(&env.run(Some("epss"), false), "#model_version");
    env.server.route(
        EPSS,
        Reply::ok(gzip(
            b"#model_version:v1,score_date:2099-01-15\ncve,epss,score\n",
        )),
    );
    env.clock.advance(60);
    failed_with(&env.run(Some("epss"), false), "en-tête");
}

#[test]
fn crlf_and_a_final_blank_line_are_read() {
    let env = Env::new();
    let csv = String::from_utf8(fixture("epss/scores.csv"))
        .unwrap()
        .replace('\n', "\r\n")
        + "\r\n";
    env.server.route(EPSS, Reply::ok(gzip(csv.as_bytes())));
    assert_eq!(env.epss(), Outcome::Loaded);
    assert_eq!(env.state("epss").entries, 4);
}

#[test]
fn bad_lines_are_dropped_and_counted() {
    let env = Env::new();
    let mut csv = String::from_utf8(epss_csv(1_000)).unwrap();
    csv.push_str("CVE-2099-40000,1.5,0.1\nCVE-2099-40001,-0.1,0.1\nCVE-99-1,0.1,0.1\n");
    env.server.route(EPSS, Reply::ok(gzip(csv.as_bytes())));
    assert_eq!(env.epss(), Outcome::Loaded);
    let src = vigie::vulns::store::sources(&env.store()).unwrap();
    let row = src.iter().find(|s| s.id == "epss").unwrap();
    assert_eq!((row.entries, row.dropped), (1_000, 3));
    assert_eq!(row.dropped_detail.get("bad_value"), Some(&2));
    assert_eq!(row.dropped_detail.get("bad_cve"), Some(&1));
}

#[test]
fn an_endless_line_stops_at_128_bytes() {
    let env = Env::new();
    let mut csv = epss_csv(2);
    csv.extend(vec![b'1'; 10_000]);
    env.server.route(EPSS, Reply::ok(gzip(&csv)));
    failed_with(&env.run(Some("epss"), false), "128 octets");
}

#[test]
fn a_gzip_bomb_stops_at_the_unpacked_cap() {
    let mut env = Env::new();
    // Plafond décompressé réduit ; lignes de 127 octets, écartées sans
    // base : seule la taille compte.
    let mut limits = epss::limits();
    limits.unpacked = 8 * 1024 * 1024;
    limits.entries = u64::MAX;
    env.limits = Some(limits.clone());
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&epss_csv(0)).unwrap();
    let line = [b"x".repeat(126), b"\n".to_vec()].concat();
    let mut written = 0;
    while written <= limits.unpacked {
        gz.write_all(&line).unwrap();
        written += line.len() as u64;
    }
    let bomb = gz.finish().unwrap();
    assert!(bomb.len() < 1024 * 1024);
    env.server.route(EPSS, Reply::ok(bomb));
    failed_with(&env.run(Some("epss"), false), "EPSS décompressé");
    assert_eq!(epss::limits().unpacked, 64 * 1024 * 1024);
}

#[test]
fn two_gzip_members_are_read_whole() {
    let env = Env::new();
    let csv = epss_csv(10);
    let (a, b) = csv.split_at(csv.len() / 2);
    let mut both = gzip(a);
    both.extend(gzip(b));
    env.server.route(EPSS, Reply::ok(both));
    assert_eq!(env.epss(), Outcome::Loaded);
    assert_eq!(env.state("epss").entries, 10);
}

#[test]
fn a_shrunk_epss_is_refused_after_the_drop_threshold() {
    let env = Env::new();
    env.server.route(EPSS, Reply::ok(gzip(&epss_csv(200))));
    env.epss();
    env.set_recent("epss", "[200]");
    env.server.route(EPSS, Reply::ok(gzip(&epss_csv(140))));
    env.clock.advance(60);
    assert_eq!(env.epss(), Outcome::RefusedShrink);
    let st = env.state("epss");
    assert_eq!(st.entries, 200);
    assert_eq!(st.loading_since, None, "génération abandonnée");
    // Un taux d'écart dépassé l'emporte sur le rétrécissement.
    let mut csv = String::from_utf8(epss_csv(140)).unwrap();
    csv.push_str(&"CVE-99-1,0.1,0.1\n".repeat(10));
    env.server.route(EPSS, Reply::ok(gzip(csv.as_bytes())));
    env.clock.advance(60);
    failed_with(&env.run(Some("epss"), false), "taux d'écart");
}

#[test]
fn content_encoding_gzip_is_kept_raw_and_br_refused() {
    let env = Env::new();
    let body = gzip(&fixture("epss/scores.csv"));
    env.server.route(
        EPSS,
        Reply::Ok {
            body: std::sync::Arc::new(body.clone()),
            etag: None,
            last_modified: None,
            content_encoding: Some("gzip".into()),
        },
    );
    assert_eq!(env.epss(), Outcome::Loaded);
    let st = env.state("epss");
    let sha: String = <sha2::Sha256 as sha2::Digest>::digest(&body)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        st.dump_sha256.as_deref(),
        Some(sha.as_str()),
        "octets bruts"
    );
    env.server.route(
        EPSS,
        Reply::Ok {
            body: std::sync::Arc::new(body),
            etag: None,
            last_modified: None,
            content_encoding: Some("br".into()),
        },
    );
    env.clock.advance(60);
    failed_with(&env.run(Some("epss"), false), "encodage de contenu");
    // KEV n'admet aucun encodage, sur aucun de ses hôtes.
    for path in [MIRROR, CISA] {
        env.server.route(
            path,
            Reply::Ok {
                body: std::sync::Arc::new(gzip(&fixture("kev/catalogue-n1.json"))),
                etag: None,
                last_modified: None,
                content_encoding: Some("gzip".into()),
            },
        );
    }
    failed_with(&env.run(Some("kev"), false), "encodage de contenu");
}

// --- Constats ---

#[test]
fn a_failing_epss_opens_vulns_sync_after_3_days_and_a_success_closes_it() {
    let env = Env::new();
    let mail = MemoryNotifier::new();
    let tick = |now: i64| {
        tick::run_with(&env.config, now, &Options::default(), &mail).unwrap();
        mail.take();
    };
    let open = || -> Vec<String> {
        env.store()
            .open_incidents()
            .unwrap()
            .into_iter()
            .map(|i| i.key)
            .collect()
    };
    env.server
        .route(MIRROR, Reply::ok(fixture("kev/catalogue-n1.json")));
    env.kev();
    tick(T0);
    env.server.route(
        EPSS,
        Reply::Status {
            code: 500,
            retry_after: None,
        },
    );
    assert_eq!(env.epss(), Outcome::Failed);
    tick(T0 + 3 * 86_400);
    assert!(!open().iter().any(|k| k.ends_with("/epss")));
    // KEV réussi (même empreinte) : aucun constat.
    env.clock.set(T0 + 3 * 86_400);
    assert_eq!(env.kev(), Outcome::Unchanged);
    tick(T0 + 3 * 86_400 + 1);
    let keys = open();
    assert!(
        keys.contains(&"_veilleur/vulns-sync/epss".to_owned()),
        "{keys:?}"
    );
    assert!(
        !keys.contains(&"_veilleur/vulns-sync/kev".to_owned()),
        "{keys:?}"
    );
    env.clock.set(T0 + 3 * 86_400 + 2);
    env.server
        .route(EPSS, Reply::ok(gzip(&fixture("epss/scores.csv"))));
    assert_eq!(env.epss(), Outcome::Loaded);
    tick(T0 + 3 * 86_400 + 3);
    assert!(!open().contains(&"_veilleur/vulns-sync/epss".to_owned()));
}

// --- Réseau ---

#[test]
fn hosts_are_hard_coded_https_origins() {
    for (meta, hosts) in [
        (
            KevSource.meta(),
            &["raw.githubusercontent.com", "www.cisa.gov"][..],
        ),
        (
            EpssSource.meta(),
            &["epss.empiricalsecurity.com", "epss.cyentia.com"][..],
        ),
    ] {
        let listed: Vec<&str> = meta.origins.iter().map(|(h, _)| *h).collect();
        assert_eq!(listed, hosts);
        assert!(meta.origins.iter().all(|(_, port)| *port == 443));
        let url = url::Url::parse(meta.url).unwrap();
        assert_eq!(url.scheme(), "https");
        assert!(hosts.contains(&url.host_str().unwrap()));
        assert_eq!(meta.min_interval, Duration::ZERO);
        assert_eq!(meta.loader_version, 1);
    }
    for raw in [kev::MIRROR_URL, kev::CISA_URL] {
        let url = url::Url::parse(raw).unwrap();
        assert!(
            KevSource
                .meta()
                .origins
                .iter()
                .any(|(h, _)| Some(*h) == url.host_str())
        );
    }
    assert_eq!(EpssSource.meta().raw_content_encodings, ["gzip"]);
    assert!(KevSource.meta().raw_content_encodings.is_empty());
}
