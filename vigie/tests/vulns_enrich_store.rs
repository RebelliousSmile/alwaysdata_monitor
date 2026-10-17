//! Stockage KEV et EPSS par générations (#18, phase 2) : chargement et
//! lecture par `StoreTables` (connexion de lecture comprise), montée de
//! gravité entre deux générations, bail, compare-and-swap,
//! `finish_unchanged` (jeu périmé compris), purge par clé, validateurs
//! liés à leur URL. CVE fictifs `CVE-2099-…` seulement.

use jiff::civil::date;

use vigie::clock::FakeClock;
use vigie::finding::Severity;
use vigie::store::Store;
use vigie::vulns::advisory::{Reason, Tally};
use vigie::vulns::enrich_store::{
    DatasetHeader, ENRICH_BATCH, EnrichLoad, EnrichSource, EpssRow, KevRow, StoreTables, active,
    datasets,
};
use vigie::vulns::exploit::{Cve, Exploitation, KevFact};
use vigie::vulns::severity::{AdvisoryFacts, Rule, assess};
use vigie::vulns::store::{
    LEASE, LoadError, Outcome, PURGE_BATCH, SourceMeta, SyncMeta, Validators, sync_state,
    upsert_source,
};

const T0: i64 = 1_800_000_000;
const MIRROR: &str = "https://mirror.example.org/kev.json";
const CANONICAL: &str = "https://canonical.example.org/kev.json";

fn setup() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vigie.db");
    let mut store = Store::open(&path).unwrap();
    for id in ["kev", "epss"] {
        upsert_source(
            &mut store,
            &SourceMeta {
                id: id.into(),
                url: format!("https://{id}.example.org/"),
                license: "fictive".into(),
                attribution: "fictive".into(),
            },
        )
        .unwrap();
    }
    (dir, path)
}

fn cve(n: usize) -> Cve {
    Cve::parse(&format!("CVE-2099-{n:05}")).unwrap()
}

fn kev_row(n: usize, ransomware: bool) -> KevRow {
    KevRow {
        cve: cve(n),
        fact: KevFact {
            date_added: date(2099, 1, 10),
            due_date: date(2099, 1, 31),
            known_ransomware: ransomware,
            name: format!("Faille fictive {n}"),
        },
    }
}

fn epss_rows(range: std::ops::Range<usize>, ppm: u32) -> Vec<(Cve, EpssRow)> {
    range
        .map(|n| {
            (
                cve(n),
                EpssRow {
                    epss_ppm: ppm,
                    percentile_ppm: ppm / 2,
                },
            )
        })
        .collect()
}

fn header(version: &str) -> DatasetHeader {
    DatasetHeader {
        version: version.into(),
        released: "2099-01-15T17:15:48.8752Z".parse().unwrap(),
    }
}

fn load_kev(store: &mut Store, clock: &FakeClock, rows: &[KevRow], version: &str) -> i64 {
    let mut load = EnrichLoad::begin(store, EnrichSource::Kev, clock, LEASE).unwrap();
    load.push_kev(rows).unwrap();
    load.commit(&header(version), &Tally::default(), &SyncMeta::default())
        .unwrap()
        .generation
}

fn load_epss(store: &mut Store, clock: &FakeClock, rows: &[(Cve, EpssRow)]) -> i64 {
    let mut load = EnrichLoad::begin(store, EnrichSource::Epss, clock, LEASE).unwrap();
    load.push_epss(rows).unwrap();
    load.commit(
        &header("v2099.01.01"),
        &Tally::default(),
        &SyncMeta::default(),
    )
    .unwrap()
    .generation
}

fn sql(path: &std::path::Path) -> rusqlite::Connection {
    rusqlite::Connection::open(path).unwrap()
}

/// Génération de chaque ligne d'une table.
fn rows(path: &std::path::Path, table: &str) -> Vec<i64> {
    let conn = sql(path);
    let mut stmt = conn
        .prepare(&format!(
            "SELECT generation FROM {table} ORDER BY generation"
        ))
        .unwrap();
    stmt.query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

// --- Happy path ---

#[test]
fn kev_and_epss_are_loaded_and_read() {
    let (_dir, path) = setup();
    let mut store = Store::open(&path).unwrap();
    let clock = FakeClock::new(T0);
    let kev = load_kev(
        &mut store,
        &clock,
        &[kev_row(1, true), kev_row(2, false), kev_row(3, false)],
        "2099.01.15",
    );
    let epss = load_epss(&mut store, &clock, &epss_rows(1..4, 123_456));
    let tables = StoreTables::open(&store).unwrap();
    let fact = tables.kev(&cve(1)).unwrap();
    assert_eq!(
        (fact.date_added, fact.due_date, fact.known_ransomware),
        (date(2099, 1, 10), date(2099, 1, 31), true)
    );
    assert_eq!(fact.name, "Faille fictive 1");
    assert!(!tables.kev(&cve(2)).unwrap().known_ransomware);
    assert_eq!(tables.kev(&cve(4)), None);
    let e = tables.epss(&cve(3)).unwrap();
    assert_eq!(
        (e.generation, e.epss_ppm, e.percentile_ppm),
        (epss, 123_456, 61_728)
    );
    assert_eq!(tables.epss(&cve(4)), None);
    let state = tables.state();
    let k = state.kev.unwrap();
    assert_eq!((k.generation, k.version.as_str()), (kev, "2099.01.15"));
    assert_eq!(k.released.to_string(), "2099-01-15T17:15:48.8752Z");
    assert_eq!(state.epss.unwrap().version, "v2099.01.01");
    let sets = datasets(&store).unwrap();
    assert_eq!(sets.len(), 2);
    assert_eq!(sets[0].1.rows, 3);
    assert_eq!(sync_state(&store, "kev").unwrap().unwrap().entries, 3);
}

#[test]
fn store_tables_work_on_a_read_only_connection() {
    let (_dir, path) = setup();
    let mut store = Store::open(&path).unwrap();
    let clock = FakeClock::new(T0);
    load_kev(&mut store, &clock, &[kev_row(1, false)], "2099.01.15");
    load_epss(&mut store, &clock, &epss_rows(1..3, 400_000));
    let reader = Store::open_read(&path).unwrap().unwrap();
    let read = StoreTables::open(&reader).unwrap();
    let write = StoreTables::open(&store).unwrap();
    for n in 1..4 {
        assert_eq!(read.kev(&cve(n)), write.kev(&cve(n)));
        assert_eq!(read.epss(&cve(n)), write.epss(&cve(n)));
    }
    assert_eq!(read.state(), write.state());
    // Le cache rend la même chose.
    assert_eq!(read.epss(&cve(1)).unwrap().epss_ppm, 400_000);
}

#[test]
fn a_new_kev_generation_raises_the_severity() {
    let (_dir, path) = setup();
    let mut store = Store::open(&path).unwrap();
    let clock = FakeClock::new(T0);
    let facts = AdvisoryFacts {
        id: "GHSA-ex18-ex18-ex18".into(),
        cves: vec![Cve::parse("CVE-2099-90001").unwrap()],
        malicious: false,
        score: None,
        informational: false,
        fix_available: true,
    };
    load_kev(&mut store, &clock, &[kev_row(1, false)], "2099.01.15");
    let before = assess(&facts, &StoreTables::open(&store).unwrap());
    assert_eq!(
        (before.severity, before.rule),
        (Severity::Warning, Rule::UnknownSeverity)
    );
    load_kev(
        &mut store,
        &clock,
        &[kev_row(1, false), kev_row(90_001, false)],
        "2099.01.16",
    );
    let after = assess(&facts, &StoreTables::open(&store).unwrap());
    assert_eq!(
        (after.severity, after.rule),
        (Severity::Critical, Rule::Kev)
    );
    assert_eq!(after.tables.kev.unwrap().version, "2099.01.16");
}

// --- Générations ---

#[test]
fn a_reader_sees_the_old_set_until_the_switch() {
    let (_dir, path) = setup();
    let mut store = Store::open(&path).unwrap();
    let clock = FakeClock::new(T0);
    let first = load_epss(&mut store, &clock, &epss_rows(0..ENRICH_BATCH + 10, 10));
    let reader = Store::open_read(&path).unwrap().unwrap();
    let mut load = EnrichLoad::begin(&mut store, EnrichSource::Epss, &clock, LEASE).unwrap();
    load.push_epss(&epss_rows(0..ENRICH_BATCH * 2, 20)).unwrap();
    // Lots écrits, pas basculés : l'ancien jeu complet.
    let t = StoreTables::open(&reader).unwrap();
    assert_eq!(
        t.epss(&cve(1)).map(|e| (e.generation, e.epss_ppm)),
        Some((first, 10))
    );
    assert_eq!(t.epss(&cve(ENRICH_BATCH + 20)), None);
    let second = load
        .commit(&header("v2"), &Tally::default(), &SyncMeta::default())
        .unwrap()
        .generation;
    let t = StoreTables::open(&reader).unwrap();
    assert_eq!(
        t.epss(&cve(1)).map(|e| (e.generation, e.epss_ppm)),
        Some((second, 20))
    );
    assert_eq!(t.epss(&cve(ENRICH_BATCH + 20)).unwrap().generation, second);
    assert!(second > first);
    assert!(
        !rows(&path, "vuln_epss").contains(&first),
        "ancienne purgée"
    );
}

#[test]
fn a_second_load_is_busy_while_the_lease_runs_and_no_generation_is_reused() {
    let (_dir, path) = setup();
    let mut a = Store::open(&path).unwrap();
    let mut b = Store::open(&path).unwrap();
    let clock = FakeClock::new(T0);
    let first = EnrichLoad::begin(&mut a, EnrichSource::Epss, &clock, LEASE).unwrap();
    let g = first.generation();
    assert!(matches!(
        EnrichLoad::begin(&mut b, EnrichSource::Epss, &clock, LEASE),
        Err(LoadError::Busy { since: T0 })
    ));
    // KEV a son propre bail.
    let kev = EnrichLoad::begin(&mut b, EnrichSource::Kev, &clock, LEASE).unwrap();
    kev.release().unwrap();
    first.release().unwrap();
    let again = EnrichLoad::begin(&mut b, EnrichSource::Epss, &clock, LEASE).unwrap();
    assert!(again.generation() > g);
}

#[test]
fn an_expired_lease_is_taken_over_and_the_old_commit_fails() {
    let (_dir, path) = setup();
    let mut a = Store::open(&path).unwrap();
    let mut b = Store::open(&path).unwrap();
    let clock = FakeClock::new(T0);
    let active_gen = load_epss(&mut a, &clock, &epss_rows(0..5, 10));
    let mut old = EnrichLoad::begin(&mut a, EnrichSource::Epss, &clock, 60).unwrap();
    old.push_epss(&epss_rows(0..3, 30)).unwrap();
    clock.advance(61);
    let mut new = EnrichLoad::begin(&mut b, EnrichSource::Epss, &clock, 60).unwrap();
    assert!(matches!(
        old.push_epss(&epss_rows(3..4, 30)),
        Err(LoadError::Supplanted)
    ));
    assert!(matches!(
        old.commit(&header("v"), &Tally::default(), &SyncMeta::default()),
        Err(LoadError::Supplanted)
    ));
    new.push_epss(&epss_rows(0..2, 50)).unwrap();
    let g = new
        .commit(&header("v"), &Tally::default(), &SyncMeta::default())
        .unwrap()
        .generation;
    let t = StoreTables::open(&b).unwrap();
    assert_eq!(
        t.epss(&cve(0)).map(|e| (e.generation, e.epss_ppm)),
        Some((g, 50))
    );
    assert_eq!(t.epss(&cve(3)), None, "aucune ligne mélangée");
    assert_ne!(g, active_gen);
    assert_eq!(rows(&path, "vuln_epss"), [g, g]);
}

fn set_validators(path: &std::path::Path, source: &str, etag: &str, url: &str) {
    sql(path)
        .execute(
            "UPDATE vuln_sources SET etag = ?2, http_last_modified = 'lm', validator_url = ?3
             WHERE id = ?1",
            rusqlite::params![source, etag, url],
        )
        .unwrap();
}

#[test]
fn finish_unchanged_is_one_statement_and_releases_the_lease() {
    let (_dir, path) = setup();
    let mut store = Store::open(&path).unwrap();
    let clock = FakeClock::new(T0);
    let g = load_kev(&mut store, &clock, &[kev_row(1, false)], "2099.01.15");
    set_validators(&path, "kev", "\"k1\"", MIRROR);
    clock.advance(60);
    let load = EnrichLoad::begin(&mut store, EnrichSource::Kev, &clock, LEASE).unwrap();
    assert!(
        load.finish_unchanged(&Validators::Keep, Outcome::NotModified, false)
            .unwrap()
    );
    let st = sync_state(&store, "kev").unwrap().unwrap();
    assert_eq!(st.active_generation, g);
    assert_eq!(st.last_success_at, Some(T0 + 60));
    assert_eq!(st.last_outcome, Some(Outcome::NotModified));
    assert_eq!(st.loading_since, None);
    assert_eq!(st.stale_count, 0);
    assert!(StoreTables::open(&store).unwrap().kev(&cve(1)).is_some());
    // Nouveau begin accepté aussitôt.
    EnrichLoad::begin(&mut store, EnrichSource::Kev, &clock, LEASE)
        .unwrap()
        .release()
        .unwrap();
}

#[test]
fn a_stale_set_keeps_the_active_validators_and_counts() {
    let (_dir, path) = setup();
    let mut store = Store::open(&path).unwrap();
    let clock = FakeClock::new(T0);
    load_kev(&mut store, &clock, &[kev_row(1, false)], "2099.01.15");
    set_validators(&path, "kev", "\"k1\"", CANONICAL);
    for i in 1..=2 {
        clock.advance(60);
        let load = EnrichLoad::begin(&mut store, EnrichSource::Kev, &clock, LEASE).unwrap();
        assert!(
            load.finish_unchanged(&Validators::Keep, Outcome::Unchanged, true)
                .unwrap()
        );
        let st = sync_state(&store, "kev").unwrap().unwrap();
        assert_eq!(st.stale_count, i);
        assert_eq!(st.etag.as_deref(), Some("\"k1\""));
        assert_eq!(st.http_last_modified.as_deref(), Some("lm"));
        assert_eq!(st.validator_url.as_deref(), Some(CANONICAL));
        assert_eq!(st.last_outcome, Some(Outcome::Unchanged));
        assert_eq!(st.last_success_at, Some(T0 + 60 * i));
    }
}

#[test]
fn finish_unchanged_or_release_after_a_takeover_write_nothing() {
    let (_dir, path) = setup();
    let mut a = Store::open(&path).unwrap();
    let mut b = Store::open(&path).unwrap();
    let c = Store::open(&path).unwrap();
    let clock = FakeClock::new(T0);
    load_kev(&mut a, &clock, &[kev_row(1, false)], "2099.01.15");
    let old = EnrichLoad::begin(&mut a, EnrichSource::Kev, &clock, 60).unwrap();
    clock.advance(61);
    let new = EnrichLoad::begin(&mut b, EnrichSource::Kev, &clock, 60).unwrap();
    let g = new.generation();
    assert!(
        !old.finish_unchanged(&Validators::Keep, Outcome::NotModified, true)
            .unwrap()
    );
    let st = sync_state(&c, "kev").unwrap().unwrap();
    assert_eq!((st.last_success_at, st.stale_count), (Some(T0), 0));
    assert_eq!(st.loading_since, Some(T0 + 61), "bail du nouveau intact");
    let old = EnrichLoad::begin(&mut a, EnrichSource::Kev, &clock, 60);
    assert!(matches!(old, Err(LoadError::Busy { .. })));
    // Bascule concurrente : finish_unchanged du nouveau n'écrit rien.
    sql(&path)
        .execute(
            "UPDATE vuln_sources SET active_generation = active_generation + 1 WHERE id = 'kev'",
            [],
        )
        .unwrap();
    assert!(
        !new.finish_unchanged(&Validators::Keep, Outcome::NotModified, false)
            .unwrap()
    );
    let st = sync_state(&c, "kev").unwrap().unwrap();
    assert_eq!(st.loading_since, Some(T0 + 61));
    assert!(g > 0);
}

#[test]
fn an_interrupted_load_leaves_the_active_set_and_its_orphan_is_purged() {
    let (_dir, path) = setup();
    let mut store = Store::open(&path).unwrap();
    let clock = FakeClock::new(T0);
    let g = load_epss(&mut store, &clock, &epss_rows(0..10, 10));
    let mut load = EnrichLoad::begin(&mut store, EnrichSource::Epss, &clock, LEASE).unwrap();
    let orphan = load.generation();
    load.push_epss(&epss_rows(0..ENRICH_BATCH + 1, 20)).unwrap();
    load.release().unwrap();
    let t = StoreTables::open(&store).unwrap();
    assert_eq!(t.epss(&cve(1)).map(|e| e.epss_ppm), Some(10));
    assert!(rows(&path, "vuln_epss").contains(&orphan));
    let next = EnrichLoad::begin(&mut store, EnrichSource::Epss, &clock, LEASE).unwrap();
    next.release().unwrap();
    let left = rows(&path, "vuln_epss");
    assert!(left.iter().all(|r| *r == g), "orpheline purgée");
    assert_eq!(left.len(), 10);
}

// --- Purge ---

#[test]
fn a_cve_shared_with_an_orphan_survives_in_the_active_set() {
    let (_dir, path) = setup();
    let mut store = Store::open(&path).unwrap();
    let clock = FakeClock::new(T0);
    let mut load = EnrichLoad::begin(&mut store, EnrichSource::Kev, &clock, LEASE).unwrap();
    load.push_kev(&[kev_row(1, true)]).unwrap();
    load.release().unwrap();
    let g = load_kev(&mut store, &clock, &[kev_row(1, false)], "2099.01.15");
    assert_eq!(rows(&path, "vuln_kev"), [g]);
    assert!(
        !StoreTables::open(&store)
            .unwrap()
            .kev(&cve(1))
            .unwrap()
            .known_ransomware
    );
}

#[test]
fn several_large_orphans_are_purged_generation_by_generation() {
    let (_dir, path) = setup();
    let mut store = Store::open(&path).unwrap();
    let clock = FakeClock::new(T0);
    let g = load_epss(&mut store, &clock, &epss_rows(0..100, 1));
    for _ in 0..3 {
        let mut load = EnrichLoad::begin(&mut store, EnrichSource::Epss, &clock, LEASE).unwrap();
        load.push_epss(&epss_rows(0..12_000, 2)).unwrap();
        load.release().unwrap();
    }
    // Les deux premières orphelines sont déjà purgées par le begin suivant.
    assert!(rows(&path, "vuln_epss").len() <= 100 + 12_000);
    const { assert!(12_000 > PURGE_BATCH) };
    let removed = vigie::vulns::enrich_store::purge(&mut store, EnrichSource::Epss, T0).unwrap();
    assert_eq!(removed, 12_000);
    let left = rows(&path, "vuln_epss");
    assert_eq!(left.len(), 100);
    assert!(left.iter().all(|r| *r == g));
    let headers: i64 = sql(&path)
        .query_row("SELECT count(*) FROM vuln_dataset", [], |r| r.get(0))
        .unwrap();
    assert_eq!(headers, 1);
}

#[test]
fn without_a_lease_only_the_active_set_is_spared() {
    let (_dir, path) = setup();
    let mut store = Store::open(&path).unwrap();
    let clock = FakeClock::new(T0);
    let g = load_kev(&mut store, &clock, &[kev_row(1, false)], "2099.01.15");
    // Orphelines écrites à la main, sans bail en cours (`loading_generation`
    // NULL : `NOT IN` ne doit jamais recevoir NULL).
    sql(&path)
        .execute_batch(
            "INSERT INTO vuln_kev VALUES (90, 'CVE-2099-00001', '2099-01-01', '2099-01-02', 0, 'x');
             INSERT INTO vuln_kev VALUES (91, 'CVE-2099-00002', '2099-01-01', '2099-01-02', 0, 'x');
             INSERT INTO vuln_dataset VALUES ('kev', 90, 'v', '2099-01-01T00:00:00Z', 1);",
        )
        .unwrap();
    vigie::vulns::enrich_store::purge(&mut store, EnrichSource::Kev, T0).unwrap();
    assert_eq!(rows(&path, "vuln_kev"), [g]);
    assert_eq!(
        active(&store, EnrichSource::Kev)
            .unwrap()
            .unwrap()
            .generation,
        g
    );
}

// --- Validateurs ---

#[test]
fn validators_are_written_with_their_url() {
    let (_dir, path) = setup();
    let mut store = Store::open(&path).unwrap();
    let clock = FakeClock::new(T0);
    let mut load = EnrichLoad::begin(&mut store, EnrichSource::Kev, &clock, LEASE).unwrap();
    load.push_kev(&[kev_row(1, false)]).unwrap();
    load.commit(
        &header("2099.01.15"),
        &Tally::default(),
        &SyncMeta {
            etag: Some("\"a1\"".into()),
            validator_url: Some(MIRROR.into()),
            loader_version: 1,
            ..SyncMeta::default()
        },
    )
    .unwrap();
    let st = sync_state(&store, "kev").unwrap().unwrap();
    assert_eq!(st.etag.as_deref(), Some("\"a1\""));
    assert_eq!(st.validator_url.as_deref(), Some(MIRROR));
    // Même empreinte servie par l'autre URL, sans ETag : effacés.
    clock.advance(60);
    let load = EnrichLoad::begin(&mut store, EnrichSource::Kev, &clock, LEASE).unwrap();
    assert!(
        load.finish_unchanged(
            &Validators::Set {
                etag: None,
                last_modified: None,
                url: Some(CANONICAL.into()),
            },
            Outcome::Unchanged,
            false,
        )
        .unwrap()
    );
    let st = sync_state(&store, "kev").unwrap().unwrap();
    assert_eq!(st.etag, None);
    assert_eq!(st.validator_url.as_deref(), Some(CANONICAL));
    let load = EnrichLoad::begin(&mut store, EnrichSource::Kev, &clock, LEASE).unwrap();
    assert!(
        load.finish_unchanged(
            &Validators::Set {
                etag: None,
                last_modified: None,
                url: None,
            },
            Outcome::Unchanged,
            false,
        )
        .unwrap()
    );
    assert_eq!(
        sync_state(&store, "kev").unwrap().unwrap().validator_url,
        None
    );
}

// --- Cas limites ---

#[test]
fn an_empty_base_has_no_tables_and_no_error() {
    let (_dir, path) = setup();
    let store = Store::open(&path).unwrap();
    let t = StoreTables::open(&store).unwrap();
    assert_eq!(t.state(), Default::default());
    assert_eq!(t.kev(&cve(1)), None);
    assert_eq!(t.epss(&cve(1)), None);
    assert!(datasets(&store).unwrap().is_empty());
}

#[test]
fn a_cve_pushed_twice_is_counted_duplicate() {
    let (_dir, path) = setup();
    let mut store = Store::open(&path).unwrap();
    let clock = FakeClock::new(T0);
    let mut load = EnrichLoad::begin(&mut store, EnrichSource::Kev, &clock, LEASE).unwrap();
    load.push_kev(&[kev_row(1, false), kev_row(2, false)])
        .unwrap();
    load.push_kev(&[kev_row(1, true)]).unwrap();
    assert_eq!(load.entries(), 2);
    assert_eq!(load.tally().get(Reason::Duplicate), 1);
    let done = load
        .commit(&header("v"), &Tally::default(), &SyncMeta::default())
        .unwrap();
    assert_eq!(done.tally.get(Reason::Duplicate), 1);
    assert!(
        !StoreTables::open(&store)
            .unwrap()
            .kev(&cve(1))
            .unwrap()
            .known_ransomware
    );
    let st = vigie::vulns::store::sources(&store).unwrap();
    let kev = st.iter().find(|s| s.id == "kev").unwrap();
    assert_eq!((kev.entries, kev.dropped), (2, 1));
}
