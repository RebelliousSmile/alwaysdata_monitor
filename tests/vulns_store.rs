//! Stockage des failles par générations (#15, phase 3) : remplacement
//! atomique, chargements concurrents, bail expiré, chargement interrompu,
//! purge, compteurs, lectures et taille du WAL.

use vigie::clock::{Clock, FakeClock};
use vigie::store::Store;
use vigie::vulns::advisory::{Reason, Tally};
use vigie::vulns::purl::Purl;
use vigie::vulns::range::{UnknownReason, Verdict};
use vigie::vulns::store::{
    LEASE, Load, LoadError, PURGE_BATCH, SyncMeta, VULN_BATCH, active_count, active_generations,
    advisory, available, candidates, generations, match_purl, purge, sources,
};
use vigie::vulns::version::SourceEcosystem;

#[path = "support/vulns_data.rs"]
mod vulns_data;
use vulns_data::{SOURCE, fictive, fixture, source};

const T0: i64 = 1_800_000_000;

fn setup() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vigie.db");
    let mut store = Store::open(&path).unwrap();
    source(&mut store, SOURCE);
    (dir, path)
}

fn load_all(store: &mut Store, clock: &dyn Clock, n: usize, tag: &str) -> i64 {
    let mut load = Load::begin(store, SOURCE, clock, LEASE).unwrap();
    let batch: Vec<_> = (0..n).map(|i| fictive(i, tag)).collect();
    load.push(&batch).unwrap();
    load.commit(&Tally::default(), &SyncMeta::default())
        .unwrap()
        .generation
}

fn reader(path: &std::path::Path) -> Store {
    Store::open_read(path).unwrap().unwrap()
}

#[test]
fn a_reader_sees_the_old_set_or_the_new_one_never_a_mix() {
    let (_dir, path) = setup();
    let clock = FakeClock::new(T0);
    let mut store = Store::open(&path).unwrap();
    let g1 = load_all(&mut store, &clock, 1_200, "a");
    let r = reader(&path);
    assert_eq!(active_count(&r, SOURCE).unwrap(), 1_200);

    let mut load = Load::begin(&mut store, SOURCE, &clock, LEASE).unwrap();
    assert!(load.generation() > g1);
    let batch: Vec<_> = (0..1_700).map(|i| fictive(i, "b")).collect();
    load.push(&batch[..VULN_BATCH * 2]).unwrap();
    // Lots déjà écrits, pas encore basculés : le lecteur voit l'ancien jeu.
    assert_eq!(active_count(&r, SOURCE).unwrap(), 1_200);
    let old = advisory(&r, "GHSA-a-000001").unwrap();
    assert_eq!(old.len(), 1);
    assert!(advisory(&r, "GHSA-b-000001").unwrap().is_empty());
    load.push(&batch[VULN_BATCH * 2..]).unwrap();
    let committed = load
        .commit(
            &Tally::default(),
            &SyncMeta {
                sha256: Some("0".repeat(64)),
                ..SyncMeta::default()
            },
        )
        .unwrap();
    assert_eq!(committed.entries, 1_700);
    assert_eq!(active_count(&r, SOURCE).unwrap(), 1_700);
    assert!(advisory(&r, "GHSA-a-000001").unwrap().is_empty());
    // L'ancienne génération est purgée.
    assert_eq!(generations(&r, SOURCE).unwrap(), [committed.generation]);
    assert_eq!(
        active_generations(&r).unwrap(),
        [(SOURCE.to_owned(), committed.generation)]
    );
}

#[test]
fn a_second_load_is_refused_while_the_lease_runs_and_no_generation_is_reused() {
    let (_dir, path) = setup();
    let clock = FakeClock::new(T0);
    let mut a = Store::open(&path).unwrap();
    let mut b = Store::open(&path).unwrap();
    let load = Load::begin(&mut a, SOURCE, &clock, LEASE).unwrap();
    let ga = load.generation();
    clock.advance(LEASE - 1);
    match Load::begin(&mut b, SOURCE, &clock, LEASE) {
        Err(LoadError::Busy { since }) => assert_eq!(since, T0),
        other => panic!("{:?}", other.map(|l| l.generation())),
    }
    load.abandon("arrêt du test").unwrap();
    // Bail rendu : un nouveau chargement prend une génération neuve.
    let load = Load::begin(&mut b, SOURCE, &clock, LEASE).unwrap();
    assert!(load.generation() > ga);
    let row = &sources(&reader(&path)).unwrap()[0];
    assert_eq!(row.last_error.as_deref(), Some("arrêt du test"));
    assert_eq!(row.loading_since, Some(T0 + LEASE - 1));
}

#[test]
fn an_expired_lease_is_taken_over_and_the_old_commit_fails_without_mixing() {
    let (_dir, path) = setup();
    let clock = FakeClock::new(T0);
    let mut a = Store::open(&path).unwrap();
    let mut b = Store::open(&path).unwrap();
    let g0 = load_all(&mut a, &clock, 10, "zero");

    let mut old = Load::begin(&mut a, SOURCE, &clock, LEASE).unwrap();
    let old_batch: Vec<_> = (0..600).map(|i| fictive(i, "old")).collect();
    old.push(&old_batch[..VULN_BATCH]).unwrap();
    clock.advance(LEASE);
    let mut new = Load::begin(&mut b, SOURCE, &clock, LEASE).unwrap();
    assert!(new.generation() > old.generation());
    // Bail revérifié à chaque lot : l'ancien s'arrête.
    assert!(matches!(
        old.push(&old_batch[VULN_BATCH..]),
        Err(LoadError::Supplanted)
    ));
    let new_batch: Vec<_> = (0..30).map(|i| fictive(i, "new")).collect();
    new.push(&new_batch).unwrap();
    assert!(matches!(
        old.commit(&Tally::default(), &SyncMeta::default()),
        Err(LoadError::Supplanted)
    ));
    let committed = new.commit(&Tally::default(), &SyncMeta::default()).unwrap();
    let r = reader(&path);
    assert_eq!(active_count(&r, SOURCE).unwrap(), 30);
    assert!(advisory(&r, "GHSA-old-000001").unwrap().is_empty());
    assert!(committed.generation > g0);
    // Génération supplantée purgée.
    assert_eq!(generations(&r, SOURCE).unwrap(), [committed.generation]);
}

#[test]
fn an_expired_lease_cannot_commit_even_without_a_rival() {
    let (_dir, path) = setup();
    let clock = FakeClock::new(T0);
    let mut store = Store::open(&path).unwrap();
    let mut load = Load::begin(&mut store, SOURCE, &clock, LEASE).unwrap();
    load.push(&[fictive(1, "x")]).unwrap();
    clock.advance(LEASE);
    assert!(matches!(
        load.commit(&Tally::default(), &SyncMeta::default()),
        Err(LoadError::LeaseExpired)
    ));
}

#[test]
fn an_interrupted_load_leaves_the_active_set_and_its_orphan_is_purged_later() {
    let (_dir, path) = setup();
    let clock = FakeClock::new(T0);
    let mut store = Store::open(&path).unwrap();
    let g1 = load_all(&mut store, &clock, 20, "actif");
    let orphan = {
        let mut load = Load::begin(&mut store, SOURCE, &clock, LEASE).unwrap();
        let batch: Vec<_> = (0..VULN_BATCH + 5).map(|i| fictive(i, "coupe")).collect();
        load.push(&batch[..VULN_BATCH]).unwrap();
        load.generation()
        // Processus tué : ni commit ni abandon.
    };
    let r = reader(&path);
    assert_eq!(active_count(&r, SOURCE).unwrap(), 20);
    assert_eq!(generations(&r, SOURCE).unwrap(), [g1, orphan]);
    // Bail toujours détenu : refusé ; expiré : repris, orpheline purgée.
    assert!(matches!(
        Load::begin(&mut store, SOURCE, &clock, LEASE),
        Err(LoadError::Busy { .. })
    ));
    clock.advance(LEASE);
    let load = Load::begin(&mut store, SOURCE, &clock, LEASE).unwrap();
    let g3 = load.generation();
    assert!(g3 > orphan);
    assert_eq!(generations(&r, SOURCE).unwrap(), [g1]);
    drop(load);
}

#[test]
fn purge_spares_the_active_and_leased_generations_in_batches() {
    let (_dir, path) = setup();
    let clock = FakeClock::new(T0);
    let mut store = Store::open(&path).unwrap();
    let g1 = load_all(&mut store, &clock, 10, "actif");
    // Orpheline de plus d'un lot de purge (lignes affected et alias).
    {
        let mut load = Load::begin(&mut store, SOURCE, &clock, LEASE).unwrap();
        let batch: Vec<_> = (0..PURGE_BATCH + 100).map(|i| fictive(i, "orph")).collect();
        load.push(&batch).unwrap();
        load.abandon("coupure").unwrap();
    }
    let mut leased = Load::begin(&mut store, SOURCE, &clock, LEASE).unwrap();
    leased.push(&[fictive(1, "bail")]).unwrap();
    let g3 = leased.generation();
    drop(leased);
    // Begin a déjà purgé l'orpheline ; une purge de plus ne retire rien.
    let r = reader(&path);
    assert_eq!(generations(&r, SOURCE).unwrap(), [g1, g3]);
    let mut other = Store::open(&path).unwrap();
    assert_eq!(purge(&mut other, SOURCE, clock.unix()).unwrap(), 0);
    // Bail expiré : sa génération n'est plus épargnée.
    assert_eq!(purge(&mut other, SOURCE, clock.unix() + LEASE).unwrap(), 3);
    assert_eq!(generations(&r, SOURCE).unwrap(), [g1]);
}

#[test]
fn counters_and_reads() {
    let (_dir, path) = setup();
    let clock = FakeClock::new(T0);
    let mut store = Store::open(&path).unwrap();
    let mut tally = Tally::default();
    let twig = fixture(
        "osv/GHSA-2q52-x2ff-qgfr.json",
        SourceEcosystem::Packagist,
        &mut tally,
    );
    let module = fixture(
        "fictif/prestashop-module.json",
        SourceEcosystem::Packagist,
        &mut tally,
    );
    let uneval = fixture(
        "fictif/composer-unevaluable.json",
        SourceEcosystem::Packagist,
        &mut tally,
    );
    let zzz = fixture(
        "hostile/keep-unknown_license-ZZZ.json",
        SourceEcosystem::Packagist,
        &mut tally,
    );
    let mut load = Load::begin(&mut store, SOURCE, &clock, LEASE).unwrap();
    load.tally_mut().merge(&tally);
    load.tally_mut().add(Reason::BadJson);
    load.tally_mut().add(Reason::Withdrawn);
    load.push(&[twig.clone(), module, uneval, zzz.clone(), twig.clone()])
        .unwrap();
    let committed = load
        .commit(&Tally::default(), &SyncMeta::default())
        .unwrap();
    assert_eq!(committed.entries, 4);
    assert_eq!(committed.tally.get(Reason::DuplicateId), 1);

    let r = reader(&path);
    assert!(available(&r).unwrap());
    let row = &sources(&r).unwrap()[0];
    assert_eq!(row.entries, 4);
    assert_eq!(row.dropped, 2, "bad_json et duplicate_id");
    assert_eq!(row.dropped_detail.get("withdrawn"), Some(&1));
    assert_eq!(row.dropped_detail.get("unknown_license"), Some(&1));
    assert_eq!(row.last_success_at, Some(T0));

    // Relue à l'identique, lignes comprises.
    let back = advisory(&r, "cve-2026-24425").unwrap();
    assert_eq!(back.len(), 1);
    assert_eq!(back[0].advisory, twig);
    assert_eq!(advisory(&r, "ZZZ-2026-0001").unwrap()[0].advisory, zzz);

    let purl = |s: &str| Purl::parse(s).unwrap();
    let c = candidates(&r, &purl("pkg:composer/twig/twig")).unwrap();
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].lines.len(), 2);
    assert!(!c[0].corrected);
    assert_eq!(c[0].generation, committed.generation);
    assert_eq!(c[0].advisory.score.map(|s| s.tenths), Some(88));
    let m = match_purl(&r, &purl("pkg:composer/twig/twig@3.10.0")).unwrap();
    assert_eq!(
        m[0].1,
        Verdict::Affected {
            fixed: Some("3.26.0".into()),
            divergence: false,
            beyond_last_known: false
        }
    );
    let m = match_purl(&r, &purl("pkg:prestashop/module/exemplemodule@1.2.0")).unwrap();
    assert!(matches!(m[0].1, Verdict::Affected { .. }));
    let m = match_purl(&r, &purl("pkg:composer/exemple/autre@1.0.5")).unwrap();
    assert_eq!(m[0].1, Verdict::Unknown(UnknownReason::RangeUnknown));
    let m = match_purl(&r, &purl("pkg:composer/twig/twig")).unwrap();
    assert_eq!(m[0].1, Verdict::Unknown(UnknownReason::VersionUnknown));
    assert!(
        candidates(&r, &purl("pkg:composer/twig/autre"))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_database_before_migration_15_has_no_vulns() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vigie.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.pragma_update(None, "user_version", 14).unwrap();
    }
    assert!(!available(&reader(&path)).unwrap());
}

fn wal_size(path: &std::path::Path) -> u64 {
    let mut wal = path.as_os_str().to_owned();
    wal.push("-wal");
    std::fs::metadata(wal).map(|m| m.len()).unwrap_or(0)
}

#[test]
fn the_wal_does_not_grow_from_one_load_to_the_next() {
    let (_dir, path) = setup();
    let clock = FakeClock::new(T0);
    let mut store = Store::open(&path).unwrap();
    load_all(&mut store, &clock, 3_000, "un");
    let first = wal_size(&path);
    assert!(first > 0);
    let mut last = 0;
    for tag in ["deux", "trois", "quatre"] {
        load_all(&mut store, &clock, 3_000, tag);
        last = wal_size(&path);
    }
    // Point de contrôle PASSIVE après chaque bascule : le WAL est réutilisé
    // depuis son début au lieu de grossir d'un chargement à l'autre.
    assert!(last <= first * 2, "WAL {first} puis {last}");
}
