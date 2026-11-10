//! Volume du rapprochement (#21, phase 2), mesuré en release :
//!
//! ```text
//! cargo test --release --locked --test vulns_match_budget -- --ignored --nocapture
//! ```
//!
//! 200 sites WordPress × 2 000 composants (40 % partagés entre sites),
//! 20 000 failles fictives, dont des lignes Packagist à 2 340 `versions[]`
//! et des lignes WordPress à 40 plages. Chaque passage tient son échéance
//! à un lot près, le lot le plus long tient sous 1 s, la transaction de
//! bascule et de réconciliation la plus longue sous 100 ms, constats d'un
//! site de 2 000 composants reconstruits compris (passage de constats seuls
//! après une dérogation). Le nombre de passages pour tout couvrir est relevé.
//! Données fictives seulement.

use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;

use vigie::clock::FakeClock;
use vigie::config::{Alerts, Config, InventorySource, Site, SiteInventory, SiteKind, Vulns};
use vigie::inventory::{Component, ComponentType, Inventory, Scope, Source};
use vigie::store::{InventoryDoc, Store};
use vigie::vulns::advisory::{Advisory, Draft, DraftAffected, DraftEvent, DraftRange, Tally};
use vigie::vulns::exploit::MemoryTables;
use vigie::vulns::matching::pass::{self, Budget};
use vigie::vulns::purl::Purl;
use vigie::vulns::store::{LEASE, Load, SourceMeta, SyncMeta, upsert_source};
use vigie::vulns::version::Scheme;

const T0: i64 = 4_070_908_800;
const SITES: usize = 200;
const COMPONENTS: usize = 2_000;
/// Paquets partagés par tous les sites (40 %).
const SHARED: usize = 800;
const ADVISORIES: usize = 20_000;

fn draft(
    id: String,
    purl: &str,
    scheme: Scheme,
    ranges: Vec<DraftRange>,
    versions: Vec<Option<String>>,
) -> Advisory {
    let draft = Draft {
        id,
        modified: Some("2099-01-01T00:00:00Z".into()),
        affected: vec![DraftAffected {
            purls: vec![Purl::parse(purl).unwrap()],
            scheme,
            ranges,
            versions,
            last_known: None,
        }],
        ghsa_severity: Some("HIGH".into()),
        license: Some("licence fictive".into()),
        attribution: Some("Données fictives (https://example.org/)".into()),
        source_url: Some("https://example.org/avis".into()),
        ..Draft::default()
    };
    Advisory::build(draft, &mut Tally::default()).expect("faille fictive")
}

fn range(introduced: &str, fixed: &str) -> DraftRange {
    DraftRange {
        kind: "ECOSYSTEM".into(),
        events: vec![
            DraftEvent::Introduced(introduced.into()),
            DraftEvent::Fixed(fixed.into()),
        ],
    }
}

/// Paquet partagé `j` : Composer, sauf un sur dix, extension WordPress.
fn shared(j: usize) -> (String, Scheme) {
    if j.is_multiple_of(10) {
        (format!("pkg:wordpress/plugin/commun-{j}"), Scheme::Php)
    } else {
        (format!("pkg:composer/exemple/commun-{j}"), Scheme::Composer)
    }
}

fn advisories() -> Vec<Advisory> {
    (0..ADVISORIES)
        .map(|i| {
            let j = i % SHARED;
            let (purl, scheme) = shared(j);
            let id = format!("GHSA-2099-vvvv-{i:05}");
            // Un paquet sur quarante touché à la version installée (1.1.0).
            let fixed = if j.is_multiple_of(40) && i < SHARED {
                "1.2.0"
            } else {
                "1.0.5"
            };
            if scheme == Scheme::Php && i % 7 == 0 {
                // Ligne WordPress à 40 plages.
                let ranges = (0..40)
                    .map(|k| range(&format!("0.{k}.0"), &format!("0.{k}.9")))
                    .chain([range("1.0.0", fixed)])
                    .collect();
                draft(id, &purl, scheme, ranges, Vec::new())
            } else if scheme == Scheme::Composer && i % 50 == 1 {
                // Ligne Packagist à 2 340 versions énumérées.
                let versions = (0..2_340)
                    .map(|k| Some(format!("0.{}.{}", k / 100, k % 100)))
                    .collect();
                draft(id, &purl, scheme, vec![range("1.0.0", fixed)], versions)
            } else {
                draft(id, &purl, scheme, vec![range("1.0.0", fixed)], Vec::new())
            }
        })
        .collect()
}

fn site(i: usize) -> Site {
    Site {
        id: format!("site-{i:03}"),
        url: format!("https://site-{i:03}.example.org/"),
        kind: SiteKind::Wordpress,
        runtime: None,
        keyword_url: None,
        keyword: None,
        interval: 300,
        agent_silence: 900,
        logs: None,
        inventory: Some(SiteInventory::new(&[InventorySource::Ci])),
        custom_checks: Vec::new(),
    }
}

#[test]
#[ignore = "volume : en release, `--ignored`"]
fn two_hundred_sites_of_two_thousand_components_hold_the_budget() {
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        alerts: Alerts {
            to: "alertes@example.org".into(),
            from: "vigie@example.org".into(),
            smtp_host: "smtp.example.org".into(),
            smtp_port: 587,
            smtp_user: None,
            password_file: dir.path().join("smtp-password"),
        },
        database: dir.path().join("vigie.db"),
        api: None,
        commands: None,
        logs: Default::default(),
        vulns: Some(Vulns {
            sources: vec!["osv-packagist".into()],
            wordfence: None,
        }),
        sites: (0..SITES).map(site).collect(),
    };
    let setup = Instant::now();
    let mut store = Store::open(&config.database).unwrap();
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
    let clock = FakeClock::new(T0);
    let mut load = Load::begin(&mut store, "osv-packagist", &clock, LEASE).unwrap();
    load.push(&advisories()).unwrap();
    load.commit(&Tally::default(), &SyncMeta::default())
        .unwrap();
    for (n, s) in config.sites.iter().enumerate() {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&(n as u64 + 1).to_le_bytes());
        let key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        store.add_inventory_key(&s.id, &key, T0).unwrap();
        let mut components: Vec<Component> = (0..COMPONENTS)
            .map(|k| {
                let purl = if k < SHARED {
                    shared(k).0
                } else {
                    format!("pkg:composer/site{n}/p{k}")
                };
                Component {
                    purl: Purl::parse(&format!("{purl}@1.1.0")).unwrap(),
                    name: "p".into(),
                    ty: ComponentType::Library,
                    scope: Scope::Required,
                    path: format!("vendor/{k}"),
                    parent: None,
                    config_version: None,
                }
            })
            .collect();
        components
            .sort_by(|a, b| (a.purl.canonical(), &a.path).cmp(&(b.purl.canonical(), &b.path)));
        let inventory = Inventory {
            site: s.id.clone(),
            source: Source::Ci,
            seq: 1,
            sent_at: T0,
            agent: "vigie-inventory/0.1.0".into(),
            complete: true,
            skipped: 0,
            spec_version: "1.7".into(),
            serial: "urn:uuid:00000000-0000-4000-8000-000000000001".into(),
            generated_at: T0,
            digest: vigie::inventory::bom::digest(&components),
            components,
            dropped: Default::default(),
        };
        store
            .accept_inventory(
                &InventoryDoc {
                    site: &s.id,
                    source: Source::Ci,
                    pubkey: &key,
                    inventory: &inventory,
                },
                T0,
            )
            .unwrap();
    }
    eprintln!("préparation : {:?}", setup.elapsed());

    let reader = Store::open_read(&config.database).unwrap().unwrap();
    let tables = MemoryTables::default();
    let budget = Duration::from_secs(10);
    let mut passes = 0;
    let mut slowest_batch = Duration::ZERO;
    let mut slowest_commit = Duration::ZERO;
    let mut slowest_pass = Duration::ZERO;
    loop {
        passes += 1;
        let started = Instant::now();
        let report = pass::run(
            &mut store,
            &reader,
            &config,
            &tables,
            T0 + 60 * passes,
            &Budget {
                deadline: started + budget,
                hard_stop: started + budget + Duration::from_secs(5),
                max_batches: usize::MAX,
            },
        );
        let elapsed = started.elapsed();
        assert_eq!(report.errors, 0, "{report:?}");
        slowest_batch = slowest_batch.max(report.max_batch);
        slowest_commit = slowest_commit.max(report.max_commit);
        slowest_pass = slowest_pass.max(elapsed);
        eprintln!(
            "passage {passes} : {elapsed:?}, {} lots, {} composants, {} sites réconciliés, {} reportés, lot le plus long {:?}, bascule la plus longue {:?}",
            report.batches,
            report.components,
            report.commits,
            report.deferred,
            report.max_batch,
            report.max_commit
        );
        assert!(
            elapsed <= budget + report.max_batch + Duration::from_millis(500),
            "passage {passes} hors échéance : {elapsed:?}"
        );
        if report.batches == 0 {
            break;
        }
        assert!(passes < 200, "rapprochement sans fin");
    }
    let incidents: i64 = rusqlite::Connection::open(&config.database)
        .unwrap()
        .query_row(
            "SELECT count(*) FROM incidents WHERE check_name = 'vulns' AND closed_at IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    eprintln!(
        "tout couvert en {} passage(s) ; incidents ouverts : {incidents} ; lot le plus long {slowest_batch:?} ; bascule la plus longue {slowest_commit:?} ; passage le plus long {slowest_pass:?}",
        passes - 1
    );
    assert_eq!(incidents, (SITES * SHARED / 40) as i64);
    assert!(slowest_batch < Duration::from_secs(1), "{slowest_batch:?}");
    assert!(
        slowest_commit < Duration::from_millis(100),
        "{slowest_commit:?}"
    );

    // Constats seuls d'un site de 2 000 composants (dérogation ajoutée).
    let conn = rusqlite::Connection::open(&config.database).unwrap();
    conn.execute(
        "INSERT INTO vuln_waivers (site, source, base, advisory_ref, version, covered_ids,
             reason, until, operator, created_at, audit_hash)
         VALUES ('site-000', 'ci', 'pkg:composer/exemple/commun-40', 'GHSA-2099-vvvv-00040',
             '1.1.0', '[\"GHSA-2099-vvvv-00040\"]', 'motif fictif', ?1, 'test', ?2, 'h')",
        rusqlite::params![T0 + 30 * 86_400, T0],
    )
    .unwrap();
    let seen: i64 = conn
        .query_row(
            "SELECT count(*) FROM vuln_match_seen WHERE site = 'site-000'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let started = Instant::now();
    let report = pass::run(
        &mut store,
        &reader,
        &config,
        &tables,
        T0 + 86_400,
        &Budget {
            deadline: started + budget,
            hard_stop: started + budget,
            max_batches: usize::MAX,
        },
    );
    eprintln!(
        "constats seuls de site-000 : passage {:?}, bascule {:?}, {seen} ligne(s) de provenance",
        started.elapsed(),
        report.max_commit
    );
    assert_eq!(report.commits, 1);
    assert!(report.max_commit < Duration::from_millis(100));
}
