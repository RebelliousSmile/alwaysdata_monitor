//! Failles fictives pour les tests du stockage (`vulns_store.rs`,
//! `vulns_cli.rs`, `store_concurrency.rs`), incluses par `#[path]`.

#![allow(dead_code)]

use std::path::Path;

use vigie::store::Store;
use vigie::vulns::advisory::{Advisory, Draft, DraftAffected, DraftEvent, DraftRange, Tally};
use vigie::vulns::purl::Purl;
use vigie::vulns::store::{SourceMeta, upsert_source};
use vigie::vulns::version::{Scheme, SourceEcosystem};

pub const SOURCE: &str = "osv-packagist";

pub fn source(store: &mut Store, id: &str) {
    upsert_source(
        store,
        &SourceMeta {
            id: id.into(),
            url: "https://example.org/all.zip".into(),
            license: String::new(),
            attribution: String::new(),
        },
    )
    .expect("source");
}

/// Faille fictive `n`, sur `pkg:composer/exemple/p<n % 50>`, touchée de
/// 1.0.0 (inclus) à 1.2.0 (exclu), avec un alias `CVE-2026-<n>`.
pub fn fictive(n: usize, tag: &str) -> Advisory {
    let purl = Purl::parse(&format!("pkg:composer/exemple/p{}", n % 50)).unwrap();
    let draft = Draft {
        id: format!("GHSA-{tag}-{n:06}"),
        aliases: vec![format!("CVE-2026-{n:06}")],
        summary: Some(format!("Faille fictive {n} ({tag})")),
        modified: Some("2026-10-01T00:00:00Z".into()),
        affected: vec![DraftAffected {
            purls: vec![purl],
            scheme: Scheme::Composer,
            ranges: vec![DraftRange {
                kind: "ECOSYSTEM".into(),
                events: vec![
                    DraftEvent::Introduced("1.0.0".into()),
                    DraftEvent::Fixed("1.2.0".into()),
                ],
            }],
            versions: Vec::new(),
            last_known: None,
        }],
        ghsa_severity: Some("HIGH".into()),
        ..Draft::default()
    };
    Advisory::build(draft, &mut Tally::default()).expect("faille fictive")
}

/// Faille d'une fixture OSV.
pub fn fixture(rel: &str, dump: SourceEcosystem, tally: &mut Tally) -> Advisory {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/vulns")
        .join(rel);
    vigie::vulns::advisory::from_osv(&std::fs::read(path).unwrap(), dump, tally)
        .unwrap_or_else(|r| panic!("{rel} : {r:?}"))
}
