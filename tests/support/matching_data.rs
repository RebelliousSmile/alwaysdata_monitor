//! Données fictives du rapprochement (F7, #21), incluses par `#[path]` :
//! sites `site-a` et `site-b`, composants, failles, CVE (`CVE-2099-…`) et
//! attributions inventés (titulaire « Exemple Intelligence SARL »), liens
//! `example.org` seulement. Chaque faille passe par `Advisory::build` (F1),
//! comme celles des sources réelles.

#![allow(dead_code)]

use jiff::civil::date;

use vigie::vulns::advisory::{
    Advisory, Draft, DraftAffected, DraftEvent, DraftRange, Score, ScoreOrigin, Tally,
};
use vigie::vulns::exploit::{Cve, DatasetInfo, EpssFact, KevFact, MemoryTables, TablesState};
use vigie::vulns::purl::Purl;
use vigie::vulns::store::Candidate;
use vigie::vulns::version::Scheme;

/// Attribution fictive d'une source « usage interne ».
pub const ATTRIBUTION_WF: &str =
    "Copyright 2099 Exemple Intelligence SARL. Données fictives, https://example.org/licence";
/// Attribution fictive d'une source libre.
pub const ATTRIBUTION_FREE: &str = "Données fictives de démonstration (https://example.org/)";

pub const PLUGIN: &str = "pkg:wordpress/plugin/exemple-plugin";
pub const MODULE: &str = "pkg:prestashop/module/exemplemodule";
pub const PAQUET: &str = "pkg:composer/exemple/paquet";
pub const NPM: &str = "pkg:npm/%40exemple/paquet";

/// Faille fictive : `ranges` en paires (introduit, corrigé), `fixed` vide
/// pour une plage ouverte.
pub struct Fake<'a> {
    pub id: &'a str,
    pub aliases: &'a [&'a str],
    pub purl: &'a str,
    pub scheme: Scheme,
    pub ranges: &'a [(&'a str, &'a str)],
    pub versions: &'a [&'a str],
    /// Dixièmes ; `None` : score inconnu.
    pub score: Option<u8>,
    pub informational: bool,
    pub attribution: &'a str,
}

impl Default for Fake<'_> {
    fn default() -> Self {
        Self {
            id: "GHSA-0000-0000-0001",
            aliases: &[],
            purl: PAQUET,
            scheme: Scheme::Composer,
            ranges: &[("0", "1.2.4")],
            versions: &[],
            score: Some(75),
            informational: false,
            attribution: ATTRIBUTION_FREE,
        }
    }
}

pub fn build(f: &Fake<'_>) -> Advisory {
    let ranges = f
        .ranges
        .iter()
        .map(|(introduced, fixed)| {
            let mut events = vec![DraftEvent::Introduced((*introduced).into())];
            if !fixed.is_empty() {
                events.push(DraftEvent::Fixed((*fixed).into()));
            }
            DraftRange {
                kind: "ECOSYSTEM".into(),
                events,
            }
        })
        .collect();
    let draft = Draft {
        id: f.id.into(),
        aliases: f.aliases.iter().map(|a| (*a).into()).collect(),
        summary: Some("Faille fictive".into()),
        modified: Some("2099-01-01T00:00:00Z".into()),
        affected: vec![DraftAffected {
            purls: vec![Purl::parse(f.purl).unwrap()],
            scheme: f.scheme,
            ranges,
            versions: f.versions.iter().map(|v| Some((*v).into())).collect(),
            last_known: None,
        }],
        provided_score: f.score.map(|tenths| Score {
            tenths,
            origin: ScoreOrigin::Wordfence,
        }),
        informational: f.informational,
        license: Some("licence fictive".into()),
        attribution: Some(f.attribution.into()),
        source_url: Some(format!("https://example.org/avis/{}", f.id)),
        ..Draft::default()
    };
    Advisory::build(draft, &mut Tally::default()).expect("faille fictive")
}

/// Candidate de `source` pour le purl de la faille.
pub fn candidate(source: &str, advisory: Advisory) -> Candidate {
    let purl = advisory.affected[0].purl.clone();
    let lines = advisory
        .lines_for(&purl)
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    Candidate {
        source: source.into(),
        generation: 1,
        advisory: vigie::vulns::advisory::Advisory {
            affected: Vec::new(),
            ..advisory
        },
        lines,
        corrected: false,
    }
}

pub fn cand(source: &str, f: &Fake<'_>) -> Candidate {
    candidate(source, build(f))
}

pub fn cve(raw: &str) -> Cve {
    Cve::parse(raw).unwrap()
}

pub fn loaded() -> TablesState {
    let info = |version: &str| DatasetInfo {
        generation: 1,
        version: version.into(),
        released: "2099-01-15T12:00:00Z".parse().unwrap(),
    };
    TablesState {
        kev: Some(info("2099.01.15")),
        epss: Some(info("v2099.01.01")),
    }
}

/// Tables : `kev` les CVE du catalogue, `epss` leurs scores en millionièmes.
pub fn tables(kev: &[&str], epss: &[(&str, u32)]) -> MemoryTables {
    MemoryTables::new(
        kev.iter().map(|c| {
            (
                cve(c),
                KevFact {
                    date_added: date(2099, 1, 10),
                    due_date: date(2099, 2, 1),
                    known_ransomware: false,
                    name: "Faille fictive".into(),
                },
            )
        }),
        epss.iter().map(|(c, p)| {
            (
                cve(c),
                EpssFact {
                    generation: 1,
                    epss_ppm: *p,
                    percentile_ppm: p / 2,
                },
            )
        }),
        loaded(),
    )
}

/// Générateur xorshift à graine fixe : le fuzz est reproductible sans
/// dépendance.
pub struct XorShift(pub u64);

impl XorShift {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}
