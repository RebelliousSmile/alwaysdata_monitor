//! Veilleur de test du rapprochement (#21), inclus par `#[path]` : base
//! réelle remplie par les bibliothèques de F1 (failles), F4 (KEV, EPSS) et
//! F5/F6 (inventaires `agent` et `ci` acceptés par `accept_inventory`),
//! puis `tick::run_with_sources` sans contrôle externe ni source de logs.
//! Données fictives seulement (`matching_data.rs`).

#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use jiff::civil::date;

use vigie::alert::{Email, MemoryNotifier};
use vigie::clock::FakeClock;
use vigie::config::{Alerts, Config, InventorySource, Site, SiteInventory, SiteKind, Vulns};
use vigie::inventory::{Component as InvComponent, ComponentType, Inventory, Scope, Source};
use vigie::store::{Incident, InventoryDoc, InventoryOutcome, Store};
use vigie::tick::{Options, Summary};
use vigie::vulns::advisory::{Advisory, Tally};
use vigie::vulns::enrich_store::{DatasetHeader, EnrichLoad, EnrichSource, EpssRow, KevRow};
use vigie::vulns::exploit::{Cve, KevFact};
use vigie::vulns::purl::Purl;
use vigie::vulns::store::{LEASE, Load, SourceMeta, SyncMeta, upsert_source};

/// 2099-01-01T00:00:00Z.
pub const T0: i64 = 4_070_908_800;
pub const DAY: i64 = 86_400;

pub fn site(id: &str, kind: SiteKind, sources: &[InventorySource]) -> Site {
    Site {
        id: id.into(),
        url: format!("https://{id}.example.org/"),
        kind,
        runtime: None,
        keyword_url: None,
        keyword: None,
        interval: 300,
        // Aucun silence d'agent pendant les tests : seul `vulns` parle.
        agent_silence: 100 * 365 * 86_400,
        logs: None,
        inventory: (!sources.is_empty()).then(|| SiteInventory::new(sources)),
        custom_checks: Vec::new(),
    }
}

pub fn agent_key(site: &str) -> SigningKey {
    let mut seed = [7u8; 32];
    for (i, b) in site.bytes().enumerate().take(32) {
        seed[i] ^= b;
    }
    SigningKey::from_bytes(&seed)
}

pub fn ci_key(site: &str) -> SigningKey {
    let mut seed = [42u8; 32];
    for (i, b) in site.bytes().enumerate().take(32) {
        seed[i] ^= b;
    }
    SigningKey::from_bytes(&seed)
}

pub struct Harness {
    pub dir: tempfile::TempDir,
    pub config: RefCell<Config>,
    pub mail: MemoryNotifier,
    pub options: RefCell<Options>,
    seq: RefCell<BTreeMap<(String, Source), i64>>,
}

impl Harness {
    /// Veilleur d'une configuration lue d'un fichier (tests de la CLI) :
    /// clés d'agent et d'inventaire enregistrées, sources de failles créées.
    pub fn from_config(dir: tempfile::TempDir, config: Config, at: i64) -> Self {
        let vulns: Vec<String> = config
            .vulns
            .as_ref()
            .map(|v| v.sources.clone())
            .unwrap_or_default();
        let mut store = Store::open(&config.database).expect("base");
        for site in &config.sites {
            store
                .add_key(
                    &site.id,
                    &agent_key(&site.id).verifying_key().to_bytes(),
                    at,
                )
                .expect("clé d'agent");
            store
                .add_inventory_key(&site.id, &ci_key(&site.id).verifying_key().to_bytes(), at)
                .expect("clé d'inventaire");
        }
        for id in vulns.iter().map(String::as_str).chain(["kev", "epss"]) {
            upsert_source(
                &mut store,
                &SourceMeta {
                    id: id.into(),
                    url: "https://example.org/dump.zip".into(),
                    license: String::new(),
                    attribution: format!("Attribution fictive de la source {id}"),
                },
            )
            .expect("source");
        }
        Self {
            dir,
            config: RefCell::new(config),
            mail: MemoryNotifier::new(),
            options: RefCell::new(Options {
                check_budget: Duration::ZERO,
                ..Options::default()
            }),
            seq: RefCell::new(BTreeMap::new()),
        }
    }

    pub fn new(sites: Vec<Site>, vulns: &[&str]) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let database = dir.path().join("vigie.db");
        let config = Config {
            alerts: Alerts {
                to: "alertes@example.org".into(),
                from: "vigie@example.org".into(),
                smtp_host: "smtp.example.org".into(),
                smtp_port: 587,
                smtp_user: None,
                password_file: dir.path().join("smtp-password"),
            },
            database,
            api: None,
            commands: None,
            logs: Default::default(),
            vulns: Some(Vulns {
                sources: vulns.iter().map(|s| (*s).into()).collect(),
                wordfence: None,
            }),
            sites,
        };
        let mut store = Store::open(&config.database).expect("base");
        for site in &config.sites {
            store
                .add_key(
                    &site.id,
                    &agent_key(&site.id).verifying_key().to_bytes(),
                    T0,
                )
                .expect("clé d'agent");
            store
                .add_inventory_key(&site.id, &ci_key(&site.id).verifying_key().to_bytes(), T0)
                .expect("clé d'inventaire");
        }
        for id in vulns.iter().chain(["kev", "epss"].iter()) {
            upsert_source(
                &mut store,
                &SourceMeta {
                    id: (*id).into(),
                    url: "https://example.org/dump.zip".into(),
                    license: String::new(),
                    attribution: format!("Attribution fictive de la source {id}"),
                },
            )
            .expect("source");
        }
        let options = Options {
            // Aucun contrôle externe : aucun test n'appelle un hôte.
            check_budget: Duration::ZERO,
            ..Options::default()
        };
        Self {
            dir,
            config: RefCell::new(config),
            mail: MemoryNotifier::new(),
            options: RefCell::new(options),
            seq: RefCell::new(BTreeMap::new()),
        }
    }

    pub fn store(&self) -> Store {
        Store::open(&self.config.borrow().database).expect("base")
    }

    pub fn raw(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(&self.config.borrow().database).expect("base")
    }

    pub fn count(&self, sql: &str) -> i64 {
        self.raw().query_row(sql, [], |r| r.get(0)).expect(sql)
    }

    /// Nouvelle génération d'une source de failles (F1).
    pub fn load(&self, source: &str, advisories: &[Advisory], at: i64) {
        let mut store = self.store();
        let clock = FakeClock::new(at);
        let mut load = Load::begin(&mut store, source, &clock, LEASE).expect("bail");
        load.push(advisories).expect("failles");
        load.commit(&Tally::default(), &SyncMeta::default())
            .expect("bascule");
    }

    /// Nouveau jeu KEV (F4).
    pub fn kev(&self, cves: &[&str], at: i64) {
        let mut store = self.store();
        let clock = FakeClock::new(at);
        let mut load = EnrichLoad::begin(&mut store, EnrichSource::Kev, &clock, LEASE).unwrap();
        let rows: Vec<KevRow> = cves
            .iter()
            .map(|c| KevRow {
                cve: Cve::parse(c).unwrap(),
                fact: KevFact {
                    date_added: date(2099, 1, 10),
                    due_date: date(2099, 2, 1),
                    known_ransomware: false,
                    name: "Faille fictive".into(),
                },
            })
            .collect();
        load.push_kev(&rows).unwrap();
        load.commit(
            &DatasetHeader {
                version: format!("2099.{at}"),
                released: jiff::Timestamp::from_second(at).unwrap(),
            },
            &Tally::default(),
            &SyncMeta::default(),
        )
        .unwrap();
    }

    /// Nouveau jeu EPSS (F4), scores en millionièmes.
    pub fn epss(&self, rows: &[(&str, u32)], at: i64) {
        let mut store = self.store();
        let clock = FakeClock::new(at);
        let mut load = EnrichLoad::begin(&mut store, EnrichSource::Epss, &clock, LEASE).unwrap();
        let rows: Vec<(Cve, EpssRow)> = rows
            .iter()
            .map(|(c, p)| {
                (
                    Cve::parse(c).unwrap(),
                    EpssRow {
                        epss_ppm: *p,
                        percentile_ppm: p / 2,
                    },
                )
            })
            .collect();
        load.push_epss(&rows).unwrap();
        load.commit(
            &DatasetHeader {
                version: format!("v{at}"),
                released: jiff::Timestamp::from_second(at).unwrap(),
            },
            &Tally::default(),
            &SyncMeta::default(),
        )
        .unwrap();
    }

    /// Inventaire accepté pour (site, source) : `components` en
    /// (purl avec version, chemin).
    pub fn inventory(
        &self,
        site: &str,
        source: Source,
        complete: bool,
        components: &[(&str, &str)],
        at: i64,
    ) -> InventoryOutcome {
        let mut list: Vec<InvComponent> = components
            .iter()
            .map(|(purl, path)| {
                let purl = Purl::parse(purl).expect("purl");
                InvComponent {
                    name: purl.name().into(),
                    purl,
                    ty: ComponentType::Library,
                    scope: Scope::Required,
                    path: (*path).into(),
                    parent: None,
                    config_version: None,
                }
            })
            .collect();
        list.sort_by(|a, b| (a.purl.canonical(), &a.path).cmp(&(b.purl.canonical(), &b.path)));
        let seq = {
            let mut seqs = self.seq.borrow_mut();
            let slot = seqs.entry((site.into(), source)).or_insert(0);
            *slot += 1;
            *slot
        };
        let inventory = Inventory {
            site: site.into(),
            source,
            seq,
            sent_at: at,
            agent: "vigie-agent-php/0.5.0".into(),
            complete,
            skipped: if complete { 0 } else { 1 },
            spec_version: "1.7".into(),
            serial: format!("urn:uuid:00000000-0000-4000-8000-{seq:012}"),
            generated_at: at,
            digest: vigie::inventory::bom::digest(&list),
            components: list,
            dropped: Default::default(),
        };
        let key = match source {
            Source::Agent => agent_key(site),
            Source::Ci => ci_key(site),
        };
        let pubkey = key.verifying_key().to_bytes();
        self.store()
            .accept_inventory(
                &InventoryDoc {
                    site,
                    source,
                    pubkey: &pubkey,
                    inventory: &inventory,
                },
                at,
            )
            .expect("inventaire")
    }

    /// `tick` ; rend les e-mails du contrôle `vulns` seulement.
    pub fn tick(&self, now: i64) -> Vec<Email> {
        self.tick_summary(now).1
    }

    pub fn tick_summary(&self, now: i64) -> (Summary, Vec<Email>) {
        let summary = vigie::tick::run_with_sources(
            &self.config.borrow(),
            now,
            &self.options.borrow(),
            &self.mail,
            &|_| None,
        )
        .expect("tick");
        let mails = self
            .mail
            .take()
            .into_iter()
            .filter(|e| e.body.contains("Contrôle : vulns"))
            .collect();
        (summary, mails)
    }

    /// Incidents `vulns` d'un site, ouverts et clos, par id.
    pub fn incidents(&self, site: &str) -> Vec<Incident> {
        let store = self.store();
        let mut all = store.open_incidents().expect("ouverts");
        all.extend(store.closed_incidents(site, 0).expect("clos"));
        all.retain(|i| i.site == site && i.check_name == "vulns");
        all.sort_by_key(|i| i.id);
        all.dedup_by_key(|i| i.id);
        all
    }

    pub fn open(&self, site: &str) -> Vec<Incident> {
        self.incidents(site)
            .into_iter()
            .filter(|i| i.closed_at.is_none())
            .collect()
    }

    pub fn by_key(&self, site: &str, key: &str) -> Vec<Incident> {
        let full = format!("{site}/vulns/{key}");
        self.incidents(site)
            .into_iter()
            .filter(|i| i.key == full)
            .collect()
    }
}
