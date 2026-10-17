//! Constat `vulns-sync` (#16, phase 3) évalué par `tick` : ouverture après
//! 3 jours sans réussite, clôture « rétabli » après une synchronisation,
//! « plus surveillé » quand la source est retirée, source jamais
//! synchronisée, lecture de l'état en échec. Base remplie par `Load::commit`,
//! `finish_unchanged` et `record_outcome` de la phase 2.

#[path = "support/veilleur.rs"]
mod veilleur;

use vigie::alert::{Email, MemoryNotifier};
use vigie::clock::FakeClock;
use vigie::config::{Config, Vulns};
use vigie::store::{CloseReason, Incident, Store};
use vigie::tick::{self, Options};
use vigie::vulns::advisory::Tally;
use vigie::vulns::store::{
    LEASE, Load, Outcome, SourceMeta, SyncMeta, Validators, record_outcome, upsert_source,
};
use vigie::vulns::sync::freshness::STALE_AFTER;

const T0: i64 = 1_800_000_000;

struct Harness {
    _dir: tempfile::TempDir,
    config: Config,
    mail: MemoryNotifier,
}

impl Harness {
    /// Veilleur sans site, sources de failles déclarées.
    fn new(sources: &[&str]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut config = veilleur::config(dir.path().join("vigie.db"));
        config.sites.clear();
        config.vulns = Some(Vulns {
            sources: sources.iter().map(|s| (*s).to_owned()).collect(),
            wordfence: None,
        });
        Store::open(&config.database).unwrap();
        Self {
            _dir: dir,
            config,
            mail: MemoryNotifier::new(),
        }
    }

    fn store(&self) -> Store {
        Store::open(&self.config.database).unwrap()
    }

    fn tick(&self, now: i64) -> Vec<Email> {
        tick::run_with(&self.config, now, &Options::default(), &self.mail).unwrap();
        self.mail.take()
    }

    fn source(&self, id: &str) {
        upsert_source(
            &mut self.store(),
            &SourceMeta {
                id: id.into(),
                url: "https://example.org/all.zip".into(),
                license: String::new(),
                attribution: String::new(),
            },
        )
        .unwrap();
    }

    /// Chargement réussi (vide) à `at`.
    fn loaded(&self, id: &str, at: i64) {
        self.source(id);
        let clock = FakeClock::new(at);
        let mut store = self.store();
        let load = Load::begin(&mut store, id, &clock, LEASE).unwrap();
        load.commit(&Tally::default(), &SyncMeta::default())
            .unwrap();
    }

    /// Dump inchangé (304) à `at`.
    fn not_modified(&self, id: &str, at: i64) {
        let clock = FakeClock::new(at);
        let mut store = self.store();
        let load = Load::begin(&mut store, id, &clock, LEASE).unwrap();
        assert!(
            load.finish_unchanged(&Validators::Keep, Outcome::NotModified)
                .unwrap()
        );
    }

    fn failed(&self, id: &str, at: i64) {
        record_outcome(
            &mut self.store(),
            id,
            Outcome::Failed,
            Some("délai de la source dépassé"),
            None,
            at,
        )
        .unwrap();
    }

    fn incidents(&self) -> Vec<Incident> {
        let store = self.store();
        let mut all = store.open_incidents().unwrap();
        all.extend(store.closed_incidents("_veilleur", 0).unwrap());
        all.sort_by_key(|i| i.id);
        all
    }

    fn open_keys(&self) -> Vec<String> {
        self.store()
            .open_incidents()
            .unwrap()
            .into_iter()
            .map(|i| i.key)
            .collect()
    }
}

#[test]
fn opens_after_three_days_and_one_second_and_mails_once() {
    let h = Harness::new(&["osv-npm"]);
    h.loaded("osv-npm", T0);
    assert!(h.tick(T0 + STALE_AFTER - 1).is_empty());
    assert!(h.open_keys().is_empty());
    let mails = h.tick(T0 + STALE_AFTER + 1);
    assert_eq!(h.open_keys(), ["_veilleur/vulns-sync/osv-npm"]);
    assert_eq!(mails.len(), 1, "{mails:?}");
    assert_eq!(
        mails[0].subject,
        "[vigie] veilleur : base de failles osv-npm non synchronisée"
    );
    assert!(mails[0].body.contains("vigie vulns sync --source osv-npm"));
    assert!(!mails[0].body.contains("site retiré de la configuration"));
    let incident = &h.incidents()[0];
    assert!(incident.detail.contains("non synchronisée depuis 3 jours"));
}

#[test]
fn a_successful_sync_closes_it_as_restored() {
    let h = Harness::new(&["osv-npm"]);
    h.loaded("osv-npm", T0);
    h.tick(T0 + STALE_AFTER + 1);
    // Un 304 compte comme une réussite.
    h.not_modified("osv-npm", T0 + STALE_AFTER + 60);
    let mails = h.tick(T0 + STALE_AFTER + 120);
    assert!(h.open_keys().is_empty());
    assert_eq!(h.incidents()[0].close_reason, Some(CloseReason::Resolved));
    assert_eq!(mails.len(), 1, "{mails:?}");
    assert!(mails[0].subject.ends_with("de nouveau synchronisée"));
}

#[test]
fn repeated_failures_after_a_recent_success_open_nothing_before_three_days() {
    let h = Harness::new(&["osv-npm"]);
    h.loaded("osv-npm", T0);
    for day in 1..3 {
        h.failed("osv-npm", T0 + day * 86_400);
        assert!(h.tick(T0 + day * 86_400 + 60).is_empty());
    }
    assert!(h.open_keys().is_empty());
    h.failed("osv-npm", T0 + STALE_AFTER);
    h.tick(T0 + STALE_AFTER + 1);
    let detail = &h.incidents()[0].detail;
    assert!(
        detail.contains("dernière issue : failed (délai de la source dépassé)"),
        "{detail}"
    );
}

#[test]
fn a_never_synchronized_source_counts_from_the_first_tick_that_sees_it() {
    let h = Harness::new(&["osv-crates-io"]);
    h.tick(T0);
    assert!(h.tick(T0 + STALE_AFTER).is_empty());
    h.tick(T0 + STALE_AFTER + 1);
    assert_eq!(h.open_keys(), ["_veilleur/vulns-sync/osv-crates-io"]);
    assert!(h.incidents()[0].detail.contains("jamais synchronisée"));
    let declared = h.store().meta("vulns.declared.osv-crates-io").unwrap();
    assert_eq!(declared.map(|(v, _)| v), Some(T0.to_string()));
}

#[test]
fn a_removed_source_is_closed_as_unwatched_never_restored() {
    let mut h = Harness::new(&["osv-npm", "osv-crates-io"]);
    h.loaded("osv-npm", T0);
    h.loaded("osv-crates-io", T0);
    h.tick(T0 + STALE_AFTER + 1);
    assert_eq!(h.open_keys().len(), 2);
    h.config.vulns = Some(Vulns {
        sources: vec!["osv-crates-io".into()],
        wordfence: None,
    });
    let mails = h.tick(T0 + STALE_AFTER + 60);
    assert_eq!(h.open_keys(), ["_veilleur/vulns-sync/osv-crates-io"]);
    let npm = h
        .incidents()
        .into_iter()
        .find(|i| i.key.ends_with("osv-npm"))
        .unwrap();
    assert_eq!(npm.close_reason, Some(CloseReason::Unwatched));
    assert_eq!(mails.len(), 1, "{mails:?}");
    assert!(mails[0].subject.ends_with("plus surveillée"), "{mails:?}");
    assert!(!mails[0].body.to_lowercase().contains("rétabli"));
    assert!(h.store().meta("vulns.declared.osv-npm").unwrap().is_none());
}

#[test]
fn removing_the_section_closes_everything_and_forgets_the_declarations() {
    let mut h = Harness::new(&["osv-npm", "osv-packagist"]);
    h.tick(T0);
    h.tick(T0 + STALE_AFTER + 1);
    assert_eq!(h.open_keys().len(), 2);
    h.config.vulns = None;
    h.tick(T0 + STALE_AFTER + 60);
    assert!(h.open_keys().is_empty());
    assert!(
        h.incidents()
            .iter()
            .all(|i| i.close_reason == Some(CloseReason::Unwatched))
    );
    for id in ["osv-npm", "osv-packagist"] {
        let key = format!("vulns.declared.{id}");
        assert!(h.store().meta(&key).unwrap().is_none(), "{key}");
    }
}

#[test]
fn an_unreadable_state_reconciles_nothing() {
    let h = Harness::new(&["osv-npm", "osv-crates-io"]);
    h.loaded("osv-npm", T0);
    h.loaded("osv-crates-io", T0 + 3_600);
    h.tick(T0 + STALE_AFTER + 1);
    assert_eq!(h.open_keys(), ["_veilleur/vulns-sync/osv-npm"]);
    // Lecture de `vuln_sources` en échec : une colonne lue disparaît.
    rusqlite::Connection::open(&h.config.database)
        .unwrap()
        .execute_batch("ALTER TABLE vuln_sources RENAME COLUMN recent_entries TO autre")
        .unwrap();
    // crates.io deviendrait périmé (avant tout rappel de npm) : rien ne bouge.
    let mails = h.tick(T0 + STALE_AFTER + 7_200);
    assert!(mails.is_empty(), "{mails:?}");
    assert_eq!(h.open_keys(), ["_veilleur/vulns-sync/osv-npm"]);
}

#[test]
fn status_prints_one_line_per_source() {
    let h = Harness::new(&["osv-npm", "osv-crates-io"]);
    h.loaded("osv-npm", vigie::now() - 7_200);
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_vigie"))
        .arg("--config")
        .arg(write_config(&h))
        .arg("status")
        .env_remove("VIGIE_CONFIG")
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.contains("failles : osv-crates-io jamais synchronisée"),
        "{text}"
    );
    assert!(
        text.contains("failles : osv-npm réussie il y a 2 h (dernière issue : loaded)"),
        "{text}"
    );
}

/// `config.toml` équivalent à celui du harnais.
fn write_config(h: &Harness) -> std::path::PathBuf {
    let dir = h.config.database.parent().unwrap();
    let raw = format!(
        "database = '{}'\n[alerts]\nto = \"alertes@example.org\"\nfrom = \"vigie@example.org\"\nsmtp_host = \"smtp.example.org\"\npassword_file = '{}'\n[vulns]\nsources = [\"osv-npm\", \"osv-crates-io\"]\n",
        h.config.database.display(),
        dir.join("smtp-password").display()
    );
    let path = dir.join("config.toml");
    std::fs::write(&path, raw).unwrap();
    path
}
