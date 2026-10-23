//! Registre des capacités (issues #2 et #4) : une seule déclaration filtre ce
//! qui s'exécute (commandes) et ce qui s'ouvre (contrôles) pour un site.
//!
//! - matrice kind × runtime × contrôle × contexte, contre une table écrite
//!   ici sans passer par le registre, et matrice des commandes ;
//! - familles de l'agent confrontées aux `finding('…'` de `vigie-agent.php` et
//!   à la fixture signée ;
//! - même verdict de l'API, de `tick` (`close_unwatched`) et de l'ingestion,
//!   sur toute la matrice, par leurs vrais chemins ;
//! - cas de bout en bout : famille retirée, famille écartée, clé d'agent sur
//!   un site sans runtime `php`, clé retirée, `logs` sans source.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vigie::alert::{Email, MemoryNotifier};
use vigie::capability::{
    self, AgentFamily, CommandKind, Control, Ctx, Refusal, TYPOLOGY, allowed, permit,
};
use vigie::checks::CheckKind;
use vigie::clock::{Clock, FakeClock};
use vigie::config::{Alerts, Config, LogSourceKind, Runtime, Site, SiteKind, SiteLogs};
use vigie::device::{self, PAIRING_TTL};
use vigie::finding::{Finding, Severity};
use vigie::ingest::{self, Accepted, Reason};
use vigie::serve;
use vigie::store::{CloseReason, Incident, RunRecord, RunResult, Store};
use vigie::tick::{self, Options};

/// Instant arbitraire : seuls les écarts comptent.
const T0: i64 = 1_800_000_000;
/// Intervalle des sites : les contrôles externes marqués faits à `T0` ne
/// sont plus dus, `tick` ne sort jamais sur le réseau.
const INTERVAL: u64 = 86_400;
const HASH: &str = "33bf0cf98fa40b5f4c44e053816b75487245c5fc01e66dd65470e2e70cbee0d8";

/// Couples (CMS, runtime déclaré) qu'admet `config.toml` : un CMS implique
/// `php` et refuse un autre runtime (`tests/config_edges.rs`).
const KINDS: [(SiteKind, Option<Runtime>); 8] = [
    (SiteKind::Generic, None),
    (SiteKind::Generic, Some(Runtime::Php)),
    (SiteKind::Generic, Some(Runtime::Node)),
    (SiteKind::Generic, Some(Runtime::Static)),
    (SiteKind::Wordpress, None),
    (SiteKind::Wordpress, Some(Runtime::Php)),
    (SiteKind::Prestashop, None),
    (SiteKind::Prestashop, Some(Runtime::Php)),
];

/// Noms éprouvés : tout le registre, plus deux noms qu'il ne connaît pas.
fn names() -> Vec<&'static str> {
    let mut names: Vec<&str> = Control::ALL.iter().map(|c| c.name()).collect();
    names.extend(["agent:php", "inconnu"]);
    names
}

fn site(id: &str, kind: SiteKind, runtime: Option<Runtime>, logs: bool) -> Site {
    Site {
        id: id.into(),
        url: format!("https://{id}.example.org/"),
        kind,
        runtime,
        keyword_url: None,
        keyword: None,
        interval: INTERVAL,
        agent_silence: 900,
        logs: logs.then(|| SiteLogs {
            source: Some(LogSourceKind::Alwaysdata),
            hosts: vec![format!("{id}.example.org")],
            ..SiteLogs::default()
        }),
        inventory: None,
        custom_checks: Vec::new(),
    }
}

/// Table du registre écrite à la main : ce que l'issue #4 exige, nom par nom.
fn expected(site: &Site, name: &str, ctx: &Ctx) -> bool {
    let php = match site.kind {
        SiteKind::Wordpress | SiteKind::Prestashop => true,
        SiteKind::Generic => site.runtime == Some(Runtime::Php),
    };
    let php_agent = ctx.agent && php;
    match name {
        "content" | "exposed" | "tls" | "headers" => true,
        "installer" => site.kind != SiteKind::Generic,
        "heartbeat"
        | "agent:root"
        | "agent:critical-file"
        | "agent:must-contain"
        | "agent:errors" => php_agent,
        "agent:uploads-php" => php_agent && site.kind == SiteKind::Wordpress,
        "agent:integrity" => php_agent && ctx.baseline,
        "logs" => site.logs.is_some(),
        "typology" => ctx.agent && !php,
        _ => false,
    }
}

const CONTEXTS: [Ctx; 3] = [
    Ctx {
        agent: false,
        baseline: false,
    },
    Ctx {
        agent: true,
        baseline: false,
    },
    Ctx {
        agent: true,
        baseline: true,
    },
];

#[test]
fn the_control_matrix_matches_the_literal_table() {
    for (kind, runtime) in KINDS {
        for logs in [false, true] {
            let site = site("site-a", kind, runtime, logs);
            for ctx in CONTEXTS {
                for name in names() {
                    assert_eq!(
                        capability::watched(&site, name, &ctx),
                        expected(&site, name, &ctx),
                        "{name} pour {kind:?}/{runtime:?}, logs {logs}, {ctx:?}"
                    );
                }
                let allowed: Vec<&str> = capability::allowed_controls(&site, &ctx)
                    .into_iter()
                    .map(Control::name)
                    .collect();
                let table: Vec<&str> = names()
                    .into_iter()
                    .filter(|name| expected(&site, name, &ctx))
                    .collect();
                assert_eq!(allowed, table, "{kind:?}/{runtime:?}, logs {logs}, {ctx:?}");
            }
        }
    }
}

#[test]
fn every_control_round_trips_and_unknown_names_are_not_watched() {
    for control in Control::ALL {
        assert_eq!(Control::from_name(control.name()), Some(control));
    }
    let names: BTreeSet<&str> = Control::ALL.iter().map(|c| c.name()).collect();
    assert_eq!(names.len(), Control::ALL.len(), "noms uniques");
    for kind in CheckKind::ALL {
        assert!(
            Control::ALL.contains(&Control::Check(kind)),
            "{}",
            kind.name()
        );
    }
    let wordpress = site("site-a", SiteKind::Wordpress, None, true);
    let all = Ctx {
        agent: true,
        baseline: true,
    };
    for name in [
        "",
        "agent:",
        "agent:php",
        "agent:INTEGRITY",
        "integrity",
        "Content",
        "heartbeat ",
        "agent:uploads_php",
    ] {
        assert!(!capability::watched(&wordpress, name, &all), "{name:?}");
    }
}

#[test]
fn the_installer_check_applies_to_wordpress_and_prestashop_only() {
    assert_eq!(
        Control::Check(CheckKind::Installer).cms(),
        [SiteKind::Wordpress, SiteKind::Prestashop]
    );
    for (kind, runtime) in KINDS {
        let site = site("site-a", kind, runtime, false);
        assert_eq!(
            CheckKind::Installer.applies(&site),
            kind != SiteKind::Generic,
            "{kind:?}/{runtime:?}"
        );
        // `custom` ne s'applique qu'avec une règle déclarée (test dédié).
        for other in CheckKind::ALL
            .into_iter()
            .filter(|k| *k != CheckKind::Installer && *k != CheckKind::Custom)
        {
            assert!(other.applies(&site), "{} pour {kind:?}", other.name());
        }
    }
}

// --- Contrôles personnalisés (#33) -----------------------------------------

fn rule(id: &str) -> vigie::config::CustomCheck {
    vigie::config::CustomCheck {
        id: id.into(),
        path: "/panier".into(),
        status: 200,
        contains: None,
        absent: None,
        severity: vigie::config::CustomSeverity::Warning,
    }
}

#[test]
fn the_custom_check_is_watched_only_with_a_declared_rule_whatever_the_cms() {
    assert_eq!(CheckKind::Custom.name(), "custom");
    assert_eq!(
        Control::from_name("custom"),
        Some(Control::Check(CheckKind::Custom))
    );
    for (kind, runtime) in KINDS {
        let without = site("site-a", kind, runtime, false);
        assert!(
            !CheckKind::Custom.applies(&without),
            "{kind:?}/{runtime:?} sans règle"
        );
        let with = Site {
            custom_checks: vec![rule("panier")],
            ..without
        };
        assert!(
            CheckKind::Custom.applies(&with),
            "{kind:?}/{runtime:?} avec règle"
        );
        for ctx in CONTEXTS {
            assert!(
                capability::watched(&with, "custom", &ctx),
                "{kind:?}/{runtime:?}"
            );
        }
    }
}

// --- Commandes (déplacés de `capability.rs`, issue #2) ------------------

fn generic(runtime: Option<Runtime>) -> Site {
    site("site-a", SiteKind::Generic, runtime, false)
}

#[test]
fn the_command_matrix_matches_the_literal_table() {
    use CommandKind::*;
    // (commande, aucun, php, node, static)
    let table = [
        (Ping, false, true, false, false),
        (RotateKey, false, true, false, false),
        // Disponibles depuis #13, pour php seulement.
        (HtaccessApply, false, true, false, false),
        (HtaccessRollback, false, true, false, false),
    ];
    assert_eq!(table.len(), CommandKind::ALL.len());
    for (command, none, php, node, stat) in table {
        for (runtime, expected) in [
            (None, none),
            (Some(Runtime::Php), php),
            (Some(Runtime::Node), node),
            (Some(Runtime::Static), stat),
        ] {
            assert_eq!(
                permit(command, &generic(runtime)).is_ok(),
                expected,
                "{command} pour {runtime:?}"
            );
        }
    }
}

#[test]
fn a_php_command_is_refused_for_static_and_node() {
    let php = generic(Some(Runtime::Php));
    assert_eq!(permit(CommandKind::RotateKey, &php), Ok(()));
    assert_eq!(permit(CommandKind::HtaccessApply, &php), Ok(()));
    for runtime in [Runtime::Static, Runtime::Node] {
        for command in CommandKind::ALL {
            assert_eq!(
                permit(command, &generic(Some(runtime))),
                Err(Refusal::RuntimeNotAllowed { runtime }),
                "{command}"
            );
        }
    }
    assert_eq!(
        permit(CommandKind::Ping, &generic(None)),
        Err(Refusal::NoRuntime)
    );
    assert!(allowed(&generic(None)).is_empty());
}

#[test]
fn a_cms_implies_php_for_commands() {
    for kind in [SiteKind::Wordpress, SiteKind::Prestashop] {
        assert_eq!(
            allowed(&site("site-a", kind, None, false)),
            CommandKind::ALL
        );
    }
}

#[test]
fn command_names_round_trip_and_unknown_names_are_refused() {
    for command in CommandKind::ALL {
        assert_eq!(CommandKind::from_name(command.name()), Some(command));
    }
    for name in ["", "PING", "shell", "eval", "rotate_key", "ping "] {
        assert_eq!(CommandKind::from_name(name), None, "{name:?}");
    }
}

// --- Inventaire (#19) ---------------------------------------------------

#[test]
fn the_inventory_ecosystem_matrix_matches_the_literal_table() {
    use vigie::vulns::purl::PurlType::*;
    // (CMS, wordpress, prestashop, composer, npm, cargo)
    let table = [
        (SiteKind::Generic, false, false, true, true, true),
        (SiteKind::Wordpress, true, false, true, true, true),
        (SiteKind::Prestashop, false, true, true, true, true),
    ];
    for (kind, wp, ps, composer, npm, cargo) in table {
        let admitted = capability::inventory_ecosystems(kind);
        for (ty, expected) in [
            (Wordpress, wp),
            (Prestashop, ps),
            (Composer, composer),
            (Npm, npm),
            (Cargo, cargo),
        ] {
            assert_eq!(admitted.contains(&ty), expected, "{ty:?} pour {kind:?}");
        }
    }
}

#[test]
fn only_a_declared_section_opens_the_inventory() {
    use vigie::config::{InventorySource, SiteInventory};
    let mut wp = site("site-a", SiteKind::Wordpress, None, false);
    assert_eq!(capability::inventory_sources(&wp), []);
    wp.inventory = Some(SiteInventory::new(&[InventorySource::AgentPhp]));
    assert_eq!(
        capability::inventory_sources(&wp),
        [InventorySource::AgentPhp]
    );
    // L'inventaire n'ouvre qu'un contrôle : `vulns` (F7, #21).
    for ctx in CONTEXTS {
        let mut without = wp.clone();
        without.inventory = None;
        let mut expected = capability::allowed_controls(&without, &ctx);
        expected.push(Control::Vulns);
        assert_eq!(capability::allowed_controls(&wp, &ctx), expected);
    }
}

/// Matrice CMS × runtime (absent compris) × sources déclarées : `agent-php`
/// n'est ouvert qu'au runtime effectif `php`, `ci` partout (#20). La
/// configuration refuse déjà `agent-php` ailleurs (`config_edges.rs`) : le
/// registre ne l'ouvre pas non plus pour une configuration construite.
#[test]
fn inventory_sources_follow_the_runtime_matrix() {
    use vigie::config::{InventorySource as S, SiteInventory};
    let declared: [&[S]; 3] = [&[S::AgentPhp], &[S::Ci], &[S::AgentPhp, S::Ci]];
    for kind in [SiteKind::Generic, SiteKind::Wordpress, SiteKind::Prestashop] {
        for runtime in [
            None,
            Some(Runtime::Php),
            Some(Runtime::Node),
            Some(Runtime::Static),
        ] {
            for sources in declared {
                let mut s = site("site-a", kind, runtime, false);
                s.inventory = Some(SiteInventory::new(sources));
                let php = s.effective_runtime() == Some(Runtime::Php);
                let expected: Vec<S> = sources
                    .iter()
                    .copied()
                    .filter(|source| *source == S::Ci || php)
                    .collect();
                assert_eq!(
                    capability::inventory_sources(&s),
                    expected,
                    "{kind:?} {runtime:?} {sources:?}"
                );
            }
        }
    }
}

// --- Familles de l'agent -------------------------------------------------

/// Familles qu'émet `vigie-agent.php` : premier argument de `finding('…'`.
fn agent_families() -> BTreeSet<String> {
    let source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("agent/php/vigie-agent.php"),
    )
    .expect("agent PHP");
    source
        .split("finding('")
        .skip(1)
        .map(|rest| rest.split('\'').next().expect("nom").to_owned())
        .collect()
}

#[test]
fn the_families_are_exactly_those_the_php_agent_emits() {
    let registry: BTreeSet<String> = AgentFamily::ALL
        .iter()
        .map(|f| f.name().to_owned())
        .collect();
    assert_eq!(agent_families(), registry);
    for family in AgentFamily::ALL {
        assert_eq!(AgentFamily::from_name(family.name()), Some(family));
        assert_eq!(family.check_name(), format!("agent:{}", family.name()));
    }
    assert_eq!(
        AgentFamily::from_name("integrity"),
        None,
        "integrity est réservé au veilleur"
    );
}

#[test]
fn every_family_of_the_signed_fixture_is_registered() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/php-signed-report.json")).expect("fixture");
    let body: Value =
        serde_json::from_str(fixture["body"].as_str().expect("corps")).expect("rapport");
    let families: BTreeSet<&str> = body["findings"]
        .as_array()
        .expect("constats")
        .iter()
        .map(|f| f["check"].as_str().expect("check"))
        .collect();
    assert!(!families.is_empty());
    for family in families {
        assert!(AgentFamily::from_name(family).is_some(), "{family}");
        assert!(agent_families().contains(family), "{family}");
    }
}

// --- Même verdict partout -------------------------------------------------

/// Un site par variante : 8 couples CMS × runtime, 3 contextes, avec et sans
/// source de logs.
struct Variant {
    site: Site,
    ctx: Ctx,
}

fn variants() -> Vec<Variant> {
    let mut out = Vec::new();
    for (kind, runtime) in KINDS {
        for ctx in CONTEXTS {
            for logs in [false, true] {
                let id = format!("s{}", out.len());
                out.push(Variant {
                    site: site(&id, kind, runtime, logs),
                    ctx,
                });
            }
        }
    }
    out
}

fn config(dir: &Path, sites: Vec<Site>) -> Config {
    Config {
        database: dir.join("vigie.db"),
        api: None,
        commands: None,
        logs: Default::default(),
        vulns: None,
        alerts: Alerts {
            to: "alertes@example.org".into(),
            from: "vigie@example.org".into(),
            smtp_host: "smtp.example.org".into(),
            smtp_port: 587,
            smtp_user: None,
            password_file: dir.join("smtp-password"),
        },
        sites,
    }
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

/// Rapport signé de l'agent, sous la forme de `vigie-agent.php`.
fn signed_report(site: &str, seq: u64, at: i64, checks: &[&str], files: bool) -> (Vec<u8>, String) {
    let findings: Vec<Value> = checks
        .iter()
        .map(|check| {
            json!({"check": check, "severity": "critical", "key": "ingest", "detail": "constat"})
        })
        .collect();
    let mut report = json!({
        "v": 1,
        "site": site,
        "seq": seq,
        "sent_at": at,
        "agent": "vigie-agent-php/0.4.0",
        "findings": findings,
        "facts": {},
    });
    if files {
        report["files"] = json!({".htaccess": HASH});
    }
    let body = serde_json::to_vec(&report).expect("json");
    let signature = STANDARD.encode(key().sign(&body).to_bytes());
    (body, signature)
}

fn ingest_report(
    store: &mut Store,
    sites: &[Site],
    site: &str,
    seq: u64,
    at: i64,
    checks: &[&str],
    files: bool,
) -> Result<Accepted, ingest::Refusal> {
    let (body, signature) = signed_report(site, seq, at, checks, files);
    ingest::ingest(store, sites, Some(site), Some(&signature), &body, at)
}

/// Familles bien formées que l'agent peut envoyer : le registre et une de
/// plus, inconnue.
const SENT: [&str; 5] = [
    "root",
    "critical-file",
    "must-contain",
    "uploads-php",
    "php",
];

/// Jeton d'un appareil appairé, comme par la console.
async fn token(config: &Config, clock: &Arc<FakeClock>) -> String {
    let code = device::new_code().expect("code");
    Store::open(&config.database)
        .expect("base")
        .create_pairing(
            &device::hash(&code),
            "pc",
            clock.unix(),
            clock.unix() + PAIRING_TTL,
        )
        .expect("pairing");
    let request = Request::post("/api/v1/pair")
        .header("content-type", "application/json")
        .body(Body::from(json!({ "code": code }).to_string()))
        .expect("requête");
    let reply = get_json(config, clock, request).await;
    reply["token"].as_str().expect("jeton").to_owned()
}

async fn get_json(config: &Config, clock: &Arc<FakeClock>, request: Request<Body>) -> Value {
    let router = serve::router_with_clock(config.clone(), Arc::clone(clock) as Arc<dyn Clock>);
    let response = router.oneshot(request).await.expect("réponse");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("corps")
        .to_bytes();
    serde_json::from_slice(&body).expect("json")
}

#[tokio::test]
async fn the_api_tick_and_ingestion_give_the_same_verdict_on_the_whole_matrix() {
    let dir = tempfile::tempdir().expect("tempdir");
    let variants = variants();
    let config = config(
        dir.path(),
        variants.iter().map(|v| v.site.clone()).collect(),
    );
    let mut store = Store::open(&config.database).expect("base");
    let public = key().verifying_key().to_bytes();
    // Une même clé pour toute la matrice, posée en base comme dans une base
    // d'avant #20 : `add_key` refuse désormais une clé déjà enregistrée.
    let raw = rusqlite::Connection::open(&config.database).expect("sqlite");
    for v in &variants {
        let id = &v.site.id;
        if v.ctx.agent {
            raw.execute(
                "INSERT INTO site_keys (site, pubkey, added_at) VALUES (?1, ?2, ?3)",
                rusqlite::params![id, public.as_slice(), T0],
            )
            .expect("clé");
        }
        // Un passage et un incident ouvert pour chaque nom éprouvé.
        for name in names() {
            store.record_run(id, name, T0).expect("record_run");
            let seed = Finding::new(id, name, Severity::Critical, "seed", "semé");
            store.reconcile(id, name, &[seed], T0).expect("reconcile");
        }
    }

    // Ingestion : un rapport de chaque agent, toutes familles, empreintes
    // seulement où le contexte veut une référence (le rapport la pose).
    let mut ingested: Vec<(usize, BTreeSet<String>)> = Vec::new();
    for (i, v) in variants.iter().enumerate() {
        let id = &v.site.id;
        let outcome = ingest_report(
            &mut store,
            &config.sites,
            id,
            1,
            T0 + 60,
            &SENT,
            v.ctx.baseline,
        );
        if !v.ctx.agent {
            let refusal = outcome.expect_err("sans clé");
            assert_eq!(refusal.reason, Reason::UnknownSite, "{id}");
            continue;
        }
        let accepted = outcome.expect("rapport accepté");
        let admitted: BTreeSet<String> = store
            .open_incidents()
            .expect("incidents")
            .into_iter()
            .filter(|i| i.site == *id && i.key.ends_with("/ingest"))
            .map(|i| i.check_name)
            .collect();
        assert_eq!(accepted.dropped, SENT.len() - admitted.len(), "{id}");
        ingested.push((i, admitted));
    }
    drop(store);

    let mail = MemoryNotifier::new();
    tick::run_with(&config, T0 + 120, &Options::default(), &mail).expect("tick");

    let clock = Arc::new(FakeClock::new(T0 + 180));
    let token = token(&config, &clock).await;
    let store = Store::open(&config.database).expect("base");
    let mut seeds: Vec<Incident> = store.open_incidents().expect("ouverts");
    for v in &variants {
        seeds.extend(store.closed_incidents(&v.site.id, 0).expect("clos"));
    }
    let agents = store.agents().expect("agents");
    let baselines = store.baseline_sites().expect("références");
    let tick_watched = tick::watched_by_tick(&config, &agents, &baselines);
    for (i, v) in variants.iter().enumerate() {
        let id = &v.site.id;
        let detail = get_json(
            &config,
            &clock,
            Request::get(format!("/api/v1/sites/{id}"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("requête"),
        )
        .await;
        let shown: BTreeSet<String> = detail["checks"]
            .as_array()
            .expect("checks")
            .iter()
            .map(|c| c["name"].as_str().expect("nom").to_owned())
            .collect();
        for name in names() {
            let registry = capability::watched(&v.site, name, &v.ctx);
            assert_eq!(registry, expected(&v.site, name, &v.ctx), "{id} {name}");
            let seed = seeds
                .iter()
                .find(|s| s.site == *id && s.key == format!("{id}/{name}/seed"))
                .expect("incident semé");
            // `typology` d'un agent sur un site en PHP est réconcilié vide
            // avant `close_unwatched` : clos « rétabli », pas « plus surveillé ».
            if name == TYPOLOGY && v.ctx.agent && !registry {
                assert_eq!(seed.close_reason, Some(CloseReason::Resolved), "{id}");
            } else {
                let tick_keeps = seed.close_reason != Some(CloseReason::Unwatched);
                assert_eq!(tick_keeps, registry, "tick : {id} {name} {seed:?}");
            }
            assert_eq!(
                tick_watched(seed),
                registry,
                "prédicat de tick : {id} {name}"
            );
            assert_eq!(
                shown.contains(name),
                registry,
                "API : {id} {name} {shown:?}"
            );
            if let Some((_, admitted)) = ingested.iter().find(|(j, _)| *j == i)
                && SENT.iter().any(|s| format!("agent:{s}") == name)
            {
                assert_eq!(admitted.contains(name), registry, "ingestion : {id} {name}");
            }
        }
    }
}

// --- Cas de bout en bout ----------------------------------------------------

/// Un site et sa base : contrôles externes faits à `T0`, clé d'agent
/// enregistrée si `agent`.
struct Harness {
    _dir: tempfile::TempDir,
    config: Config,
    mail: MemoryNotifier,
}

impl Harness {
    fn new(site: Site, agent: bool) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = config(dir.path(), vec![site]);
        let mut store = Store::open(&config.database).expect("base");
        for kind in CheckKind::ALL {
            store
                .record_run("site-a", kind.name(), T0)
                .expect("record_run");
        }
        if agent {
            store
                .add_key("site-a", &key().verifying_key().to_bytes(), T0)
                .expect("add_key");
        }
        Self {
            _dir: dir,
            config,
            mail: MemoryNotifier::new(),
        }
    }

    fn store(&self) -> Store {
        Store::open(&self.config.database).expect("base")
    }

    fn report(&self, seq: u64, at: i64, checks: &[&str]) -> Accepted {
        ingest_report(
            &mut self.store(),
            &self.config.sites,
            "site-a",
            seq,
            at,
            checks,
            false,
        )
        .expect("rapport accepté")
    }

    /// `tick` sans source de logs : seul `close_unwatched` touche `logs`.
    fn tick(&self, now: i64) -> Vec<Email> {
        tick::run_with_sources(&self.config, now, &Options::default(), &self.mail, &|_| {
            None
        })
        .expect("tick");
        self.mail.take()
    }

    /// Incidents du site, ouverts et clos, par id.
    fn incidents(&self) -> Vec<Incident> {
        let store = self.store();
        let mut all = store.open_incidents().expect("ouverts");
        all.extend(store.closed_incidents("site-a", 0).expect("clos"));
        all.sort_by_key(|i| i.id);
        all
    }

    fn open_checks(&self) -> Vec<String> {
        self.store()
            .open_incidents()
            .expect("ouverts")
            .into_iter()
            .map(|i| i.check_name)
            .collect()
    }

    /// Incident ouvert, annoncé, pour qu'une clôture parte par e-mail.
    fn seed(&self, check: &str, at: i64) -> i64 {
        let mut store = self.store();
        let finding = Finding::new("site-a", check, Severity::Critical, "seed", "semé");
        store
            .record_result(
                "site-a",
                check,
                at,
                &RunRecord::concluded(std::slice::from_ref(&finding)),
            )
            .expect("record_result");
        store
            .reconcile("site-a", check, &[finding], at)
            .expect("reconcile");
        let incident = store
            .open_incidents()
            .expect("ouverts")
            .into_iter()
            .find(|i| i.check_name == check)
            .expect("ouvert");
        store.mark_open_notified(incident.id, at).expect("annoncé");
        incident.id
    }

    fn drops(&self) -> Vec<(String, i64)> {
        self.store().report_drops().expect("écartés")
    }
}

fn assert_never_restored(emails: &[Email]) {
    for email in emails {
        assert!(
            !email.subject.to_lowercase().contains("rétabli")
                && !email.body.to_lowercase().contains("rétabli"),
            "{email:?}"
        );
    }
}

#[test]
fn an_incident_of_a_retired_family_closes_as_unwatched_and_never_reopens() {
    let h = Harness::new(site("site-a", SiteKind::Wordpress, None, false), true);
    let id = h.seed("agent:php", T0);

    let emails = h.tick(T0 + 60);
    let closed = h.store().incident(id).expect("lu").expect("présent");
    assert_eq!(closed.close_reason, Some(CloseReason::Unwatched));
    assert_eq!(emails.len(), 1, "{emails:?}");
    assert!(emails[0].subject.contains("plus surveillé"), "{emails:?}");
    assert_never_restored(&emails);

    // L'agent l'émet encore : écarté et compté, rien ne se rouvre.
    let accepted = h.report(1, T0 + 120, &["php"]);
    assert_eq!(accepted.dropped, 1);
    assert_eq!(h.drops(), [("site-a".to_owned(), 1)]);
    let emails = h.tick(T0 + 180);
    assert!(emails.is_empty(), "{emails:?}");
    assert!(!h.open_checks().contains(&"agent:php".to_owned()));
    let report = h.report(2, T0 + 240, &[]);
    assert_eq!(report.dropped, 0);
    assert!(h.drops().is_empty(), "le compte suit le dernier rapport");
}

#[test]
fn a_dropped_family_is_neither_restored_nor_recorded_ok() {
    // `uploads-php` d'un site generic en PHP : non admis, WordPress seul.
    let h = Harness::new(
        site("site-a", SiteKind::Generic, Some(Runtime::Php), false),
        true,
    );
    let id = h.seed("agent:uploads-php", T0);
    let run_before = || {
        h.store()
            .check_results()
            .expect("passages")
            .into_iter()
            .find(|r| r.check_name == "agent:uploads-php")
            .expect("passage")
    };
    let before = run_before();

    // Un rapport sans le constat ne clôt pas « rétabli », et ne note pas « ok ».
    let accepted = h.report(1, T0 + 60, &[]);
    assert_eq!(accepted.dropped, 0);
    let incident = h.store().incident(id).expect("lu").expect("présent");
    assert_eq!(incident.closed_at, None, "pas de faux « rétabli »");
    assert_eq!(run_before(), before, "pas de passage « ok »");

    // Avec le constat : écarté et compté, toujours rien de noté.
    let accepted = h.report(2, T0 + 120, &["uploads-php", "critical-file"]);
    assert_eq!(accepted.dropped, 1);
    assert_eq!(run_before(), before);
    assert_eq!(run_before().result, Some(RunResult::Finding));
    assert!(h.open_checks().contains(&"agent:critical-file".to_owned()));

    // `tick` le clôt « plus surveillé ».
    let emails = h.tick(T0 + 180);
    let incident = h.store().incident(id).expect("lu").expect("présent");
    assert_eq!(incident.close_reason, Some(CloseReason::Unwatched));
    let closes: Vec<&Email> = emails
        .iter()
        .filter(|e| e.subject.contains("agent:uploads-php") || e.body.contains("agent:uploads-php"))
        .collect();
    assert_eq!(closes.len(), 1, "{emails:?}");
    assert!(closes[0].subject.contains("plus surveillé"));
    assert_never_restored(&emails);
}

#[test]
fn a_key_on_a_static_site_opens_only_the_typology_warning() {
    let h = Harness::new(
        site("site-a", SiteKind::Generic, Some(Runtime::Static), false),
        true,
    );
    let accepted = h.report(1, T0 + 60, &SENT[..4]);
    assert_eq!(accepted.dropped, 4, "aucune famille admise");
    assert!(h.open_checks().is_empty());

    // Silence dépassé : aucun heartbeat, seulement `typology`.
    h.tick(T0 + 10_000);
    assert_eq!(h.open_checks(), [TYPOLOGY]);
    let runs: Vec<String> = h
        .store()
        .check_results()
        .expect("passages")
        .into_iter()
        .map(|r| r.check_name)
        .filter(|name| !CheckKind::ALL.iter().any(|k| k.name() == name))
        .collect();
    assert_eq!(runs, [TYPOLOGY], "aucun passage d'un contrôle d'agent");
    let ctx = Ctx {
        agent: true,
        baseline: false,
    };
    let controls = capability::allowed_controls(&h.config.sites[0], &ctx);
    assert!(controls.contains(&Control::Typology));
    assert!(
        !controls
            .iter()
            .any(|c| c.is_agent() || *c == Control::Heartbeat)
    );
}

#[test]
fn a_key_on_a_generic_site_without_runtime_warns_until_php_is_declared() {
    let mut h = Harness::new(site("site-a", SiteKind::Generic, None, false), true);
    let emails = h.tick(T0 + 60);
    assert_eq!(h.open_checks(), [TYPOLOGY]);
    assert_eq!(emails.len(), 1, "{emails:?}");
    assert!(
        emails[0]
            .subject
            .contains("agent enregistré sur un site sans runtime php : déclarer runtime = \"php\""),
        "{emails:?}"
    );
    let first = h.incidents();
    h.tick(T0 + 120);
    h.tick(T0 + 180);
    assert_eq!(h.incidents(), first, "toujours le même incident ouvert");

    // `runtime = "php"` déclaré : clos « rétabli ».
    h.config.sites[0].runtime = Some(Runtime::Php);
    let emails = h.tick(T0 + 240);
    let typology = &h.incidents()[0];
    assert_eq!(typology.close_reason, Some(CloseReason::Resolved));
    assert_eq!(emails.len(), 1, "{emails:?}");
    assert!(emails[0].subject.contains("rétabli"), "{emails:?}");
    assert!(h.open_checks().is_empty());
}

#[test]
fn a_typology_warning_closes_as_unwatched_when_the_key_is_removed() {
    let h = Harness::new(site("site-a", SiteKind::Generic, None, false), true);
    h.tick(T0 + 60);
    assert_eq!(h.open_checks(), [TYPOLOGY]);
    assert!(h.store().remove_key("site-a", 0).expect("retrait"));
    let emails = h.tick(T0 + 120);
    assert_eq!(h.incidents()[0].close_reason, Some(CloseReason::Unwatched));
    assert_eq!(emails.len(), 1, "{emails:?}");
    assert!(emails[0].subject.contains("plus surveillé"), "{emails:?}");
    assert_never_restored(&emails);
}

#[test]
fn agent_incidents_close_as_unwatched_when_the_key_is_removed() {
    let h = Harness::new(site("site-a", SiteKind::Wordpress, None, false), true);
    h.report(1, T0 + 60, &["critical-file", "uploads-php"]);
    h.tick(T0 + 120);
    let mut open = h.open_checks();
    open.sort();
    assert_eq!(open, ["agent:critical-file", "agent:uploads-php"]);

    assert!(h.store().remove_key("site-a", 0).expect("retrait"));
    let emails = h.tick(T0 + 180);
    assert!(h.open_checks().is_empty());
    for incident in h.incidents() {
        assert_eq!(
            incident.close_reason,
            Some(CloseReason::Unwatched),
            "{incident:?}"
        );
    }
    assert_eq!(emails.len(), 2, "{emails:?}");
    assert!(emails.iter().all(|e| e.subject.contains("plus surveillé")));
    assert_never_restored(&emails);
}

#[test]
fn the_logs_incident_is_kept_only_with_a_source() {
    let with = Harness::new(site("site-a", SiteKind::Generic, None, true), false);
    let id = with.seed("logs", T0);
    with.tick(T0 + 60);
    let incident = with.store().incident(id).expect("lu").expect("présent");
    assert_eq!(incident.closed_at, None, "gardé avec une source");

    let without = Harness::new(site("site-a", SiteKind::Generic, None, false), false);
    let id = without.seed("logs", T0);
    let emails = without.tick(T0 + 60);
    let incident = without.store().incident(id).expect("lu").expect("présent");
    assert_eq!(incident.close_reason, Some(CloseReason::Unwatched));
    assert_never_restored(&emails);
}

#[test]
fn vulns_is_watched_only_with_a_declared_inventory_source() {
    use vigie::config::{InventorySource, SiteInventory};
    assert_eq!(Control::from_name("vulns"), Some(Control::Vulns));
    for (kind, runtime) in KINDS {
        for ctx in CONTEXTS {
            let mut site = site("site-a", kind, runtime, false);
            assert!(!capability::watched(&site, "vulns", &ctx), "{kind:?}");
            site.inventory = Some(SiteInventory::new(&[InventorySource::Ci]));
            assert!(capability::watched(&site, "vulns", &ctx), "{kind:?}");
            site.inventory = Some(SiteInventory::new(&[InventorySource::AgentPhp]));
            let php = site.effective_runtime() == Some(Runtime::Php);
            assert_eq!(capability::watched(&site, "vulns", &ctx), php, "{kind:?}");
        }
    }
}

// --- Contrôles du veilleur (#16) --------------------------------------------

#[test]
fn vulns_sync_is_a_watcher_control_never_watched_for_a_site() {
    assert_eq!(Control::ALL.len(), 17);
    assert_eq!(Control::from_name("vulns-sync"), Some(Control::VulnsSync));
    for (kind, runtime) in KINDS {
        for ctx in CONTEXTS {
            let site = site("site-a", kind, runtime, true);
            assert!(!capability::watched(&site, "vulns-sync", &ctx));
        }
    }
    // Le pseudo-site est hors de la grammaire des identifiants de site.
    assert!(!vigie::config::is_valid_id(capability::WATCHER_SITE));
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = config(dir.path(), Vec::new());
    assert!(!capability::watched_by_watcher(
        &config,
        "vulns-sync",
        Some("osv-npm")
    ));
    config.vulns = Some(vigie::config::Vulns {
        sources: vec!["osv-npm".into()],
        wordfence: None,
    });
    assert!(capability::watched_by_watcher(
        &config,
        "vulns-sync",
        Some("osv-npm")
    ));
    for (check, key) in [
        ("vulns-sync", Some("osv-crates-io")),
        ("vulns-sync", None),
        ("exposed", Some("osv-npm")),
        ("inconnu", Some("osv-npm")),
    ] {
        assert!(
            !capability::watched_by_watcher(&config, check, key),
            "{check} {key:?}"
        );
    }
}
