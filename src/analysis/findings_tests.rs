//! Phase 3 : constats, instantanés, partage et branchement à `tick`.
//!
//! IP des plages de documentation (RFC 5737, et 2001:db8::/32 quand il en
//! faut plus de 768) ; domaines en example.org.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::path::Path;
use std::time::Duration;

use super::catalog::BotClass;
use super::findings::{
    self, Analysis, BOTS_AI_TRAINING, BotSeen, CHECK, IpVerdict, LOAD, MASKED, SUSPICIOUS_IPS,
};
use super::load::{DEFAULT_THRESHOLD_US, HourLoad};
use super::profile::{HOUR_MS, MINUTE_MS};
use super::rules::DEFAULT_IDS;
use super::score::Level;
use super::shared::{self, TTL_SECS};
use super::store as agg;
use crate::alert::MemoryNotifier;
use crate::clock::{Clock, FakeClock};
use crate::config::Config;
use crate::finding::{Finding, Severity};
use crate::logs::Entry;
use crate::logs::source::{LogSource, MemorySource};
use crate::store::{Incident, Store};
use crate::tick::{self, Options, Summary};

/// 2026-10-15T10:00:00Z, en secondes.
const T0: i64 = 1_792_022_400 + 10 * 3600;
const CURL: &str = "curl/8.4.0";
const FIREFOX: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0";
const SCRAPER: &str =
    "Mozilla/5.0 (compatible; ExampleScraperBot/2.1; +https://scraper.example.org/bot)";

fn ip(text: &str) -> IpAddr {
    text.parse().expect("ip")
}

fn v6(n: u32) -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(
        0x2001,
        0xdb8,
        0,
        0,
        0,
        0,
        (n >> 16) as u16,
        n as u16,
    ))
}

fn req(timestamp_ms: i64, from: IpAddr, path: &str, status: u16, ua: &str) -> Entry {
    Entry {
        ip: Some(from),
        method: Some("GET".into()),
        user_agent: ua.into(),
        ..Entry::new(timestamp_ms, path, status)
    }
}

fn facet(timestamp_ms: i64, from: IpAddr, ua: &str) -> Entry {
    Entry {
        query_keys: vec!["q".into()],
        ..req(timestamp_ms, from, "/categorie", 200, ua)
    }
}

/// Sites `ids`, chacun avec une source de logs déclarée (`with_source`).
fn config(dir: &Path, ids: &[&str], with_source: bool) -> Config {
    let mut text = format!(
        "database = '{}'\n[alerts]\nto = \"a@example.org\"\nfrom = \"v@example.org\"\nsmtp_host = \"smtp.example.org\"\npassword_file = \"/x\"\n",
        dir.join("vigie.db").display()
    );
    for id in ids {
        text.push_str(&format!(
            "[[sites]]\nid = \"{id}\"\nurl = \"https://{id}.example.org/\"\nagent_silence = 900\n"
        ));
        if with_source {
            text.push_str(&format!(
                "[sites.logs]\nsource = \"alwaysdata\"\nhosts = [\"{id}.example.org\"]\n"
            ));
        }
    }
    crate::config::parse(Path::new("config.toml"), &text).expect("configuration")
}

/// Un passage de `tick`, sans contrôle externe, sur des `MemorySource` :
/// chaque passage voit toutes les entrées et reprend au curseur enregistré.
fn tick_at(
    config: &Config,
    now: i64,
    logs: &HashMap<&str, Vec<Entry>>,
    max_batches: usize,
) -> Summary {
    let options = Options {
        check_budget: Duration::ZERO,
        analysis_max_batches: max_batches,
        ..Options::default()
    };
    let mail = MemoryNotifier::new();
    tick::run_with_sources(config, now, &options, &mail, &|site| {
        logs.get(site.id.as_str()).map(|entries| {
            Box::new(MemorySource::new("memoire", entries.clone())) as Box<dyn LogSource>
        })
    })
    .expect("tick")
}

fn open_logs(store: &Store, site: &str) -> Vec<Incident> {
    store
        .open_incidents()
        .expect("incidents")
        .into_iter()
        .filter(|i| i.site == site && i.check_name == CHECK)
        .collect()
}

fn find<'a>(incidents: &'a [Incident], key: &str) -> Option<&'a Incident> {
    incidents
        .iter()
        .find(|i| i.key.ends_with(&format!("/{key}")))
}

// --- Assainissement --------------------------------------------------------

#[test]
fn details_are_sanitized_and_paths_cut() {
    let cases = [
        ("a\u{0}b", "a\u{FFFD}b"),
        ("ligne\nsuivante\r", "ligne\u{FFFD}suivante\u{FFFD}"),
        ("\u{1b}[31mrouge", "\u{FFFD}[31mrouge"),
        ("del\u{7f}", "del\u{FFFD}"),
        ("c1\u{85}\u{9b}", "c1\u{FFFD}\u{FFFD}"),
        ("sep\u{2028}\u{2029}", "sep\u{FFFD}\u{FFFD}"),
        ("bidi\u{202e}txt.exe\u{202c}", "bidi\u{FFFD}txt.exe\u{FFFD}"),
        (
            "iso\u{2066}x\u{2069}\u{200f}\u{61c}",
            "iso\u{FFFD}x\u{FFFD}\u{FFFD}\u{FFFD}",
        ),
        ("accentué : é ✓", "accentué : é ✓"),
    ];
    for (raw, clean) in cases {
        assert_eq!(findings::sanitize(raw), clean, "{raw:?}");
    }
    assert_eq!(
        findings::detail_path("/panier?token=secret&id=1"),
        "/panier"
    );
    assert_eq!(findings::detail_path("/a\u{202e}b"), "/a\u{FFFD}b");
    let long = format!("/{}", "x".repeat(300));
    let cut = findings::detail_path(&long);
    assert_eq!(cut.chars().count(), findings::DETAIL_PATH);
    assert!(cut.ends_with('…'));
}

// --- Constats agrégés et bornés -------------------------------------------

#[test]
fn a_rule_cannot_take_the_key_of_a_finding() {
    for id in [SUSPICIOUS_IPS, BOTS_AI_TRAINING, LOAD] {
        let rule = super::rules::Rule {
            id: id.into(),
            path: Default::default(),
            methods: Vec::new(),
            statuses: Default::default(),
            scope: super::rules::Scope::Site,
            min_count: 1,
            min_ips: 1,
            window_secs: 600,
            severity: Severity::Info,
        };
        let err = super::rules::compile_rules(&[], &[rule], &[]).expect_err(id);
        assert!(err.to_string().contains("réservé"), "{err}");
    }
}

#[test]
fn a_thousand_suspicious_ips_make_one_incident_and_no_key_holds_an_ip_or_a_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = config(dir.path(), &["site-a"], true);
    let start = (T0 - 600) * 1000;
    let mut entries = Vec::new();
    // 1 000 IP, 20 facettes chacune en une minute, UA curl, sans referer ni
    // ressource statique : score élevé pour chacune.
    for n in 0..1000u32 {
        for j in 0..20 {
            entries.push(facet(start + i64::from(n) * 30 + j * 1000, v6(n), CURL));
        }
    }
    // Chemins sensibles depuis six IP, avec une query string.
    for k in 1..=6 {
        entries.push(Entry {
            query_keys: vec!["token".into()],
            ..req(
                start + 60_000 + k * 1000,
                ip(&format!("203.0.113.{k}")),
                "/.env",
                404,
                FIREFOX,
            )
        });
    }
    let logs = HashMap::from([("site-a", entries)]);
    let summary = tick_at(&config, T0, &logs, usize::MAX);
    assert_eq!(summary.logs_folded, 20_006);

    let store = Store::open(&config.database).expect("base");
    let open = open_logs(&store, "site-a");
    let suspicious: Vec<_> = open
        .iter()
        .filter(|i| i.key.ends_with("/suspicious-ips"))
        .collect();
    assert_eq!(suspicious.len(), 1, "{open:#?}");
    let incident = suspicious[0];
    assert_eq!(incident.severity, Severity::Warning);
    assert!(
        incident.detail.starts_with("1000 IP au score élevé"),
        "{}",
        incident.detail
    );
    let cited = incident
        .detail
        .split([' ', ','])
        .filter(|t| t.parse::<IpAddr>().is_ok())
        .count();
    assert_eq!(cited, findings::DETAIL_ITEMS, "{}", incident.detail);

    let sensitive = find(&open, "sensitive-path").expect("sensitive-path");
    assert_eq!(sensitive.severity, Severity::Info);
    let many = find(&open, "sensitive-path-many").expect("sensitive-path-many");
    assert_eq!(many.severity, Severity::Warning);
    assert!(!many.detail.contains(".env") && !many.detail.contains("token"));

    // Aucune IP ni chemin dans une clé : `site/logs/<identifiant>`.
    let allowed: Vec<&str> = DEFAULT_IDS
        .iter()
        .copied()
        .chain([SUSPICIOUS_IPS, BOTS_AI_TRAINING, LOAD])
        .collect();
    for incident in &open {
        let id = incident
            .key
            .strip_prefix("site-a/logs/")
            .expect("clé du contrôle logs");
        assert!(allowed.contains(&id), "{}", incident.key);
        assert!(
            id.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
            "{}",
            incident.key
        );
        assert!(
            !id.split('-').any(|t| t.parse::<IpAddr>().is_ok()),
            "{}",
            incident.key
        );
    }

    // L'instantané garde les 1 000 verdicts élevés, du pire au moins pire.
    let latest = findings::latest(&store, "site-a")
        .expect("lecture")
        .expect("instantané");
    assert_eq!(latest.verdicts.len(), 1000);
    assert!(latest.verdicts.iter().all(|v| v.level == Level::High));
    assert!(
        latest
            .verdicts
            .windows(2)
            .all(|w| (w[0].score, w[1].ip) >= (w[1].score, w[0].ip))
    );
    // Le résumé ne contient aucune IP.
    let summary: String = store
        .conn
        .query_row(
            "SELECT summary FROM log_analysis WHERE site = 'site-a'",
            [],
            |row| row.get(0),
        )
        .expect("résumé");
    assert!(!summary.contains("2001:db8") && !summary.contains("203.0.113"));
    assert!(!shared::contains_ip(&summary), "{summary}");
}

#[test]
fn spike_404_resolves_once_data_stops_for_window_plus_agent_silence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = config(dir.path(), &["site-a"], true);
    let clock = FakeClock::new(T0);
    let last = clock.unix_ms() - 1000;
    let entries: Vec<_> = (0..100)
        .map(|i| {
            req(
                last - (99 - i) * 3000,
                ip(&format!("198.51.100.{}", i % 50 + 1)),
                "/disparu",
                404,
                FIREFOX,
            )
        })
        .collect();
    let logs = HashMap::from([("site-a", entries)]);
    tick_at(&config, clock.unix(), &logs, usize::MAX);
    let store = Store::open(&config.database).expect("base");
    let opened = find(&open_logs(&store, "site-a"), "spike-404")
        .expect("spike-404 ouvert")
        .clone();

    // Référence = dernière entrée : fenêtre (600 s) + agent_silence (900 s)
    // tout juste atteints, le constat reste.
    clock.advance(1500 - 1);
    tick_at(&config, clock.unix(), &logs, usize::MAX);
    let still = find(&open_logs(&store, "site-a"), "spike-404")
        .expect("toujours ouvert")
        .clone();
    assert_eq!(still.id, opened.id);

    clock.advance(2);
    tick_at(&config, clock.unix(), &logs, usize::MAX);
    assert!(find(&open_logs(&store, "site-a"), "spike-404").is_none());
    let closed = store
        .incident(opened.id)
        .expect("lecture")
        .expect("incident");
    assert_eq!(closed.closed_at, Some(clock.unix()));
}

#[test]
fn two_ticks_with_the_budget_spent_mid_series_count_nothing_twice() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = config(dir.path(), &["site-a"], true);
    let now_ms = T0 * 1000;
    let entries: Vec<_> = (0..1_200)
        .map(|i| {
            req(
                now_ms - 9 * MINUTE_MS + i * 400,
                ip(&format!("192.0.2.{}", i % 40 + 1)),
                "/ancien",
                404,
                FIREFOX,
            )
        })
        .collect();
    let logs = HashMap::from([("site-a", entries)]);
    let total = |store: &Store, at: i64| -> u64 {
        agg::load(store, "site-a", at)
            .expect("charge")
            .iter()
            .map(|h| h.requests)
            .sum()
    };

    // Premier passage : un lot, puis budget épuisé.
    let first = tick_at(&config, T0, &logs, 1);
    assert_eq!(first.logs_folded, 500);
    let store = Store::open(&config.database).expect("base");
    assert_eq!(total(&store, now_ms), 500);
    let opened = find(&open_logs(&store, "site-a"), "spike-404")
        .expect("ouvert dès le premier lot")
        .clone();

    // Passage suivant : reprise au curseur, jusqu'au bout.
    let second = tick_at(&config, T0 + 60, &logs, usize::MAX);
    assert_eq!(second.logs_folded, 700);
    assert_eq!(total(&store, now_ms), 1_200);
    let third = tick_at(&config, T0 + 120, &logs, usize::MAX);
    assert_eq!(third.logs_folded, 0);
    assert_eq!(total(&store, now_ms), 1_200);
    let profiles = agg::profiles(&store, "site-a", now_ms).expect("profils");
    assert_eq!(profiles.len(), 40);
    assert!(profiles.iter().all(|p| p.stats.requests == 30));

    let open = open_logs(&store, "site-a");
    let spike = find(&open, "spike-404").expect("toujours ouvert");
    assert_eq!(spike.id, opened.id, "pas de clôture puis réouverture");
    assert!(
        spike.detail.starts_with("1200 requête(s)"),
        "{}",
        spike.detail
    );
    assert!(
        store
            .closed_incidents("site-a", 0)
            .expect("clos")
            .is_empty(),
        "aucun incident clos"
    );
}

// --- Partage -----------------------------------------------------------------

#[test]
fn a_signature_noted_on_a_adds_15_points_on_b_without_b_noting_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = config(dir.path(), &["site-a", "site-b"], true);
    let start = (T0 - 600) * 1000;
    // Site A : 60 facettes en une minute, score propre 75.
    let on_a: Vec<_> = (0..60)
        .map(|i| facet(start + i * 900, ip("192.0.2.10"), SCRAPER))
        .collect();
    // Site B : le même UA, 20 facettes espacées, score propre 60.
    let on_b: Vec<_> = (0..20)
        .map(|i| facet(start + i * 25_000, ip("198.51.100.20"), SCRAPER))
        .collect();
    let logs = HashMap::from([("site-a", on_a), ("site-b", on_b)]);
    tick_at(&config, T0, &logs, usize::MAX);
    let store = Store::open(&config.database).expect("base");

    let signature = shared::signature(SCRAPER).expect("signature");
    assert_eq!(
        shared::noted(&store, "site-a").expect("A"),
        [(signature.clone(), 75)]
    );
    let a = findings::latest(&store, "site-a")
        .expect("A")
        .expect("instantané");
    assert_eq!(a.verdicts[0].own_score, 75);
    assert!(!a.verdicts[0].shared);

    let b = findings::latest(&store, "site-b")
        .expect("B")
        .expect("instantané");
    let verdict = &b.verdicts[0];
    assert_eq!(verdict.ip, ip("198.51.100.20"));
    assert_eq!((verdict.own_score, verdict.score), (60, 75));
    assert_eq!(verdict.level, Level::High);
    assert!(verdict.shared);
    assert!(verdict.reasons.iter().any(|r| r.points == 15));
    // Le bonus seul ne note pas : B n'a rien noté.
    assert!(shared::noted(&store, "site-b").expect("B").is_empty());
    assert!(find(&open_logs(&store, "site-b"), SUSPICIOUS_IPS).is_some());

    // Aucune IP dans `log_signatures`.
    let mut stmt = store
        .conn
        .prepare("SELECT ua, site, score, seen_at, expires_at FROM log_signatures")
        .expect("prepare");
    let rows: Vec<(String, String, i64, i64, i64)> = stmt
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .expect("query")
        .collect::<rusqlite::Result<_>>()
        .expect("rows");
    assert_eq!(rows.len(), 1);
    for (ua, site, _, seen_at, expires_at) in &rows {
        for text in [ua, site] {
            assert!(!shared::contains_ip(text), "{text}");
            assert!(!text.contains("192.0.2") && !text.contains("198.51.100"));
        }
        assert_eq!(expires_at - seen_at, TTL_SECS);
    }
    drop(stmt);

    // Expiration à 30 jours.
    assert!(
        shared::elsewhere(&store, "site-b", T0 + TTL_SECS - 1)
            .expect("lecture")
            .contains(&signature)
    );
    assert!(
        shared::elsewhere(&store, "site-b", T0 + TTL_SECS)
            .expect("lecture")
            .is_empty()
    );
    drop(store);
    let mut store = Store::open(&config.database).expect("base");
    assert_eq!(
        shared::purge(&mut store, T0 + TTL_SECS - 1).expect("purge"),
        0
    );
    assert_eq!(shared::purge(&mut store, T0 + TTL_SECS).expect("purge"), 1);
}

#[test]
fn a_site_keeps_its_100_most_recent_signatures() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = Store::open(&dir.path().join("vigie.db")).expect("base");
    for n in 0..120 {
        let signature =
            shared::signature(&format!("ExampleBot{}x/1.0", n * 7 + 1)).expect("signature");
        shared::note(&mut store, "site-a", &[(signature, 80)], T0 + n).expect("note");
    }
    let noted = shared::noted(&store, "site-a").expect("lecture");
    assert_eq!(noted.len(), shared::MAX_PER_SITE);
    assert_eq!(noted[0].0, "examplebot834x/");
}

// --- Instantanés et purges --------------------------------------------------

fn verdict(n: u32, score: u8) -> IpVerdict {
    IpVerdict {
        ip: v6(n),
        score,
        own_score: score,
        level: Level::of(score),
        class: BotClass::Browser,
        bot: None,
        requests: 100,
        shared: false,
        reasons: Vec::new(),
    }
}

fn snapshot(site: &str, generated_at: i64) -> Analysis {
    Analysis {
        site: site.into(),
        generated_at,
        reference_ms: generated_at * 1000,
        bots: Vec::new(),
        verdicts: vec![verdict(1, 85), verdict(2, 45)],
        scored: 2,
        unscored: 0,
        rules: Vec::new(),
        load: Vec::new(),
        load_threshold_us: DEFAULT_THRESHOLD_US,
    }
}

fn snapshot_times(store: &Store, table: &str) -> Vec<i64> {
    let mut stmt = store
        .conn
        .prepare(&format!(
            "SELECT DISTINCT generated_at FROM {table} ORDER BY generated_at"
        ))
        .expect("prepare");
    stmt.query_map([], |row| row.get(0))
        .expect("query")
        .collect::<rusqlite::Result<_>>()
        .expect("rows")
}

#[test]
fn snapshots_keep_the_latest_and_purge_verdicts_at_48_hours_and_summaries_at_30_days() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = Store::open(&dir.path().join("vigie.db")).expect("base");
    // Un site qui n'a pas (ou plus) de source : purgé quand même.
    let g = T0;
    for at in [g, g + 300, g + 1000] {
        findings::persist(&mut store, &snapshot("site-z", at)).expect("instantané");
    }
    // `g` a plus de 15 min de moins que `g + 1000` ; `g + 300` non.
    assert_eq!(snapshot_times(&store, "log_analysis"), [g + 300, g + 1000]);
    assert_eq!(snapshot_times(&store, "log_verdicts"), [g + 300, g + 1000]);
    let latest = findings::latest(&store, "site-z")
        .expect("lecture")
        .expect("instantané");
    assert_eq!(latest.generated_at, g + 1000);
    assert_eq!(latest.verdicts, [verdict(1, 85), verdict(2, 45)]);

    findings::purge(&mut store, g + 1000 + 48 * 3600).expect("purge");
    assert_eq!(snapshot_times(&store, "log_verdicts"), [g + 1000]);
    findings::purge(&mut store, g + 1000 + 48 * 3600 + 1).expect("purge");
    assert!(snapshot_times(&store, "log_verdicts").is_empty());
    let latest = findings::latest(&store, "site-z")
        .expect("lecture")
        .expect("résumé gardé");
    assert!(latest.verdicts.is_empty());
    assert_eq!(latest.scored, 2);

    findings::purge(&mut store, g + 1000 + 30 * 86_400 + 1).expect("purge");
    assert!(
        findings::latest(&store, "site-z")
            .expect("lecture")
            .is_none()
    );
}

#[test]
fn closed_logs_details_are_masked_after_30_days() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = Store::open(&dir.path().join("vigie.db")).expect("base");
    let logs = Finding::new(
        "site-a",
        CHECK,
        Severity::Warning,
        SUSPICIOUS_IPS,
        "1 IP au score élevé : 192.0.2.10",
    );
    let other = Finding::new("site-a", "tls", Severity::Warning, "expiry", "12 jours");
    store
        .reconcile("site-a", CHECK, &[logs], T0)
        .expect("ouvert");
    store
        .reconcile("site-a", "tls", &[other], T0)
        .expect("ouvert");
    store
        .reconcile("site-a", CHECK, &[], T0 + 60)
        .expect("clos");
    store
        .reconcile("site-a", "tls", &[], T0 + 60)
        .expect("clos");

    findings::purge(&mut store, T0 + 60 + 30 * 86_400).expect("purge");
    let detail = |store: &Store, check: &str| {
        store
            .closed_incidents("site-a", 0)
            .expect("clos")
            .into_iter()
            .find(|i| i.check_name == check)
            .expect("incident")
            .detail
    };
    assert_eq!(detail(&store, CHECK), "1 IP au score élevé : 192.0.2.10");
    findings::purge(&mut store, T0 + 60 + 30 * 86_400 + 1).expect("purge");
    assert_eq!(detail(&store, CHECK), MASKED);
    assert_eq!(detail(&store, "tls"), "12 jours");
}

#[test]
fn site_remove_purges_the_analysis_of_the_site() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = config(dir.path(), &["site-a"], true);
    let start = (T0 - 600) * 1000;
    let entries: Vec<_> = (0..60)
        .map(|i| facet(start + i * 900, ip("192.0.2.10"), SCRAPER))
        .collect();
    tick_at(
        &config,
        T0,
        &HashMap::from([("site-a", entries)]),
        usize::MAX,
    );
    let mut store = Store::open(&config.database).expect("base");
    store.add_key("site-a", &[7; 32], T0).expect("clé");
    let tables = [
        "log_buckets",
        "log_profiles",
        "log_bots",
        "log_load",
        "log_cursors",
        "log_analysis",
        "log_verdicts",
        "log_signatures",
    ];
    let rows = |store: &Store, table: &str| -> i64 {
        store
            .conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE site = 'site-a'"),
                [],
                |row| row.get(0),
            )
            .expect("count")
    };
    for table in [
        "log_profiles",
        "log_load",
        "log_cursors",
        "log_analysis",
        "log_verdicts",
        "log_signatures",
    ] {
        assert!(rows(&store, table) > 0, "{table}");
    }
    assert!(store.remove_key("site-a", 0).expect("retrait"));
    for table in tables {
        assert_eq!(rows(&store, table), 0, "{table}");
    }
}

#[test]
fn logs_incidents_are_closed_only_for_a_site_without_a_source() {
    let dir = tempfile::tempdir().expect("tempdir");
    let with = config(dir.path(), &["site-a"], true);
    let start = (T0 - 600) * 1000;
    let entries: Vec<_> = (0..60)
        .map(|i| facet(start + i * 900, ip("192.0.2.10"), SCRAPER))
        .collect();
    let logs = HashMap::from([("site-a", entries)]);
    tick_at(&with, T0, &logs, usize::MAX);
    let store = Store::open(&with.database).expect("base");
    let opened = find(&open_logs(&store, "site-a"), SUSPICIOUS_IPS)
        .expect("ouvert")
        .clone();
    drop(store);

    // Rien de nouveau : les verdicts sont repris de l'instantané, le constat
    // reste le même incident.
    let summary = tick_at(&with, T0 + 60, &logs, usize::MAX);
    assert_eq!(summary.logs_folded, 0);
    let store = Store::open(&with.database).expect("base");
    let open = open_logs(&store, "site-a");
    let kept = find(&open, SUSPICIOUS_IPS).expect("gardé");
    assert_eq!(kept.id, opened.id);
    drop(store);

    // Plus de source : le contrôle `logs` n'est plus surveillé.
    let without = config(dir.path(), &["site-a"], false);
    tick_at(&without, T0 + 120, &HashMap::new(), usize::MAX);
    let store = Store::open(&without.database).expect("base");
    assert!(open_logs(&store, "site-a").is_empty());
    let closed = store
        .incident(opened.id)
        .expect("lecture")
        .expect("incident");
    assert_eq!(closed.closed_at, Some(T0 + 120));
}

// --- Robots d'entraînement et charge ----------------------------------------

#[test]
fn ai_training_bots_are_information_and_load_is_a_warning_while_fresh() {
    let reference = T0 * 1000;
    let hour = reference.div_euclid(HOUR_MS);
    let busy = HourLoad {
        hour,
        requests: 10_000,
        timed: 10_000,
        service_us: 2_400_000_000,
        facets_us: 1_200_000_000,
        bots_us: 600_000_000,
        ..HourLoad::default()
    };
    let analysis = Analysis {
        site: "site-a".into(),
        generated_at: T0,
        reference_ms: reference,
        bots: vec![BotSeen {
            name: "GPTBot".into(),
            publisher: "OpenAI".into(),
            purpose: "entraînement de modèles".into(),
            robots_only: false,
            honours_robots: true,
            class: BotClass::AiTraining,
            protected: false,
            requests: 120,
        }],
        verdicts: Vec::new(),
        scored: 0,
        unscored: 0,
        rules: Vec::new(),
        load: vec![busy],
        load_threshold_us: DEFAULT_THRESHOLD_US,
    };
    let silence = 900_000;
    let found = findings::findings(&analysis, reference, silence);
    let keys: Vec<(&str, Severity)> = found.iter().map(|f| (f.key.as_str(), f.severity)).collect();
    assert_eq!(
        keys,
        [
            (BOTS_AI_TRAINING, Severity::Info),
            (LOAD, Severity::Warning)
        ]
    );
    assert!(found[0].detail.contains("GPTBot (OpenAI) : 120"));
    assert!(
        found[1].detail.starts_with("2400 s de service"),
        "{}",
        found[1].detail
    );
    assert!(found[1].detail.contains("facettes 50 %, robots 25 %"));

    // Une heure sans durée n'ouvre jamais `load`.
    let mut untimed = analysis.clone();
    untimed.load[0].timed = 0;
    assert!(
        findings::findings(&untimed, reference, silence)
            .iter()
            .all(|f| f.key != LOAD)
    );

    // Plus de données depuis une heure plus agent_silence : `load` se résout.
    let later = reference + 3_600_000 + silence + 1;
    let keys: Vec<String> = findings::findings(&analysis, later, silence)
        .into_iter()
        .map(|f| f.key)
        .collect();
    assert_eq!(keys, [BOTS_AI_TRAINING]);
}
