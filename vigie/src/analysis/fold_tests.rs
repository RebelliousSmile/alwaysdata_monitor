//! Phase 2 : repli incrémental, agrégats, profils, score, charge.
//!
//! IP des plages de documentation (RFC 5737, et 2001:db8::/32 quand il en
//! faut plus de 768).

use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};

use super::catalog::{BotClass, classify};
use super::fold::{BATCH_SIZE, SiteState, fold};
use super::load::DEFAULT_THRESHOLD_US;
use super::profile::{self, HOUR_MS, IpProfile, MAX_PROFILES, MINUTE_MS, Slice};
use super::rules::{self, RuleSet};
use super::score::Level;
use super::store::{self as agg, RuleWindow};
use crate::clock::{Clock, FakeClock};
use crate::logs::Entry;
use crate::logs::source::{Cursor, Fetched, LogSource, MemorySource};
use crate::store::Store;

/// 2026-10-15T00:00:00Z, en ms : un minuit UTC.
const MIDNIGHT: i64 = 1_792_022_400_000;
const SITE: &str = "site-a";
const FIREFOX: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0";
const GOOGLEBOT: &str = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
const GPTBOT: &str = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)";

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

fn req(timestamp_ms: i64, from: IpAddr, path: &str, status: u16) -> Entry {
    Entry {
        ip: Some(from),
        method: Some("GET".into()),
        user_agent: FIREFOX.into(),
        ..Entry::new(timestamp_ms, path, status)
    }
}

fn facet(timestamp_ms: i64, from: IpAddr) -> Entry {
    Entry {
        query_keys: vec!["q".into()],
        ..req(timestamp_ms, from, "/categorie", 200)
    }
}

fn default_rules() -> RuleSet {
    RuleSet {
        rules: rules::compile_rules(&[], &[], &[]).expect("défauts"),
        exclude: Vec::new(),
        behind_proxy: false,
    }
}

fn temp_store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(&dir.path().join("vigie.db")).expect("open");
    (dir, store)
}

/// Replie `entries` par lots, curseur = rang, comme `tick` le fera.
fn fold_all(
    store: &mut Store,
    state: &mut SiteState,
    rules: &RuleSet,
    entries: &[Entry],
    now_ms: i64,
) {
    for chunk in entries.chunks(BATCH_SIZE) {
        fold_chunk(store, state, rules, chunk.to_vec(), now_ms);
    }
}

fn fold_chunk(
    store: &mut Store,
    state: &mut SiteState,
    rules: &RuleSet,
    entries: Vec<Entry>,
    now_ms: i64,
) {
    let done: usize = state.cursor.0.parse().unwrap_or(0);
    let fetched = Fetched {
        next: Cursor((done + entries.len()).to_string()),
        entries,
        ..Fetched::default()
    };
    agg::fold_batch(store, state, rules, &fetched, now_ms).expect("lot");
}

fn profile_of(store: &Store, reference_ms: i64, of: IpAddr) -> Option<IpProfile> {
    agg::profiles(store, SITE, reference_ms)
        .expect("profils")
        .into_iter()
        .find(|p| p.ip == of)
}

fn window(store: &Store, rules: &RuleSet, reference_ms: i64, id: &str) -> RuleWindow {
    agg::rule_windows(store, SITE, rules, reference_ms)
        .expect("fenêtres")
        .into_iter()
        .find(|w| w.rule == id)
        .expect("règle")
}

// --- Statiques, facettes, tranches -----------------------------------------

#[test]
fn statics_follow_the_php_list_without_case() {
    for path in [
        "/a.js",
        "/a.CSS",
        "/i.png",
        "/i.JPG",
        "/i.jpeg",
        "/i.gif",
        "/i.webp",
        "/i.avif",
        "/f.woff",
        "/f.woff2",
        "/i.svg",
        "/favicon.ico",
        "/a.js.map",
        "/f.ttf",
        "/f.eot",
        "/f.otf",
    ] {
        assert!(profile::is_static(path), "{path}");
    }
    for path in [
        "/",
        "/a.json",
        "/a.js.php",
        "/dir.css/page",
        "/css",
        "/a.",
        "/.png/x",
    ] {
        assert!(!profile::is_static(path), "{path}");
    }
    let mut entry = req(MIDNIGHT, ip("192.0.2.1"), "/p", 200);
    assert!(!profile::is_facet(&entry));
    entry.query_keys = vec!["page".into(), "q".into()];
    assert!(profile::is_facet(&entry));
}

#[test]
fn pages_without_referer_count_only_pages() {
    let from = ip("192.0.2.1");
    let browser = classify(FIREFOX);
    let mut slice = Slice::default();
    slice.add(&req(MIDNIGHT, from, "/style.css", 200), &browser, true);
    slice.add(&req(MIDNIGHT, from, "/page", 403), &browser, false);
    let mut with_referer = req(MIDNIGHT, from, "/page", 200);
    with_referer.referer_present = true;
    slice.add(&with_referer, &browser, false);
    assert_eq!(slice.requests, 3);
    assert_eq!(slice.statics, 1);
    assert_eq!(slice.empty_referer_pages, 1);
    assert_eq!(slice.refused, 1);
    assert_eq!(slice.class, None);
    assert_eq!(slice.uas, [FIREFOX]);
}

// --- Score à partir des agrégats -------------------------------------------

#[test]
fn a_facet_scraper_with_a_firefox_ua_scores_high() {
    let (_dir, mut store) = temp_store();
    let rules = default_rules();
    let mut state = agg::open_site(&mut store, SITE, 900, MIDNIGHT).expect("état");
    let scraper = ip("192.0.2.10");
    let entries: Vec<_> = (0..600)
        .map(|i| facet(MIDNIGHT + i * 1000, scraper))
        .collect();
    let now = MIDNIGHT + 600_000;
    fold_all(&mut store, &mut state, &rules, &entries, now);
    let profile = profile_of(&store, now, scraper).expect("profil");
    assert_eq!(profile.class, BotClass::Browser);
    assert_eq!(profile.stats.requests, 600);
    assert_eq!(profile.stats.peak_minute, 60);
    let verdict = profile.verdict().expect("score");
    assert_eq!(verdict.level, Level::High, "{verdict:?}");
    assert_eq!(verdict.score, 75);
    // `repeated-ip` (600 en 10 min) la voit aussi, sans que l'IP soit une clé
    // d'autre chose qu'un seau de portée `ip`. La fenêtre se lit à l'heure
    // de référence (dernière entrée), pas à celle du veilleur.
    let reference = state.reference(now).expect("référence");
    assert_eq!(reference, MIDNIGHT + 599_000);
    let repeated = window(&store, &rules, reference, "repeated-ip");
    assert!(repeated.exceeded);
    assert_eq!(repeated.keys, [(scraper, 600)]);
}

#[test]
fn an_ip_admitted_after_eviction_has_only_its_own_counters() {
    let (_dir, mut store) = temp_store();
    let rules = default_rules();
    let mut state = agg::open_site(&mut store, SITE, 900, MIDNIGHT)
        .expect("état")
        .with_max_profiles(2);
    let (a, b, c) = (ip("192.0.2.1"), ip("192.0.2.2"), ip("192.0.2.3"));
    let mut entries = Vec::new();
    for i in 0..30 {
        let path = if i % 2 == 0 { "/style.css" } else { "/page" };
        entries.push(req(MIDNIGHT + i, a, path, 200));
    }
    for i in 0..40 {
        entries.push(req(MIDNIGHT + 100 + i, b, "/page", 200));
    }
    // C arrive : la place de A (compte 30) lui revient, avec 30 d'erreur.
    for i in 0..25 {
        entries.push(facet(MIDNIGHT + 200 + i, c));
    }
    let now = MIDNIGHT + 60_000;
    fold_all(&mut store, &mut state, &rules, &entries, now);
    assert_eq!(agg::profile_count(&store, SITE).expect("compte"), 2);
    assert!(profile_of(&store, now, a).is_none());
    let fresh = profile_of(&store, now, c).expect("C");
    assert_eq!(fresh.stats.requests, 25);
    assert_eq!(fresh.stats.statics, 0);
    assert_eq!(fresh.stats.facets, 25);
    assert_eq!(fresh.error, 30);
    assert_eq!(fresh.rank(), 55);
    assert_eq!(state.rank(&c), Some(55));
    // 25 pages sans statique, mais l'erreur dépasse le dixième : pas de score,
    // donc pas d'« aucune ressource statique » tiré d'un compte hérité.
    assert!(!fresh.scorable());
    assert_eq!(fresh.verdict(), None);

    // C continue en navigateur : 300 requêtes dont la moitié statiques.
    let more: Vec<_> = (0..300)
        .map(|i| {
            let path = if i % 2 == 0 { "/app.js" } else { "/page" };
            req(MIDNIGHT + 1000 + i, c, path, 200)
        })
        .collect();
    fold_all(&mut store, &mut state, &rules, &more, now);
    let grown = profile_of(&store, now, c).expect("C");
    assert_eq!(grown.stats.requests, 325);
    assert_eq!(grown.stats.statics, 150);
    assert_eq!(grown.error, 30);
    let verdict = grown.verdict().expect("score");
    assert!(
        verdict
            .reasons
            .iter()
            .all(|r| !r.label.contains("statique")),
        "{verdict:?}"
    );
    // 25 facettes sur 325 : moins de 40 %, rien à ce titre.
    assert!(
        verdict
            .reasons
            .iter()
            .all(|r| !r.label.contains("facettes"))
    );
}

#[test]
fn space_saving_keeps_at_most_10000_ips_and_every_heavy_hitter() {
    let (_dir, mut store) = temp_store();
    let rules = default_rules();
    let mut state = agg::open_site(&mut store, SITE, 900, MIDNIGHT).expect("état");
    let heavy: Vec<IpAddr> = (1..=5).map(|n| ip(&format!("203.0.113.{n}"))).collect();
    let singles = 50_000u32;
    let per_heavy = 100usize;
    // Les gros sont répartis tout au long du flux, sur 20 h.
    let total = singles as usize + heavy.len() * per_heavy;
    let step = (20 * HOUR_MS) / total as i64;
    let mut stream = Vec::with_capacity(total);
    let mut single = 0u32;
    for at in 0..total {
        let from = if at % 101 == 50 && stream.len() < total {
            heavy[(at / 101) % heavy.len()]
        } else {
            single += 1;
            v6(single)
        };
        stream.push(req(MIDNIGHT + at as i64 * step, from, "/", 200));
    }
    let n = stream.len() as u64;
    let now = MIDNIGHT + 20 * HOUR_MS;
    for chunk in stream.chunks(BATCH_SIZE) {
        fold_chunk(&mut store, &mut state, &rules, chunk.to_vec(), now);
    }
    assert!(single >= singles - 1, "{single} IP isolées");
    assert!(state.tracked() <= MAX_PROFILES);
    let count = agg::profile_count(&store, SITE).expect("compte");
    assert!(count <= MAX_PROFILES, "{count} profils");
    // Garantie de Space-Saving : au-dessus de N / 10 000 requêtes, gardée.
    let threshold = n / MAX_PROFILES as u64;
    for from in &heavy {
        let sent = stream.iter().filter(|e| e.ip == Some(*from)).count() as u64;
        assert!(sent > threshold, "{sent} ≤ {threshold}");
        assert!(state.rank(from).is_some(), "{from} évincée");
        let profile = profile_of(&store, now, *from).expect("profil gardé");
        assert!(profile.rank() >= sent, "{profile:?}");
    }
}

#[test]
fn a_million_entries_from_one_ip_stay_bounded() {
    let (_dir, mut store) = temp_store();
    let rules = default_rules();
    let mut state = agg::open_site(&mut store, SITE, 900, MIDNIGHT).expect("état");
    let from = ip("198.51.100.7");
    // 1 000 000 d'entrées sur ~2 h 47, UA tournants, un 404 sur dix.
    let total = 1_000_000i64;
    let now = MIDNIGHT + total * 10;
    let mut max_delta = 0;
    for start in (0..total).step_by(BATCH_SIZE) {
        let batch: Vec<Entry> = (start..(start + BATCH_SIZE as i64).min(total))
            .map(|i| {
                let mut entry = if i % 10 == 0 {
                    req(
                        MIDNIGHT + i * 10,
                        from,
                        &format!("/absent-{}", i % 1000),
                        404,
                    )
                } else {
                    req(MIDNIGHT + i * 10, from, "/", 200)
                };
                entry.user_agent = format!("Mozilla/5.0 Firefox/{}", i % 100);
                entry
            })
            .collect();
        let done: usize = state.cursor.0.parse().unwrap_or(0);
        let fetched = Fetched {
            next: Cursor((done + batch.len()).to_string()),
            entries: batch,
            ..Fetched::default()
        };
        let delta = fold(&fetched.entries, &rules, &mut state, now);
        max_delta = max_delta.max(
            delta.profiles.values().map(|s| s.len()).sum::<usize>()
                + delta.site_buckets.len()
                + delta.ip_buckets.values().map(|b| b.len()).sum::<usize>(),
        );
        agg::commit(&mut store, &mut state, &delta, &fetched.next, now).expect("écriture");
    }
    assert_eq!(state.cursor, Cursor(total.to_string()));
    assert_eq!(state.tracked(), 1);
    // Un lot de 500 entrées sur moins de 6 s touche une poignée de lignes.
    assert!(max_delta <= 10, "{max_delta} lignes touchées par lot");
    let rows = agg::row_counts(&store, SITE);
    // 3 tranches horaires ; seaux : `spike-404` par minute sur 24 h (≤ 168
    // ici), `repeated-ip` sur 1 h + agent_silence (≤ 76).
    assert!(rows["log_profiles"] <= 3, "{rows:?}");
    assert!(rows["log_load"] <= 3, "{rows:?}");
    assert!(rows["log_buckets"] <= 168 + 76, "{rows:?}");
    let profile = profile_of(&store, now, from).expect("profil");
    assert_eq!(profile.stats.requests, total as u64);
    assert_eq!(profile.stats.uas.len(), profile::MAX_UAS);
}

// --- Heure de référence ----------------------------------------------------

#[test]
fn a_scraper_from_23h_to_1h_keeps_its_score_at_midnight() {
    let (_dir, mut store) = temp_store();
    let rules = default_rules();
    let start = MIDNIGHT - HOUR_MS;
    let clock = FakeClock::new(start / 1000);
    let mut state = agg::open_site(&mut store, SITE, 900, clock.unix_ms()).expect("état");
    let scraper = ip("192.0.2.66");
    // 60 facettes par minute, de 23 h à 1 h.
    let minutes = 120;
    let mut before_midnight = None;
    for minute in 0..minutes {
        let at = start + minute * MINUTE_MS;
        let batch: Vec<_> = (0..60).map(|i| facet(at + i * 1000, scraper)).collect();
        clock.set((at + MINUTE_MS) / 1000);
        fold_all(&mut store, &mut state, &rules, &batch, clock.unix_ms());
        if minute == 59 {
            let reference = state.reference(clock.unix_ms()).expect("référence");
            before_midnight = profile_of(&store, reference, scraper)
                .and_then(|p| p.verdict())
                .map(|v| v.score);
        }
        if minute == 75 {
            // 00:15 : les tranches de 23 h comptent toujours.
            let reference = state.reference(clock.unix_ms()).expect("référence");
            let profile = profile_of(&store, reference, scraper).expect("profil");
            assert_eq!(profile.stats.requests, 76 * 60);
            let verdict = profile.verdict().expect("score");
            assert_eq!(Some(verdict.score), before_midnight);
            assert_eq!(verdict.level, Level::High);
        }
    }
    let before = before_midnight.expect("score à 23 h 59");
    assert!(before >= 70, "{before}");
    // Une nouvelle ouverture (passage suivant) garde le compte des deux jours.
    let reopened = agg::open_site(&mut store, SITE, 900, clock.unix_ms()).expect("état");
    assert_eq!(reopened.rank(&scraper), Some(minutes as u64 * 60));
    let reference = reopened.reference(clock.unix_ms()).expect("référence");
    let verdict = profile_of(&store, reference, scraper)
        .and_then(|p| p.verdict())
        .expect("score");
    assert_eq!(verdict.score, before);
}

#[test]
fn an_entry_dated_tomorrow_does_not_move_the_reference_past_now() {
    let (_dir, mut store) = temp_store();
    let rules = default_rules();
    let clock = FakeClock::new(MIDNIGHT / 1000);
    let now = clock.unix_ms();
    let mut state = agg::open_site(&mut store, SITE, 900, now).expect("état");
    let from = ip("192.0.2.5");
    fold_all(
        &mut store,
        &mut state,
        &rules,
        &[req(now - HOUR_MS, from, "/", 200)],
        now,
    );
    assert_eq!(state.reference_ms, Some(now - HOUR_MS));
    fold_all(
        &mut store,
        &mut state,
        &rules,
        &[req(now + 20 * HOUR_MS, from, "/", 200)],
        now,
    );
    assert_eq!(state.reference_ms, Some(now));
    assert_eq!(
        agg::cursor(&store, SITE).expect("curseur"),
        Some((Cursor("2".into()), Some(now)))
    );
    // Plus tard, la référence reste celle de l'écriture tant qu'aucune
    // entrée plus récente n'arrive, et jamais au-delà de l'heure du veilleur.
    clock.advance(600);
    let later = clock.unix_ms();
    let reopened = agg::open_site(&mut store, SITE, 900, later).expect("état");
    assert_eq!(reopened.reference(later), Some(now));
    assert_eq!(reopened.reference(now - 1), Some(now - 1));
}

fn late_404s(count: i64) -> RuleWindow {
    let (_dir, mut store) = temp_store();
    let rules = default_rules();
    let hour = MIDNIGHT + 10 * HOUR_MS;
    // L'agent pousse avec 15 min de retard.
    let clock = FakeClock::new((hour + 15 * MINUTE_MS) / 1000);
    let mut state = agg::open_site(&mut store, SITE, 900, clock.unix_ms()).expect("état");
    let entries: Vec<_> = (0..count)
        .map(|i| {
            let from = ip(&format!("198.51.100.{}", i % 200 + 1));
            req(hour - 9 * MINUTE_MS + i * 5000, from, "/disparu", 404)
        })
        .collect();
    fold_all(&mut store, &mut state, &rules, &entries, clock.unix_ms());
    let reference = state.reference(clock.unix_ms()).expect("référence");
    assert!(reference < clock.unix_ms());
    // Lue à l'heure du veilleur, la fenêtre serait vide.
    assert_eq!(
        window(&store, &rules, clock.unix_ms(), "spike-404").count,
        0
    );
    window(&store, &rules, reference, "spike-404")
}

#[test]
fn a_hundred_late_404s_open_spike_404_and_ninety_nine_do_not() {
    let hundred = late_404s(100);
    assert_eq!(hundred.count, 100);
    assert!(hundred.exceeded);
    let ninety_nine = late_404s(99);
    assert_eq!(ninety_nine.count, 99);
    assert!(!ninety_nine.exceeded);
}

// --- Règles ----------------------------------------------------------------

#[test]
fn brute_force_is_counted_per_ip_and_sensitive_paths_by_distinct_ips() {
    let (_dir, mut store) = temp_store();
    let rules = default_rules();
    let now = MIDNIGHT + HOUR_MS;
    let mut state = agg::open_site(&mut store, SITE, 900, now).expect("état");
    let attacker = ip("203.0.113.9");
    let mut entries: Vec<_> = (0..30)
        .map(|i| Entry {
            method: Some("POST".into()),
            ..req(
                now - 5 * MINUTE_MS + i * 1000,
                attacker,
                "/wp-login.php",
                200,
            )
        })
        .collect();
    for n in 1..=4 {
        entries.push(req(
            now - MINUTE_MS,
            ip(&format!("192.0.2.{n}")),
            "/.env",
            404,
        ));
    }
    fold_all(&mut store, &mut state, &rules, &entries, now);
    let brute = window(&store, &rules, now, "brute-force");
    assert!(brute.exceeded);
    assert_eq!(brute.keys, [(attacker, 30)]);
    let one = window(&store, &rules, now, "sensitive-path");
    assert!(one.exceeded);
    assert_eq!(one.count, 4);
    assert!(!window(&store, &rules, now, "sensitive-path-many").exceeded);

    // Une cinquième IP distincte sur un chemin sensible.
    fold_all(
        &mut store,
        &mut state,
        &rules,
        &[req(
            now - MINUTE_MS,
            ip("192.0.2.5"),
            "/backup/site.sql",
            200,
        )],
        now,
    );
    let many = window(&store, &rules, now, "sensitive-path-many");
    assert!(many.exceeded);
    assert_eq!(many.ips.len(), 5);
    // 29 POST d'une autre IP : rien.
    let other = ip("203.0.113.10");
    let entries: Vec<_> = (0..29)
        .map(|i| Entry {
            method: Some("POST".into()),
            ..req(now - 5 * MINUTE_MS + i * 1000, other, "/connexion", 200)
        })
        .collect();
    fold_all(&mut store, &mut state, &rules, &entries, now);
    assert_eq!(
        window(&store, &rules, now, "brute-force").keys,
        [(attacker, 30)]
    );
}

#[test]
fn behind_a_proxy_no_profile_nor_ip_rule_and_excluded_paths_are_ignored() {
    let (_dir, mut store) = temp_store();
    let mut rules = default_rules();
    rules.behind_proxy = true;
    rules.exclude = rules::compile_excludes(&["/admin/**".to_string()]).expect("exclude");
    let now = MIDNIGHT + HOUR_MS;
    let mut state = agg::open_site(&mut store, SITE, 900, now).expect("état");
    let proxy = ip("192.0.2.200");
    let mut entries: Vec<_> = (0..700)
        .map(|i| req(now - 9 * MINUTE_MS + i * 100, proxy, "/", 404))
        .collect();
    entries.extend((0..50).map(|i| req(now - MINUTE_MS + i, proxy, "/admin/index.php", 404)));
    let delta = fold(&entries, &rules, &mut state, now);
    assert_eq!(delta.excluded, 50);
    assert_eq!(delta.folded, 700);
    assert!(delta.profiles.is_empty());
    assert!(delta.ip_buckets.is_empty());
    assert!(
        delta
            .rules
            .iter()
            .all(|(_, scope)| *scope == rules::Scope::Site)
    );
    agg::commit(&mut store, &mut state, &delta, &Cursor("750".into()), now).expect("écriture");
    assert_eq!(agg::profile_count(&store, SITE).expect("compte"), 0);
    assert!(window(&store, &rules, now, "spike-404").exceeded);
    let load = agg::load(&store, SITE, now).expect("charge");
    assert_eq!(load.iter().map(|h| h.requests).sum::<u64>(), 700);
}

// --- Gardes et purge -------------------------------------------------------

#[test]
fn aggregates_are_purged_after_their_retention() {
    let (_dir, mut store) = temp_store();
    let rules = default_rules();
    let from = ip("192.0.2.30");
    let t = MIDNIGHT + 2 * HOUR_MS;
    let mut state = agg::open_site(&mut store, SITE, 900, t).expect("état");
    let mut first = req(t, from, "/absent", 404);
    first.user_agent = GOOGLEBOT.into();
    fold_all(&mut store, &mut state, &rules, &[first], t);
    let buckets = |store: &Store| agg::row_counts(store, SITE)["log_buckets"];
    // spike-404 (site) et repeated-ip (ip).
    assert_eq!(buckets(&store), 2);

    // 1 h 16 plus tard : le seau de portée `ip` est sorti (1 h + 15 min).
    let t2 = t + HOUR_MS + 16 * MINUTE_MS;
    fold_all(
        &mut store,
        &mut state,
        &rules,
        &[req(t2, from, "/", 200)],
        t2,
    );
    let rule_keys: Vec<(String, String, i64)> = {
        let mut stmt = store
            .conn
            .prepare("SELECT rule, key, minute FROM log_buckets ORDER BY minute, rule")
            .expect("prepare");
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .expect("query")
            .collect::<rusqlite::Result<_>>()
            .expect("rows")
    };
    let minute = profile::minute_of(t);
    let key = from.to_string();
    assert_eq!(
        rule_keys,
        [
            ("spike-404".to_string(), String::new(), minute),
            ("repeated-ip".to_string(), key, profile::minute_of(t2)),
        ]
    );

    // 24 h plus tard : seaux de site, robots et charge de `t` sortis.
    let t3 = t + 24 * HOUR_MS + MINUTE_MS;
    fold_all(
        &mut store,
        &mut state,
        &rules,
        &[req(t3, from, "/", 200)],
        t3,
    );
    assert!(agg::bots(&store, SITE, t3).expect("robots").is_empty());
    let rows = agg::row_counts(&store, SITE);
    assert_eq!(rows["log_bots"], 0, "{rows:?}");
    assert_eq!(rows["log_load"], 2, "{rows:?}");
    assert_eq!(rows["log_buckets"], 1, "{rows:?}");
    // Le compte de classement a perdu la tranche sortie de la fenêtre.
    let reopened = agg::open_site(&mut store, SITE, 900, t3).expect("état");
    assert_eq!(reopened.rank(&from), Some(2));
    // Profils : purgés 48 h après l'heure du veilleur, même sans source.
    assert_eq!(rows["log_profiles"], 3);
    // À l'heure près : une tranche part quand son début a 48 h ; à
    // t + 48 h 30, seule celle de `t` est sortie.
    agg::purge(&mut store, t + 48 * HOUR_MS + 30 * MINUTE_MS).expect("purge");
    assert_eq!(agg::row_counts(&store, SITE)["log_profiles"], 2);
    agg::purge(&mut store, t3 + 49 * HOUR_MS).expect("purge");
    let rows = agg::row_counts(&store, SITE);
    assert!(rows.values().all(|&n| n == 0), "{rows:?}");
}

// --- Curseur ---------------------------------------------------------------

#[test]
fn batches_resume_from_the_cursor_without_counting_twice() {
    let (_dir, mut store) = temp_store();
    let rules = default_rules();
    let now = MIDNIGHT + HOUR_MS;
    let entries: Vec<_> = (0..1_200)
        .map(|i| {
            req(
                now - 30 * MINUTE_MS + i,
                ip(&format!("192.0.2.{}", i % 50 + 1)),
                "/",
                200,
            )
        })
        .collect();
    let source = MemorySource::new("memoire", entries);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    let total = |store: &Store| -> u64 {
        agg::load(store, SITE, now)
            .expect("charge")
            .iter()
            .map(|h| h.requests)
            .sum()
    };
    // Premier passage : un seul lot, puis budget épuisé.
    let mut state = agg::open_site(&mut store, SITE, 900, now).expect("état");
    let fetched = runtime
        .block_on(source.fetch(&state.cursor, BATCH_SIZE))
        .expect("lot");
    assert!(fetched.more);
    agg::fold_batch(&mut store, &mut state, &rules, &fetched, now).expect("repli");
    assert_eq!(total(&store), 500);
    // Passages suivants : reprise au curseur enregistré, jusqu'au bout, deux fois.
    for _ in 0..2 {
        let mut state = agg::open_site(&mut store, SITE, 900, now).expect("état");
        loop {
            let fetched = runtime
                .block_on(source.fetch(&state.cursor, BATCH_SIZE))
                .expect("lot");
            agg::fold_batch(&mut store, &mut state, &rules, &fetched, now).expect("repli");
            if !fetched.more {
                break;
            }
        }
    }
    assert_eq!(total(&store), 1_200);
    let profiles = agg::profiles(&store, SITE, now).expect("profils");
    assert_eq!(profiles.len(), 50);
    assert!(profiles.iter().all(|p| p.stats.requests == 24));
    assert_eq!(
        agg::cursor(&store, SITE).expect("curseur").map(|c| c.0),
        Some(Cursor("1200".into()))
    );
}

// --- Robots et charge ------------------------------------------------------

#[test]
fn bots_load_and_the_first_robot_of_an_ip() {
    let (_dir, mut store) = temp_store();
    let rules = default_rules();
    let now = MIDNIGHT + 3 * HOUR_MS;
    let mut state = agg::open_site(&mut store, SITE, 900, now).expect("état");
    let at = now - 10 * MINUTE_MS;
    let mixed = ip("192.0.2.40");
    let with = |ua: &str, duration_us: Option<u64>, from: IpAddr| Entry {
        user_agent: ua.into(),
        duration_us,
        ..req(at, from, "/produit", 200)
    };
    let mut entries = vec![
        with("curl/8.4.0", Some(1_000), mixed),
        with(GOOGLEBOT, Some(2_000), mixed),
        with(GOOGLEBOT, Some(3_000), ip("192.0.2.41")),
        with(GOOGLEBOT, Some(4_000), ip("192.0.2.41")),
        with(GPTBOT, Some(5_000), ip("192.0.2.42")),
        with(GPTBOT, None, ip("192.0.2.42")),
    ];
    entries.push(Entry {
        query_keys: vec!["q".into()],
        status: 403,
        ..with(FIREFOX, Some(10_000), ip("192.0.2.43"))
    });
    fold_all(&mut store, &mut state, &rules, &entries, now);

    let bots: Vec<_> = agg::bots(&store, SITE, now)
        .expect("robots")
        .iter()
        .map(|v| (v.bot.name, v.requests))
        .collect();
    assert_eq!(bots, [("Googlebot", 3), ("GPTBot", 2)]);

    let first = profile_of(&store, now, mixed).expect("profil");
    assert_eq!(first.class, BotClass::Tool);
    assert_eq!(first.bot.map(|b| b.name), Some("Googlebot"));
    let gpt = profile_of(&store, now, ip("192.0.2.42")).expect("profil");
    assert_eq!(gpt.class, BotClass::AiTraining);
    // Robot déclaré hors des quatre moteurs : +20 ; sans reverse DNS : +5.
    assert_eq!(gpt.verdict().map(|v| v.score), Some(25));
    let google = profile_of(&store, now, ip("192.0.2.41")).expect("profil");
    assert_eq!(google.verdict().map(|v| v.level), Some(Level::Engine));

    let load = agg::load(&store, SITE, now).expect("charge");
    assert_eq!(load.len(), 1);
    let hour = load[0];
    assert_eq!(hour.hour, profile::hour_of(at));
    assert_eq!(hour.requests, 7);
    assert_eq!(hour.refused, 1);
    assert_eq!(hour.timed, 6);
    assert_eq!(hour.service_us, 25_000);
    assert_eq!((hour.facets, hour.facets_us), (1, 10_000));
    assert_eq!((hour.bots, hour.bots_us), (5, 14_000));
    assert_eq!(hour.facets_share(), Some(0.4));
    assert!(!hour.exceeds(DEFAULT_THRESHOLD_US));
    assert!(hour.exceeds(20_000));
}

#[test]
fn without_durations_only_the_volume_is_kept_and_load_never_exceeds() {
    let (_dir, mut store) = temp_store();
    let rules = default_rules();
    let now = MIDNIGHT + HOUR_MS;
    let mut state = agg::open_site(&mut store, SITE, 900, now).expect("état");
    let entries: Vec<_> = (0..5_000)
        .map(|i| req(now - 30 * MINUTE_MS + i, ip("192.0.2.50"), "/", 200))
        .collect();
    fold_all(&mut store, &mut state, &rules, &entries, now);
    let load = agg::load(&store, SITE, now).expect("charge");
    assert_eq!(load.iter().map(|h| h.requests).sum::<u64>(), 5_000);
    assert!(load.iter().all(|h| !h.has_durations() && !h.exceeds(0)));
    assert!(load.iter().all(|h| h.facets_share().is_none()));
}

// --- Coût d'un lot ---------------------------------------------------------

/// Chemins de 2 Kio taillés contre les motifs par défaut. `near` : ils
/// frôlent `.git/`, `.env`, `wp-config.php.` et `.sql` sans les former (le
/// préfiltre des littéraux les écarte) ; sinon ils contiennent les
/// littéraux de `/**/wp-config.php.*` sans y correspondre (fini par `/`) :
/// la programmation dynamique tourne sur toute la longueur.
fn hostile_path(n: usize, near: bool) -> String {
    let mut path = format!("/{n}");
    let near_pieces = [
        "/.gi",
        "/.en",
        "/wp-config.ph",
        "/x.sq",
        "/.bak.",
        "/phpinfo.ph",
    ];
    let full_pieces = ["/wp-config.php.", "/a.sq", "/.gi"];
    let pieces: &[&str] = if near { &near_pieces } else { &full_pieces };
    let mut i = 0;
    while path.len() < crate::logs::MAX_PATH {
        path.push_str(pieces[i % pieces.len()]);
        i += 1;
    }
    path.truncate(crate::logs::MAX_PATH - 1);
    path.push('/');
    path
}

#[test]
fn a_batch_of_500_long_paths_folds_in_under_100_ms_in_release() {
    let rules = default_rules();
    let now = MIDNIGHT + HOUR_MS;
    for near in [true, false] {
        let entries: Vec<_> = (0..BATCH_SIZE)
            .map(|n| {
                let path = hostile_path(n, near);
                assert_eq!(path.len(), crate::logs::MAX_PATH);
                Entry {
                    user_agent: format!("Mozilla/5.0 (compatible; Agent{}/1.0)", n % 20),
                    ..req(
                        now - (n as i64) * 100,
                        ip(&format!("192.0.2.{}", n % 250 + 1)),
                        &path,
                        404,
                    )
                }
            })
            .collect();
        let mut state = SiteState::new(SITE, 900);
        let started = Instant::now();
        let delta = fold(&entries, &rules, &mut state, now);
        let elapsed = started.elapsed();
        assert_eq!(delta.folded, BATCH_SIZE);
        // Aucun motif sensible formé : seul spike-404 compte parmi les
        // règles de portée site.
        let site_rules: Vec<_> = delta
            .site_buckets
            .keys()
            .map(|(rank, _)| delta.rules[*rank].0.as_str())
            .collect();
        assert!(
            site_rules.iter().all(|r| *r == "spike-404"),
            "{site_rules:?}"
        );
        // La borne vaut en release (`cargo test --release` : 10 à 30 ms
        // mesurés) ; en debug, le code non optimisé n'en dit rien, seule une
        // borne large y est vérifiée.
        let bound = if cfg!(debug_assertions) {
            Duration::from_secs(10)
        } else {
            Duration::from_millis(100)
        };
        assert!(elapsed < bound, "lot de 500 en {elapsed:?} (near = {near})");
    }
}
