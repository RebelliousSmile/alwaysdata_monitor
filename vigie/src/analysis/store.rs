//! Agrégats de l'analyse de logs en base (migration 10) : ouverture de
//! l'état d'un site, écriture d'un lot replié avec son curseur, lectures
//! pour les constats (phase 3) et purge.
//!
//! Seul `tick` écrit ces tables. Chaque lot s'écrit dans une transaction
//! IMMEDIATE de [`fold::BATCH_SIZE`] entrées au plus : le verrou n'est
//! jamais tenu longtemps face aux écritures de `serve`. Seules les lignes
//! touchées par le lot sont réécrites.
//!
//! Gardes : seaux de portée `site`, robots et charge 24 h avant la
//! référence ; seaux de portée `ip` la fenêtre maximale plus
//! `agent_silence` ; profils 48 h avant l'heure du veilleur (minimisation),
//! même pour un site qui n'a plus de source ([`purge`]).

use std::collections::BTreeMap;
use std::net::IpAddr;

use anyhow::{Context, Result};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

use super::catalog::{self, Bot, BotClass};
use super::fold::{self, Delta, SiteState};
use super::load::HourLoad;
use super::profile::{
    IpProfile, LIVE_HOURS, MAX_PROFILES, RETENTION_HOURS, Slice, Tracker, hour_of, minute_of,
};
use super::rules::{RuleSet, Scope};
use crate::finding::Severity;
use crate::logs::source::{Cursor, Fetched};
use crate::store::Store;

fn int(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn count(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

/// Lit l'état d'un site pour un passage : curseur, référence, et comptes de
/// classement de ses IP (tranches vivantes plus erreur vivante ; une IP
/// dont aucune tranche n'est vivante compte 0 et part la première). Purge
/// d'abord les profils de plus de 48 h.
pub fn open_site(
    store: &mut Store,
    site: &str,
    agent_silence_secs: u64,
    now_ms: i64,
) -> Result<SiteState> {
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    purge_profiles(&tx, Some(site), now_ms)?;
    let mut state = SiteState::new(site, agent_silence_secs);
    if let Some((cursor, reference_ms)) = read_cursor(&tx, site)? {
        state.cursor = cursor;
        state.reference_ms = reference_ms;
    }
    let reference = state.reference(now_ms).unwrap_or(now_ms);
    let ranks: Vec<(IpAddr, u64)> = {
        let mut stmt = tx.prepare(
            "SELECT ip, SUM(CASE WHEN hour > ?2 THEN requests + error ELSE 0 END)
             FROM log_profiles WHERE site = ?1 GROUP BY ip",
        )?;
        let rows = stmt.query_map(params![site, hour_of(reference) - LIVE_HOURS], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        let mut ranks = Vec::new();
        for row in rows {
            let (ip, rank) = row?;
            if let Ok(ip) = ip.parse() {
                ranks.push((ip, count(rank)));
            }
        }
        ranks
    };
    state.tracker = Tracker::with_ranks(MAX_PROFILES, ranks);
    tx.commit()?;
    Ok(state)
}

fn read_cursor(tx: &Transaction<'_>, site: &str) -> Result<Option<(Cursor, Option<i64>)>> {
    Ok(tx
        .query_row(
            "SELECT cursor, reference_ms FROM log_cursors WHERE site = ?1",
            [site],
            |row| Ok((Cursor(row.get(0)?), row.get(1)?)),
        )
        .optional()?)
}

/// Curseur et référence enregistrés d'un site.
pub fn cursor(store: &Store, site: &str) -> Result<Option<(Cursor, Option<i64>)>> {
    Ok(store
        .conn
        .query_row(
            "SELECT cursor, reference_ms FROM log_cursors WHERE site = ?1",
            [site],
            |row| Ok((Cursor(row.get(0)?), row.get(1)?)),
        )
        .optional()?)
}

/// Replie un lot lu d'un `LogSource` et l'écrit avec son curseur suivant.
pub fn fold_batch(
    store: &mut Store,
    state: &mut SiteState,
    rules: &RuleSet,
    fetched: &Fetched,
    now_ms: i64,
) -> Result<Delta> {
    let delta = fold::fold(&fetched.entries, rules, state, now_ms);
    commit(store, state, &delta, &fetched.next, now_ms)?;
    Ok(delta)
}

/// Écrit les lignes touchées par `delta`, le curseur `next` et la
/// référence, dans une transaction IMMEDIATE ; puis purge ce qui est sorti
/// des gardes. `state` prend le curseur et la référence une fois la
/// transaction validée.
pub fn commit(
    store: &mut Store,
    state: &mut SiteState,
    delta: &Delta,
    next: &Cursor,
    now_ms: i64,
) -> Result<()> {
    let site = state.site.as_str();
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    write_delta(&tx, site, delta).context("écriture des agrégats de logs")?;
    let reference = delta.reference_ms.or(state.reference_ms);
    tx.execute(
        "INSERT INTO log_cursors (site, cursor, reference_ms, updated_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (site) DO UPDATE SET cursor = excluded.cursor,
           reference_ms = excluded.reference_ms, updated_at = excluded.updated_at",
        params![site, next.0, reference, now_ms.div_euclid(1000)],
    )?;
    if let Some(reference) = reference {
        purge_site(&tx, site, reference, state.ip_retention_ms())?;
    }
    purge_profiles(&tx, Some(site), now_ms)?;
    tx.commit()?;
    state.cursor = next.clone();
    state.reference_ms = reference;
    Ok(())
}

fn write_delta(tx: &Transaction<'_>, site: &str, delta: &Delta) -> Result<()> {
    // Les IP évincées d'abord : une IP évincée puis réadmise dans le même
    // lot repart de ses seules tranches neuves.
    let mut evicted: Vec<_> = delta.evicted.iter().collect();
    evicted.sort();
    for ip in evicted {
        let ip = ip.to_string();
        tx.execute(
            "DELETE FROM log_profiles WHERE site = ?1 AND ip = ?2",
            params![site, ip],
        )?;
        tx.execute(
            "DELETE FROM log_buckets WHERE site = ?1 AND key = ?2",
            params![site, ip],
        )?;
    }

    for (ip, slices) in &delta.profiles {
        let ip = ip.to_string();
        for (hour, touched) in slices {
            let mut slice = read_slice(tx, site, &ip, *hour)?.unwrap_or_default();
            slice.merge(&touched.slice);
            write_slice(tx, site, &ip, *hour, &slice)?;
        }
    }

    for ((rank, minute), bucket) in &delta.site_buckets {
        let rule = &delta.rules[*rank].0;
        let stored: Option<(i64, String)> = tx
            .prepare_cached(
                "SELECT count, ips FROM log_buckets
                 WHERE site = ?1 AND rule = ?2 AND key = '' AND minute = ?3",
            )?
            .query_row(params![site, rule, minute], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .optional()?;
        let (before, mut ips) = match stored {
            Some((before, ips)) => (
                count(before),
                serde_json::from_str::<Vec<String>>(&ips).unwrap_or_default(),
            ),
            None => (0, Vec::new()),
        };
        for ip in &bucket.ips {
            let ip = ip.to_string();
            if ips.len() < delta.ips_cap && !ips.contains(&ip) {
                ips.push(ip);
            }
        }
        tx.prepare_cached(
            "INSERT OR REPLACE INTO log_buckets (site, rule, key, minute, count, ips)
             VALUES (?1, ?2, '', ?3, ?4, ?5)",
        )?
        .execute(params![
            site,
            rule,
            minute,
            int(before + bucket.count),
            serde_json::to_string(&ips)?
        ])?;
    }

    for (ip, buckets) in &delta.ip_buckets {
        let ip = ip.to_string();
        for ((rank, minute), added) in buckets {
            tx.prepare_cached(
                "INSERT INTO log_buckets (site, rule, key, minute, count) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (site, rule, key, minute) DO UPDATE SET count = count + excluded.count",
            )?
            .execute(params![
                site,
                delta.rules[*rank].0,
                ip,
                minute,
                int(*added)
            ])?;
        }
    }

    for ((hour, bot), added) in &delta.bots {
        tx.prepare_cached(
            "INSERT INTO log_bots (site, hour, bot, count) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (site, hour, bot) DO UPDATE SET count = count + excluded.count",
        )?
        .execute(params![site, hour, bot, int(*added)])?;
    }

    for load in delta.load.values() {
        tx.prepare_cached(
            "INSERT INTO log_load (site, hour, requests, refused, timed, service_us, facets,
               facets_us, bots, bots_us)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT (site, hour) DO UPDATE SET
               requests = requests + excluded.requests,
               refused = refused + excluded.refused,
               timed = timed + excluded.timed,
               service_us = service_us + excluded.service_us,
               facets = facets + excluded.facets,
               facets_us = facets_us + excluded.facets_us,
               bots = bots + excluded.bots,
               bots_us = bots_us + excluded.bots_us",
        )?
        .execute(params![
            site,
            load.hour,
            int(load.requests),
            int(load.refused),
            int(load.timed),
            int(load.service_us),
            int(load.facets),
            int(load.facets_us),
            int(load.bots),
            int(load.bots_us)
        ])?;
    }
    Ok(())
}

const SLICE_COLUMNS: &str = "requests, static, facets, refused, empty_referer_pages, peak_minute, \
                             error, uas, class, bot";

fn slice_from_row(row: &rusqlite::Row<'_>, at: usize) -> rusqlite::Result<Slice> {
    let uas: String = row.get(at + 7)?;
    let class: Option<String> = row.get(at + 8)?;
    let bot: Option<String> = row.get(at + 9)?;
    Ok(Slice {
        requests: count(row.get(at)?),
        statics: count(row.get(at + 1)?),
        facets: count(row.get(at + 2)?),
        refused: count(row.get(at + 3)?),
        empty_referer_pages: count(row.get(at + 4)?),
        peak_minute: count(row.get(at + 5)?),
        error: count(row.get(at + 6)?),
        uas: serde_json::from_str(&uas).unwrap_or_default(),
        class: class.as_deref().and_then(BotClass::parse),
        bot: bot.as_deref().and_then(catalog::find).map(|b| b.name),
    })
}

fn read_slice(tx: &Transaction<'_>, site: &str, ip: &str, hour: i64) -> Result<Option<Slice>> {
    Ok(tx
        .prepare_cached(&format!(
            "SELECT {SLICE_COLUMNS} FROM log_profiles WHERE site = ?1 AND ip = ?2 AND hour = ?3"
        ))?
        .query_row(params![site, ip, hour], |row| slice_from_row(row, 0))
        .optional()?)
}

fn write_slice(tx: &Transaction<'_>, site: &str, ip: &str, hour: i64, slice: &Slice) -> Result<()> {
    tx.prepare_cached(&format!(
        "INSERT OR REPLACE INTO log_profiles (site, ip, hour, {SLICE_COLUMNS})
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)"
    ))?
    .execute(params![
        site,
        ip,
        hour,
        int(slice.requests),
        int(slice.statics),
        int(slice.facets),
        int(slice.refused),
        int(slice.empty_referer_pages),
        int(slice.peak_minute),
        int(slice.error),
        serde_json::to_string(&slice.uas)?,
        slice.class.map(BotClass::as_str),
        slice.bot
    ])?;
    Ok(())
}

/// Gardes relatives à la référence d'un site.
fn purge_site(
    tx: &Transaction<'_>,
    site: &str,
    reference_ms: i64,
    ip_retention_ms: i64,
) -> Result<()> {
    tx.execute(
        "DELETE FROM log_buckets WHERE site = ?1 AND minute < ?2",
        params![site, minute_of(reference_ms - fold::SITE_RETENTION_MS)],
    )?;
    tx.execute(
        "DELETE FROM log_buckets WHERE site = ?1 AND key <> '' AND minute < ?2",
        params![site, minute_of(reference_ms - ip_retention_ms)],
    )?;
    let dead_hour = hour_of(reference_ms) - LIVE_HOURS;
    tx.execute(
        "DELETE FROM log_bots WHERE site = ?1 AND hour <= ?2",
        params![site, dead_hour],
    )?;
    tx.execute(
        "DELETE FROM log_load WHERE site = ?1 AND hour <= ?2",
        params![site, dead_hour],
    )?;
    Ok(())
}

/// Profils de plus de 48 h avant `now_ms`, d'un site ou de tous.
fn purge_profiles(tx: &Transaction<'_>, site: Option<&str>, now_ms: i64) -> Result<()> {
    let dead_hour = hour_of(now_ms) - RETENTION_HOURS;
    match site {
        Some(site) => tx.execute(
            "DELETE FROM log_profiles WHERE site = ?1 AND hour <= ?2",
            params![site, dead_hour],
        )?,
        None => tx.execute("DELETE FROM log_profiles WHERE hour <= ?1", [dead_hour])?,
    };
    Ok(())
}

/// Purge de tous les sites à l'heure du veilleur, y compris ceux qui n'ont
/// plus de source : profils de plus de 48 h, seaux, robots et charge de
/// plus de 24 h.
pub fn purge(store: &mut Store, now_ms: i64) -> Result<()> {
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    purge_profiles(&tx, None, now_ms)?;
    tx.execute(
        "DELETE FROM log_buckets WHERE minute < ?1",
        [minute_of(now_ms - fold::SITE_RETENTION_MS)],
    )?;
    let dead_hour = hour_of(now_ms) - LIVE_HOURS;
    tx.execute("DELETE FROM log_bots WHERE hour <= ?1", [dead_hour])?;
    tx.execute("DELETE FROM log_load WHERE hour <= ?1", [dead_hour])?;
    tx.commit()?;
    Ok(())
}

/// Efface les agrégats et le curseur d'un site : sa source repart de son
/// début (curseur invalide) sans rien compter deux fois.
pub fn reset_site(store: &mut Store, site: &str) -> Result<()> {
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    for table in [
        "log_buckets",
        "log_profiles",
        "log_bots",
        "log_load",
        "log_cursors",
    ] {
        tx.execute(&format!("DELETE FROM {table} WHERE site = ?1"), [site])?;
    }
    tx.commit()?;
    Ok(())
}

// --- Lectures ----------------------------------------------------------------

/// Profils des IP d'un site sur les 24 h qui finissent à `reference_ms`,
/// du plus fort compte de classement au plus faible.
pub fn profiles(store: &Store, site: &str, reference_ms: i64) -> Result<Vec<IpProfile>> {
    let mut stmt = store.conn.prepare(&format!(
        "SELECT ip, {SLICE_COLUMNS} FROM log_profiles
         WHERE site = ?1 AND hour > ?2 ORDER BY ip, hour"
    ))?;
    let rows = stmt.query_map(params![site, hour_of(reference_ms) - LIVE_HOURS], |row| {
        Ok((row.get::<_, String>(0)?, slice_from_row(row, 1)?))
    })?;
    let mut by_ip: BTreeMap<String, Vec<Slice>> = BTreeMap::new();
    for row in rows {
        let (ip, slice) = row?;
        by_ip.entry(ip).or_default().push(slice);
    }
    let mut profiles: Vec<IpProfile> = by_ip
        .into_iter()
        .filter_map(|(ip, slices)| Some(IpProfile::from_slices(ip.parse().ok()?, &slices)))
        .collect();
    profiles.sort_by(|a, b| b.rank().cmp(&a.rank()).then(a.ip.cmp(&b.ip)));
    Ok(profiles)
}

/// Comptes d'une règle sur sa fenêtre, finie à la référence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleWindow {
    pub rule: String,
    pub scope: Scope,
    pub severity: Severity,
    pub min_count: u32,
    pub min_ips: u32,
    pub window_secs: u32,
    /// Portée `site` : requêtes de la fenêtre ; portée `ip` : celles de
    /// l'IP la plus active.
    pub count: u64,
    /// Portée `site` : IP distinctes vues (plafonnées par minute au plus
    /// grand `min_ips`, donc exactes jusqu'à ce seuil).
    pub ips: Vec<IpAddr>,
    /// Portée `ip` : IP au-dessus du seuil, de la plus active à la moins
    /// active.
    pub keys: Vec<(IpAddr, u64)>,
    pub exceeded: bool,
}

/// Fenêtre de chaque règle active : les minutes `(référence − fenêtre,
/// référence]`.
pub fn rule_windows(
    store: &Store,
    site: &str,
    rules: &RuleSet,
    reference_ms: i64,
) -> Result<Vec<RuleWindow>> {
    let last = minute_of(reference_ms);
    let mut windows = Vec::new();
    for rule in rules.active() {
        let first = last - i64::from(rule.window_secs.div_ceil(60));
        let mut window = RuleWindow {
            rule: rule.id.clone(),
            scope: rule.scope,
            severity: rule.severity,
            min_count: rule.min_count,
            min_ips: rule.min_ips,
            window_secs: rule.window_secs,
            count: 0,
            ips: Vec::new(),
            keys: Vec::new(),
            exceeded: false,
        };
        match rule.scope {
            Scope::Site => {
                let mut stmt = store.conn.prepare_cached(
                    "SELECT count, ips FROM log_buckets
                     WHERE site = ?1 AND rule = ?2 AND key = '' AND minute > ?3 AND minute <= ?4",
                )?;
                let rows = stmt.query_map(params![site, rule.id, first, last], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })?;
                for row in rows {
                    let (n, ips) = row?;
                    window.count += count(n);
                    for ip in serde_json::from_str::<Vec<String>>(&ips).unwrap_or_default() {
                        if let Ok(ip) = ip.parse()
                            && !window.ips.contains(&ip)
                        {
                            window.ips.push(ip);
                        }
                    }
                }
                window.ips.sort();
                window.exceeded = window.count >= u64::from(rule.min_count)
                    && window.ips.len() >= rule.min_ips as usize;
            }
            Scope::Ip => {
                let mut stmt = store.conn.prepare_cached(
                    "SELECT key, SUM(count) FROM log_buckets
                     WHERE site = ?1 AND rule = ?2 AND key <> '' AND minute > ?3 AND minute <= ?4
                     GROUP BY key",
                )?;
                let rows = stmt.query_map(params![site, rule.id, first, last], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })?;
                for row in rows {
                    let (ip, n) = row?;
                    let n = count(n);
                    window.count = window.count.max(n);
                    if n >= u64::from(rule.min_count)
                        && let Ok(ip) = ip.parse()
                    {
                        window.keys.push((ip, n));
                    }
                }
                window
                    .keys
                    .sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                window.exceeded = !window.keys.is_empty();
            }
        }
        windows.push(window);
    }
    Ok(windows)
}

/// Volume d'un robot du catalogue sur 24 h.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BotVolume {
    pub bot: &'static Bot,
    pub requests: u64,
}

/// Robots vus sur les 24 h qui finissent à `reference_ms`, du plus actif
/// au moins actif.
pub fn bots(store: &Store, site: &str, reference_ms: i64) -> Result<Vec<BotVolume>> {
    let mut stmt = store.conn.prepare(
        "SELECT bot, SUM(count) FROM log_bots WHERE site = ?1 AND hour > ?2 GROUP BY bot",
    )?;
    let rows = stmt.query_map(params![site, hour_of(reference_ms) - LIVE_HOURS], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    let mut volumes = Vec::new();
    for row in rows {
        let (name, n) = row?;
        if let Some(bot) = catalog::find(&name) {
            volumes.push(BotVolume {
                bot,
                requests: count(n),
            });
        }
    }
    volumes.sort_by(|a, b| b.requests.cmp(&a.requests).then(a.bot.name.cmp(b.bot.name)));
    Ok(volumes)
}

/// Charge des 24 heures qui finissent à `reference_ms`, dans l'ordre.
pub fn load(store: &Store, site: &str, reference_ms: i64) -> Result<Vec<HourLoad>> {
    let mut stmt = store.conn.prepare(
        "SELECT hour, requests, refused, timed, service_us, facets, facets_us, bots, bots_us
         FROM log_load WHERE site = ?1 AND hour > ?2 ORDER BY hour",
    )?;
    let rows = stmt.query_map(params![site, hour_of(reference_ms) - LIVE_HOURS], |row| {
        Ok(HourLoad {
            hour: row.get(0)?,
            requests: count(row.get(1)?),
            refused: count(row.get(2)?),
            timed: count(row.get(3)?),
            service_us: count(row.get(4)?),
            facets: count(row.get(5)?),
            facets_us: count(row.get(6)?),
            bots: count(row.get(7)?),
            bots_us: count(row.get(8)?),
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// IP distinctes d'un site dans `log_profiles` (tests et `status`).
pub fn profile_count(store: &Store, site: &str) -> Result<usize> {
    let n: i64 = store.conn.query_row(
        "SELECT COUNT(DISTINCT ip) FROM log_profiles WHERE site = ?1",
        [site],
        |row| row.get(0),
    )?;
    Ok(usize::try_from(n).unwrap_or(0))
}

/// Pour les tests : comptes de lignes par table d'agrégats.
#[cfg(test)]
pub(crate) fn row_counts(
    store: &Store,
    site: &str,
) -> std::collections::HashMap<&'static str, usize> {
    let mut counts = std::collections::HashMap::new();
    for table in ["log_buckets", "log_profiles", "log_bots", "log_load"] {
        let n: i64 = store
            .conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE site = ?1"),
                [site],
                |row| row.get(0),
            )
            .expect("count");
        counts.insert(table, usize::try_from(n).unwrap_or(0));
    }
    counts
}
