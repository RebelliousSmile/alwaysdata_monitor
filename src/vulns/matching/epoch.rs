//! Époques comparées par `tick` (lectures seules) : ce qui, en changeant,
//! rend un (site, source) dû.
//!
//! - [`match_epoch`] : générations actives des sources de failles
//!   **déclarées** (F1) et dernière correction de plage (F3) : un
//!   changement fait rapprocher de nouveau, plages relues ;
//! - [`enrich_epoch`] : générations actives de KEV et d'EPSS (F4) : un
//!   changement fait réévaluer la gravité sur les faits gardés ;
//! - [`waiver_epoch`] : dérogations du site, `(max(id), max(revoked_at),
//!   count(*), count(revoked_at))` : ajout, retrait (même deux de suite) ;
//! - [`declared_text`] : sources d'inventaire déclarées du site, triées.
//!
//! Chacune se relit sur une connexion quelconque, dans la transaction de
//! bascule comprise (`store::commit_and_reconcile`).

use std::collections::BTreeMap;

use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::config::{Config, Site};
use crate::inventory::Source;
use crate::store::{SCHEMA_ENRICHMENT, SCHEMA_RANGE_CORRECTIONS};
use crate::vulns::sync::registry;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn version(conn: &Connection) -> rusqlite::Result<usize> {
    let v: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    Ok(usize::try_from(v).unwrap_or(0))
}

/// Générations actives par source (`vuln_sources`).
fn generations(conn: &Connection) -> rusqlite::Result<BTreeMap<String, i64>> {
    let mut stmt =
        conn.prepare_cached("SELECT id, active_generation FROM vuln_sources ORDER BY id")?;
    let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
    rows.collect()
}

/// Sources de failles déclarées (`[vulns] sources`), sans KEV ni EPSS.
pub fn declared_vulns(config: &Config) -> Vec<&'static str> {
    registry::declared(config)
        .into_iter()
        .filter(|id| !registry::ENRICHMENT.contains(id))
        .collect()
}

/// SHA-256 des générations actives des sources de failles déclarées et du
/// plus grand id des corrections de plage.
pub fn match_epoch(conn: &Connection, declared: &[&str]) -> anyhow::Result<String> {
    let generations = generations(conn)?;
    let mut hasher = Sha256::new();
    for id in declared {
        hasher.update(format!("{id}={};", generations.get(*id).copied().unwrap_or(0)).as_bytes());
    }
    let correction: Option<i64> = if version(conn)? >= SCHEMA_RANGE_CORRECTIONS {
        conn.query_row("SELECT max(id) FROM vuln_range_corrections", [], |r| {
            r.get(0)
        })?
    } else {
        None
    };
    hasher.update(format!("corrections={};", correction.unwrap_or(0)).as_bytes());
    Ok(hex(&hasher.finalize()))
}

/// Générations actives de KEV et d'EPSS : `kev=G;epss=G`.
pub fn enrich_epoch(conn: &Connection) -> anyhow::Result<String> {
    if version(conn)? < SCHEMA_ENRICHMENT {
        return Ok("kev=0;epss=0".into());
    }
    let generations = generations(conn)?;
    Ok(format!(
        "kev={};epss={}",
        generations.get("kev").copied().unwrap_or(0),
        generations.get("epss").copied().unwrap_or(0)
    ))
}

/// Époque des dérogations du site.
pub fn waiver_epoch(conn: &Connection, site: &str) -> anyhow::Result<String> {
    let (max_id, max_revoked, count, revoked): (Option<i64>, Option<i64>, i64, i64) = conn
        .query_row(
            "SELECT max(id), max(revoked_at), count(*), count(revoked_at)
             FROM vuln_waivers WHERE site = ?1",
            [site],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
    Ok(format!(
        "{};{};{count};{revoked}",
        max_id.unwrap_or(0),
        max_revoked.unwrap_or(0)
    ))
}

/// Sources d'inventaire déclarées du site, triées (`agent` avant `ci`).
pub fn declared_sources(site: &Site) -> Vec<Source> {
    let mut sources: Vec<Source> = crate::capability::inventory_sources(site)
        .into_iter()
        .map(Source::from)
        .collect();
    sources.sort();
    sources.dedup();
    sources
}

/// Texte de l'ensemble des sources déclarées, gardé dans l'état.
pub fn declared_text(sources: &[Source]) -> String {
    sources
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join(",")
}
