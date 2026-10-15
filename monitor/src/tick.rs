//! `monitor tick` : passage lancé chaque minute par `monitor-tick.timer`.
//!
//! Phase 1 : enregistre seulement le passage, que `/health` surveille. Les
//! contrôles et les envois d'e-mail arrivent en phase 2.

use anyhow::Result;

use crate::config::Config;
use crate::store::Store;

pub fn run(config: &Config, now: i64) -> Result<()> {
    let mut store = Store::open(&config.database)?;
    store.record_tick(now)?;
    log::info!(
        "tick enregistré ({} site(s) configuré(s))",
        config.sites.len()
    );
    Ok(())
}
