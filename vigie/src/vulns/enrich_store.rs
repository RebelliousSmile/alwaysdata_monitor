//! Stockage des tables d'enrichissement CISA KEV et FIRST EPSS (migration
//! `0019.sql`, issue #18) : mêmes générations sous bail que les failles de
//! F1, mêmes primitives (`reserve`, `check_lease`, `switch`,
//! `finish_unchanged`, `purge_batches`), lecture pour la règle de gravité.
//!
//! **Écrivain** : `vigie vulns sync` seul, par [`EnrichLoad`] :
//!
//! 1. [`EnrichLoad::begin`] réserve une génération et prend le bail ;
//! 2. [`EnrichLoad::push_kev`] / [`EnrichLoad::push_epss`] écrivent par
//!    transactions IMMEDIATE de [`ENRICH_BATCH`] lignes, bail revérifié
//!    dans chacune : `serve` et `tick` écrivent entre deux lots ;
//! 3. [`EnrichLoad::commit`] écrit `vuln_dataset` de la génération et
//!    bascule en compare-and-swap dans la même transaction courte, puis
//!    purge par lots et `PRAGMA wal_checkpoint(PASSIVE)` ; jeu inchangé :
//!    [`EnrichLoad::finish_unchanged`] (une instruction) ; abandon :
//!    [`EnrichLoad::release`].
//!
//! **Lecteurs** : [`StoreTables`], sur une connexion de lecture
//! (`Store::open_read`, `query_only`) ou celle de l'écrivain, ne lisent que
//! la génération active : l'ancien jeu complet ou le nouveau.

use std::cell::RefCell;
use std::collections::HashMap;

use jiff::Timestamp;
use jiff::civil::Date;
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::clock::Clock;
use crate::store::{SCHEMA_ENRICHMENT, Store};
use crate::vulns::advisory::{Reason, Tally};
use crate::vulns::exploit::{Cve, DatasetInfo, EpssFact, Exploitation, KevFact, TablesState};
use crate::vulns::store::{
    Committed, KeyShape, LEASE, LoadError, Outcome, Switch, SyncMeta, Validators, check_lease,
    claim_request, finish_unchanged, purge_batches, reserve, switch,
};

/// Lignes écrites par transaction. Mesure du test de contention
/// (`tests/store_concurrency.rs`, 2026-10-17, build debug, 400 000 lignes
/// EPSS face aux écritures de `serve` et `tick`) : le lot le plus lent
/// tient ≈ 60 ms, loin des 5 s de `busy_timeout` des autres écrivains ;
/// le test exige moins de 100 ms en release.
pub const ENRICH_BATCH: usize = 5_000;

/// Une table d'enrichissement, et sa source dans `vuln_sources`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EnrichSource {
    Kev,
    Epss,
}

impl EnrichSource {
    /// Identifiant de la source (`vuln_sources.id`, `vuln_dataset.source`).
    pub fn id(self) -> &'static str {
        match self {
            Self::Kev => "kev",
            Self::Epss => "epss",
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "kev" => Some(Self::Kev),
            "epss" => Some(Self::Epss),
            _ => None,
        }
    }

    fn table(self) -> &'static str {
        match self {
            Self::Kev => "vuln_kev",
            Self::Epss => "vuln_epss",
        }
    }
}

/// Ligne KEV validée.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KevRow {
    pub cve: Cve,
    pub fact: KevFact,
}

/// Ligne EPSS validée, en millionièmes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpssRow {
    pub epss_ppm: u32,
    pub percentile_ppm: u32,
}

/// En-tête d'un jeu (KEV : `catalogVersion`, `dateReleased` complet ;
/// EPSS : `model_version`, `score_date` à minuit UTC).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetHeader {
    pub version: String,
    pub released: Timestamp,
}

/// Jeu actif d'une source, pour décider avant d'écrire (KEV : régression
/// de `dateReleased`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveDataset {
    pub generation: i64,
    pub version: String,
    pub released: Timestamp,
    pub rows: u64,
}

/// `true` si la base porte les tables KEV et EPSS.
pub fn available(store: &Store) -> anyhow::Result<bool> {
    Ok(store.schema_version()? >= SCHEMA_ENRICHMENT)
}

/// Chargement d'une génération KEV ou EPSS sous bail.
pub struct EnrichLoad<'a> {
    store: &'a mut Store,
    clock: &'a dyn Clock,
    source: EnrichSource,
    generation: i64,
    expected_active: i64,
    since: i64,
    lease: i64,
    tally: Tally,
    entries: u64,
}

impl<'a> EnrichLoad<'a> {
    /// Réserve une génération et prend le bail pour `lease` secondes
    /// ([`LEASE`] au plus), puis purge les générations orphelines.
    pub fn begin(
        store: &'a mut Store,
        source: EnrichSource,
        clock: &'a dyn Clock,
        lease: i64,
    ) -> Result<EnrichLoad<'a>, LoadError> {
        let lease = lease.clamp(1, LEASE);
        let now = clock.unix();
        let (generation, expected_active) = reserve(store, source.id(), now, lease)?;
        purge(store, source, now)?;
        Ok(EnrichLoad {
            store,
            clock,
            source,
            generation,
            expected_active,
            since: now,
            lease,
            tally: Tally::default(),
            entries: 0,
        })
    }

    pub fn source(&self) -> EnrichSource {
        self.source
    }

    /// Génération réservée.
    pub fn generation(&self) -> i64 {
        self.generation
    }

    /// Génération active attendue à la bascule.
    pub fn expected_active(&self) -> i64 {
        self.expected_active
    }

    /// Lignes écrites jusqu'ici (retenues).
    pub fn entries(&self) -> u64 {
        self.entries
    }

    /// Compteurs du chargement (`duplicate`).
    pub fn tally(&self) -> &Tally {
        &self.tally
    }

    /// Réserve une requête vers la source, sous ce bail.
    pub fn claim_request(&mut self, min_interval: i64) -> anyhow::Result<bool> {
        claim_request(
            self.store,
            self.source.id(),
            self.clock.unix(),
            min_interval,
        )
    }

    /// Jeu actif de la source.
    pub fn active(&self) -> anyhow::Result<Option<ActiveDataset>> {
        active(self.store, self.source)
    }

    /// Écrit des lignes par transactions de [`ENRICH_BATCH`] ; un CVE déjà
    /// écrit dans cette génération est ignoré et compté `duplicate`.
    pub fn push_kev(&mut self, rows: &[KevRow]) -> Result<(), LoadError> {
        debug_assert_eq!(self.source, EnrichSource::Kev);
        self.push(rows, |tx, g, row| {
            let mut stmt = tx.prepare_cached(
                "INSERT OR IGNORE INTO vuln_kev (generation, cve, date_added, due_date,
                     known_ransomware, name)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            Ok(stmt.execute(params![
                g,
                row.cve.as_str(),
                row.fact.date_added.to_string(),
                row.fact.due_date.to_string(),
                row.fact.known_ransomware,
                row.fact.name,
            ])?)
        })
    }

    /// Comme [`EnrichLoad::push_kev`], pour EPSS.
    pub fn push_epss(&mut self, rows: &[(Cve, EpssRow)]) -> Result<(), LoadError> {
        debug_assert_eq!(self.source, EnrichSource::Epss);
        self.push(rows, |tx, g, (cve, row)| {
            let mut stmt = tx.prepare_cached(
                "INSERT OR IGNORE INTO vuln_epss (generation, cve, epss_ppm, percentile_ppm)
                 VALUES (?1, ?2, ?3, ?4)",
            )?;
            Ok(stmt.execute(params![g, cve.as_str(), row.epss_ppm, row.percentile_ppm])?)
        })
    }

    fn push<T>(
        &mut self,
        rows: &[T],
        insert: impl Fn(&rusqlite::Transaction<'_>, i64, &T) -> anyhow::Result<usize>,
    ) -> Result<(), LoadError> {
        for chunk in rows.chunks(ENRICH_BATCH) {
            let now = self.clock.unix();
            let tx = self
                .store
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            check_lease(
                &tx,
                self.source.id(),
                self.generation,
                self.expected_active,
                now,
                self.lease,
            )?;
            let mut written = 0u64;
            let mut duplicates = 0u64;
            for row in chunk {
                if insert(&tx, self.generation, row)? == 1 {
                    written += 1;
                } else {
                    duplicates += 1;
                }
            }
            tx.commit()?;
            self.entries += written;
            for _ in 0..duplicates {
                self.tally.add(Reason::Duplicate);
            }
        }
        Ok(())
    }

    /// Écrit l'en-tête du jeu et bascule en compare-and-swap dans la même
    /// transaction, avec les compteurs (`tally`, ajouté à ceux du
    /// chargement) et l'état de synchronisation (`meta`, validateurs et leur
    /// URL compris). Puis purge et point de contrôle du WAL.
    pub fn commit(
        mut self,
        header: &DatasetHeader,
        tally: &Tally,
        meta: &SyncMeta,
    ) -> Result<Committed, LoadError> {
        self.tally.merge(tally);
        let now = self.clock.unix();
        let tx = self
            .store
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: String = header.version.chars().take(32).collect();
        tx.execute(
            "INSERT OR REPLACE INTO vuln_dataset (source, generation, version, released, rows)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                self.source.id(),
                self.generation,
                version,
                header.released.to_string(),
                i64::try_from(self.entries).unwrap_or(i64::MAX),
            ],
        )?;
        switch(
            &tx,
            &Switch {
                source: self.source.id(),
                generation: self.generation,
                expected_active: self.expected_active,
                since: self.since,
                lease: self.lease,
                now,
                entries: self.entries,
                tally: &self.tally,
            },
            meta,
        )?;
        tx.commit()?;
        purge(self.store, self.source, now)?;
        // PASSIVE : n'attend aucun lecteur ; le WAL est réutilisé ensuite.
        self.store
            .conn
            .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |_| Ok(()))?;
        Ok(Committed {
            generation: self.generation,
            entries: self.entries,
            tally: self.tally,
        })
    }

    /// Jeu inchangé (304, même empreinte) ou périmé (`stale`) : primitive
    /// [`finish_unchanged`] de F2 sous ce bail, une seule instruction.
    /// `false` : bail repris ou bascule concurrente, rien écrit.
    pub fn finish_unchanged(
        self,
        validators: &Validators,
        outcome: Outcome,
        stale: bool,
    ) -> Result<bool, LoadError> {
        Ok(finish_unchanged(
            &self.store.conn,
            self.source.id(),
            self.generation,
            self.expected_active,
            validators,
            outcome,
            stale,
            self.clock.unix(),
        )?)
    }

    /// Rend le bail s'il est encore détenu, sans rien noter ; la génération
    /// réservée reste orpheline (purgée au chargement suivant). Aucune ligne
    /// active n'est touchée.
    pub fn release(self) -> Result<(), LoadError> {
        self.store.conn.execute(
            "UPDATE vuln_sources SET loading_generation = NULL, loading_since = NULL
             WHERE id = ?1 AND loading_generation = ?2",
            params![self.source.id(), self.generation],
        )?;
        Ok(())
    }
}

/// Purge les générations orphelines d'une table et de ses en-têtes.
pub fn purge(store: &mut Store, source: EnrichSource, now: i64) -> anyhow::Result<u64> {
    let removed = purge_batches(
        store,
        source.id(),
        now,
        &[(source.table(), KeyShape::GenerationCve)],
    )?;
    // Une ligne par génération : une seule instruction suffit.
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "DELETE FROM vuln_dataset WHERE source = ?1 AND generation NOT IN
             (SELECT active_generation FROM vuln_sources WHERE id = ?1
              UNION SELECT loading_generation FROM vuln_sources
                  WHERE id = ?1 AND loading_generation IS NOT NULL AND ?2 - loading_since < ?3)",
        params![source.id(), now, LEASE],
    )?;
    tx.commit()?;
    Ok(removed)
}

fn timestamp(raw: &str) -> rusqlite::Result<Timestamp> {
    raw.parse().map_err(|e: jiff::Error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })
}

fn date(raw: &str) -> rusqlite::Result<Date> {
    raw.parse().map_err(|e: jiff::Error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })
}

/// Jeu actif d'une source ; `None` si jamais chargée (ou base antérieure à
/// la migration).
pub fn active(store: &Store, source: EnrichSource) -> anyhow::Result<Option<ActiveDataset>> {
    if !available(store)? {
        return Ok(None);
    }
    Ok(store
        .conn
        .query_row(
            "SELECT d.generation, d.version, d.released, d.rows FROM vuln_dataset d
             JOIN vuln_sources s ON s.id = d.source AND s.active_generation = d.generation
             WHERE d.source = ?1",
            [source.id()],
            |r| {
                Ok(ActiveDataset {
                    generation: r.get(0)?,
                    version: r.get(1)?,
                    released: timestamp(&r.get::<_, String>(2)?)?,
                    rows: u64::try_from(r.get::<_, i64>(3)?).unwrap_or(0),
                })
            },
        )
        .optional()?)
}

/// Jeux actifs de KEV et d'EPSS, pour `vigie vulns sources`.
pub fn datasets(store: &Store) -> anyhow::Result<Vec<(EnrichSource, ActiveDataset)>> {
    let mut out = Vec::new();
    for source in [EnrichSource::Kev, EnrichSource::Epss] {
        if let Some(d) = active(store, source)? {
            out.push((source, d));
        }
    }
    Ok(out)
}

fn info(d: ActiveDataset) -> DatasetInfo {
    DatasetInfo {
        generation: d.generation,
        version: d.version,
        released: d.released,
    }
}

/// Tables KEV et EPSS de la base, pour la règle de gravité : KEV entier en
/// mémoire (20 000 lignes au plus) et état des deux jeux lus dans une même
/// transaction de lecture ; EPSS lu par CVE, joint sur la génération active
/// ([`EpssFact::generation`] rempli), gardé en cache le temps d'un passage.
/// N'écrit rien : marche sur `Store::open_read` (`query_only`).
pub struct StoreTables<'s> {
    store: &'s Store,
    state: TablesState,
    kev: HashMap<Cve, KevFact>,
    epss: RefCell<HashMap<Cve, Option<EpssFact>>>,
}

impl<'s> StoreTables<'s> {
    pub fn open(store: &'s Store) -> anyhow::Result<StoreTables<'s>> {
        let mut tables = StoreTables {
            store,
            state: TablesState::default(),
            kev: HashMap::new(),
            epss: RefCell::new(HashMap::new()),
        };
        if !available(store)? {
            return Ok(tables);
        }
        // Transaction différée : lecture seule, permise par `query_only`.
        let tx = store.conn.unchecked_transaction()?;
        tables.state = TablesState {
            kev: active(store, EnrichSource::Kev)?.map(info),
            epss: active(store, EnrichSource::Epss)?.map(info),
        };
        {
            let mut stmt = tx.prepare(
                "SELECT k.cve, k.date_added, k.due_date, k.known_ransomware, k.name
                 FROM vuln_kev k
                 JOIN vuln_sources s ON s.id = 'kev' AND s.active_generation = k.generation",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    KevFact {
                        date_added: date(&r.get::<_, String>(1)?)?,
                        due_date: date(&r.get::<_, String>(2)?)?,
                        known_ransomware: r.get(3)?,
                        name: r.get(4)?,
                    },
                ))
            })?;
            for row in rows {
                let (cve, fact) = row?;
                if let Some(cve) = Cve::parse(&cve) {
                    tables.kev.insert(cve, fact);
                }
            }
        }
        tx.finish()?;
        Ok(tables)
    }

    /// Score EPSS d'un CVE, erreur de lecture comprise.
    pub fn epss_checked(&self, cve: &Cve) -> anyhow::Result<Option<EpssFact>> {
        if let Some(hit) = self.epss.borrow().get(cve) {
            return Ok(*hit);
        }
        if self.state.epss.is_none() {
            return Ok(None);
        }
        let fact = self
            .store
            .conn
            .prepare_cached(
                "SELECT e.generation, e.epss_ppm, e.percentile_ppm FROM vuln_epss e
                 JOIN vuln_sources s ON s.id = 'epss' AND s.active_generation = e.generation
                 WHERE e.cve = ?1",
            )?
            .query_row([cve.as_str()], |r| {
                Ok(EpssFact {
                    generation: r.get(0)?,
                    epss_ppm: r.get(1)?,
                    percentile_ppm: r.get(2)?,
                })
            })
            .optional()?;
        self.epss.borrow_mut().insert(cve.clone(), fact);
        Ok(fact)
    }
}

impl Exploitation for StoreTables<'_> {
    fn kev(&self, cve: &Cve) -> Option<KevFact> {
        self.kev.get(cve).cloned()
    }

    /// Une erreur de lecture est journalisée et vaut « absent » : le trait
    /// est infaillible ; `epss_checked` la rend.
    fn epss(&self, cve: &Cve) -> Option<EpssFact> {
        self.epss_checked(cve).unwrap_or_else(|e| {
            log::error!("EPSS illisible pour {cve} : {e:#}");
            None
        })
    }

    fn state(&self) -> TablesState {
        self.state.clone()
    }
}
