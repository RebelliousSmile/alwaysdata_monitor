//! Repli d'un lot d'[`Entry`] dans les agrégats d'un site.
//!
//! `tick` lit les entrées nouvelles d'un site par son `LogSource` en lots de
//! [`BATCH_SIZE`] ; chaque lot est replié **entier** en mémoire ([`fold`]),
//! puis ses lignes touchées et le curseur suivant sont écrits dans une même
//! transaction IMMEDIATE (`analysis/store.rs`). Le budget se vérifie entre
//! deux lots, jamais au milieu : le curseur opaque de #7 n'a pas de position
//! partielle.
//!
//! Pour chaque entrée, dans l'ordre du `LogSource` : chemin exclu → ignorée ;
//! classement de l'UA (en cache), charge, robots, profil de son IP (sauf
//! `behind_proxy`), puis toutes les règles actives, dans l'ordre déclaré.
//! Le résultat d'un glob est gardé par chemin distinct du lot.
//!
//! Heure de référence = min(dernière `timestamp_ms` repliée, heure du
//! veilleur) : une entrée datée dans le futur ne la pousse pas au-delà de
//! `now`. Une entrée plus vieille que 24 h avant la référence ne compte plus
//! (ses agrégats seraient déjà purgés).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;

use super::catalog::{Classification, classify};
use super::load::HourLoad;
use super::profile::{self, Hit, MAX_PROFILES, Slice, Tracker, hour_of, minute_of};
use super::rules::{MAX_WINDOW, RuleSet, Scope};
use crate::logs::Entry;
use crate::logs::source::Cursor;

/// Entrées lues par lot, et par transaction.
pub const BATCH_SIZE: usize = 500;
/// Seaux de portée `site`, robots et charge : gardés 24 h.
pub const SITE_RETENTION_MS: i64 = 24 * profile::HOUR_MS;

/// Ce qui reste en mémoire d'un site le temps d'un passage de `tick` :
/// curseur, référence et comptes de classement des IP. Lu par
/// `analysis::store::open_site`, tenu à jour par `commit`. Après une erreur
/// d'écriture, il faut le relire : le repli l'a déjà avancé.
#[derive(Debug, Clone)]
pub struct SiteState {
    pub site: String,
    pub cursor: Cursor,
    /// Heure de référence, en ms ; `None` avant la première entrée.
    pub reference_ms: Option<i64>,
    /// `agent_silence` du site, en ms : allonge la garde des seaux de
    /// portée `ip`.
    pub agent_silence_ms: i64,
    pub(crate) tracker: Tracker,
}

impl SiteState {
    /// État vide : début de la source, aucune IP suivie.
    pub fn new(site: impl Into<String>, agent_silence_secs: u64) -> Self {
        Self {
            site: site.into(),
            cursor: Cursor::start(),
            reference_ms: None,
            agent_silence_ms: secs_to_ms(agent_silence_secs),
            tracker: Tracker::new(MAX_PROFILES),
        }
    }

    /// Change le plafond d'IP suivies (tests).
    pub fn with_max_profiles(mut self, capacity: usize) -> Self {
        self.tracker = self.tracker.resized(capacity);
        self
    }

    /// IP suivies.
    pub fn tracked(&self) -> usize {
        self.tracker.len()
    }

    /// Compte de classement d'une IP suivie.
    pub fn rank(&self, ip: &IpAddr) -> Option<u64> {
        self.tracker.rank(ip)
    }

    /// Référence vue à `now_ms` : jamais après l'heure du veilleur.
    pub fn reference(&self, now_ms: i64) -> Option<i64> {
        self.reference_ms.map(|r| r.min(now_ms))
    }

    /// Les seaux de portée `ip` sont gardés la fenêtre maximale plus
    /// `agent_silence`.
    pub fn ip_retention_ms(&self) -> i64 {
        i64::from(MAX_WINDOW) * 1000 + self.agent_silence_ms
    }
}

pub(crate) fn secs_to_ms(secs: u64) -> i64 {
    i64::try_from(secs)
        .unwrap_or(i64::MAX / 1000)
        .saturating_mul(1000)
}

/// Seau d'une règle de portée `site` pour une minute.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SiteBucket {
    pub count: u64,
    /// IP distinctes, plafonnées à `Delta::ips_cap`.
    pub ips: Vec<IpAddr>,
}

/// Tranche d'un profil touchée par le lot, avec ses comptes par minute
/// (pour le pic approché).
#[derive(Debug, Clone, Default)]
pub struct SliceDelta {
    pub slice: Slice,
    minutes: HashMap<i64, u64>,
}

impl SliceDelta {
    fn add(&mut self, entry: &Entry, classification: &Classification, statics: bool) {
        self.slice.add(entry, classification, statics);
        let minute = self
            .minutes
            .entry(minute_of(entry.timestamp_ms))
            .or_default();
        *minute += 1;
        self.slice.peak_minute = self.slice.peak_minute.max(*minute);
    }
}

/// Ce qu'un lot change aux agrégats : les seules lignes à réécrire.
#[derive(Debug, Clone, Default)]
pub struct Delta {
    /// Règles actives du lot, dans l'ordre : identifiant et portée.
    pub rules: Vec<(String, Scope)>,
    /// IP distinctes gardées par seau de portée `site`.
    pub ips_cap: usize,
    /// (rang de règle, minute) → seau.
    pub site_buckets: HashMap<(usize, i64), SiteBucket>,
    /// IP → (rang de règle, minute) → compte.
    pub ip_buckets: HashMap<IpAddr, HashMap<(usize, i64), u64>>,
    /// IP → heure → tranche.
    pub profiles: HashMap<IpAddr, BTreeMap<i64, SliceDelta>>,
    /// IP évincées par Space-Saving : leurs lignes sont supprimées avant
    /// l'écriture du lot.
    pub evicted: HashSet<IpAddr>,
    /// (heure, robot) → requêtes.
    pub bots: HashMap<(i64, &'static str), u64>,
    pub load: HashMap<i64, HourLoad>,
    /// Référence après ce lot.
    pub reference_ms: Option<i64>,
    /// Entrées repliées, exclues (`exclude`) et trop vieilles.
    pub folded: usize,
    pub excluded: usize,
    pub stale: usize,
}

impl Delta {
    fn evict(&mut self, ip: IpAddr) {
        self.profiles.remove(&ip);
        self.ip_buckets.remove(&ip);
        self.evicted.insert(ip);
    }
}

/// Préfixe des dossiers du bac à sable de l'agent (#13).
pub const SANDBOX_PREFIX: &str = "/vigie-essai-";

/// Trafic de Vigie elle-même, retiré de l'analyse (#13) : les contrôles du
/// veilleur (`vigie/…`), l'agent (`vigie-agent-php/…`) et les requêtes du bac
/// à sable de l'agent (`/vigie-essai-*`). Sans cela, le veilleur (UA d'outil,
/// IP d'hébergeur, sans statiques) atteindrait le niveau élevé du score.
pub fn is_vigie_traffic(entry: &Entry) -> bool {
    let ua = entry.user_agent.as_bytes();
    let starts =
        |prefix: &[u8]| ua.len() >= prefix.len() && ua[..prefix.len()].eq_ignore_ascii_case(prefix);
    entry.path.starts_with(SANDBOX_PREFIX) || starts(b"vigie/") || starts(b"vigie-agent-php/")
}

/// Résultats de chemin d'un lot, par chemin distinct.
struct PathInfo {
    excluded: bool,
    /// Par rang de règle active : `None` tant que non calculé.
    hits: Vec<Option<bool>>,
}

/// Replie `entries` (un lot, dans l'ordre du `LogSource`) : avance les
/// comptes de classement de `state` et rend les lignes à écrire. `now_ms`
/// vient de l'horloge injectée (`clock.rs`).
pub fn fold(entries: &[Entry], rules: &RuleSet, state: &mut SiteState, now_ms: i64) -> Delta {
    let active: Vec<_> = rules.active().collect();
    let mut delta = Delta {
        rules: active.iter().map(|r| (r.id.clone(), r.scope)).collect(),
        ips_cap: active
            .iter()
            .filter(|r| r.scope == Scope::Site)
            .map(|r| r.min_ips as usize)
            .max()
            .unwrap_or(1),
        ..Delta::default()
    };
    let newest = entries.iter().map(|e| e.timestamp_ms).max();
    let reference = match (state.reference_ms, newest) {
        (Some(old), Some(new)) => Some(old.max(new)),
        (old, new) => old.or(new),
    }
    .map(|r| r.min(now_ms));
    delta.reference_ms = reference;
    let Some(reference) = reference else {
        return delta;
    };
    let site_horizon = reference - SITE_RETENTION_MS;
    let ip_horizon = reference - state.ip_retention_ms();
    let profiles = !rules.behind_proxy;

    let mut classes: HashMap<&str, Classification> = HashMap::new();
    let mut paths: HashMap<&str, PathInfo> = HashMap::new();
    for entry in entries {
        if entry.timestamp_ms <= site_horizon {
            delta.stale += 1;
            continue;
        }
        let path = entry.path.as_str();
        if is_vigie_traffic(entry) {
            delta.excluded += 1;
            continue;
        }
        let info = paths.entry(path).or_insert_with(|| PathInfo {
            excluded: rules.excluded(path),
            hits: vec![None; active.len()],
        });
        if info.excluded {
            delta.excluded += 1;
            continue;
        }
        delta.folded += 1;
        let classification = *classes
            .entry(entry.user_agent.as_str())
            .or_insert_with(|| classify(&entry.user_agent));
        let hour = hour_of(entry.timestamp_ms);
        let minute = minute_of(entry.timestamp_ms);
        let statics = profile::is_static(path);
        let facet = profile::is_facet(entry);

        delta
            .load
            .entry(hour)
            .or_insert_with(|| HourLoad::new(hour))
            .add(entry, facet, classification.bot.is_some());
        if let Some(bot) = classification.bot {
            *delta.bots.entry((hour, bot.name)).or_default() += 1;
        }

        let tracked = match entry
            .ip
            .filter(|_| profiles && profile::is_live(hour, reference))
        {
            Some(ip) => {
                let error = match state.tracker.hit(ip) {
                    Hit::Known | Hit::Admitted => 0,
                    Hit::Replaced { evicted, error } => {
                        delta.evict(evicted);
                        error
                    }
                };
                let slice = delta
                    .profiles
                    .entry(ip)
                    .or_default()
                    .entry(hour)
                    .or_default();
                slice.slice.error += error;
                slice.add(entry, &classification, statics);
                Some(ip)
            }
            None => None,
        };

        for (rank, rule) in active.iter().enumerate() {
            if !rule.matches_request(entry) {
                continue;
            }
            if rule.has_paths() && !*info.hits[rank].get_or_insert_with(|| rule.matches_path(path))
            {
                continue;
            }
            match rule.scope {
                Scope::Site => {
                    let bucket = delta.site_buckets.entry((rank, minute)).or_default();
                    bucket.count += 1;
                    if let Some(ip) = entry.ip
                        && bucket.ips.len() < delta.ips_cap
                        && !bucket.ips.contains(&ip)
                    {
                        bucket.ips.push(ip);
                    }
                }
                Scope::Ip => {
                    if let Some(ip) = tracked
                        && entry.timestamp_ms > ip_horizon
                    {
                        *delta
                            .ip_buckets
                            .entry(ip)
                            .or_default()
                            .entry((rank, minute))
                            .or_default() += 1;
                    }
                }
            }
        }
    }
    delta
}
