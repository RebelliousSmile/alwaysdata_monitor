//! Profil d'IP glissant sur 24 h : tranches horaires sommées, bornées par
//! l'heure de référence, jamais remises à zéro à minuit.
//!
//! Une tranche compte les requêtes, ressources statiques, facettes, refus,
//! pages sans referer, UA distincts (20 au plus), le pic par minute
//! (approché : maximum des minutes vues dans un même lot, puis maximum des
//! lots) et la classe du premier robot vu.
//!
//! Les profils d'un site sont plafonnés à [`MAX_PROFILES`] IP par
//! l'algorithme Space-Saving ([`Tracker`]) : une IP entrante prend la place
//! de celle dont le compte de classement est le plus faible et hérite de ce
//! compte comme **borne d'erreur**, jamais de ses compteurs observés. Le
//! compte de classement est la somme des tranches vivantes plus l'erreur
//! héritée, elle-même datée de la tranche d'admission : il baisse quand une
//! tranche sort de la fenêtre. Garantie : toute IP de plus de N / 10 000
//! requêtes sur la fenêtre reste suivie.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use super::catalog::{self, Bot, BotClass, Classification};
use super::score::{self, Stats, Verdict};
use crate::logs::Entry;

/// IP suivies au plus par site.
pub const MAX_PROFILES: usize = 10_000;
/// UA distincts gardés par IP.
pub const MAX_UAS: usize = 20;
/// Tranches vivantes : celles des 24 heures qui finissent à l'heure de
/// référence.
pub const LIVE_HOURS: i64 = 24;
/// Au-delà, une tranche est purgée (minimisation).
pub const RETENTION_HOURS: i64 = 48;
pub const MINUTE_MS: i64 = 60_000;
pub const HOUR_MS: i64 = 3_600_000;

/// Extensions statiques de `HttpLogParserService.php`, sans casse.
pub const STATIC_EXTENSIONS: [&str; 16] = [
    "js", "css", "png", "jpg", "jpeg", "gif", "webp", "avif", "woff", "woff2", "svg", "ico", "map",
    "ttf", "eot", "otf",
];

/// Ressource statique : le chemin finit par `.` et l'une des extensions de
/// `HttpLogParserService.php` (`STATIC_ASSETS_REGEX`), sans casse.
pub fn is_static(path: &str) -> bool {
    path.rsplit_once('.').is_some_and(|(_, ext)| {
        STATIC_EXTENSIONS
            .iter()
            .any(|known| ext.eq_ignore_ascii_case(known))
    })
}

/// Liste à facettes (`ps_facetedsearch`) : clé de requête `q`.
pub fn is_facet(entry: &Entry) -> bool {
    entry.query_keys.iter().any(|k| k == "q")
}

/// Tranche horaire d'un horodatage.
pub fn hour_of(timestamp_ms: i64) -> i64 {
    timestamp_ms.div_euclid(HOUR_MS)
}

pub fn minute_of(timestamp_ms: i64) -> i64 {
    timestamp_ms.div_euclid(MINUTE_MS)
}

/// La tranche `hour` est vivante pour l'heure de référence `reference_ms`.
pub fn is_live(hour: i64, reference_ms: i64) -> bool {
    hour > hour_of(reference_ms) - LIVE_HOURS
}

/// Profil d'une IP sur une heure.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Slice {
    pub requests: u64,
    pub statics: u64,
    pub facets: u64,
    pub refused: u64,
    pub empty_referer_pages: u64,
    pub peak_minute: u64,
    /// Borne d'erreur héritée à l'admission dans cette tranche.
    pub error: u64,
    pub uas: Vec<String>,
    /// Classe du premier robot vu (tout sauf `Browser`).
    pub class: Option<BotClass>,
    /// Premier robot du catalogue vu.
    pub bot: Option<&'static str>,
}

impl Slice {
    /// Compte une entrée ; le pic par minute est tenu par l'appelant.
    pub fn add(&mut self, entry: &Entry, classification: &Classification, statics: bool) {
        self.requests += 1;
        if statics {
            self.statics += 1;
        } else if !entry.referer_present {
            self.empty_referer_pages += 1;
        }
        if is_facet(entry) {
            self.facets += 1;
        }
        if entry.status == 403 {
            self.refused += 1;
        }
        self.add_ua(&entry.user_agent);
        if self.class.is_none() && classification.class != BotClass::Browser {
            self.class = Some(classification.class);
        }
        if self.bot.is_none() {
            self.bot = classification.bot.map(|b| b.name);
        }
    }

    fn add_ua(&mut self, ua: &str) {
        if self.uas.len() < MAX_UAS && !self.uas.iter().any(|u| u == ua) {
            self.uas.push(ua.to_string());
        }
    }

    /// Ajoute une tranche plus récente de la même heure (lot suivant) : les
    /// comptes s'additionnent, le pic est le plus haut des deux, le premier
    /// robot reste celui de `self`.
    pub fn merge(&mut self, later: &Slice) {
        self.requests += later.requests;
        self.statics += later.statics;
        self.facets += later.facets;
        self.refused += later.refused;
        self.empty_referer_pages += later.empty_referer_pages;
        self.peak_minute = self.peak_minute.max(later.peak_minute);
        self.error += later.error;
        for ua in &later.uas {
            self.add_ua(ua);
        }
        if self.class.is_none() {
            self.class = later.class;
        }
        if self.bot.is_none() {
            self.bot = later.bot;
        }
    }
}

/// Profil d'une IP : ses tranches vivantes sommées.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpProfile {
    pub ip: IpAddr,
    /// Compteurs observés seulement.
    pub stats: Stats,
    /// Borne d'erreur héritée encore vivante.
    pub error: u64,
    /// Classe du premier robot vu, `Browser` s'il n'y en a pas.
    pub class: BotClass,
    /// Premier robot du catalogue vu.
    pub bot: Option<&'static Bot>,
}

impl IpProfile {
    /// Somme des tranches, prises dans l'ordre des heures.
    pub fn from_slices<'a>(ip: IpAddr, slices: impl IntoIterator<Item = &'a Slice>) -> Self {
        let mut total = Slice::default();
        for slice in slices {
            total.merge(slice);
        }
        Self {
            ip,
            stats: Stats {
                requests: total.requests,
                statics: total.statics,
                facets: total.facets,
                refused: total.refused,
                empty_referer_pages: total.empty_referer_pages,
                uas: total.uas,
                peak_minute: total.peak_minute,
            },
            error: total.error,
            class: total.class.unwrap_or(BotClass::Browser),
            bot: total.bot.and_then(catalog::find),
        }
    }

    /// Compte de classement de Space-Saving.
    pub fn rank(&self) -> u64 {
        self.stats.requests.saturating_add(self.error)
    }

    /// Le score n'a de sens que si l'erreur héritée est nulle ou inférieure
    /// au dixième des requêtes observées. Sinon l'IP reste sans score, ce
    /// qui n'est pas un verdict de trafic sain.
    pub fn scorable(&self) -> bool {
        self.stats.requests > 0
            && (self.error == 0 || self.error.saturating_mul(10) < self.stats.requests)
    }

    /// Score sur les compteurs observés, sans reverse DNS (V1).
    pub fn verdict(&self) -> Option<Verdict> {
        self.scorable()
            .then(|| score::score(&self.stats, None, self.bot.map(|b| b.name)))
    }
}

/// Issue d'une requête vue par le [`Tracker`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hit {
    /// IP déjà suivie.
    Known,
    /// IP admise dans une place libre.
    Admitted,
    /// IP admise à la place de `evicted`, dont elle hérite `error`.
    Replaced { evicted: IpAddr, error: u64 },
}

/// Space-Saving sur les IP d'un site : compte de classement par IP, et
/// l'ordre des comptes pour trouver le plus faible en O(log n). Déterministe :
/// à compte égal, la plus petite IP part la première.
#[derive(Debug, Clone)]
pub struct Tracker {
    capacity: usize,
    ranks: HashMap<IpAddr, u64>,
    order: BTreeSet<(u64, IpAddr)>,
}

impl Tracker {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            ranks: HashMap::new(),
            order: BTreeSet::new(),
        }
    }

    /// Reprend les comptes lus en base (`analysis/store.rs`).
    pub fn with_ranks(capacity: usize, ranks: impl IntoIterator<Item = (IpAddr, u64)>) -> Self {
        let mut tracker = Self::new(capacity);
        for (ip, rank) in ranks {
            tracker.ranks.insert(ip, rank);
            tracker.order.insert((rank, ip));
        }
        tracker
    }

    /// Même suivi, autre plafond.
    pub fn resized(&self, capacity: usize) -> Self {
        Self::with_ranks(capacity, self.ranks.iter().map(|(ip, rank)| (*ip, *rank)))
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.ranks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ranks.is_empty()
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.ranks.contains_key(ip)
    }

    pub fn rank(&self, ip: &IpAddr) -> Option<u64> {
        self.ranks.get(ip).copied()
    }

    /// Une requête de `ip`.
    pub fn hit(&mut self, ip: IpAddr) -> Hit {
        if let Some(rank) = self.ranks.get_mut(&ip) {
            self.order.remove(&(*rank, ip));
            *rank += 1;
            self.order.insert((*rank, ip));
            return Hit::Known;
        }
        if self.ranks.len() < self.capacity {
            self.ranks.insert(ip, 1);
            self.order.insert((1, ip));
            return Hit::Admitted;
        }
        let Some((error, evicted)) = self.order.pop_first() else {
            // Capacité nulle impossible (`new` la porte à 1).
            return Hit::Known;
        };
        self.ranks.remove(&evicted);
        self.ranks.insert(ip, error + 1);
        self.order.insert((error + 1, ip));
        Hit::Replaced { evicted, error }
    }
}
