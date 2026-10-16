//! Charge par heure, portée de `LoadDiagnosticService.php` : volume, refus
//! (403), temps de service cumulé (`Entry::duration_us`), et part des
//! facettes (`?q=`) et des robots du catalogue dans ce temps.
//!
//! Sans durée dans les logs (format autre que « Advanced » d'Alwaysdata),
//! seul le volume horaire est relevé : [`HourLoad::exceeds`] reste faux et le
//! constat `load` (phase 3) ne s'ouvre pas.

use crate::logs::Entry;

/// Seuil par défaut du constat `load` : 1 800 s de service cumulées dans
/// une heure, soit un worker PHP occupé une demi-heure sur l'heure.
pub const DEFAULT_THRESHOLD_US: u64 = 1_800 * 1_000_000;

/// Charge d'une heure (tranche `timestamp_ms / 3 600 000`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HourLoad {
    pub hour: i64,
    pub requests: u64,
    /// Requêtes refusées (403) : un scraper bloqué reste dans le log.
    pub refused: u64,
    /// Requêtes qui portent une durée de service.
    pub timed: u64,
    pub service_us: u64,
    pub facets: u64,
    pub facets_us: u64,
    /// Requêtes d'un robot du catalogue.
    pub bots: u64,
    pub bots_us: u64,
}

impl HourLoad {
    pub fn new(hour: i64) -> Self {
        Self {
            hour,
            ..Self::default()
        }
    }

    /// Compte une entrée : `facet` et `bot` viennent du repli (`fold.rs`).
    pub fn add(&mut self, entry: &Entry, facet: bool, bot: bool) {
        let duration = entry.duration_us.unwrap_or(0);
        self.requests += 1;
        if entry.status == 403 {
            self.refused += 1;
        }
        if entry.duration_us.is_some() {
            self.timed += 1;
            self.service_us = self.service_us.saturating_add(duration);
        }
        if facet {
            self.facets += 1;
            self.facets_us = self.facets_us.saturating_add(duration);
        }
        if bot {
            self.bots += 1;
            self.bots_us = self.bots_us.saturating_add(duration);
        }
    }

    /// Ajoute les comptes d'une autre tranche de la même heure.
    pub fn merge(&mut self, other: &Self) {
        self.requests += other.requests;
        self.refused += other.refused;
        self.timed += other.timed;
        self.service_us = self.service_us.saturating_add(other.service_us);
        self.facets += other.facets;
        self.facets_us = self.facets_us.saturating_add(other.facets_us);
        self.bots += other.bots;
        self.bots_us = self.bots_us.saturating_add(other.bots_us);
    }

    /// Les logs de l'heure portent des durées.
    pub fn has_durations(&self) -> bool {
        self.timed > 0
    }

    /// Le temps de service de l'heure dépasse `threshold_us` ; toujours faux
    /// sans durée.
    pub fn exceeds(&self, threshold_us: u64) -> bool {
        self.has_durations() && self.service_us > threshold_us
    }

    /// Part du temps de service prise par les facettes, de 0 à 1.
    pub fn facets_share(&self) -> Option<f64> {
        (self.service_us > 0).then(|| self.facets_us as f64 / self.service_us as f64)
    }

    /// Part du temps de service prise par les robots, de 0 à 1.
    pub fn bots_share(&self) -> Option<f64> {
        (self.service_us > 0).then(|| self.bots_us as f64 / self.service_us as f64)
    }
}
