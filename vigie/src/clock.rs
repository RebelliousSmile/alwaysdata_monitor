//! Horloge injectable : la seule source de temps des décisions de fenêtre.
//!
//! Règle : une décision qui dépend de l'heure (décalage d'horloge d'un
//! rapport, âge du dernier `tick`, expiration d'un code, jours avant
//! l'expiration d'un certificat, fenêtres glissantes de l'analyse de logs)
//! lit l'heure d'une [`Clock`], passée en paramètre. Un test la remplace par
//! une [`FakeClock`] et rejoue la décision à l'heure voulue.
//!
//! Les délais d'E/S réelles restent sur `Instant::now()` : délais réseau de
//! `tick`, `http`, `checks/tls`, patience d'ouverture de `store`,
//! `tokio::time::timeout` de `serve` et `api`. Simuler le temps d'une E/S
//! réelle ne teste rien.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub trait Clock: Send + Sync {
    /// Heure courante, en secondes Unix.
    fn unix(&self) -> i64;
    /// Instant monotone, pour mesurer un écart sans subir un réglage de
    /// l'heure système.
    fn monotonic(&self) -> Instant;
}

/// Horloge du système.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn unix(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    }

    fn monotonic(&self) -> Instant {
        Instant::now()
    }
}

/// Horloge de test : ne bouge que quand on l'avance. Publique, sans
/// `cfg(test)`, parce que les tests d'intégration la partagent.
#[derive(Debug)]
pub struct FakeClock {
    unix: AtomicI64,
    base: Instant,
    /// Nanosecondes ajoutées à `base`.
    offset: AtomicU64,
}

impl FakeClock {
    pub fn new(unix: i64) -> Self {
        Self {
            unix: AtomicI64::new(unix),
            base: Instant::now(),
            offset: AtomicU64::new(0),
        }
    }

    /// Avance les deux horloges de `seconds` (une valeur négative recule
    /// l'heure Unix seulement : une horloge monotone ne recule pas).
    pub fn advance(&self, seconds: i64) {
        self.unix.fetch_add(seconds, Ordering::SeqCst);
        if let Ok(forward) = u64::try_from(seconds) {
            self.advance_monotonic(Duration::from_secs(forward));
        }
    }

    /// Avance l'instant monotone seul, à la nanoseconde.
    pub fn advance_monotonic(&self, by: Duration) {
        let nanos = u64::try_from(by.as_nanos()).unwrap_or(u64::MAX);
        self.offset.fetch_add(nanos, Ordering::SeqCst);
    }

    /// Règle l'heure Unix, comme un réglage de l'heure système : l'instant
    /// monotone ne bouge pas.
    pub fn set(&self, unix: i64) {
        self.unix.store(unix, Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn unix(&self) -> i64 {
        self.unix.load(Ordering::SeqCst)
    }

    fn monotonic(&self) -> Instant {
        self.base + Duration::from_nanos(self.offset.load(Ordering::SeqCst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fake_clock_moves_only_by_hand() {
        let clock = FakeClock::new(1_000);
        let start = clock.monotonic();
        assert_eq!(clock.unix(), 1_000);
        assert_eq!(clock.monotonic(), start);

        clock.advance(60);
        assert_eq!(clock.unix(), 1_060);
        assert_eq!(clock.monotonic() - start, Duration::from_secs(60));

        // Réglage de l'heure : l'instant monotone n'en voit rien.
        clock.set(500);
        clock.advance(-10);
        assert_eq!(clock.unix(), 490);
        assert_eq!(clock.monotonic() - start, Duration::from_secs(60));

        clock.advance_monotonic(Duration::from_millis(5));
        assert_eq!(clock.unix(), 490);
        assert_eq!(clock.monotonic() - start, Duration::from_millis(60_005));
    }

    #[test]
    fn the_system_clock_is_after_2026() {
        assert!(SystemClock.unix() > 1_767_225_600);
    }
}
