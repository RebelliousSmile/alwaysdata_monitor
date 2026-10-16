//! Veilleur multi-sites : bibliothèque partagée par le binaire `vigie` et
//! par les tests d'intégration, qui y branchent un notifier en mémoire et une
//! autorité de certification de test.

pub mod alert;
pub mod api;
pub mod checks;
pub mod clock;
pub mod config;
pub mod device;
pub mod error;
pub mod facts;
pub mod finding;
pub mod http;
pub mod ingest;
pub mod logs;
pub mod report;
pub mod request_id;
pub mod serve;
pub mod store;
pub mod tick;
pub mod writer;

/// Heure courante, en secondes Unix.
/// Raccourci de [`clock::SystemClock`], pour les appelants qui ne décident
/// rien de l'heure qu'ils lisent (voir la règle de `clock.rs`).
pub fn now() -> i64 {
    use clock::Clock;
    clock::SystemClock.unix()
}

/// `2026-10-15T15:53:00Z` : heure UTC lisible dans un e-mail ou dans `status`.
pub fn iso_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rest = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// Jours depuis 1970-01-01 → (année, mois, jour), d'après l'algorithme
/// `civil_from_days` de Howard Hinnant (calendrier grégorien proleptique).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// Durée lisible : `42 s`, `5 min`, `3 h`, `2 j`.
pub fn human_age(seconds: i64) -> String {
    let s = seconds.max(0);
    match s {
        0..60 => format!("{s} s"),
        60..3600 => format!("{} min", s / 60),
        3600..86_400 => format!("{} h", s / 3600),
        _ => format!("{} j", s / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_utc_dates() {
        assert_eq!(iso_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(iso_utc(1_792_079_580), "2026-10-15T15:53:00Z");
        assert_eq!(iso_utc(-1), "1969-12-31T23:59:59Z");
    }

    #[test]
    fn formats_ages() {
        assert_eq!(human_age(-5), "0 s");
        assert_eq!(human_age(59), "59 s");
        assert_eq!(human_age(300), "5 min");
        assert_eq!(human_age(7200), "2 h");
        assert_eq!(human_age(3 * 86_400), "3 j");
    }
}
