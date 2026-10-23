//! Erreurs des sites (issue #52) : lots de groupes d'erreurs poussés par
//! l'agent PHP (`docs/protocole-agent.md`, « Lots d'erreurs »).
//!
//! Un lot porte l'état d'un jour UTC d'un site : au plus 50 groupes
//! `(message normalisé, compteur, première vue, dernière vue)`. Jamais une
//! ligne brute : l'agent a déjà retiré chemins, requêtes et adresses, et le
//! veilleur applique la même normalisation avant de calculer l'empreinte et
//! refuse un lot dont un message contient encore une adresse IP ou un
//! caractère de contrôle.

pub mod receive;

use std::net::IpAddr;

use sha2::{Digest, Sha256};

/// Groupes d'un lot, au plus.
pub const MAX_GROUPS: usize = 50;
/// Longueur d'un message, en caractères.
pub const MAX_MESSAGE_CHARS: usize = 200;
/// Jours conservés et lus, aujourd'hui compris.
pub const RETENTION_DAYS: i64 = 14;
/// Compteur d'un groupe, au plus : borne défensive d'un jour d'erreurs.
pub const MAX_COUNT: i64 = 1_000_000_000;

/// Premier jour (`AAAA-MM-JJ`, UTC) encore conservé et lu à l'instant `now`.
pub fn first_kept_day(now: i64) -> String {
    crate::utc_day(now.saturating_sub((RETENTION_DAYS - 1) * 86_400))
}

/// Un jour `AAAA-MM-JJ` existe-t-il au calendrier grégorien ?
pub fn valid_day(day: &str) -> bool {
    let b = day.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    if ![0, 1, 2, 3, 5, 6, 8, 9]
        .iter()
        .all(|&i| b[i].is_ascii_digit())
    {
        return false;
    }
    let num = |from: usize, to: usize| day[from..to].parse::<i64>().ok();
    let (Some(y), Some(m), Some(d)) = (num(0, 4), num(5, 7), num(8, 10)) else {
        return false;
    };
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return false;
    }
    // Aller-retour par le calendrier : 31 février devient 3 mars et diffère.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    crate::utc_day(days * 86_400) == day
}

/// Normalise un message, de façon idempotente : un UUID devient `<uuid>`,
/// puis chaque suite de chiffres ASCII devient `#`. La longueur ne peut que
/// diminuer.
pub fn normalize(message: &str) -> String {
    let chars: Vec<char> = message.chars().collect();
    let mut out = String::with_capacity(message.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let boundary = i == 0 || !chars[i - 1].is_ascii_alphanumeric();
        if boundary && is_uuid_at(&chars, i) {
            out.push_str("<uuid>");
            i += 36;
        } else if c.is_ascii_digit() {
            while chars.get(i).is_some_and(char::is_ascii_digit) {
                i += 1;
            }
            out.push('#');
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// UUID `8-4-4-4-12` hexadécimal à `start`, suivi d'un non-alphanumérique ou
/// de la fin.
fn is_uuid_at(chars: &[char], start: usize) -> bool {
    const SHAPE: [usize; 5] = [8, 4, 4, 4, 12];
    let mut at = start;
    for (n, len) in SHAPE.into_iter().enumerate() {
        if n > 0 {
            if chars.get(at) != Some(&'-') {
                return false;
            }
            at += 1;
        }
        for _ in 0..len {
            if !chars.get(at).is_some_and(char::is_ascii_hexdigit) {
                return false;
            }
            at += 1;
        }
    }
    !chars.get(at).is_some_and(char::is_ascii_alphanumeric)
}

/// SHA-256 hexadécimal (minuscules) du message normalisé.
pub fn fingerprint(normalized: &str) -> String {
    Sha256::digest(normalized.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Le message contient-il encore une adresse IP (v4 ou v6) ? Analyse stricte
/// de chaque suite de `[A-Za-z0-9:.%]`, avec ses variantes sans zone
/// (`%eth0`), sans port, sans ponctuation de bord et après chaque `:`, plus
/// la forme IPv4 « quatre groupes de un à trois chiffres ≤ 255 » (que
/// l'analyseur de la bibliothèque refuse avec des zéros de tête). L'adresse
/// non spécifiée `::` seule n'en est pas une : `Foo::bar` reste un message.
pub fn contains_address(message: &str) -> bool {
    message
        .split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '%')))
        .filter(|token| !token.is_empty())
        .any(token_has_address)
}

fn token_has_address(token: &str) -> bool {
    let starts = std::iter::once(0).chain(token.match_indices(':').map(|(at, _)| at + 1));
    starts.into_iter().any(|start| {
        let raw = &token[start..];
        let part = raw.trim_start_matches('.').trim_end_matches(['.', ':']);
        let no_zone = part.split('%').next().unwrap_or(part);
        let no_port = match no_zone.rsplit_once(':') {
            Some((host, port))
                if host.contains('.')
                    && !port.is_empty()
                    && port.bytes().all(|b| b.is_ascii_digit()) =>
            {
                host
            }
            _ => no_zone,
        };
        [raw, part, no_zone, no_port].into_iter().any(is_address)
    })
}

fn is_address(candidate: &str) -> bool {
    if candidate.is_empty() || candidate == "::" {
        return false;
    }
    candidate.parse::<IpAddr>().is_ok() || is_loose_ipv4(candidate)
}

/// `a.b.c.d`, un à trois chiffres chacun, ≤ 255, zéros de tête permis.
fn is_loose_ipv4(candidate: &str) -> bool {
    let parts: Vec<&str> = candidate.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            (1..=3).contains(&p.len())
                && p.bytes().all(|b| b.is_ascii_digit())
                && p.parse::<u16>().is_ok_and(|n| n <= 255)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digits_and_uuids_are_masked() {
        assert_eq!(
            normalize("Undefined array key 12 in include #3 at line 456"),
            "Undefined array key # in include ## at line #"
        );
        assert_eq!(
            normalize("job 123e4567-e89b-12d3-a456-426614174000 failed"),
            "job <uuid> failed"
        );
        assert_eq!(normalize("123E4567-E89B-12D3-A456-426614174000"), "<uuid>");
        // Pas un UUID : trop court, ou collé à des alphanumériques.
        assert_eq!(
            normalize("123e4567-e89b-12d3-a456-42661417400"),
            "#e#-e#b-#d#-a#-#"
        );
        assert_eq!(
            normalize("x123e4567-e89b-12d3-a456-426614174000"),
            "x#e#-e#b-#d#-a#-#"
        );
        assert_eq!(normalize("sans chiffre"), "sans chiffre");
        assert_eq!(normalize("é1à22"), "é#à#");
    }

    #[test]
    fn normalization_is_idempotent_and_never_longer() {
        for message in [
            "Undefined array key 12",
            "job 123e4567-e89b-12d3-a456-426614174000 failed 3 times",
            "<uuid> # <ip>",
            "000 111 2222",
            "",
        ] {
            let once = normalize(message);
            assert_eq!(normalize(&once), once, "{message}");
            assert!(once.chars().count() <= message.chars().count(), "{message}");
        }
    }

    #[test]
    fn a_fingerprint_is_a_lowercase_sha256_of_the_normalized_message() {
        assert_eq!(
            fingerprint(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let print = fingerprint("Undefined array key #");
        assert_eq!(print.len(), 64);
        assert!(
            print
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        );
        assert_eq!(print, fingerprint(&normalize("Undefined array key 7")));
    }

    #[test]
    fn addresses_left_in_a_message_are_found() {
        for message in [
            "connexion refusée 192.0.2.7",
            "from 198.51.100.4:8080 failed",
            "from 198.51.100.4: failed",
            "addr=203.0.113.9.",
            "ip 192.000.002.001 vue",
            "[2001:db8::1]:443 injoignable",
            "2001:db8::1",
            "fe80::1%eth0 zone",
            "::1 boucle",
            "::ffff:192.0.2.1",
            "2001:0db8:0000:0000:0000:0000:0000:0001",
            "client:192.0.2.1",
            "(192.0.2.1)",
            "255.255.255.255",
        ] {
            assert!(contains_address(message), "{message}");
        }
    }

    #[test]
    fn ordinary_messages_are_not_addresses() {
        for message in [
            "Undefined array key #",
            "Class Foo::bar not found",
            "::",
            "appel de ::",
            "Call to undefined method Foo::bar()",
            "version #.#.#",
            "1.2.3",
            "1.2.3.4.5",
            "256.1.1.1",
            "1.2.3.4444",
            "12:34:56",
            "file.php:12",
            "a.b.c.d",
            "",
        ] {
            assert!(!contains_address(message), "{message}");
        }
    }

    #[test]
    fn days_must_exist_on_the_calendar() {
        for ok in ["2026-10-16", "2024-02-29", "2000-02-29", "1970-01-01"] {
            assert!(valid_day(ok), "{ok}");
        }
        for bad in [
            "2026-02-29",
            "2026-13-01",
            "2026-00-10",
            "2026-04-31",
            "2026-10-00",
            "2026-1-16",
            "2026/10/16",
            "26-10-16",
            "2026-10-16Z",
            "２０２６-10-16",
            "",
        ] {
            assert!(!valid_day(bad), "{bad}");
        }
    }

    #[test]
    fn the_oldest_kept_day_is_thirteen_days_back() {
        // 2026-10-16T12:00:00Z
        assert_eq!(first_kept_day(1_792_152_000), "2026-10-03");
        assert_eq!(first_kept_day(1_792_108_800), "2026-10-03");
    }
}
