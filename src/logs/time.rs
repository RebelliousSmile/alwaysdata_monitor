//! Horodatage Apache (`%t`) → millisecondes UTC.
//!
//! `[10/Oct/2026:13:55:36 +0200]` : le décalage écrit dans la ligne l'emporte.
//! Sans décalage, le fuseau IANA déclaré pour la source ; ses ambiguïtés sont
//! levées en mode `compatible` de jiff : au recul d'heure, la plus tôt des
//! deux heures ; dans le trou d'une avance d'heure, l'heure décalée d'autant
//! après le trou. Sans décalage ni fuseau, aucune heure n'est devinée.

use jiff::civil::DateTime;
use jiff::tz::{Offset, TimeZone};

const MONTHS: [&[u8; 3]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

/// Millisecondes UTC, ou `None` si l'horodatage est illisible, hors des
/// années 1970 à 9999, ou sans décalage ni fuseau de source.
pub fn parse_apache(raw: &[u8], source_tz: Option<&TimeZone>) -> Option<i64> {
    let raw = raw.strip_prefix(b"[").unwrap_or(raw);
    let raw = raw.strip_suffix(b"]").unwrap_or(raw);
    let (stamp, offset) = match raw.iter().position(|&b| b == b' ') {
        Some(at) => (&raw[..at], Some(&raw[at + 1..])),
        None => (raw, None),
    };
    // dd/Mon/yyyy:HH:MM:SS
    if stamp.len() != 20
        || stamp[2] != b'/'
        || stamp[6] != b'/'
        || stamp[11] != b':'
        || stamp[14] != b':'
        || stamp[17] != b':'
    {
        return None;
    }
    let day = digits(&stamp[0..2])?;
    let month = MONTHS.iter().position(|m| m[..] == stamp[3..6])? + 1;
    let year = digits(&stamp[7..11])?;
    let hour = digits(&stamp[12..14])?;
    let minute = digits(&stamp[15..17])?;
    let second = digits(&stamp[18..20])?;
    if !(1970..=9999).contains(&year) {
        return None;
    }
    let civil = DateTime::new(
        i16::try_from(year).ok()?,
        i8::try_from(month).ok()?,
        i8::try_from(day).ok()?,
        i8::try_from(hour).ok()?,
        i8::try_from(minute).ok()?,
        i8::try_from(second).ok()?,
        0,
    )
    .ok()?;
    let zone = match offset {
        Some(offset) => TimeZone::fixed(parse_offset(offset)?),
        None => source_tz?.clone(),
    };
    let ms = zone.to_timestamp(civil).ok()?.as_millisecond();
    (ms >= 0).then_some(ms)
}

/// `+0200`, `-0530`.
fn parse_offset(raw: &[u8]) -> Option<Offset> {
    if raw.len() != 5 {
        return None;
    }
    let sign: i32 = match raw[0] {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let hours = i32::try_from(digits(&raw[1..3])?).ok()?;
    let minutes = i32::try_from(digits(&raw[3..5])?).ok()?;
    if hours > 23 || minutes > 59 {
        return None;
    }
    Offset::from_seconds(sign * (hours * 3600 + minutes * 60)).ok()
}

fn digits(raw: &[u8]) -> Option<u32> {
    if raw.is_empty() || !raw.iter().all(u8::is_ascii_digit) {
        return None;
    }
    raw.iter().try_fold(0u32, |acc, &b| {
        acc.checked_mul(10)?.checked_add(u32::from(b - b'0'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paris() -> TimeZone {
        TimeZone::get("Europe/Paris").expect("base tz embarquée")
    }

    #[test]
    fn a_written_offset_wins() {
        // 2026-04-12T12:32:10Z
        let expected = 1_775_997_130_000;
        assert_eq!(
            parse_apache(b"[12/Apr/2026:14:32:10 +0200]", None),
            Some(expected)
        );
        assert_eq!(
            parse_apache(b"12/Apr/2026:12:32:10 +0000", None),
            Some(expected)
        );
        assert_eq!(
            parse_apache(b"[12/Apr/2026:07:02:10 -0530]", Some(&paris())),
            Some(expected)
        );
    }

    #[test]
    fn without_offset_the_source_zone_applies_with_dst() {
        let tz = paris();
        // Été : +02:00 ; hiver : +01:00.
        assert_eq!(
            parse_apache(b"[12/Apr/2026:14:32:10]", Some(&tz)),
            Some(1_775_997_130_000)
        );
        assert_eq!(
            parse_apache(b"[12/Jan/2026:14:32:10]", Some(&tz)),
            Some(1_768_224_730_000)
        );
        // Recul d'heure du 2026-10-25 : 02:30 existe deux fois, la plus tôt
        // (encore à +02:00) est retenue.
        assert_eq!(
            parse_apache(b"[25/Oct/2026:02:30:00]", Some(&tz)),
            Some(1_792_888_200_000)
        );
        // Sans fuseau, rien n'est deviné.
        assert_eq!(parse_apache(b"[12/Apr/2026:14:32:10]", None), None);
    }

    #[test]
    fn malformed_stamps_are_refused() {
        for raw in [
            &b""[..],
            b"[]",
            b"[12/Foo/2026:14:32:10 +0200]",
            b"[32/Apr/2026:14:32:10 +0200]",
            b"[12/Apr/2026:24:32:10 +0200]",
            b"[12/Apr/1969:14:32:10 +0200]",
            b"[12/Apr/2026:14:32:10 0200]",
            b"[12/Apr/2026:14:32:10 +2400]",
            b"[1x/Apr/2026:14:32:10 +0200]",
            b"[12/Apr/2026:14:32:10 +0200 extra]",
            "[12/Avr/2026:14:32:10 +0200]".as_bytes(),
        ] {
            assert_eq!(
                parse_apache(raw, Some(&paris())),
                None,
                "{:?}",
                String::from_utf8_lossy(raw)
            );
        }
    }
}
