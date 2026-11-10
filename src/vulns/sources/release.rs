//! Grammaire **fermée** de « Impacted release » (Friends-Of-Presta), partagée
//! avec les corrections de plage (`vulns/corrections.rs`). Une formulation
//! hors grammaire ne devine jamais : elle donne `None`, la ligne devient
//! `unevaluable` (« plage inconnue » pour toute version).
//!
//! Mots-clés sans casse, `v` initial d'une version retiré, chaque version
//! analysable par le comparateur PHP (`[0-9][0-9A-Za-z.+_-]*`) :
//!
//! | Forme | Événements |
//! | --- | --- |
//! | `<= V` | plancher, `last_affected V` |
//! | `< V` | plancher, `fixed V` |
//! | `V`, `= V` | `introduced V`, `last_affected V` |
//! | `>= A <= B`, `>= A, <= B`, `A - B` (espaces exigés), `A to B`, `from A to B`, `between A and B` | `introduced A`, `last_affected B` |
//! | `>= A < B`, `>= A, < B` | `introduced A`, `fixed B` |
//! | `>= A` | `introduced A` (plage ouverte) |
//!
//! Remarque finale entre parenthèses, reconnue sous trois formes seulement :
//! `(V fixed the vulnerability)`, `(fixed in V)`, `(V fixes …)`. Borne haute
//! `last_affected B` : V > B ajoute `fixed V`, sinon plage douteuse ; borne
//! haute `fixed B` : V = B ne change rien, sinon plage douteuse ; plage
//! ouverte : douteuse. Toute autre remarque est ignorée. Borne basse au-dessus
//! de la haute (ou égale à une borne `fixed`) : refusée.

use crate::vulns::advisory::Event;
use crate::vulns::version::{Scheme, Version, parse};

/// Version de la grammaire : `v` initial retiré, premier caractère
/// chiffre, analysable par le comparateur PHP.
fn version(token: &str) -> Option<(String, Version)> {
    let raw = token
        .strip_prefix(['v', 'V'])
        .filter(|r| r.starts_with(|c: char| c.is_ascii_digit()))
        .unwrap_or(token);
    if !raw.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    let v = parse(Scheme::Php, raw).ok()?;
    Some((raw.to_owned(), v))
}

/// Découpe en jetons : opérateurs `<=`, `>=`, `<`, `=` et `,` isolés.
fn tokens(text: &str) -> Vec<String> {
    let mut spaced = String::with_capacity(text.len() * 2);
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '<' | '>' if chars.get(i + 1) == Some(&'=') => {
                spaced.push(' ');
                spaced.push(c);
                spaced.push('=');
                spaced.push(' ');
                i += 2;
                continue;
            }
            '<' | '>' | '=' | ',' => {
                spaced.push(' ');
                spaced.push(c);
                spaced.push(' ');
            }
            _ => spaced.push(c),
        }
        i += 1;
    }
    spaced.split_whitespace().map(str::to_owned).collect()
}

/// Borne haute d'une plage.
enum Upper {
    Open,
    LastAffected(Version),
    Fixed(Version),
}

/// Plage sans remarque : événements et borne haute.
fn main_range(tokens: &[String]) -> Option<(Vec<Event>, Upper)> {
    let words: Vec<String> = tokens.iter().map(|t| t.to_ascii_lowercase()).collect();
    let w: Vec<&str> = words.iter().map(String::as_str).collect();
    let floor = || Event::Introduced("0".to_owned());
    let closed = |a: &str, b: &str, fixed: bool| {
        let (ra, va) = version(a)?;
        let (rb, vb) = version(b)?;
        if va > vb || (fixed && va == vb) {
            return None;
        }
        let (last, upper) = if fixed {
            (Event::Fixed(rb), Upper::Fixed(vb))
        } else {
            (Event::LastAffected(rb), Upper::LastAffected(vb))
        };
        Some((vec![Event::Introduced(ra), last], upper))
    };
    // Les versions gardent leur casse : on lit `tokens`, on compare `w`.
    let t = tokens;
    match w.as_slice() {
        ["<=", _] => {
            let (r, v) = version(&t[1])?;
            Some((
                vec![floor(), Event::LastAffected(r)],
                Upper::LastAffected(v),
            ))
        }
        ["<", _] => {
            let (r, v) = version(&t[1])?;
            Some((vec![floor(), Event::Fixed(r)], Upper::Fixed(v)))
        }
        [_] | ["=", _] => {
            let (r, v) = version(t.last()?)?;
            // `1.0-2.0` : plage sans espaces, pas une version.
            if r.as_bytes()
                .windows(2)
                .any(|p| p[0] == b'-' && p[1].is_ascii_digit())
            {
                return None;
            }
            Some((
                vec![Event::Introduced(r.clone()), Event::LastAffected(r)],
                Upper::LastAffected(v),
            ))
        }
        [">=", _, "<=", _] => closed(&t[1], &t[3], false),
        [">=", _, ",", "<=", _] => closed(&t[1], &t[4], false),
        [_, "-" | "to", _] => closed(&t[0], &t[2], false),
        ["from", _, "to", _] | ["between", _, "and", _] => closed(&t[1], &t[3], false),
        [">=", _, "<", _] => closed(&t[1], &t[3], true),
        [">=", _, ",", "<", _] => closed(&t[1], &t[4], true),
        [">=", _] => {
            let (r, _) = version(&t[1])?;
            Some((vec![Event::Introduced(r)], Upper::Open))
        }
        _ => None,
    }
}

/// Version d'une remarque reconnue, `Some(None)` pour une remarque ignorée.
fn remark(text: &str) -> Option<Option<(String, Version)>> {
    let t: Vec<&str> = text.split_whitespace().collect();
    let w: Vec<String> = t.iter().map(|s| s.to_ascii_lowercase()).collect();
    let w: Vec<&str> = w.iter().map(String::as_str).collect();
    let at = match w.as_slice() {
        [_, "fixed", "the", "vulnerability"] => 0,
        ["fixed", "in", _] => 2,
        [_, "fixes", ..] => 0,
        _ => return Some(None),
    };
    // Forme reconnue mais version illisible : plage douteuse.
    version(t[at]).map(Some)
}

/// Événements d'une plage écrite en texte libre, ou `None` hors grammaire.
/// `allow_remark` : faux pour une correction de plage saisie.
pub fn parse_release(raw: &str, allow_remark: bool) -> Option<Vec<Event>> {
    let text = raw.trim();
    if text.is_empty() || text.len() > 256 {
        return None;
    }
    let (main, note) = match text.strip_suffix(')') {
        Some(inner) => {
            let open = inner.rfind('(')?;
            (&inner[..open], Some(&inner[open + 1..]))
        }
        None => (text, None),
    };
    if main.contains(['(', ')']) || note.is_some_and(|n| n.contains('(')) {
        return None;
    }
    if note.is_some() && !allow_remark {
        return None;
    }
    let (mut events, upper) = main_range(&tokens(main))?;
    let Some(note) = note else {
        return Some(events);
    };
    let Some((raw_fix, fix)) = remark(note)? else {
        return Some(events);
    };
    match upper {
        Upper::LastAffected(b) if fix > b => events.push(Event::Fixed(raw_fix)),
        Upper::Fixed(b) if fix == b => {}
        _ => return None,
    }
    Some(events)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_isolate_operators() {
        assert_eq!(tokens(">=1.0,<2.0"), [">=", "1.0", ",", "<", "2.0"]);
        assert_eq!(tokens("1.0-2.0"), ["1.0-2.0"]);
    }
}
