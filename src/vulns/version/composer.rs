//! Versions Composer : `VersionParser::normalize` de `composer/semver`, puis
//! `version_compare` de PHP sur la forme normalisée, comme le `Comparator`
//! de Composer.
//!
//! Source lue : `src/VersionParser.php` de `composer/semver`, branche `main`
//! le 2026-10-17 (dernière version publiée : 3.5.1). Ses vecteurs de
//! `tests/VersionParserTest.php` repris dans
//! `tests/fixtures/versions/composer.json` (licence MIT, `NOTICE`).
//!
//! - `+build` retiré ; `v` initial retiré ; majeur de 5 chiffres au plus
//!   (forme classique), complété à quatre composants (`1.2` → `1.2.0.0`) ;
//!   sinon versions-dates `AAAA[.MM…]` (tout non-chiffre devient `.`).
//! - Suffixes insensibles à la casse, canonisés comme `expandStability` :
//!   `a`/`alpha` → `alpha`, `b`/`beta` → `beta`, `rc` → `RC`,
//!   `p`/`pl`/`patch` → `patch`, `-stable` (en minuscules) retiré, numéro
//!   accolé (`beta.2` → `beta2`), `-dev` final.
//! - Branches (`dev-*`, `*.x-dev`), alias et contraintes : [`Unparsable`].
//!
//! La comparaison reprend les jetons de [`super::php`] ; Composer y injecte
//! `patch` au rang de `pl` (PHP l'apparie à `p` par préfixe).

use std::cmp::Ordering;

use super::php::{self, Token};
use super::{Unparsable, in_grammar};

/// Mots d'une forme normalisée par Composer.
fn composer_word(word: &str) -> Option<u8> {
    match word {
        "dev" => Some(0),
        "alpha" => Some(1),
        "beta" => Some(2),
        "RC" => Some(3),
        "patch" => Some(5),
        _ => None,
    }
}

/// Alternatives de `(stable|beta|b|RC|alpha|a|patch|pl|p)`, dans l'ordre de
/// l'expression régulière.
const STABILITIES: [&str; 9] = [
    "stable", "beta", "b", "RC", "alpha", "a", "patch", "pl", "p",
];

/// Suffixe reconnu par `$modifierRegex`.
struct Modifier<'a> {
    /// Stabilité telle qu'écrite (casse d'origine).
    stability: Option<&'a str>,
    /// Groupe `((?:[.-]?\d+)*+)`.
    number: &'a str,
    dev: bool,
}

/// `([.-]?dev)?$`, insensible à la casse.
fn dev_tail(s: &str) -> Option<bool> {
    let lower = s.to_ascii_lowercase();
    match lower.as_str() {
        "" => Some(false),
        "dev" | ".dev" | "-dev" => Some(true),
        _ => None,
    }
}

/// `(?:[.-]?\d+)*+` : possessif, rend la longueur consommée.
fn number_group(s: &str) -> usize {
    let b = s.as_bytes();
    let mut i = 0;
    loop {
        let start = if i < b.len() && matches!(b[i], b'.' | b'-') {
            i + 1
        } else {
            i
        };
        let digits = b[start.min(b.len())..]
            .iter()
            .take_while(|c| c.is_ascii_digit())
            .count();
        if digits == 0 {
            // Sans séparateur, l'itération échoue aussi : le séparateur
            // consommé n'était suivi d'aucun chiffre.
            return i;
        }
        i = start + digits;
    }
}

/// Stabilité, numéro et `dev` à partir de `s` (sans séparateur initial).
fn after_separator(s: &str) -> Option<Modifier<'_>> {
    for alt in STABILITIES {
        if s.len() >= alt.len() && s[..alt.len()].eq_ignore_ascii_case(alt) {
            let rest = &s[alt.len()..];
            let n = number_group(rest);
            if let Some(dev) = dev_tail(&rest[n..]) {
                return Some(Modifier {
                    stability: Some(&s[..alt.len()]),
                    number: &rest[..n],
                    dev,
                });
            }
        }
    }
    dev_tail(s).map(|dev| Modifier {
        stability: None,
        number: "",
        dev,
    })
}

/// `$modifierRegex` ancré en fin : `[._-]?(?:(stab)((?:[.-]?\d+)*+)?)?([.-]?dev)?$`,
/// chemins essayés dans l'ordre de priorité de PCRE.
fn modifier(s: &str) -> Option<Modifier<'_>> {
    if let Some(rest) = s.strip_prefix(['.', '_', '-'])
        && let Some(m) = after_separator(rest)
    {
        return Some(m);
    }
    after_separator(s)
}

/// Forme classique : `^v?(\d{1,5}+)(\.\d++)?(\.\d++)?(\.\d++)?MOD$`.
fn classical(v: &str) -> Option<(String, Modifier<'_>)> {
    let b = v.as_bytes();
    let mut i = 0;
    let major = b.iter().take_while(|c| c.is_ascii_digit()).count().min(5);
    if major == 0 {
        return None;
    }
    i += major;
    let mut out = v[..major].to_owned();
    let mut groups = 0;
    while groups < 3 && i + 1 < b.len() && b[i] == b'.' && b[i + 1].is_ascii_digit() {
        let digits = b[i + 1..].iter().take_while(|c| c.is_ascii_digit()).count();
        out.push_str(&v[i..i + 1 + digits]);
        i += 1 + digits;
        groups += 1;
    }
    for _ in groups..3 {
        out.push_str(".0");
    }
    // Un reste « .<chiffre> » ne peut être consommé par le suffixe : le
    // retour arrière de PCRE n'y trouverait rien de plus.
    modifier(&v[i..]).map(|m| (out, m))
}

/// Positions de fin possibles de
/// `\d{4}(?:[.:-]?\d{2}){1,6}(?:[.:-]?\d{1,3}){0,2}`, dans l'ordre de
/// priorité de PCRE (quantificateurs gourmands, séparateur pris d'abord).
fn date_ends(b: &[u8]) -> Vec<usize> {
    fn digits_at(b: &[u8], at: usize, n: usize) -> bool {
        at + n <= b.len() && b[at..at + n].iter().all(u8::is_ascii_digit)
    }
    fn is_sep(c: u8) -> bool {
        matches!(c, b'.' | b':' | b'-')
    }
    fn tail(b: &[u8], at: usize, count: usize, out: &mut Vec<usize>) {
        if count < 2 {
            for start in [
                Some(at + 1).filter(|_| at < b.len() && is_sep(b[at])),
                Some(at),
            ]
            .into_iter()
            .flatten()
            {
                for n in (1..=3).rev() {
                    if digits_at(b, start, n) {
                        tail(b, start + n, count + 1, out);
                    }
                }
            }
        }
        out.push(at);
    }
    fn pairs(b: &[u8], at: usize, count: usize, out: &mut Vec<usize>) {
        if count < 6 {
            for start in [
                Some(at + 1).filter(|_| at < b.len() && is_sep(b[at])),
                Some(at),
            ]
            .into_iter()
            .flatten()
            {
                if digits_at(b, start, 2) {
                    pairs(b, start + 2, count + 1, out);
                }
            }
        }
        if count >= 1 {
            tail(b, at, 0, out);
        }
    }
    let mut out = Vec::new();
    if digits_at(b, 0, 4) {
        pairs(b, 4, 0, &mut out);
    }
    out
}

/// Forme date : `^v?(…date…)MOD$`, puis `preg_replace('{\D}', '.')`.
fn date(v: &str) -> Option<(String, Modifier<'_>)> {
    for end in date_ends(v.as_bytes()) {
        if let Some(m) = modifier(&v[end..]) {
            let version = v[..end]
                .chars()
                .map(|c| if c.is_ascii_digit() { c } else { '.' })
                .collect();
            return Some((version, m));
        }
    }
    None
}

/// `VersionParser::normalize`, restreint aux versions exactes de la
/// grammaire commune.
pub fn normalize(raw: &str) -> Result<String, Unparsable> {
    if !in_grammar(raw) {
        return Err(Unparsable::new("caractère hors de [0-9A-Za-z.+_-]"));
    }
    if matches!(raw, "master" | "trunk" | "default")
        || raw.len() >= 4 && raw[..4].eq_ignore_ascii_case("dev-")
    {
        return Err(Unparsable::new("branche Composer"));
    }
    // `^([^,\s+]++)\+[^\s]++$` : métadonnée de build retirée.
    let mut version = raw;
    if let Some((head, build)) = raw.split_once('+')
        && !head.is_empty()
        && !build.is_empty()
    {
        version = head;
    }
    let unversioned = version
        .strip_prefix(['v', 'V'])
        .filter(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
        .unwrap_or(version);
    let matched = classical(unversioned).or_else(|| date(unversioned));
    let Some((mut out, m)) = matched else {
        let lower = version.to_ascii_lowercase();
        return Err(if lower.ends_with("dev") {
            Unparsable::new("branche Composer")
        } else {
            Unparsable::new("hors de VersionParser::normalize")
        });
    };
    if let Some(stability) = m.stability {
        // Comparaison sensible à la casse dans Composer : `STABLE` devient
        // `-stable`, mot que `version_compare` ne connaît pas (refusé plus
        // loin).
        if stability == "stable" {
            return Ok(out);
        }
        out.push('-');
        out.push_str(&expand_stability(stability));
        out.push_str(m.number.trim_start_matches(['.', '-']));
    }
    if m.dev {
        out.push_str("-dev");
    }
    Ok(out)
}

/// `expandStability`.
fn expand_stability(stability: &str) -> String {
    let lower = stability.to_ascii_lowercase();
    match lower.as_str() {
        "a" => "alpha".to_owned(),
        "b" => "beta".to_owned(),
        "p" | "pl" => "patch".to_owned(),
        "rc" => "RC".to_owned(),
        _ => lower,
    }
}

/// Jetons de la forme normalisée.
pub fn tokens(raw: &str) -> Result<Vec<Token>, Unparsable> {
    let normalized = normalize(raw)?;
    php::tokens_with(&php::canonize(&normalized), composer_word)
}

/// Comparaison de deux versions Composer (pour les tests).
pub fn compare(a: &str, b: &str) -> Result<Ordering, Unparsable> {
    Ok(php::compare_tokens(&tokens(a)?, &tokens(b)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_like_composer() {
        for (raw, out) in [
            ("v1.2", "1.2.0.0"),
            ("1.0.0-b2", "1.0.0.0-beta2"),
            ("1.0-beta.2", "1.0.0.0-beta2"),
            ("1.0.0-p1", "1.0.0.0-patch1"),
            ("1.0.0-pl1", "1.0.0.0-patch1"),
            ("1.0.0-patch1", "1.0.0.0-patch1"),
            ("1.0-ALPHA", "1.0.0.0-alpha"),
            ("1.0-Rc1", "1.0.0.0-RC1"),
            ("1.0.0+build.5", "1.0.0.0"),
            ("1.0-stable", "1.0.0.0"),
            ("20260101", "20260101"),
            ("2026-01-01", "2026.01.01"),
            ("2026.01.01", "2026.01.01.0"),
            ("1.0.0RC1dev", "1.0.0.0-RC1-dev"),
            ("20100102-203040-p1", "20100102.203040-patch1"),
        ] {
            assert_eq!(normalize(raw).as_deref(), Ok(out), "{raw}");
        }
    }

    #[test]
    fn rejects_branches_and_garbage() {
        for bad in [
            "dev-main",
            "1.x-dev",
            "123456.1.1.1",
            "",
            "master",
            "1.0.0-meh",
            "1.0.0.0.0",
            "a",
        ] {
            assert!(normalize(bad).is_err(), "{bad}");
        }
        // Normalisé en `-stable`, mot inconnu de version_compare.
        assert!(tokens("1.0-STABLE").is_err());
    }

    #[test]
    fn composer_order() {
        let chain = [
            "1.0.0-dev",
            "1.0.0-alpha",
            "1.0.0-beta2",
            "1.0.0-RC1",
            "1.0.0",
            "1.0.0-patch1",
        ];
        for w in chain.windows(2) {
            assert_eq!(
                compare(w[0], w[1]),
                Ok(Ordering::Less),
                "{} < {}",
                w[0],
                w[1]
            );
        }
    }
}
