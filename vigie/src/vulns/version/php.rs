//! `version_compare` de PHP, pour WordPress et PrestaShop, en deux étapes
//! séparées : la canonisation exacte de PHP, puis une comparaison sur jetons
//! classés que Composer réutilise avec ses propres mots ([`super::composer`]).
//!
//! Source lue : `ext/standard/versioning.c` de php-src, branche `PHP-8.3`
//! (identique en 8.1, version de la CI), le 2026-10-17.
//!
//! **Domaine accepté.** PHP apparie un mot inconnu par préfixe (`bogus` vaut
//! `b`) et n'est pas transitif sur ces mots. Vigie n'accepte que les mots
//! exacts de la table de PHP, sensibles à la casse comme lui (`dev`, `alpha`,
//! `a`, `beta`, `b`, `RC`, `rc`, `pl`, `p`), et des composants numériques de
//! 18 chiffres au plus. Un composant vide (point initial ou final) est aussi
//! refusé : PHP le compare comme un mot inconnu. Hors domaine : [`Unparsable`].
//! Sur le domaine, l'ordre est total et identique à celui de PHP (test
//! différentiel `tests/vulns_php_diff.rs`).

use std::cmp::Ordering;

use super::{MAX_NUMERIC_DIGITS, Unparsable};

/// Rang de `#`, que PHP donne à un composant numérique comparé à un mot.
pub const RANK_NUMBER: u8 = 4;

/// Composant d'une version canonisée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Token {
    /// Composant numérique (`strtol`).
    Num(u64),
    /// Mot spécial et son rang : `dev` 0, `alpha`/`a` 1, `beta`/`b` 2,
    /// `RC`/`rc` 3, (`#` 4), `pl`/`p` 5.
    Special(u8),
}

/// Copie de `php_canonicalize_version` :
///
/// ```c
/// /*  s/[-_+]/./g;
///  *  s/([^\d\.])([^\D\.])/$1.$2/g;
///  *  s/([^\D\.])([^\d\.])/$1.$2/g;
///  */
/// ```
///
/// Le premier octet est recopié tel quel ; ensuite `-`, `_`, `+` et tout
/// octet non alphanumérique deviennent `.`, un `.` est inséré à chaque
/// transition chiffre ↔ non-chiffre, et jamais deux `.` ne se suivent du fait
/// de ces insertions. Entrée attendue en ASCII (grammaire commune) ; un octet
/// non ASCII est traité comme PHP en locale C, en non-alphanumérique.
pub fn canonize(version: &str) -> String {
    let bytes = version.as_bytes();
    let Some((&first, rest)) = bytes.split_first() else {
        return String::new();
    };
    let isdig = |x: u8| x.is_ascii_digit() && x != b'.';
    let isndig = |x: u8| !x.is_ascii_digit() && x != b'.';
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len() * 2);
    out.push(first);
    let mut lp = first;
    for &p in rest {
        let lq = *out.last().expect("au moins le premier octet");
        if matches!(p, b'-' | b'_' | b'+') {
            if lq != b'.' {
                out.push(b'.');
            }
        } else if (isndig(lp) && isdig(p)) || (isdig(lp) && isndig(p)) {
            if lq != b'.' {
                out.push(b'.');
            }
            out.push(p);
        } else if !p.is_ascii_alphanumeric() {
            if lq != b'.' {
                out.push(b'.');
            }
        } else {
            out.push(p);
        }
        lp = p;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Mots exacts de la table `special_forms` de PHP (hors `#`, interne).
pub fn php_word(word: &str) -> Option<u8> {
    match word {
        "dev" => Some(0),
        "alpha" | "a" => Some(1),
        "beta" | "b" => Some(2),
        "RC" | "rc" => Some(3),
        "pl" | "p" => Some(5),
        _ => None,
    }
}

/// Découpe une forme canonique en jetons ; `word` classe les mots admis.
pub(crate) fn tokens_with(
    canonical: &str,
    word: impl Fn(&str) -> Option<u8>,
) -> Result<Vec<Token>, Unparsable> {
    let mut out = Vec::new();
    for part in canonical.split('.') {
        if part.is_empty() {
            return Err(Unparsable::new("composant vide"));
        }
        if part.bytes().all(|b| b.is_ascii_digit()) {
            if part.len() > MAX_NUMERIC_DIGITS {
                return Err(Unparsable::new(
                    "composant numérique de plus de 18 chiffres",
                ));
            }
            let n = part
                .parse()
                .map_err(|_| Unparsable::new("composant numérique illisible"))?;
            out.push(Token::Num(n));
        } else if part.bytes().any(|b| b.is_ascii_digit()) {
            // Impossible après canonisation, sauf premier octet recopié.
            return Err(Unparsable::new("composant mêlant chiffres et lettres"));
        } else {
            match word(part) {
                Some(rank) => out.push(Token::Special(rank)),
                None => return Err(Unparsable::new("mot hors de version_compare")),
            }
        }
    }
    Ok(out)
}

/// Jetons d'une version WordPress ou PrestaShop.
pub fn tokens(version: &str) -> Result<Vec<Token>, Unparsable> {
    tokens_with(&canonize(version), php_word)
}

fn rank(t: Token) -> u8 {
    match t {
        Token::Num(_) => RANK_NUMBER,
        Token::Special(r) => r,
    }
}

fn compare_one(a: Token, b: Token) -> Ordering {
    match (a, b) {
        (Token::Num(x), Token::Num(y)) => x.cmp(&y),
        _ => rank(a).cmp(&rank(b)),
    }
}

/// Fin de liste face au composant restant de l'autre version : PHP rend
/// « plus grand » pour un nombre restant, sinon compare le mot à `#`.
fn remainder(next: Token) -> Ordering {
    match next {
        Token::Num(_) => Ordering::Greater,
        Token::Special(r) => r.cmp(&RANK_NUMBER),
    }
}

/// Comparaison de `php_version_compare` sur jetons : composant par
/// composant (deux nombres numériquement, sinon par rang, un nombre valant
/// `#`) ; à préfixe égal, le premier composant restant décide (un nombre :
/// la plus longue l'emporte ; un mot : comparé à `#`, si bien que
/// `5.9 < 5.9.0`, `1.0-beta < 1.0 < 1.0pl1`).
pub fn compare_tokens(a: &[Token], b: &[Token]) -> Ordering {
    for (x, y) in a.iter().zip(b) {
        let c = compare_one(*x, *y);
        if c != Ordering::Equal {
            return c;
        }
    }
    match a.len().cmp(&b.len()) {
        Ordering::Equal => Ordering::Equal,
        Ordering::Greater => remainder(a[b.len()]),
        Ordering::Less => remainder(b[a.len()]).reverse(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonize_matches_php() {
        for (raw, canonical) in [
            ("1.0", "1.0"),
            ("1.0RC1", "1.0.RC.1"),
            ("6.4-beta1", "6.4.beta.1"),
            ("1_0+1", "1.0.1"),
            ("1--0", "1.0"),
            ("a1", "a.1"),
            ("-1", "-.1"),
            ("1.", "1."),
            (".1", ".1"),
            ("1..2", "1.2"),
            ("1.-a", "1.a"),
            ("", ""),
        ] {
            assert_eq!(canonize(raw), canonical, "{raw}");
        }
    }

    fn cmp(a: &str, b: &str) -> Ordering {
        compare_tokens(&tokens(a).unwrap(), &tokens(b).unwrap())
    }

    #[test]
    fn php_order() {
        assert_eq!(cmp("5.9", "5.9.0"), Ordering::Less);
        assert_eq!(cmp("1.0-beta", "1.0"), Ordering::Less);
        assert_eq!(cmp("1.0", "1.0pl1"), Ordering::Less);
        assert_eq!(cmp("1.0-dev", "1.0-alpha"), Ordering::Less);
        assert_eq!(cmp("1.0a", "1.0alpha"), Ordering::Equal);
        assert_eq!(cmp("1.0rc1", "1.0RC1"), Ordering::Equal);
        assert_eq!(cmp("1.01", "1.1"), Ordering::Equal);
    }

    #[test]
    fn out_of_domain() {
        for bad in [
            "1.0-bogus",
            "1.0-ALPHA",
            "1.0-patch",
            "1.",
            ".1",
            "-1",
            "1.0-Rc1",
        ] {
            assert!(tokens(bad).is_err(), "{bad}");
        }
    }
}
