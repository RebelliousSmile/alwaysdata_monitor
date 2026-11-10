//! semver 2.0 strict (https://semver.org/spec/v2.0.0.html), pour npm, Cargo
//! et toute plage OSV `SEMVER`.
//!
//! - `MAJOR.MINOR.PATCH[-pre][+build]`, sans `v`, `=`, forme partielle ni
//!   zéro initial ; noyau de 18 chiffres au plus par composant.
//! - Préversions selon la §11 : identifiant numérique < alphanumérique ;
//!   numériques comparés par (longueur, ordre lexical), sans conversion ni
//!   débordement ; à préfixe égal, la liste la plus longue l'emporte ; une
//!   version sans préversion est au-dessus de ses préversions.
//! - Build validé puis **ignoré** dans l'ordre et l'égalité (§10), là où la
//!   crate `semver` départage par lui.

use std::cmp::Ordering;

use super::{MAX_NUMERIC_DIGITS, Unparsable};

/// Version semver analysée (build exclu).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Semver {
    core: [u64; 3],
    pre: Vec<Ident>,
}

/// Identifiant de préversion.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Ident {
    /// Chiffres sans zéro initial (ou `0`), gardés en texte.
    Num(String),
    Alpha(String),
}

impl Ord for Ident {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            // Sans zéro initial, la plus longue est la plus grande ; à
            // longueur égale, l'ordre lexical est l'ordre numérique.
            (Self::Num(a), Self::Num(b)) => a.len().cmp(&b.len()).then_with(|| a.cmp(b)),
            (Self::Num(_), Self::Alpha(_)) => Ordering::Less,
            (Self::Alpha(_), Self::Num(_)) => Ordering::Greater,
            // Ordre ASCII des octets.
            (Self::Alpha(a), Self::Alpha(b)) => a.as_bytes().cmp(b.as_bytes()),
        }
    }
}

impl PartialOrd for Ident {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Semver {
    fn cmp(&self, other: &Self) -> Ordering {
        self.core
            .cmp(&other.core)
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                // Lexicographique, puis la plus longue à préfixe égal :
                // l'ordre des `Vec` le fait.
                (false, false) => self.pre.cmp(&other.pre),
            })
    }
}

impl PartialOrd for Semver {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-'
}

fn core_number(part: &str) -> Result<u64, Unparsable> {
    if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Unparsable::new("noyau semver non numérique"));
    }
    if part.len() > 1 && part.starts_with('0') {
        return Err(Unparsable::new("zéro initial dans le noyau semver"));
    }
    if part.len() > MAX_NUMERIC_DIGITS {
        return Err(Unparsable::new(
            "composant numérique de plus de 18 chiffres",
        ));
    }
    part.parse()
        .map_err(|_| Unparsable::new("noyau semver non numérique"))
}

/// Analyse stricte ; la grammaire commune a déjà été vérifiée par l'appelant
/// ou l'est ici de nouveau par les classes de caractères.
pub fn parse(raw: &str) -> Result<Semver, Unparsable> {
    let (rest, build) = match raw.split_once('+') {
        Some((rest, build)) => (rest, Some(build)),
        None => (raw, None),
    };
    if let Some(build) = build {
        for id in build.split('.') {
            if id.is_empty() || !id.bytes().all(is_ident_char) {
                return Err(Unparsable::new("métadonnée de build semver invalide"));
            }
        }
    }
    let (core, pre) = match rest.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (rest, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 {
        return Err(Unparsable::new("noyau semver sans trois composants"));
    }
    let core = [
        core_number(parts[0])?,
        core_number(parts[1])?,
        core_number(parts[2])?,
    ];
    let mut idents = Vec::new();
    if let Some(pre) = pre {
        for id in pre.split('.') {
            if id.is_empty() || !id.bytes().all(is_ident_char) {
                return Err(Unparsable::new("préversion semver invalide"));
            }
            if id.bytes().all(|b| b.is_ascii_digit()) {
                if id.len() > 1 && id.starts_with('0') {
                    return Err(Unparsable::new("zéro initial dans une préversion semver"));
                }
                idents.push(Ident::Num(id.to_owned()));
            } else {
                idents.push(Ident::Alpha(id.to_owned()));
            }
        }
    }
    Ok(Semver { core, pre: idents })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Semver {
        parse(s).unwrap_or_else(|e| panic!("{s} : {e}"))
    }

    #[test]
    fn precedence_follows_section_11() {
        let chain = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.1",
            "1.1.0",
            "2.0.0",
        ];
        for w in chain.windows(2) {
            assert!(v(w[0]) < v(w[1]), "{} < {}", w[0], w[1]);
        }
    }

    #[test]
    fn build_is_ignored_and_long_numeric_prereleases_do_not_overflow() {
        assert_eq!(v("1.0.0+a"), v("1.0.0+b.1"));
        assert!(v("1.0.0-99999999999999999999999") > v("1.0.0-9999999999999999999999"));
        assert!(v("1.0.0-99999999999999999999999") < v("1.0.0-a"));
    }

    #[test]
    fn strict_forms_only() {
        for bad in [
            "01.2.3",
            "1.2",
            "v1.2.3",
            "=1.2.3",
            "1.2.3-",
            "1.2.3-01",
            "1.2.3+",
            "1.2.3-a..b",
            "1.2.3.4",
            "1_2.3",
            "1234567890123456789.0.0",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        assert!(parse("123456789012345678.0.0").is_ok());
    }
}
