//! Versions et comparateurs par écosystème (`docs/failles.md`, « Modèle
//! interne et versions »).
//!
//! Le comparateur est choisi selon l'écosystème de **la source** de la faille,
//! jamais selon le site : une plage Packagist sur un module PrestaShop reste
//! une plage Composer.
//!
//! | Schéma | Écosystèmes | Règle |
//! | --- | --- | --- |
//! | [`Scheme::Semver`] | npm, crates.io, toute plage OSV `SEMVER` | semver 2.0 strict ([`semver`]) |
//! | [`Scheme::Composer`] | Packagist | `VersionParser::normalize` de `composer/semver`, puis `version_compare` ([`composer`]) |
//! | [`Scheme::Php`] | Wordfence (WordPress), Friends-Of-Presta (PrestaShop) | `version_compare` de PHP, sur un domaine accepté ([`php`]) |
//!
//! Une chaîne hors de la grammaire commune des versions
//! (`[0-9A-Za-z.+_-]{1,128}`) ou hors du domaine du schéma est
//! [`Unparsable`] : le rapprochement en fait « version inconnue », jamais
//! « non vulnérable ».

use std::cmp::Ordering;
use std::fmt;

pub mod composer;
pub mod php;
pub mod semver;

/// Longueur maximale d'une version, en caractères (grammaire commune de
/// `failles.md`).
pub const MAX_VERSION_CHARS: usize = 128;
/// Chiffres au plus d'un composant numérique comparé comme nombre : 18
/// chiffres tiennent dans un `u64` (et dans le `long` de PHP).
pub const MAX_NUMERIC_DIGITS: usize = 18;

/// Comparateur de versions.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    Semver,
    Composer,
    Php,
}

impl Scheme {
    /// Nom stocké en base (`vuln_affected.scheme`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Semver => "semver",
            Self::Composer => "composer",
            Self::Php => "php",
        }
    }

    /// Inverse de [`Scheme::as_str`].
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "semver" => Some(Self::Semver),
            "composer" => Some(Self::Composer),
            "php" => Some(Self::Php),
            _ => None,
        }
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Écosystème d'une source de failles : il fixe le comparateur.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceEcosystem {
    /// Export OSV `Packagist` (GHSA, DRUPAL, MAL).
    Packagist,
    /// Export OSV `npm`.
    Npm,
    /// Export OSV `crates.io`.
    CratesIo,
    /// Wordfence Intelligence (WordPress, F3).
    Wordfence,
    /// Friends-Of-Presta (PrestaShop, F3).
    FriendsOfPresta,
}

impl SourceEcosystem {
    /// Comparateur de l'écosystème. Un `match` sans joker : un écosystème
    /// ajouté ne compile pas sans son comparateur.
    pub fn scheme(self) -> Scheme {
        match self {
            Self::Packagist => Scheme::Composer,
            Self::Npm | Self::CratesIo => Scheme::Semver,
            Self::Wordfence | Self::FriendsOfPresta => Scheme::Php,
        }
    }

    /// Nom d'écosystème OSV (`affected[].package.ecosystem`), pour les
    /// exports OSV seulement.
    pub fn osv_name(self) -> Option<&'static str> {
        match self {
            Self::Packagist => Some("Packagist"),
            Self::Npm => Some("npm"),
            Self::CratesIo => Some("crates.io"),
            Self::Wordfence | Self::FriendsOfPresta => None,
        }
    }

    /// Écosystème d'un export OSV, casse exacte de `ecosystems.txt` ; un
    /// dépôt suffixé (`Packagist:https://…`) n'en est pas un.
    pub fn from_osv_name(name: &str) -> Option<Self> {
        match name {
            "Packagist" => Some(Self::Packagist),
            "npm" => Some(Self::Npm),
            "crates.io" => Some(Self::CratesIo),
            _ => None,
        }
    }
}

/// Version hors grammaire ou hors du domaine du comparateur.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("version illisible : {reason}")]
pub struct Unparsable {
    /// Raison courte, sans le texte de la version.
    pub reason: &'static str,
}

impl Unparsable {
    pub(crate) const fn new(reason: &'static str) -> Self {
        Self { reason }
    }
}

/// Clé de comparaison, propre au schéma.
#[derive(Debug, Clone)]
enum Key {
    Semver(semver::Semver),
    Tokens(Vec<php::Token>),
}

/// Version analysée par un comparateur. Opaque : l'ordre et l'égalité sont
/// ceux du comparateur (`1.01` égale `1.1` en PHP ; `1.0.0+a` égale
/// `1.0.0+b` en semver), l'affichage rend la chaîne d'origine.
#[derive(Debug, Clone)]
pub struct Version {
    scheme: Scheme,
    raw: String,
    key: Key,
}

impl Version {
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// Chaîne d'origine.
    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        // Deux schémas ne se comparent pas entre eux ; l'ordre par schéma
        // garde seulement `Ord` total.
        self.scheme
            .cmp(&other.scheme)
            .then_with(|| match (&self.key, &other.key) {
                (Key::Semver(a), Key::Semver(b)) => a.cmp(b),
                (Key::Tokens(a), Key::Tokens(b)) => php::compare_tokens(a, b),
                (Key::Semver(_), Key::Tokens(_)) => Ordering::Less,
                (Key::Tokens(_), Key::Semver(_)) => Ordering::Greater,
            })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Version {}

/// Borne d'une plage OSV. `introduced: "0"` est le plancher « depuis
/// toujours », jamais analysé comme une version (`0` n'est pas une version
/// semver).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Bound {
    Floor,
    At(Version),
}

/// Grammaire commune des versions : `[0-9A-Za-z.+_-]{1,128}`.
pub fn in_grammar(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= MAX_VERSION_CHARS
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'_' | b'-'))
}

/// Analyse `raw` avec le comparateur `scheme`.
pub fn parse(scheme: Scheme, raw: &str) -> Result<Version, Unparsable> {
    if raw.is_empty() {
        return Err(Unparsable::new("chaîne vide"));
    }
    if raw.len() > MAX_VERSION_CHARS {
        return Err(Unparsable::new("plus de 128 caractères"));
    }
    if !in_grammar(raw) {
        return Err(Unparsable::new("caractère hors de [0-9A-Za-z.+_-]"));
    }
    let key = match scheme {
        Scheme::Semver => Key::Semver(semver::parse(raw)?),
        Scheme::Php => Key::Tokens(php::tokens(raw)?),
        Scheme::Composer => Key::Tokens(composer::tokens(raw)?),
    };
    Ok(Version {
        scheme,
        raw: raw.to_owned(),
        key,
    })
}

/// Analyse une borne OSV : `"0"` est le plancher « depuis toujours » quel
/// que soit le schéma (en semver, `0` n'est pas une version ; en PHP, `dev`
/// est sous `0`), toute autre chaîne une version du schéma.
pub fn parse_bound(scheme: Scheme, raw: &str) -> Result<Bound, Unparsable> {
    if raw == "0" {
        return Ok(Bound::Floor);
    }
    parse(scheme, raw).map(Bound::At)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_ecosystems_choose_their_scheme() {
        assert_eq!(SourceEcosystem::Packagist.scheme(), Scheme::Composer);
        assert_eq!(SourceEcosystem::Npm.scheme(), Scheme::Semver);
        assert_eq!(SourceEcosystem::CratesIo.scheme(), Scheme::Semver);
        assert_eq!(SourceEcosystem::Wordfence.scheme(), Scheme::Php);
        assert_eq!(SourceEcosystem::FriendsOfPresta.scheme(), Scheme::Php);
        for e in [
            SourceEcosystem::Packagist,
            SourceEcosystem::Npm,
            SourceEcosystem::CratesIo,
        ] {
            assert_eq!(
                SourceEcosystem::from_osv_name(e.osv_name().unwrap()),
                Some(e)
            );
        }
        assert_eq!(
            SourceEcosystem::from_osv_name("Packagist:https://packages.drupal.org/8"),
            None
        );
        assert_eq!(SourceEcosystem::from_osv_name("packagist"), None);
    }

    #[test]
    fn scheme_names_round_trip() {
        for s in [Scheme::Semver, Scheme::Composer, Scheme::Php] {
            assert_eq!(Scheme::from_name(s.as_str()), Some(s));
        }
        assert_eq!(Scheme::from_name("SEMVER"), None);
    }

    #[test]
    fn the_floor_is_below_every_version_and_never_parsed() {
        assert_eq!(parse_bound(Scheme::Semver, "0"), Ok(Bound::Floor));
        assert!(parse(Scheme::Semver, "0").is_err());
        for (scheme, v) in [
            (Scheme::Semver, "0.0.0-0"),
            (Scheme::Composer, "0"),
            (Scheme::Composer, "0.0.0-dev"),
            (Scheme::Php, "0"),
            (Scheme::Php, "dev"),
        ] {
            let at = Bound::At(parse(scheme, v).unwrap());
            assert!(Bound::Floor < at, "{scheme} {v}");
        }
    }

    #[test]
    fn display_keeps_the_original_string() {
        let v = parse(Scheme::Php, "6.4-RC1").unwrap();
        assert_eq!(v.to_string(), "6.4-RC1");
        assert_eq!(v.scheme(), Scheme::Php);
        assert_eq!(
            parse(Scheme::Php, "1.01").unwrap(),
            parse(Scheme::Php, "1.1").unwrap()
        );
    }
}
