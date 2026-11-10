//! purl (Package URL) : **le** module unique de Vigie, partagé par le
//! rapprochement des failles (F1) et l'inventaire reçu des sites (F5).
//!
//! Grammaire commune de `docs/failles.md` (« Conventions purl ») :
//!
//! | Type | Espace de noms | Nom | Casse |
//! | --- | --- | --- | --- |
//! | `composer` | vendor | nom ; `vendor/nom` de Composer, 214 caractères au plus | minuscules |
//! | `npm` | `@scope` facultatif | nom npm ; `@scope/nom` de 214 caractères au plus | telle quelle |
//! | `cargo` | aucun | nom de crate (`[A-Za-z][A-Za-z0-9_-]{0,63}`) | telle quelle |
//! | `wordpress` | `plugin`, `theme` | slug `[A-Za-z0-9._-]{1,200}` | tel quel |
//! | `wordpress` | `core` | `core` | — |
//! | `prestashop` | `module` | nom technique `[A-Za-z0-9_-]{1,64}` | tel quel |
//! | `prestashop` | `core` | `prestashop` | — |
//!
//! Version facultative, `[0-9A-Za-z.+_-]{1,128}`, telle quelle. Les
//! qualificatifs (`?…`) et le sous-chemin (`#…`) sont validés mais hors de
//! la clé de rapprochement : la forme canonique ne les garde pas. Tout le
//! reste est refusé. Forme canonique : type en minuscules, chaque segment
//! encodé comme `rawurlencode` de PHP (tout octet hors de
//! `[A-Za-z0-9._~-]` en `%XX` majuscules : `@` du scope npm en `%40`, `+`
//! d'une version en `%2B`).
//!
//! Vecteurs partagés avec l'agent PHP : `tests/fixtures/vulns/purl.json`.

use std::fmt;

use crate::vulns::version::in_grammar as version_in_grammar;

/// Longueur maximale d'un purl reçu, en octets.
pub const MAX_PURL_CHARS: usize = 1024;
/// Longueur maximale de `vendor/nom` (Composer) et de `@scope/nom` (npm).
pub const MAX_PACKAGE_NAME_CHARS: usize = 214;
/// Longueur maximale d'un slug WordPress.
pub const MAX_WORDPRESS_SLUG_CHARS: usize = 200;
/// Longueur maximale d'un nom de module PrestaShop.
pub const MAX_PRESTASHOP_MODULE_CHARS: usize = 64;
/// Longueur maximale d'un nom de crate.
pub const MAX_CRATE_CHARS: usize = 64;

/// Types admis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PurlType {
    Composer,
    Npm,
    Cargo,
    Wordpress,
    Prestashop,
}

impl PurlType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Composer => "composer",
            Self::Npm => "npm",
            Self::Cargo => "cargo",
            Self::Wordpress => "wordpress",
            Self::Prestashop => "prestashop",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "composer" => Some(Self::Composer),
            "npm" => Some(Self::Npm),
            "cargo" => Some(Self::Cargo),
            "wordpress" => Some(Self::Wordpress),
            "prestashop" => Some(Self::Prestashop),
            _ => None,
        }
    }
}

/// Refus d'un purl. La raison ne cite jamais le texte reçu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("purl invalide : {0}")]
pub struct PurlError(pub &'static str);

/// purl validé, sous forme canonique (Composer en minuscules).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Purl {
    ty: PurlType,
    /// Vide quand le type n'a pas d'espace de noms (`cargo`, npm sans scope).
    namespace: String,
    name: String,
    version: Option<String>,
}

impl Purl {
    /// Construit et valide un purl à partir de ses composants décodés.
    pub fn new(
        ty: PurlType,
        namespace: Option<&str>,
        name: &str,
        version: Option<&str>,
    ) -> Result<Self, PurlError> {
        let namespace = namespace.unwrap_or("");
        let (namespace, name) = match ty {
            PurlType::Composer => {
                let (ns, n) = (namespace.to_ascii_lowercase(), name.to_ascii_lowercase());
                if !composer_part(&ns, true) || !composer_part(&n, false) {
                    return Err(PurlError("nom Composer hors grammaire"));
                }
                if ns.len() + 1 + n.len() > MAX_PACKAGE_NAME_CHARS {
                    return Err(PurlError("nom Composer de plus de 214 caractères"));
                }
                (ns, n)
            }
            PurlType::Npm => {
                if !namespace.is_empty() {
                    let Some(scope) = namespace.strip_prefix('@') else {
                        return Err(PurlError("scope npm sans @"));
                    };
                    if !npm_part(scope) {
                        return Err(PurlError("scope npm hors grammaire"));
                    }
                }
                if !npm_part(name) {
                    return Err(PurlError("nom npm hors grammaire"));
                }
                let full = if namespace.is_empty() {
                    0
                } else {
                    namespace.len() + 1
                } + name.len();
                if full > MAX_PACKAGE_NAME_CHARS {
                    return Err(PurlError("nom npm de plus de 214 caractères"));
                }
                (namespace.to_owned(), name.to_owned())
            }
            PurlType::Cargo => {
                if !namespace.is_empty() {
                    return Err(PurlError("une crate n'a pas d'espace de noms"));
                }
                if !crate_name(name) {
                    return Err(PurlError("nom de crate hors grammaire"));
                }
                (String::new(), name.to_owned())
            }
            PurlType::Wordpress => {
                let ok = match namespace {
                    "plugin" | "theme" => slug(name, MAX_WORDPRESS_SLUG_CHARS, true),
                    "core" => name == "core",
                    _ => return Err(PurlError("catégorie WordPress inconnue")),
                };
                if !ok {
                    return Err(PurlError("slug WordPress hors grammaire"));
                }
                (namespace.to_owned(), name.to_owned())
            }
            PurlType::Prestashop => {
                let ok = match namespace {
                    "module" => slug(name, MAX_PRESTASHOP_MODULE_CHARS, false),
                    "core" => name == "prestashop",
                    _ => return Err(PurlError("catégorie PrestaShop inconnue")),
                };
                if !ok {
                    return Err(PurlError("module PrestaShop hors grammaire"));
                }
                (namespace.to_owned(), name.to_owned())
            }
        };
        if let Some(v) = version
            && !version_in_grammar(v)
        {
            return Err(PurlError("version hors de [0-9A-Za-z.+_-]{1,128}"));
        }
        Ok(Self {
            ty,
            namespace,
            name,
            version: version.map(str::to_owned),
        })
    }

    /// Analyse `pkg:type/namespace/name@version?qualifiers#subpath`.
    pub fn parse(raw: &str) -> Result<Self, PurlError> {
        if raw.len() > MAX_PURL_CHARS {
            return Err(PurlError("purl de plus de 1 024 octets"));
        }
        if !raw.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(PurlError("caractère hors ASCII imprimable"));
        }
        let (rest, subpath) = match raw.rsplit_once('#') {
            Some((rest, sub)) => (rest, Some(sub)),
            None => (raw, None),
        };
        if let Some(sub) = subpath {
            check_subpath(sub)?;
        }
        let (rest, qualifiers) = match rest.rsplit_once('?') {
            Some((rest, q)) => (rest, Some(q)),
            None => (rest, None),
        };
        if let Some(q) = qualifiers {
            check_qualifiers(q)?;
        }
        let Some(rest) = rest.strip_prefix("pkg:") else {
            return Err(PurlError("schéma pkg: absent"));
        };
        let rest = rest.trim_start_matches('/');
        let (path, version) = match rest.rsplit_once('@') {
            // Un `@` littéral de scope npm n'est pas une version : il est
            // suivi d'un `/`.
            Some((path, v)) if !v.contains('/') => (path, Some(decode(v)?)),
            _ => (rest, None),
        };
        if version.as_deref() == Some("") {
            return Err(PurlError("version vide"));
        }
        let mut segments = path.trim_end_matches('/').split('/');
        let ty = segments.next().unwrap_or("").to_ascii_lowercase();
        let ty = PurlType::from_name(&ty).ok_or(PurlError("type non admis"))?;
        let parts: Vec<String> = segments.map(decode).collect::<Result<_, _>>()?;
        if parts.iter().any(String::is_empty) {
            return Err(PurlError("segment vide"));
        }
        let (namespace, name) = match parts.as_slice() {
            [name] => (None, name.as_str()),
            [ns, name] => (Some(ns.as_str()), name.as_str()),
            [] => return Err(PurlError("nom absent")),
            _ => return Err(PurlError("trop de segments")),
        };
        Self::new(ty, namespace, name, version.as_deref())
    }

    pub fn ty(&self) -> PurlType {
        self.ty
    }

    /// Espace de noms décodé, `None` s'il n'y en a pas.
    pub fn namespace(&self) -> Option<&str> {
        (!self.namespace.is_empty()).then_some(self.namespace.as_str())
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// Même paquet, sans version : la clé de rapprochement.
    pub fn without_version(&self) -> Self {
        Self {
            version: None,
            ..self.clone()
        }
    }

    /// Même paquet, à la version donnée (validée).
    pub fn with_version(&self, version: &str) -> Result<Self, PurlError> {
        Self::new(self.ty, self.namespace(), &self.name, Some(version))
    }

    /// Forme canonique, version comprise si présente.
    pub fn canonical(&self) -> String {
        let mut out = format!("pkg:{}/", self.ty.as_str());
        if !self.namespace.is_empty() {
            out.push_str(&encode(&self.namespace));
            out.push('/');
        }
        out.push_str(&encode(&self.name));
        if let Some(v) = &self.version {
            out.push('@');
            out.push_str(&encode(v));
        }
        out
    }
}

impl fmt::Display for Purl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical())
    }
}

/// Paquet d'un export OSV hors de la grammaire ou de l'écosystème.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FromOsvError {
    /// Écosystème hors périmètre (`PyPI`, `Packagist:https://…`).
    OutOfScope,
    /// Nom hors grammaire.
    BadName,
}

/// purl direct d'un paquet OSV (`composer`, `npm` ou `cargo` du nom), sans
/// la correspondance WordPress et PrestaShop : sert à contrôler le
/// `package.purl` fourni par OSV.
pub fn osv_base(ecosystem: &str, name: &str) -> Result<Purl, FromOsvError> {
    match ecosystem {
        "Packagist" => {
            let (vendor, n) = name.split_once('/').ok_or(FromOsvError::BadName)?;
            Purl::new(PurlType::Composer, Some(vendor), n, None).map_err(|_| FromOsvError::BadName)
        }
        "npm" => {
            let (ns, n) = match name.split_once('/') {
                Some((scope, n)) => (Some(scope), n),
                None => (None, name),
            };
            Purl::new(PurlType::Npm, ns, n, None).map_err(|_| FromOsvError::BadName)
        }
        "crates.io" => {
            Purl::new(PurlType::Cargo, None, name, None).map_err(|_| FromOsvError::BadName)
        }
        _ => Err(FromOsvError::OutOfScope),
    }
}

/// purl d'un paquet d'un export OSV (`docs/failles.md`, « Correspondance
/// source → purl ») : un ou deux.
///
/// - `Packagist` (exact) : `prestashop/prestashop` → `pkg:prestashop/core/prestashop` ;
///   `prestashop/<x>` → `pkg:composer/prestashop/<x>` **et**
///   `pkg:prestashop/module/<x>` (le second seulement si `<x>` est un nom
///   de module valide) ; `wpackagist-plugin|theme/<slug>` →
///   `pkg:wordpress/plugin|theme/<slug>` ; sinon `pkg:composer/…`.
/// - `npm` → `pkg:npm/…` ; `crates.io` → `pkg:cargo/…`.
/// - Tout autre écosystème, dont `Packagist:<dépôt>` : hors périmètre.
pub fn from_osv(ecosystem: &str, name: &str) -> Result<Vec<Purl>, FromOsvError> {
    let base = osv_base(ecosystem, name)?;
    if base.ty != PurlType::Composer {
        return Ok(vec![base]);
    }
    let bad = |_| FromOsvError::BadName;
    match (base.namespace.as_str(), base.name.as_str()) {
        ("prestashop", "prestashop") => Ok(vec![
            Purl::new(PurlType::Prestashop, Some("core"), "prestashop", None).map_err(bad)?,
        ]),
        ("prestashop", module) => {
            let mut out = vec![base.clone()];
            if let Ok(m) = Purl::new(PurlType::Prestashop, Some("module"), module, None) {
                out.push(m);
            }
            Ok(out)
        }
        ("wpackagist-plugin", slug) => Ok(vec![
            Purl::new(PurlType::Wordpress, Some("plugin"), slug, None).map_err(bad)?,
        ]),
        ("wpackagist-theme", slug) => Ok(vec![
            Purl::new(PurlType::Wordpress, Some("theme"), slug, None).map_err(bad)?,
        ]),
        _ => Ok(vec![base]),
    }
}

/// Partie d'un nom Composer, d'après `ValidatingArrayLoader` de Composer :
/// vendor `[a-z0-9]([_.-]?[a-z0-9]+)*`, nom
/// `[a-z0-9](([_.]?|-{0,2})[a-z0-9]+)*`.
fn composer_part(s: &str, vendor: bool) -> bool {
    let b = s.as_bytes();
    let alnum = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    if b.is_empty() || !alnum(b[0]) || !alnum(b[b.len() - 1]) {
        return false;
    }
    let mut i = 0;
    while i < b.len() {
        if alnum(b[i]) {
            i += 1;
            continue;
        }
        // Séparateurs entre deux alphanumériques : `_`, `.`, `-` ; un
        // double tiret admis dans le nom seulement.
        let run = b[i..].iter().take_while(|c| !alnum(**c)).count();
        let sep = &s[i..i + run];
        let ok = matches!(sep, "_" | "." | "-") || (!vendor && sep == "--");
        if !ok {
            return false;
        }
        i += run;
    }
    true
}

/// Partie d'un nom npm (`validate-npm-package-name`) : caractères sûrs dans
/// une URL, sans `.` ni `_` en tête.
fn npm_part(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with(['.', '_'])
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'.' | b'_' | b'-' | b'~' | b'!' | b'*' | b'\'' | b'(' | b')'
                )
        })
}

/// Nom de crate de crates.io : lettre initiale, puis alphanumériques, `_`
/// ou `-`, 64 caractères au plus.
fn crate_name(s: &str) -> bool {
    s.len() <= MAX_CRATE_CHARS
        && s.starts_with(|c: char| c.is_ascii_alphabetic())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// Slug WordPress (`dot` admis) ou module PrestaShop (sans `.`).
fn slug(s: &str, max: usize, dot: bool) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-') || (dot && b == b'.'))
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Décodage pourcent strict : `%` suivi de deux chiffres hexadécimaux, UTF-8
/// valide.
fn decode(s: &str) -> Result<String, PurlError> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let (Some(h), Some(l)) = (
                b.get(i + 1).copied().and_then(hex),
                b.get(i + 2).copied().and_then(hex),
            ) else {
                return Err(PurlError("encodage pourcent invalide"));
            };
            out.push(h << 4 | l);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| PurlError("UTF-8 invalide"))
}

/// Encodage de `rawurlencode` (RFC 3986) : tout sauf `[A-Za-z0-9._~-]`.
fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn check_qualifiers(q: &str) -> Result<(), PurlError> {
    let mut keys = Vec::new();
    for pair in q.split('&') {
        let (key, value) = pair
            .split_once('=')
            .ok_or(PurlError("qualificatif sans valeur"))?;
        let key = key.to_ascii_lowercase();
        let key_ok = !key.is_empty()
            && !key.starts_with(|c: char| c.is_ascii_digit())
            && key.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
            });
        if !key_ok {
            return Err(PurlError("clé de qualificatif invalide"));
        }
        if decode(value)?.is_empty() {
            return Err(PurlError("qualificatif vide"));
        }
        if keys.contains(&key) {
            return Err(PurlError("qualificatif en double"));
        }
        keys.push(key);
    }
    Ok(())
}

fn check_subpath(sub: &str) -> Result<(), PurlError> {
    for seg in sub.trim_matches('/').split('/') {
        let seg = decode(seg)?;
        if seg.is_empty() || seg == "." || seg == ".." || seg.contains('/') {
            return Err(PurlError("sous-chemin invalide"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(raw: &str) -> Option<String> {
        Purl::parse(raw).ok().map(|p| p.canonical())
    }

    #[test]
    fn canonical_forms() {
        assert_eq!(
            canon("pkg:composer/Vendor/Name@1.0").as_deref(),
            Some("pkg:composer/vendor/name@1.0")
        );
        assert_eq!(
            canon("pkg:npm/%40Scope/Name@2.0.0-rc.1").as_deref(),
            Some("pkg:npm/%40Scope/Name@2.0.0-rc.1")
        );
        assert_eq!(
            canon("pkg:cargo/Serde_X").as_deref(),
            Some("pkg:cargo/Serde_X")
        );
        assert_eq!(
            canon("pkg:cargo/a@1.0.0%2Bb").as_deref(),
            Some("pkg:cargo/a@1.0.0%2Bb")
        );
        assert_eq!(canon("pkg:prestashop/module/a.b"), None);
        assert_eq!(
            canon("pkg:wordpress/plugin/Mon.Plugin").as_deref(),
            Some("pkg:wordpress/plugin/Mon.Plugin")
        );
    }

    #[test]
    fn composer_names() {
        assert!(composer_part("symfony", true));
        assert!(composer_part("http-kernel", false));
        assert!(composer_part("a--b", false));
        assert!(!composer_part("a--b", true));
        assert!(!composer_part("-a", false));
        assert!(!composer_part("a_", false));
        assert!(!composer_part("a._b", false));
    }

    #[test]
    fn osv_mapping() {
        let one = |e, n| {
            from_osv(e, n)
                .unwrap()
                .iter()
                .map(Purl::canonical)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            one("Packagist", "prestashop/prestashop"),
            ["pkg:prestashop/core/prestashop"]
        );
        assert_eq!(
            one("Packagist", "PrestaShop/ExempleModule"),
            [
                "pkg:composer/prestashop/exemplemodule",
                "pkg:prestashop/module/exemplemodule"
            ]
        );
        assert_eq!(one("npm", "@exemple/paquet"), ["pkg:npm/%40exemple/paquet"]);
        assert_eq!(
            from_osv("Packagist:https://packages.drupal.org/8", "drupal/core"),
            Err(FromOsvError::OutOfScope)
        );
        assert_eq!(
            from_osv("Packagist", "pas un nom"),
            Err(FromOsvError::BadName)
        );
    }
}
