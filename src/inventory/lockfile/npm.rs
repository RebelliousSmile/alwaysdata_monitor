//! `package-lock.json`, `lockfileVersion` 2 ou 3 : section `packages`, règles
//! de l'agent PHP (F5), vecteurs communs `tests/fixtures/inventory/npm-alias.json`.
//!
//! - clé `""` (le projet), clés hors `node_modules/` (workspaces), `link:
//!   true` et `extraneous: true` : ignorées, ni émises ni comptées ;
//! - `resolved` en `git+`, `git:`, `github:`, `file:` ou hors de la forme
//!   `…/-/<fichier>.tgz` : hors registre, compté ;
//! - nom : champ `name` de l'entrée s'il existe (alias npm : le vrai paquet),
//!   sinon ce qui suit le dernier `node_modules/` de la clé ;
//! - `dev: true` → développement ; `devOptional: true` → exécuté.

use serde::Deserialize;

use super::{Entry, LockError, Ordered, Parsed, json_error, registry_tarball};

#[derive(Deserialize)]
struct Lock {
    #[serde(rename = "lockfileVersion")]
    lockfile_version: Option<serde_json::Value>,
    #[serde(default)]
    packages: Option<Ordered<PackageEntry>>,
}

/// Entrée de `packages`, champs utiles seulement.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PackageEntry {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub resolved: Option<String>,
    #[serde(default)]
    pub link: Option<bool>,
    #[serde(default)]
    pub dev: Option<bool>,
    #[serde(default)]
    pub extraneous: Option<bool>,
}

/// Lecture d'une entrée, commune au lecteur et aux vecteurs partagés.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Projet, workspace, lien, paquet étranger à l'arbre : ignoré.
    Ignored,
    /// Git, `file:`, archive hors registre : compté.
    OffRegistry,
    Package(Entry),
}

/// Verdict de l'entrée `key` de `packages`.
pub fn classify(key: &str, entry: &PackageEntry) -> Verdict {
    let in_tree = key.starts_with("node_modules/") || key.contains("/node_modules/");
    if !in_tree || entry.link == Some(true) || entry.extraneous == Some(true) {
        return Verdict::Ignored;
    }
    if entry
        .resolved
        .as_deref()
        .is_some_and(|resolved| !registry_tarball(resolved))
    {
        return Verdict::OffRegistry;
    }
    let name = match &entry.name {
        Some(name) => name.as_str(),
        None => key
            .rsplit_once("node_modules/")
            .map_or(key, |(_, name)| name),
    };
    Verdict::Package(Entry::npm(
        name,
        entry.version.as_deref().unwrap_or(""),
        entry.dev == Some(true),
    ))
}

pub fn parse(text: &str) -> Result<Parsed, LockError> {
    let lock: Lock = serde_json::from_str(text).map_err(json_error)?;
    match lock
        .lockfile_version
        .as_ref()
        .and_then(serde_json::Value::as_i64)
    {
        Some(2 | 3) => {}
        _ => return Err(LockError::UnsupportedVersion),
    }
    let mut parsed = Parsed::default();
    for (key, entry) in lock.packages.map(|p| p.0).unwrap_or_default() {
        match classify(&key, &entry) {
            Verdict::Ignored => parsed.ignore()?,
            Verdict::OffRegistry => parsed.offregistry()?,
            Verdict::Package(entry) => parsed.push(entry)?,
        }
    }
    Ok(parsed)
}
