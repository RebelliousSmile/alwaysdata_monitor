//! `pnpm-lock.yaml`, `lockfileVersion` `'6.0'` (pnpm 8) ou `'9.0'` (pnpm 9
//! et 10), par le lecteur ligne à ligne de [`super::lines`].
//!
//! Seule la section `packages` est lue ; les autres (`settings`, `importers`,
//! `snapshots`, `catalogs`, `overrides`, `patchedDependencies`…) sont sautées
//! par indentation. Clé d'entrée à deux espaces : `/nom@version` ou
//! `/@scope/nom@version` (6.0), `nom@version` ou `'@scope/nom@version'`
//! (9.0) ; suffixes de pairs `(…)` retirés ; `nom@npm:vrai@v` → nom réel.
//! Dans l'entrée, seuls `resolution` et `dev` (6.0) sont lus. `resolution`
//! `tarball:`, `directory:`, `type: git` ou version `file:`, `git+`, `://`
//! → hors registre ; `link:` et `workspace:` → membre du projet. pnpm 9 ne dit
//! pas ce qui est de développement : tout y est exécuté.

use super::lines::{self, Line};
use super::{Entry, LockError, Parsed};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Version {
    V6,
    V9,
}

pub fn parse(text: &str) -> Result<Parsed, LockError> {
    let lines = lines::split(text)?;
    let mut version = None;
    let mut parsed = Parsed::default();
    let mut i = 0;
    while i < lines.len() {
        let line = &lines[i];
        if line.indent != 0 {
            return Err(line.error());
        }
        let (key, value) = lines::key_value(line, true)?;
        let end = lines::block_end(&lines, i);
        match key.as_str() {
            "lockfileVersion" => {
                version = match lines::scalar(line, value)?.as_str() {
                    "6.0" => Some(Version::V6),
                    "9.0" => Some(Version::V9),
                    _ => return Err(LockError::UnsupportedVersion),
                };
                if end != i + 1 {
                    return Err(lines[i + 1].error());
                }
            }
            "packages" => {
                let version = version.ok_or(LockError::UnsupportedVersion)?;
                if !(value.is_empty() || value == "{}") {
                    return Err(line.error());
                }
                packages(&lines[i + 1..end], version, &mut parsed)?;
            }
            _ => lines::skip_flow(line, value)?,
        }
        i = end;
    }
    version.ok_or(LockError::UnsupportedVersion)?;
    Ok(parsed)
}

/// Entrées de `packages`, à deux espaces.
fn packages(lines: &[Line<'_>], version: Version, parsed: &mut Parsed) -> Result<(), LockError> {
    let mut i = 0;
    while i < lines.len() {
        let line = &lines[i];
        if line.indent != 2 {
            return Err(line.error());
        }
        let (key, value) = lines::key_value(line, true)?;
        let end = lines::block_end(lines, i);
        let mut resolution = None;
        let mut dev = false;
        if value == "{}" {
            // Entrée vide : rien à lire.
        } else if !value.is_empty() {
            return Err(line.error());
        }
        for field in &lines[i + 1..end] {
            if field.indent != 4 {
                // Sous-bloc d'un champ non lu : déjà sauté.
                if field.indent > 4 {
                    continue;
                }
                return Err(field.error());
            }
            let (name, value) = lines::key_value(field, false)?;
            match name.as_str() {
                "resolution" => resolution = Some(lines::flow_map(field, value)?),
                "dev" if version == Version::V6 => {
                    dev = match lines::scalar(field, value)?.as_str() {
                        "true" => true,
                        "false" => false,
                        _ => return Err(field.error()),
                    };
                }
                _ => lines::skip_flow(field, value)?,
            }
        }
        let resolution = resolution.ok_or_else(|| line.error())?;
        entry(line, &key, &resolution, version, dev, parsed)?;
        i = end;
    }
    Ok(())
}

fn entry(
    line: &Line<'_>,
    key: &str,
    resolution: &[(String, String)],
    version: Version,
    dev: bool,
    parsed: &mut Parsed,
) -> Result<(), LockError> {
    let field = |name: &str| resolution.iter().any(|(k, _)| k == name);
    let git = resolution.iter().any(|(k, v)| k == "type" && v == "git");
    if field("tarball") || field("directory") || field("repo") || git {
        return parsed.offregistry();
    }
    if !field("integrity") {
        return Err(line.error());
    }
    let key = match version {
        Version::V6 => key.strip_prefix('/').unwrap_or(key),
        Version::V9 => key,
    };
    // Suffixe de pairs : `nom@1.0.0(react@18.3.1)`.
    let key = key.split_once('(').map_or(key, |(head, _)| head);
    let Some((name, version)) = split_name(key) else {
        return Err(line.error());
    };
    package(name, version, dev, parsed)
}

/// `nom@version`, le séparateur étant le premier `@` après la tête (un scope
/// commence par `@`).
pub(super) fn split_name(spec: &str) -> Option<(&str, &str)> {
    let at = spec.get(1..)?.find('@')? + 1;
    Some((&spec[..at], &spec[at + 1..]))
}

/// Paquet de registre, ou membre et hors registre selon la version.
fn package(name: &str, version: &str, dev: bool, parsed: &mut Parsed) -> Result<(), LockError> {
    if let Some(alias) = version.strip_prefix("npm:") {
        // Alias : le vrai paquet.
        return match split_name(alias) {
            Some((real, version)) => package(real, version, dev, parsed),
            None => parsed.offregistry(),
        };
    }
    if version.starts_with("link:") || version.starts_with("workspace:") {
        return parsed.ignore();
    }
    if version.starts_with("file:") || version.starts_with("git+") || version.contains("://") {
        return parsed.offregistry();
    }
    parsed.push(Entry::npm(name, version, dev))
}
