//! `yarn.lock`, v1 (yarn 1) ou berry (`__metadata.version` 6, 8 ou 10 :
//! yarn 3, yarn 4 jusqu'à 4.5, yarn 4 récent).
//!
//! - **v1** si une ligne `# yarn lockfile v1` figure dans le bloc de
//!   commentaires de tête (yarn 1 en écrit deux avant) ; entrée = ligne en
//!   colonne 0 finie par `:` (spécificateurs séparés par `, `, cités ou non),
//!   puis `version "x"` et `resolved "…"` ; le reste est sauté. Nom tiré du
//!   premier spécificateur ; `alias@npm:vrai@^1` → nom réel ; `file:`, git,
//!   URL, `github:` → hors registre ; `link:` → membre du projet.
//! - **berry** sinon : `__metadata.version` exigé ; entrée = clé de niveau 0,
//!   seul `resolution` est lu : `nom@npm:1.2.3` → nom et version ;
//!   `nom@patch:nom@npm%3A1.2.3#…` → `nom`, `1.2.3` (un correctif local ne
//!   retire pas la faille amont) ; `workspace:`, `portal:`, `link:` → membre ;
//!   `file:`, `exec:`, git, URL → hors registre.
//!
//! Aucun `dev` : yarn ne dit pas ce qui est de développement, tout est
//! exécuté.

use super::lines::{self, Line};
use super::pnpm::split_name;
use super::{Entry, LockError, Parsed, registry_tarball};

pub fn parse(text: &str) -> Result<Parsed, LockError> {
    let header = text
        .lines()
        .map(str::trim_end)
        .take_while(|line| line.is_empty() || line.starts_with('#'))
        .any(|line| line == "# yarn lockfile v1");
    if header { v1(text) } else { berry(text) }
}

/// Lecture d'un `resolved`/plage, commune à v1 et berry.
enum Verdict<'a> {
    Member,
    OffRegistry,
    /// Paquet de registre : nom réel, version (berry seulement).
    Package(&'a str, Option<&'a str>),
}

/// Plage d'un spécificateur v1 (`nom@<plage>`).
fn v1_range<'a>(name: &'a str, range: &'a str) -> Verdict<'a> {
    if let Some(alias) = range.strip_prefix("npm:") {
        return match split_name(alias) {
            Some((real, _)) => Verdict::Package(real, None),
            None => Verdict::Package(alias, None),
        };
    }
    if ["link:", "portal:", "workspace:"]
        .iter()
        .any(|p| range.starts_with(p))
    {
        return Verdict::Member;
    }
    let offregistry = [
        "file:", "git+", "git:", "git@", "github:", "http:", "https:",
    ]
    .iter()
    .any(|p| range.starts_with(p))
        || range.contains("://")
        || (range.contains('/') && !range.starts_with('@'));
    if offregistry {
        Verdict::OffRegistry
    } else {
        Verdict::Package(name, None)
    }
}

fn v1(text: &str) -> Result<Parsed, LockError> {
    let lines = lines::split(text)?;
    let mut parsed = Parsed::default();
    let mut i = 0;
    while i < lines.len() {
        let line = &lines[i];
        if line.indent != 0 {
            return Err(line.error());
        }
        let first = first_spec(line)?;
        let end = lines::block_end(&lines, i);
        let (mut version, mut resolved) = (None, None);
        for field in &lines[i + 1..end] {
            if field.indent > 2 {
                continue;
            }
            if field.indent != 2 {
                return Err(field.error());
            }
            let (name, value) = match field.text.split_once(' ') {
                Some((name, value)) => (name, value.trim()),
                None => (field.text, ""),
            };
            match name {
                "version" => version = Some(lines::scalar(field, value)?),
                "resolved" => resolved = Some(lines::scalar(field, value)?),
                _ => {}
            }
        }
        let (name, range) = split_name(&first).ok_or_else(|| line.error())?;
        let version = version.ok_or_else(|| line.error())?;
        let verdict = v1_range(name, range);
        let registry = resolved
            .as_deref()
            .is_none_or(|r| registry_tarball(r.split_once('#').map_or(r, |(head, _)| head)));
        match verdict {
            Verdict::Member => parsed.ignore()?,
            Verdict::OffRegistry => parsed.offregistry()?,
            Verdict::Package(..) if !registry => parsed.offregistry()?,
            Verdict::Package(name, _) => parsed.push(Entry::npm(name, &version, false))?,
        }
        i = end;
    }
    Ok(parsed)
}

/// Premier spécificateur d'une ligne d'entrée v1 : `a@^1, "b@^2":`.
fn first_spec(line: &Line<'_>) -> Result<String, LockError> {
    let head = line.text.strip_suffix(':').ok_or_else(|| line.error())?;
    let first = if head.starts_with('"') {
        let (spec, rest) = lines::quoted(head).ok_or_else(|| line.error())?;
        if !(rest.is_empty() || rest.starts_with(", ")) {
            return Err(line.error());
        }
        spec
    } else {
        head.split(", ").next().unwrap_or("").to_owned()
    };
    if first.is_empty() {
        return Err(line.error());
    }
    Ok(first)
}

/// `resolution` berry.
fn berry_resolution(resolution: &str) -> Verdict<'_> {
    let Some((name, rest)) = split_name(resolution) else {
        return Verdict::OffRegistry;
    };
    if let Some(version) = rest.strip_prefix("npm:") {
        return match split_name(version) {
            // `alias@npm:vrai@1.2.3`.
            Some((real, version)) => Verdict::Package(real, Some(version)),
            None => Verdict::Package(name, Some(version)),
        };
    }
    if let Some(patched) = rest.strip_prefix("patch:") {
        // `nom@npm%3A1.2.3#…` : le paquet publié, `%3A` seul décodé.
        let inner = patched.split_once('#').map_or(patched, |(head, _)| head);
        return match inner.split_once("@npm%3A") {
            Some((real, version)) if !real.is_empty() => Verdict::Package(real, Some(version)),
            _ => Verdict::OffRegistry,
        };
    }
    if ["workspace:", "portal:", "link:"]
        .iter()
        .any(|p| rest.starts_with(p))
    {
        return Verdict::Member;
    }
    Verdict::OffRegistry
}

fn berry(text: &str) -> Result<Parsed, LockError> {
    let lines = lines::split(text)?;
    // Ni en-tête v1 ni `__metadata` en tête : format non reconnu.
    if lines.first().is_none_or(|line| line.text != "__metadata:") {
        return Err(LockError::UnsupportedVersion);
    }
    let mut metadata = false;
    let mut parsed = Parsed::default();
    let mut i = 0;
    while i < lines.len() {
        let line = &lines[i];
        if line.indent != 0 {
            return Err(line.error());
        }
        let (key, value) = lines::key_value(line, true)?;
        let end = lines::block_end(&lines, i);
        if !value.is_empty() {
            return Err(line.error());
        }
        let mut resolution = None;
        let mut version = None;
        for field in &lines[i + 1..end] {
            if field.indent > 2 {
                continue;
            }
            if field.indent != 2 {
                return Err(field.error());
            }
            let (name, value) = lines::key_value(field, false)?;
            match name.as_str() {
                "resolution" if key != "__metadata" => {
                    resolution = Some(lines::scalar(field, value)?);
                }
                "version" if key == "__metadata" => version = Some(lines::scalar(field, value)?),
                _ => lines::skip_flow(field, value)?,
            }
        }
        if key == "__metadata" {
            if metadata || !matches!(version.as_deref(), Some("6" | "8" | "10")) {
                return Err(LockError::UnsupportedVersion);
            }
            metadata = true;
        } else {
            if !metadata {
                return Err(LockError::UnsupportedVersion);
            }
            let resolution = resolution.ok_or_else(|| line.error())?;
            match berry_resolution(&resolution) {
                Verdict::Member => parsed.ignore()?,
                Verdict::OffRegistry => parsed.offregistry()?,
                Verdict::Package(name, version) => {
                    parsed.push(Entry::npm(name, version.unwrap_or(""), false))?;
                }
            }
        }
        i = end;
    }
    if !metadata {
        return Err(LockError::UnsupportedVersion);
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(resolution: &str) -> Option<(String, String)> {
        match berry_resolution(resolution) {
            Verdict::Package(name, version) => {
                Some((name.to_owned(), version.unwrap_or("").to_owned()))
            }
            _ => None,
        }
    }

    #[test]
    fn berry_resolutions_give_the_published_package() {
        let p = |n: &str, v: &str| Some((n.to_owned(), v.to_owned()));
        assert_eq!(package("@types/ms@npm:0.7.34"), p("@types/ms", "0.7.34"));
        assert_eq!(
            package(
                "resolve@patch:resolve@npm%3A1.22.13#optional!builtin<compat/resolve>::version=1.22.13&hash=c3c19d"
            ),
            p("resolve", "1.22.13")
        );
        assert_eq!(
            package(
                "resolve@patch:resolve@npm%3A1.22.13#~builtin<compat/resolve>::version=1.22.13&hash=c3c19d"
            ),
            p("resolve", "1.22.13")
        );
        assert_eq!(
            package("@exemple/a@patch:@exemple/a@npm%3A2.0.0#./correctif.patch::locator=x"),
            p("@exemple/a", "2.0.0")
        );
        assert_eq!(package("alias@npm:vrai@1.0.0"), p("vrai", "1.0.0"));
        for member in [
            "espace@workspace:packages/espace",
            "a@portal:../a",
            "b@link:./b",
        ] {
            assert!(
                matches!(berry_resolution(member), Verdict::Member),
                "{member}"
            );
        }
        for off in [
            "local@file:./packages/local#./packages/local::hash=cb25a5",
            "lib@git+https://git.example.org/exemple/lib.git#commit=abc",
            "outil@exec:./generer.js",
            "lien@https://files.example.org/a.tgz",
            "a@patch:a@file%3A./a#./p.patch",
        ] {
            assert!(
                matches!(berry_resolution(off), Verdict::OffRegistry),
                "{off}"
            );
        }
    }
}
