//! `Cargo.lock`, `version = 3` ou `4`, par `toml` sur une structure minimale
//! (`checksum`, `dependencies` ignorés). `source` absent : membre du
//! workspace ou chemin du dépôt (ignoré) ; crates.io
//! (`registry+https://github.com/rust-lang/crates.io-index`,
//! `sparse+https://index.crates.io/`) : paquet ; tout autre `source` (git,
//! autre registre) : hors registre. Cargo ne dit pas ce qui est de
//! développement : tout y est exécuté.

use serde::Deserialize;

use super::{Entry, LockError, Parsed};
use crate::vulns::purl::PurlType;

#[derive(Deserialize)]
struct Lock {
    version: Option<i64>,
    #[serde(default)]
    package: Vec<Package>,
}

#[derive(Deserialize)]
struct Package {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<String>,
}

fn crates_io(source: &str) -> bool {
    source == "registry+https://github.com/rust-lang/crates.io-index"
        || source.starts_with("sparse+https://index.crates.io/")
}

pub fn parse(text: &str) -> Result<Parsed, LockError> {
    // Le texte d'erreur de `toml` recopie des octets lus : jamais formaté.
    let lock: Lock = toml::from_str(text).map_err(|_| LockError::Unreadable)?;
    if !matches!(lock.version, Some(3 | 4)) {
        return Err(LockError::UnsupportedVersion);
    }
    let mut parsed = Parsed::default();
    for package in lock.package {
        match package.source.as_deref() {
            None => parsed.ignore()?,
            Some(source) if crates_io(source) => parsed.push(Entry {
                ecosystem: PurlType::Cargo,
                namespace: None,
                name: package.name,
                version: package.version,
                dev: false,
            })?,
            Some(_) => parsed.offregistry()?,
        }
    }
    Ok(parsed)
}
