//! `composer.lock` : `packages` (exécutés) et `packages-dev` (développement).
//!
//! Un paquet vient d'un registre **si et seulement si** `notification-url`
//! est présent (Packagist, dépôts Composer) ou son nom commence par
//! `wpackagist-plugin/` ou `wpackagist-theme/` (WPackagist n'en écrit pas) ;
//! sinon (`path`, vcs, `package` en ligne) il est hors registre, non émis et
//! compté. Même règle que l'agent PHP (F5).

use serde::Deserialize;
use serde::de::IgnoredAny;

use super::{Entry, LockError, Parsed, json_error};
use crate::vulns::purl::PurlType;

/// Longueur maximale d'un nom de paquet, écarté avant tout découpage.
const MAX_NAME_BYTES: usize = 214;

#[derive(Deserialize)]
struct Lock {
    #[serde(default)]
    packages: Vec<Package>,
    #[serde(default, rename = "packages-dev")]
    packages_dev: Vec<Package>,
}

#[derive(Deserialize)]
struct Package {
    name: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default, rename = "notification-url")]
    notification_url: Option<IgnoredAny>,
}

pub fn parse(text: &str) -> Result<Parsed, LockError> {
    let lock: Lock = serde_json::from_str(text).map_err(json_error)?;
    let mut parsed = Parsed::default();
    for (packages, dev) in [(lock.packages, false), (lock.packages_dev, true)] {
        for package in packages {
            let name = package.name.to_ascii_lowercase();
            let wpackagist =
                name.starts_with("wpackagist-plugin/") || name.starts_with("wpackagist-theme/");
            if package.notification_url.is_none() && !wpackagist {
                parsed.offregistry()?;
                continue;
            }
            // Un nom trop long ou sans vendor reste une entrée : `build.rs`
            // l'écarte par la grammaire purl et le compte.
            let (namespace, short) = if name.len() > MAX_NAME_BYTES {
                (None, name.as_str())
            } else {
                match name.split_once('/') {
                    Some((vendor, short)) => (Some(vendor.to_owned()), short),
                    None => (None, name.as_str()),
                }
            };
            parsed.push(Entry {
                ecosystem: PurlType::Composer,
                namespace,
                name: short.to_owned(),
                version: package.version.unwrap_or_default(),
                dev,
            })?;
        }
    }
    Ok(parsed)
}
