//! Configuration de production, lue sur le veilleur seulement.
//!
//! Le dépôt est public : ce fichier ne contient jamais de secret, et la liste
//! réelle des sites ne vit que dans `~/monitor/config.toml` sur le veilleur.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;

pub const ENV_CONFIG: &str = "MONITOR_CONFIG";

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error(
        "aucun fichier de configuration : ni --config, ni {ENV_CONFIG}, et le dossier personnel est introuvable"
    )]
    NoPath,
    #[error("lecture de {path} impossible : {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{path} invalide : {source}")]
    Parse {
        path: PathBuf,
        source: Box<toml::de::Error>,
    },
    #[error("{path} invalide : {reason}")]
    Invalid { path: PathBuf, reason: String },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Base SQLite partagée par `serve` et `tick`, chemin absolu.
    pub database: PathBuf,
    pub alerts: Alerts,
    #[serde(default)]
    pub sites: Vec<Site>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Alerts {
    pub to: String,
    pub from: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Site {
    pub id: String,
    pub url: String,
}

/// `--config`, sinon `MONITOR_CONFIG`, sinon `~/monitor/config.toml`.
pub fn resolve_path(cli: Option<PathBuf>) -> Result<PathBuf, ConfigError> {
    if let Some(path) = cli {
        return Ok(path);
    }
    if let Some(path) = std::env::var_os(ENV_CONFIG).filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    dirs::home_dir()
        .map(|home| home.join("monitor").join("config.toml"))
        .ok_or(ConfigError::NoPath)
}

pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    parse(path, &raw)
}

pub fn parse(path: &Path, raw: &str) -> Result<Config, ConfigError> {
    let config: Config = toml::from_str(raw).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source: Box::new(source),
    })?;
    config.validate().map_err(|reason| ConfigError::Invalid {
        path: path.to_path_buf(),
        reason,
    })?;
    Ok(config)
}

pub fn is_valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn is_plausible_email(value: &str) -> bool {
    match value.split_once('@') {
        Some((local, domain)) => {
            !local.is_empty()
                && domain.contains('.')
                && !value
                    .chars()
                    .any(|c| c.is_whitespace() || c == ',' || c == ';')
        }
        None => false,
    }
}

/// `https://`, un hôte non vide jusqu'au premier `/`, `?` ou `#`, aucun espace
/// ni caractère de contrôle. Sans dépendance : l'analyse complète viendra avec
/// le client HTTP des contrôles (phase 2).
fn is_plausible_https_url(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    !host.is_empty()
        && !host.starts_with(':')
        && !host.contains('@')
        && !value.chars().any(|c| c.is_whitespace() || c.is_control())
}

impl Config {
    fn validate(&self) -> Result<(), String> {
        // Path::is_absolute suit la plateforme : « /home/… » n'est pas absolu
        // sous Windows, où le binaire sert aussi aux tests et à la reprise locale.
        let db = self.database.to_string_lossy();
        if !(self.database.is_absolute() || db.starts_with('/')) {
            return Err(format!("database doit être un chemin absolu (reçu : {db})"));
        }
        for (key, value) in [
            ("alerts.to", &self.alerts.to),
            ("alerts.from", &self.alerts.from),
        ] {
            if !is_plausible_email(value) {
                return Err(format!(
                    "{key} n'est pas une adresse e-mail (reçu : {value})"
                ));
            }
        }
        let mut seen = HashSet::new();
        for site in &self.sites {
            if !is_valid_id(&site.id) {
                return Err(format!(
                    "identifiant de site invalide « {} » : [a-z0-9-], 64 caractères au plus",
                    site.id
                ));
            }
            if !seen.insert(site.id.as_str()) {
                return Err(format!("site « {} » déclaré deux fois", site.id));
            }
            if !is_plausible_https_url(&site.url) {
                return Err(format!(
                    "url du site « {} » doit être https://hôte/… sans espace (reçu : {})",
                    site.id, site.url
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
database = "/home/veilleur/monitor/monitor.db"

[alerts]
to = "alertes@example.org"
from = "monitor@example.org"

[[sites]]
id = "exemple"
url = "https://www.example.org/"
"#;

    fn parse_str(raw: &str) -> Result<Config, ConfigError> {
        parse(Path::new("config.toml"), raw)
    }

    #[test]
    fn accepts_the_example() {
        let config = parse_str(VALID).expect("valide");
        assert_eq!(config.sites.len(), 1);
        assert_eq!(config.sites[0].id, "exemple");
    }

    #[test]
    fn accepts_the_shipped_example_file() {
        let raw = include_str!("../config.example.toml");
        parse_str(raw).expect("config.example.toml doit rester valide");
    }

    #[test]
    fn refuses_an_unknown_key() {
        let raw = VALID.replace("[alerts]", "inconnu = 1\n[alerts]");
        let err = parse_str(&raw).expect_err("clé inconnue");
        assert!(err.to_string().contains("inconnu"), "{err}");
    }

    #[test]
    fn refuses_an_unknown_key_in_a_site() {
        let raw = format!("{VALID}secret = \"x\"\n");
        assert!(parse_str(&raw).is_err());
    }

    #[test]
    fn refuses_a_relative_database() {
        let raw = VALID.replace("/home/veilleur/monitor/monitor.db", "monitor.db");
        let err = parse_str(&raw).expect_err("relatif");
        assert!(err.to_string().contains("absolu"), "{err}");
    }

    #[test]
    fn refuses_bad_site_ids_duplicates_and_plain_http() {
        assert!(parse_str(&VALID.replace("id = \"exemple\"", "id = \"Exemple\"")).is_err());
        assert!(parse_str(&VALID.replace("id = \"exemple\"", "id = \"a;b\"")).is_err());
        let duplicated =
            format!("{VALID}\n[[sites]]\nid = \"exemple\"\nurl = \"https://b.example.org/\"\n");
        assert!(parse_str(&duplicated).is_err());
        assert!(parse_str(&VALID.replace("https://www", "http://www")).is_err());
    }

    #[test]
    fn checks_the_site_url_host() {
        assert!(is_plausible_https_url("https://www.example.org/"));
        assert!(is_plausible_https_url("https://example.org"));
        assert!(is_plausible_https_url("https://example.org:8443/kb/?q=1#x"));
        for bad in [
            "https://",
            "https:///chemin",
            "https://?q=1",
            "https://#x",
            "https://:443/",
            "https://user@example.org/",
            "https://exa mple.org/",
            "https://example.org/a b",
            "https://example.org/\n",
            "ftp://example.org/",
        ] {
            assert!(!is_plausible_https_url(bad), "{bad:?}");
        }
        let spaced = VALID.replace("https://www.example.org/", "https://www.example.org/ x");
        assert!(parse_str(&spaced).is_err());
    }

    #[test]
    fn refuses_a_recipient_list() {
        let raw = VALID.replace("alertes@example.org", "a@example.org, b@example.org");
        assert!(parse_str(&raw).is_err());
    }

    #[test]
    fn cli_path_wins() {
        let path = resolve_path(Some(PathBuf::from("/tmp/x.toml"))).expect("chemin");
        assert_eq!(path, PathBuf::from("/tmp/x.toml"));
    }
}
