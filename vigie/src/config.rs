//! Configuration de production, lue sur le veilleur seulement.
//!
//! Le dépôt est public : ce fichier ne contient jamais de secret, et la liste
//! réelle des sites ne vit que dans `~/vigie/config.toml` sur le veilleur.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;

pub const ENV_CONFIG: &str = "VIGIE_CONFIG";

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
    /// API de la console ; sans elle, `device pair` est refusé.
    pub api: Option<Api>,
    /// Canal de commandes (`docs/protocole-commandes.md`) ; sans lui, aucune
    /// commande n'est créée ni servie.
    pub commands: Option<Commands>,
    pub alerts: Alerts,
    #[serde(default)]
    pub sites: Vec<Site>,
}

/// API de la console (`docs/api-console.md`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Api {
    /// Adresse publique du veilleur, telle que la console l'appelle. La règle
    /// « https hors boucle locale » est appliquée par `device pair`, pour
    /// qu'une adresse mal saisie n'arrête ni `serve` ni `tick`.
    pub public_url: String,
}

/// Clés du canal de commandes : fichiers 0600 dans un dossier 0700, au
/// propriétaire du veilleur, ouverts sans suivre de lien (`command/key.rs`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commands {
    /// Clé de signature des réponses de `/r/v1/commands`, lue par `serve`
    /// seulement.
    pub key_file: PathBuf,
    /// Clé de signature du journal d'audit, lue par `serve`, `tick` et la CLI.
    pub audit_key_file: PathBuf,
}

/// Envoi par un relais SMTP authentifié, en STARTTLS obligatoire.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Alerts {
    /// Destinataire unique.
    pub to: String,
    /// Adresse de la boîte qui sert de relais.
    pub from: String,
    pub smtp_host: String,
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,
    /// Identifiant SMTP, `from` par défaut.
    pub smtp_user: Option<String>,
    /// Fichier du mot de passe, en 0600 et au même propriétaire que le
    /// processus. Lu au moment de l'envoi, jamais copié ailleurs.
    pub password_file: PathBuf,
}

impl Alerts {
    pub fn smtp_user(&self) -> &str {
        self.smtp_user.as_deref().unwrap_or(&self.from)
    }
}

fn default_smtp_port() -> u16 {
    587
}

/// Type de CMS : filtre les contrôles (`CheckKind::cms`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SiteKind {
    #[default]
    Generic,
    Wordpress,
    Prestashop,
}

impl SiteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::Wordpress => "wordpress",
            Self::Prestashop => "prestashop",
        }
    }
}

/// Ce que le site exécute : filtre les commandes (`capability.rs`). Déclaré
/// par l'exploitant, jamais détecté ni rapporté par l'agent. Pas de valeur
/// par défaut : un site sans runtime n'admet aucune commande.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Runtime {
    Php,
    Node,
    Static,
}

impl Runtime {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Php => "php",
            Self::Node => "node",
            Self::Static => "static",
        }
    }
}

/// Intervalle par défaut des contrôles d'un site, en secondes.
pub const DEFAULT_INTERVAL: u64 = 300;
/// En dessous, le site serait sondé à chaque passage du timer.
pub const MIN_INTERVAL: u64 = 60;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Site {
    pub id: String,
    pub url: String,
    #[serde(default)]
    pub kind: SiteKind,
    /// `php`, `node` ou `static`. Facultatif : `wordpress` et `prestashop`
    /// impliquent `php` ; un site `generic` sans runtime n'en a aucun.
    pub runtime: Option<Runtime>,
    /// Page du contrôle `content`, `url` par défaut.
    pub keyword_url: Option<String>,
    /// Texte attendu dans cette page.
    pub keyword: Option<String>,
    /// Secondes entre deux passages des contrôles du site.
    #[serde(default = "default_interval")]
    pub interval: u64,
    /// Secondes sans rapport accepté de l'agent avant l'incident `heartbeat`.
    /// Sans effet tant que le site n'a pas de clé.
    #[serde(default = "default_agent_silence")]
    pub agent_silence: u64,
}

fn default_interval() -> u64 {
    DEFAULT_INTERVAL
}

/// Silence toléré par défaut : trois envois de 5 min manqués.
pub const DEFAULT_AGENT_SILENCE: u64 = 900;
/// En dessous, un seul rapport refusé par le débit (60 s) suffirait à alerter.
pub const MIN_AGENT_SILENCE: u64 = 180;

fn default_agent_silence() -> u64 {
    DEFAULT_AGENT_SILENCE
}

impl Site {
    /// Runtime déclaré, sinon celui qu'impose le CMS, sinon aucun.
    pub fn effective_runtime(&self) -> Option<Runtime> {
        self.runtime.or(match self.kind {
            SiteKind::Wordpress | SiteKind::Prestashop => Some(Runtime::Php),
            SiteKind::Generic => None,
        })
    }

    pub fn content_url(&self) -> &str {
        self.keyword_url.as_deref().unwrap_or(&self.url)
    }

    /// Les chemins sondés (`.env`, `wp-admin/…`) sont joints à cette URL :
    /// elle doit finir par `/` quand le site vit dans un sous-dossier.
    pub fn base_url(&self) -> Result<url::Url, url::ParseError> {
        url::Url::parse(&self.url)
    }
}

/// Version de la typologie (registre des capacités) : SHA-256 hex de la
/// projection `id kind runtime` de chaque site, triée par `id`. Un commentaire,
/// un intervalle ou l'ordre des blocs `[[sites]]` ne la changent pas.
pub fn typology_fingerprint(config: &Config) -> String {
    use sha2::{Digest, Sha256};
    let mut lines = typology(config);
    lines.sort();
    let digest = Sha256::digest(lines.join("\n").as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Ce qu'on écrit en base pour une typologie : son empreinte et ses lignes,
/// pour journaliser plus tard quels sites ont changé.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize)]
pub struct TypologyRecord {
    pub fingerprint: String,
    pub sites: Vec<String>,
}

impl TypologyRecord {
    pub fn of(config: &Config) -> Self {
        let mut sites = typology(config);
        sites.sort();
        Self {
            fingerprint: typology_fingerprint(config),
            sites,
        }
    }

    /// Lignes `id kind runtime` apparues ou disparues entre `self` et `next`.
    pub fn changes(&self, next: &Self) -> Vec<String> {
        let removed = self
            .sites
            .iter()
            .filter(|l| !next.sites.contains(l))
            .map(|l| format!("- {l}"));
        let added = next
            .sites
            .iter()
            .filter(|l| !self.sites.contains(l))
            .map(|l| format!("+ {l}"));
        removed.chain(added).collect()
    }
}

/// `id kind runtime` de chaque site, dans l'ordre de la configuration.
pub fn typology(config: &Config) -> Vec<String> {
    config
        .sites
        .iter()
        .map(|site| {
            format!(
                "{} {} {}",
                site.id,
                site.kind.as_str(),
                site.effective_runtime().map_or("-", Runtime::as_str)
            )
        })
        .collect()
}

/// `--config`, sinon `VIGIE_CONFIG`, sinon `~/vigie/config.toml`.
pub fn resolve_path(cli: Option<PathBuf>) -> Result<PathBuf, ConfigError> {
    if let Some(path) = cli {
        return Ok(path);
    }
    if let Some(path) = std::env::var_os(ENV_CONFIG).filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    dirs::home_dir()
        .map(|home| home.join("vigie").join("config.toml"))
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
/// ni caractère de contrôle, et une URL que le client HTTP sait analyser.
fn is_plausible_https_url(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    !host.is_empty()
        && !host.starts_with(':')
        && !host.contains('@')
        && !value.chars().any(|c| c.is_whitespace() || c.is_control())
        && url::Url::parse(value).is_ok_and(|u| u.host_str().is_some())
}

/// `http://` ou `https://`, un hôte, ni identifiant, ni requête, ni fragment,
/// aucun espace ni caractère de contrôle.
fn is_plausible_base_url(value: &str) -> bool {
    !value.chars().any(|c| c.is_whitespace() || c.is_control())
        && url::Url::parse(value).is_ok_and(|u| {
            matches!(u.scheme(), "http" | "https")
                && u.host_str().is_some_and(|h| !h.is_empty())
                && u.username().is_empty()
                && u.password().is_none()
                && u.query().is_none()
                && u.fragment().is_none()
        })
}

fn is_plausible_host(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
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
        if let Some(user) = &self.alerts.smtp_user
            && (user.is_empty() || user.chars().any(char::is_whitespace))
        {
            return Err(format!("alerts.smtp_user invalide (reçu : {user})"));
        }
        if !is_plausible_host(&self.alerts.smtp_host) {
            return Err(format!(
                "alerts.smtp_host doit être un nom d'hôte (reçu : {})",
                self.alerts.smtp_host
            ));
        }
        if self.alerts.smtp_port == 0 {
            return Err("alerts.smtp_port ne peut pas valoir 0".into());
        }
        let pw = self.alerts.password_file.to_string_lossy();
        if !(self.alerts.password_file.is_absolute() || pw.starts_with('/')) {
            return Err(format!(
                "alerts.password_file doit être un chemin absolu (reçu : {pw})"
            ));
        }
        if let Some(commands) = &self.commands {
            for (key, path) in [
                ("commands.key_file", &commands.key_file),
                ("commands.audit_key_file", &commands.audit_key_file),
            ] {
                let shown = path.to_string_lossy();
                if !(path.is_absolute() || shown.starts_with('/')) {
                    return Err(format!("{key} doit être un chemin absolu (reçu : {shown})"));
                }
            }
            if commands.key_file == commands.audit_key_file {
                return Err(
                    "commands.key_file et commands.audit_key_file doivent être deux fichiers : une clé par usage".into(),
                );
            }
        }
        if let Some(api) = &self.api
            && !is_plausible_base_url(&api.public_url)
        {
            return Err(format!(
                "api.public_url doit être http(s)://hôte[:port][/chemin], sans requête (reçu : {})",
                api.public_url
            ));
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
            if let Some(keyword_url) = &site.keyword_url
                && !is_plausible_https_url(keyword_url)
            {
                return Err(format!(
                    "keyword_url du site « {} » doit être https://hôte/… sans espace (reçu : {keyword_url})",
                    site.id
                ));
            }
            if site.keyword.as_deref().is_some_and(|k| k.trim().is_empty()) {
                return Err(format!("keyword du site « {} » est vide", site.id));
            }
            if site.interval < MIN_INTERVAL {
                return Err(format!(
                    "interval du site « {} » : {MIN_INTERVAL} s au moins (reçu : {})",
                    site.id, site.interval
                ));
            }
            if matches!(site.kind, SiteKind::Wordpress | SiteKind::Prestashop)
                && site.runtime.is_some_and(|r| r != Runtime::Php)
            {
                return Err(format!(
                    "runtime du site « {} » : {} implique php (reçu : {})",
                    site.id,
                    site.kind.as_str(),
                    site.runtime.map_or("-", Runtime::as_str)
                ));
            }
            if site.agent_silence < MIN_AGENT_SILENCE {
                return Err(format!(
                    "agent_silence du site « {} » : {MIN_AGENT_SILENCE} s au moins (reçu : {})",
                    site.id, site.agent_silence
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
database = "/home/veilleur/vigie/vigie.db"

[alerts]
to = "alertes@example.org"
from = "vigie@example.org"
smtp_host = "smtp.example.org"
password_file = "/home/veilleur/vigie/smtp-password"

[[sites]]
id = "exemple"
url = "https://www.example.org/"
"#;

    fn parse_str(raw: &str) -> Result<Config, ConfigError> {
        parse(Path::new("config.toml"), raw)
    }

    #[test]
    fn a_cms_implies_php_and_refuses_another_runtime() {
        let site = |extra: &str| parse_str(&format!("{VALID}{extra}"));
        let wp = site("kind = \"wordpress\"\n").expect("valide");
        assert_eq!(wp.sites[0].effective_runtime(), Some(Runtime::Php));
        let generic = site("").expect("valide");
        assert_eq!(generic.sites[0].effective_runtime(), None);
        let node = site("runtime = \"node\"\n").expect("valide");
        assert_eq!(node.sites[0].effective_runtime(), Some(Runtime::Node));
        let declared = site("kind = \"prestashop\"\nruntime = \"php\"\n").expect("valide");
        assert_eq!(declared.sites[0].effective_runtime(), Some(Runtime::Php));

        let err = site("kind = \"wordpress\"\nruntime = \"node\"\n").unwrap_err();
        assert!(matches!(err, ConfigError::Invalid { .. }), "{err}");
        assert!(err.to_string().contains("« exemple »"), "{err}");
        let err = site("runtime = \"python\"\n").unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }), "{err}");
    }

    #[test]
    fn the_typology_fingerprint_ignores_order_and_unrelated_keys() {
        let two = |first: &str, second: &str| {
            parse_str(&format!(
                "{VALID}{first}\n[[sites]]\nid = \"autre\"\nurl = \"https://autre.example.org/\"\n{second}"
            ))
            .expect("valide")
        };
        let a = two("kind = \"wordpress\"", "");
        let interval = two("kind = \"wordpress\"\ninterval = 900", "# commentaire\n");
        assert_eq!(typology_fingerprint(&a), typology_fingerprint(&interval));
        let mut swapped = a.clone();
        swapped.sites.reverse();
        assert_eq!(typology_fingerprint(&a), typology_fingerprint(&swapped));
        let runtime = two("kind = \"wordpress\"", "runtime = \"static\"");
        assert_ne!(typology_fingerprint(&a), typology_fingerprint(&runtime));
        assert_eq!(typology_fingerprint(&a).len(), 64);
        assert_eq!(
            TypologyRecord::of(&a).changes(&TypologyRecord::of(&runtime)),
            ["- autre generic -", "+ autre generic static"]
        );
    }

    #[test]
    fn accepts_the_example() {
        let config = parse_str(VALID).expect("valide");
        assert_eq!(config.sites.len(), 1);
        let site = &config.sites[0];
        assert_eq!(site.id, "exemple");
        assert_eq!(site.kind, SiteKind::Generic);
        assert_eq!(site.interval, DEFAULT_INTERVAL);
        assert_eq!(site.agent_silence, DEFAULT_AGENT_SILENCE);
        assert_eq!(site.content_url(), "https://www.example.org/");
        assert_eq!(config.alerts.smtp_port, 587);
        assert_eq!(config.alerts.smtp_user(), "vigie@example.org");
    }

    #[test]
    fn reads_site_kind_keyword_and_interval() {
        let raw = format!(
            "{VALID}kind = \"wordpress\"\nkeyword_url = \"https://www.example.org/kb/\"\nkeyword = \"/problemes/\"\ninterval = 600\nagent_silence = 1800\n"
        );
        let config = parse_str(&raw).expect("valide");
        let site = &config.sites[0];
        assert_eq!(site.kind, SiteKind::Wordpress);
        assert_eq!(site.content_url(), "https://www.example.org/kb/");
        assert_eq!(site.keyword.as_deref(), Some("/problemes/"));
        assert_eq!(site.interval, 600);
        assert_eq!(site.agent_silence, 1800);
    }

    #[test]
    fn refuses_bad_site_options() {
        for extra in [
            "kind = \"joomla\"",
            "interval = 30",
            "agent_silence = 120",
            "keyword = \"  \"",
            "keyword_url = \"http://www.example.org/kb/\"",
        ] {
            assert!(parse_str(&format!("{VALID}{extra}\n")).is_err(), "{extra}");
        }
    }

    #[test]
    fn refuses_bad_smtp_settings() {
        assert!(parse_str(&VALID.replace("smtp.example.org", "smtp example")).is_err());
        assert!(
            parse_str(&VALID.replace("/home/veilleur/vigie/smtp-password", "smtp-password"))
                .is_err()
        );
        let missing = VALID.replace("smtp_host = \"smtp.example.org\"\n", "");
        assert!(parse_str(&missing).is_err());
        let port = VALID.replace(
            "smtp_host = \"smtp.example.org\"",
            "smtp_host = \"smtp.example.org\"\nsmtp_port = 0",
        );
        assert!(parse_str(&port).is_err());
    }

    #[test]
    fn reads_the_api_section() {
        let raw = VALID.replace(
            "[alerts]",
            "[api]\npublic_url = \"https://veilleur.example.org\"\n\n[alerts]",
        );
        let config = parse_str(&raw).expect("valide");
        assert_eq!(
            config.api.expect("api").public_url,
            "https://veilleur.example.org"
        );
        assert!(parse_str(VALID).expect("valide").api.is_none());
        // Forme seulement : http est refusé plus tard, par `device pair`.
        let http = raw.replace("https://veilleur", "http://veilleur");
        assert!(parse_str(&http).is_ok());
        for bad in [
            "veilleur.example.org",
            "https://veilleur.example.org/?x=1",
            "https://moi@veilleur.example.org",
            "ftp://veilleur.example.org",
        ] {
            let raw = raw.replace("https://veilleur.example.org", bad);
            assert!(parse_str(&raw).is_err(), "{bad}");
        }
        let unknown = raw.replace("[api]", "[api]\nsecret = 1");
        assert!(parse_str(&unknown).is_err());
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
        let raw = VALID.replace("/home/veilleur/vigie/vigie.db", "vigie.db");
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
