//! Logique de `vigie-inventory` (issue #20, `docs/inventaire.md`), testable
//! hors du binaire : projet et lockfiles, clé d'inventaire, point d'entrée,
//! signature et envoi. Aucun accès à `config.toml` ni à la base du veilleur.
//!
//! Codes de sortie : 0 écrit ou envoyé (204) ; 1 refus du veilleur ou réseau ;
//! 2 usage, clé, lockfile, projet. Aucun message ne porte la graine, une
//! signature, le corps envoyé ni un nom de composant.

use std::io::Write;
use std::path::{Component as PathPart, Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::SigningKey;
use url::Url;

use super::build::{self, Document, Lockfile, Options, Stamp};
use super::lockfile::{self, Kind};
use crate::command::key::{self, DOMAIN_INVENTORY, KeyError};
use crate::ingest::{HEADER_SIGNATURE, HEADER_SITE};

/// Variable d'environnement de la graine (secret de CI) : lue par
/// [`signing_key`], jamais liée à un argument de la CLI.
pub const KEY_ENV: &str = "VIGIE_INVENTORY_KEY";
/// `--lockfile` au plus.
pub const MAX_LOCKFILES: usize = 10;
/// Délai global d'un envoi.
pub const TIMEOUT: Duration = Duration::from_secs(30);

/// Erreur rendue par le binaire : code de sortie et message, sur stderr.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolError {
    pub code: u8,
    pub message: String,
}

impl ToolError {
    /// Usage, clé, lockfile, projet : code 2.
    pub fn usage(message: impl Into<String>) -> Self {
        Self {
            code: 2,
            message: message.into(),
        }
    }

    /// Refus du veilleur ou réseau : code 1.
    pub fn refused(message: impl Into<String>) -> Self {
        Self {
            code: 1,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ToolError {}

/// Lockfile retenu : chemin absolu et `vigie:path` (relatif, `/`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub path: PathBuf,
    pub relative: String,
    pub kind: Kind,
}

/// Chemin relatif au projet, séparateur `/` même sous Windows.
fn relative(root: &Path, path: &Path) -> Option<String> {
    let rest = path.strip_prefix(root).ok()?;
    let parts: Option<Vec<&str>> = rest
        .components()
        .map(|part| match part {
            PathPart::Normal(name) => name.to_str(),
            _ => None,
        })
        .collect();
    let parts = parts?;
    (!parts.is_empty()).then(|| parts.join("/"))
}

/// Lockfiles du projet : ceux de `--lockfile` (relatifs au projet, sans
/// `..`, sans lien sortant du projet, sans doublon, 10 au plus), sinon les
/// cinq noms connus à la racine seulement. Un lockfile npm par dossier.
pub fn find_lockfiles(project_dir: &Path, explicit: &[PathBuf]) -> Result<Vec<Found>, ToolError> {
    let root = std::fs::canonicalize(project_dir)
        .map_err(|_| ToolError::usage(format!("projet introuvable : {}", project_dir.display())))?;
    if !root.is_dir() {
        return Err(ToolError::usage(format!(
            "{} n'est pas un dossier",
            project_dir.display()
        )));
    }
    let mut found: Vec<Found> = Vec::new();
    if explicit.is_empty() {
        for kind in Kind::ALL {
            let path = root.join(kind.file_name());
            if path.is_file() {
                found.push(Found {
                    path,
                    relative: kind.file_name().to_owned(),
                    kind,
                });
            }
        }
        if found.is_empty() {
            return Err(ToolError::usage(format!(
                "aucun lockfile reconnu dans {} (composer.lock, package-lock.json, \
                 pnpm-lock.yaml, yarn.lock, Cargo.lock)",
                project_dir.display()
            )));
        }
    } else {
        if explicit.len() > MAX_LOCKFILES {
            return Err(ToolError::usage(format!(
                "--lockfile : {MAX_LOCKFILES} au plus"
            )));
        }
        for given in explicit {
            let shown = given.display();
            if given.is_absolute()
                || given
                    .components()
                    .any(|p| !matches!(p, PathPart::Normal(_) | PathPart::CurDir))
            {
                return Err(ToolError::usage(format!(
                    "--lockfile {shown} : chemin relatif au projet, sans .., attendu"
                )));
            }
            let kind = given
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(Kind::from_file_name)
                .ok_or_else(|| ToolError::usage(format!("--lockfile {shown} : format inconnu")))?;
            let path = std::fs::canonicalize(root.join(given))
                .map_err(|_| ToolError::usage(format!("--lockfile {shown} : introuvable")))?;
            let relative = relative(&root, &path).ok_or_else(|| {
                ToolError::usage(format!("--lockfile {shown} : hors du projet (lien ?)"))
            })?;
            if !path.is_file() {
                return Err(ToolError::usage(format!(
                    "--lockfile {shown} : pas un fichier"
                )));
            }
            if found.iter().any(|f| f.path == path) {
                return Err(ToolError::usage(format!("--lockfile {shown} : en double")));
            }
            found.push(Found {
                path,
                relative,
                kind,
            });
        }
    }
    let names: Vec<String> = found.iter().map(|f| f.relative.clone()).collect();
    lockfile::one_npm_lockfile_per_dir(&names, !explicit.is_empty())
        .map_err(|e| ToolError::usage(e.to_string()))?;
    Ok(found)
}

/// Lit chaque lockfile ; le premier illisible, inconnu ou corrompu arrête
/// tout (code 2, rien d'écrit ni d'envoyé).
pub fn read_lockfiles(found: &[Found]) -> Result<Vec<Lockfile>, ToolError> {
    found
        .iter()
        .map(|f| {
            let text = lockfile::read_bounded(&f.path)
                .map_err(|e| ToolError::usage(format!("{} : {e}", f.relative)))?;
            let parsed = lockfile::parse(f.kind, &text)
                .map_err(|e| ToolError::usage(format!("{} : {e}", f.relative)))?;
            Ok(Lockfile {
                path: f.relative.clone(),
                parsed,
            })
        })
        .collect()
}

/// Construit le document ; une erreur de construction est une erreur
/// interne (code 2), jamais envoyée.
pub fn document(
    name: &str,
    lockfiles: &[Lockfile],
    options: Options,
    stamp: Stamp,
) -> Result<Document, ToolError> {
    build::document(name, lockfiles, options, stamp).map_err(|e| ToolError::usage(e.to_string()))
}

/// Faits de la construction, une ligne par fait, en nombres.
pub fn summary(document: &Document) -> Vec<String> {
    let r = &document.report;
    let mut lines = vec![format!(
        "composants : {} ; membres du projet ignorés : {} ; hors registre : {} ; \
         noms hors grammaire écartés : {} ; doublons : {}",
        r.components, r.ignored, r.offregistry, r.invalid, r.duplicates
    )];
    if r.omitted > 0 {
        lines.push(format!(
            "dépendances de développement omises (--omit-dev) : {}",
            r.omitted
        ));
    }
    if r.truncated > 0 {
        lines.push(format!(
            "attention : {} composant(s) retiré(s) par les bornes du veilleur (2 000 \
             composants, 512 Kio), développement d'abord : inventaire incomplet ; \
             --omit-dev allège le document",
            r.truncated
        ));
    }
    lines.push(if document.envelope.complete {
        "inventaire complet".to_owned()
    } else {
        "inventaire incomplet : l'absence d'un composant n'y prouve rien".to_owned()
    });
    lines
}

/// Graine de 32 octets en base64 standard, tampons écrasés après usage.
fn decode_seed(mut encoded: String) -> Option<SigningKey> {
    let decoded = STANDARD.decode(encoded.trim()).ok();
    // Copie lue de l'environnement, effacée.
    wipe(&mut encoded);
    let mut bytes = decoded?;
    let seed = <[u8; 32]>::try_from(bytes.as_slice()).ok();
    bytes.fill(0);
    let mut seed = seed?;
    let key = SigningKey::from_bytes(&seed);
    seed.fill(0);
    Some(key)
}

/// Écrase le contenu d'une chaîne avant de la rendre.
fn wipe(text: &mut String) {
    let mut bytes = std::mem::take(text).into_bytes();
    bytes.fill(0);
}

/// Clé d'inventaire : `VIGIE_INVENTORY_KEY` (lue ici, après l'analyse des
/// arguments) ou `--key-file` (`command::key::load` : 0600, dossier 0700, sans
/// lien, sous Unix). Les deux ensemble : code 2. `None` : aucune clé fournie.
pub fn signing_key(key_file: Option<&Path>) -> Result<Option<SigningKey>, ToolError> {
    let env = std::env::var_os(KEY_ENV).filter(|v| !v.is_empty());
    match (env, key_file) {
        (Some(_), Some(_)) => Err(ToolError::usage(format!(
            "{KEY_ENV} et --key-file ensemble : n'en fournir qu'un"
        ))),
        (Some(value), None) => {
            let value = value
                .into_string()
                .map_err(|_| ToolError::usage(format!("{KEY_ENV} : graine illisible")))?;
            decode_seed(value).map(Some).ok_or_else(|| {
                ToolError::usage(format!(
                    "{KEY_ENV} : graine illisible (32 octets en base64 attendus)"
                ))
            })
        }
        (None, Some(path)) => key::load(path).map(Some).map_err(|e| key_error(path, e)),
        (None, None) => Ok(None),
    }
}

/// Message clair pour un fichier de graine refusé : le dossier et la
/// commande qui le corrige.
pub fn key_error(path: &Path, err: KeyError) -> ToolError {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    match err {
        KeyError::Unsafe {
            path: shown,
            reason,
        } if Path::new(&shown) == parent => ToolError::usage(format!(
            "{shown} doit être en 0700 et à vous : chmod 700 {shown} ({reason})"
        )),
        KeyError::Unsafe {
            path: shown,
            reason,
        } => ToolError::usage(format!(
            "{shown} doit être un fichier en 0600 et à vous : chmod 600 {shown} ({reason})"
        )),
        other => ToolError::usage(other.to_string()),
    }
}

/// Clé publique d'une clé, en base64.
pub fn public_key(key: &SigningKey) -> String {
    STANDARD.encode(key.verifying_key().to_bytes())
}

/// `--endpoint` : URL de base du veilleur, `https`, chemin vide ou `/`, ni
/// requête, ni fragment, ni identifiants ; `http` seulement avec
/// `--allow-http-loopback` vers `127.0.0.1` ou `[::1]`. Rend l'URL de
/// `/r/v1/inventory`.
pub fn endpoint(raw: &str, allow_http_loopback: bool) -> Result<Url, ToolError> {
    let bad = |why: &str| ToolError::usage(format!("--endpoint : {why}"));
    let mut url = Url::parse(raw).map_err(|_| bad("URL illisible"))?;
    match url.scheme() {
        "https" => {}
        "http" if allow_http_loopback && matches!(url.host_str(), Some("127.0.0.1" | "[::1]")) => {}
        _ => return Err(bad("https exigé")),
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(bad("hôte absent"));
    }
    if !(url.path().is_empty() || url.path() == "/") {
        return Err(bad(
            "URL de base du veilleur attendue (sans chemin : l'outil ajoute /r/v1/inventory)",
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(bad("ni requête ni fragment"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(bad("ni identifiant ni mot de passe"));
    }
    url.set_path(super::receive::ROUTE);
    Ok(url)
}

/// Agent HTTP propre à l'outil : aucun proxy (même si `HTTPS_PROXY` est
/// posé), aucune redirection suivie, https seul hors boucle locale admise,
/// 30 s, racines webpki.
pub fn agent(allow_http_loopback: bool) -> ureq::Agent {
    ureq::Agent::config_builder()
        .proxy(None)
        .https_only(!allow_http_loopback)
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_global(Some(TIMEOUT))
        .user_agent(format!("vigie-inventory/{}", super::TOOL_VERSION))
        .build()
        .new_agent()
}

/// Signe et envoie le document : 204 → `Ok`, tout autre statut ou une
/// erreur réseau → code 1, sans URL complète ni corps.
pub fn push(
    agent: &ureq::Agent,
    url: &Url,
    site: &str,
    document: &Document,
    key: &SigningKey,
) -> Result<(), ToolError> {
    let body = serde_json::to_vec(&document.envelope)
        .map_err(|_| ToolError::usage("erreur interne : sérialisation"))?;
    let signature = key::sign(key, DOMAIN_INVENTORY, &[&body]);
    let response = agent
        .post(url.as_str())
        .header("Content-Type", "application/json")
        .header(HEADER_SITE, site)
        .header(HEADER_SIGNATURE, &signature)
        .send(&body[..])
        .map_err(|err| ToolError::refused(format!("veilleur injoignable : {}", network(&err))))?;
    match response.status().as_u16() {
        204 => Ok(()),
        status => Err(ToolError::refused(format!(
            "inventaire refusé (HTTP {status} ; raison dans journalctl -u vigie-serve ; \
             horloge de cette machine à ±5 min de celle du veilleur ?)"
        ))),
    }
}

/// Genre d'erreur réseau, sans URL.
fn network(err: &ureq::Error) -> &'static str {
    match err {
        ureq::Error::Timeout(_) => "délai dépassé",
        ureq::Error::HostNotFound => "nom d'hôte introuvable",
        ureq::Error::ConnectionFailed => "connexion refusée ou impossible",
        ureq::Error::RequireHttpsOnly(_) => "https exigé",
        ureq::Error::Io(_) => "connexion interrompue",
        _ => "erreur TLS ou HTTP",
    }
}

/// Écriture atomique : fichier temporaire du même dossier, puis `rename`.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ToolError> {
    let shown = path.display();
    let name = path
        .file_name()
        .ok_or_else(|| ToolError::usage(format!("{shown} : nom de fichier attendu")))?;
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let temporary = dir.join(format!(
        ".{}.{}.tmp",
        name.to_string_lossy(),
        std::process::id()
    ));
    let written = std::fs::File::create(&temporary)
        .and_then(|mut file| file.write_all(bytes).and_then(|()| file.sync_all()))
        .and_then(|()| std::fs::rename(&temporary, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
        return Err(ToolError::usage(format!("{shown} : écriture impossible")));
    }
    Ok(())
}

/// JSON indenté du BOM seul (`sbom`, `--output`), fin de ligne comprise.
pub fn bom_json(document: &Document) -> Vec<u8> {
    let mut out = serde_json::to_vec_pretty(&document.envelope.bom).unwrap_or_default();
    out.push(b'\n');
    out
}

/// Aléa d'un `serialNumber`.
pub fn serial() -> Result<[u8; 16], ToolError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| ToolError::usage("tirage aléatoire impossible"))?;
    Ok(bytes)
}

/// Heure Unix en millisecondes (`seq`) et en secondes (`sent_at`).
pub fn now() -> (i64, i64) {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
    (ms, ms / 1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_are_base_urls_over_https() {
        assert_eq!(
            endpoint("https://vigie.example.org", false)
                .expect("ok")
                .as_str(),
            "https://vigie.example.org/r/v1/inventory"
        );
        assert!(endpoint("https://vigie.example.org/", false).is_ok());
        for bad in [
            "http://192.0.2.10",
            "http://127.0.0.1:8080",
            "https://vigie.example.org/r/v1/inventory",
            "https://vigie.example.org/?x",
            "https://vigie.example.org/#y",
            "https://moi:secret@vigie.example.org",
            "ftp://vigie.example.org",
            "vigie.example.org",
        ] {
            let err = endpoint(bad, false).expect_err(bad);
            assert_eq!(err.code, 2, "{bad}");
        }
        assert!(endpoint("http://127.0.0.1:8080", true).is_ok());
        assert!(endpoint("http://[::1]:8080/", true).is_ok());
        assert!(endpoint("http://192.0.2.10", true).is_err());
        assert!(endpoint("http://localhost:8080", true).is_err());
    }

    #[test]
    fn seeds_are_32_bytes_of_base64() {
        let key = SigningKey::from_bytes(&[5; 32]);
        let seed = STANDARD.encode([5u8; 32]);
        assert_eq!(
            decode_seed(format!(" {seed}\n")).map(|k| k.to_bytes()),
            Some(key.to_bytes())
        );
        assert!(decode_seed(STANDARD.encode([5u8; 31])).is_none());
        assert!(decode_seed("pas*du*base64".into()).is_none());
    }
}
