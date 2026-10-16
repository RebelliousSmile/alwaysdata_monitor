//! Appairage : lecture du lien `vigie://pair?u=…&c=…` et fichier privé de
//! l'appareil dans `app_data_dir`. Le jeton reste dans ce fichier et dans
//! la mémoire du processus ; il n'est jamais renvoyé au webview.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use url::{Host, Url};

use crate::client::{ApiError, ErrorKind};

/// Nom du fichier de l'appareil, dans `app_data_dir`.
const DEVICE_FILE: &str = "device.json";
/// Longueur d'un code : 16 octets en base64url sans remplissage.
const CODE_LEN: usize = 22;

/// Lien d'appairage lu et validé.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    /// Adresse publique du veilleur, sans barre finale.
    pub url: String,
    pub code: String,
}

fn invalid(message: &str) -> ApiError {
    ApiError::new(ErrorKind::InvalidLink, message)
}

/// Lit `vigie://pair?u=<adresse>&c=<code>`. L'adresse doit être en https ;
/// http n'est admis que sur la boucle locale, et seulement si
/// `allow_loopback` (build de debug). Même règle que
/// `vigie::device::check_public_url`, côté veilleur.
pub fn parse_link(link: &str, allow_loopback: bool) -> Result<Link, ApiError> {
    let link = Url::parse(link.trim()).map_err(|_| invalid("lien d'appairage illisible"))?;
    if link.scheme() != "vigie" || link.host_str() != Some("pair") {
        return Err(invalid("ce n'est pas un lien vigie://pair"));
    }
    let mut url = None;
    let mut code = None;
    for (key, value) in link.query_pairs() {
        match key.as_ref() {
            "u" => url = Some(value.into_owned()),
            "c" => code = Some(value.into_owned()),
            _ => {}
        }
    }
    let url = url.ok_or_else(|| invalid("adresse du veilleur absente du lien"))?;
    let code = code.ok_or_else(|| invalid("code absent du lien"))?;
    if code.len() != CODE_LEN
        || !code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(invalid("code d'appairage mal formé"));
    }
    check_url(&url, allow_loopback)?;
    Ok(Link {
        url: url.trim_end_matches('/').to_owned(),
        code,
    })
}

fn check_url(url: &str, allow_loopback: bool) -> Result<(), ApiError> {
    let parsed = Url::parse(url).map_err(|_| invalid("adresse du veilleur illisible"))?;
    let loopback = match parsed.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    match parsed.scheme() {
        "https" if parsed.host().is_some() => Ok(()),
        "http" if loopback && allow_loopback => Ok(()),
        "http" if loopback => Err(invalid(
            "adresse en http refusée : la boucle locale n'est admise qu'en build de debug",
        )),
        _ => Err(invalid("adresse du veilleur refusée : https exigé")),
    }
}

/// Contenu de `device.json`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stored {
    pub url: String,
    pub token: String,
    pub device_id: i64,
    pub name: String,
}

impl std::fmt::Debug for Stored {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stored")
            .field("url", &self.url)
            .field("device_id", &self.device_id)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

fn storage(message: String) -> ApiError {
    ApiError::new(ErrorKind::Storage, message)
}

fn path(dir: &Path) -> PathBuf {
    dir.join(DEVICE_FILE)
}

/// Appareil enregistré, ou `None` si ce poste n'est pas appairé.
pub fn load(dir: &Path) -> Result<Option<Stored>, ApiError> {
    match fs::read(path(dir)) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|err| storage(format!("fichier de l'appareil illisible : {err}"))),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(storage(format!(
            "fichier de l'appareil inaccessible : {err}"
        ))),
    }
}

/// Écrit le fichier d'un coup : fichier temporaire, puis renommage. Sous
/// unix (Android), lisible par l'application seule.
pub fn save(dir: &Path, stored: &Stored) -> Result<(), ApiError> {
    fs::create_dir_all(dir)
        .map_err(|err| storage(format!("dossier de données impossible : {err}")))?;
    let json = serde_json::to_vec(stored).map_err(|err| storage(err.to_string()))?;
    let tmp = dir.join(format!("{DEVICE_FILE}.tmp"));
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let write = || -> std::io::Result<()> {
        let mut file = options.open(&tmp)?;
        file.write_all(&json)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path(dir))
    };
    write().map_err(|err| {
        let _ = fs::remove_file(&tmp);
        storage(format!("fichier de l'appareil impossible à écrire : {err}"))
    })
}

/// Supprime le fichier ; absent, il n'y a rien à faire.
pub fn clear(dir: &Path) -> Result<(), ApiError> {
    match fs::remove_file(path(dir)) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(storage(format!(
            "fichier de l'appareil impossible à supprimer : {err}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CODE: &str = "abcdefghijklmnopqrst-_";

    fn link(u: &str, c: &str) -> String {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("u", u)
            .append_pair("c", c)
            .finish();
        format!("vigie://pair?{query}")
    }

    #[test]
    fn reads_a_link_built_like_the_veilleur() {
        let parsed = parse_link(&link("https://veilleur.example.org/", CODE), false).expect("lien");
        assert_eq!(
            parsed,
            Link {
                url: "https://veilleur.example.org".into(),
                code: CODE.into()
            }
        );
    }

    #[test]
    fn http_is_refused_except_loopback_in_debug() {
        let remote = link("http://veilleur.example.org", CODE);
        assert_eq!(
            parse_link(&remote, true).expect_err("http distant").kind,
            ErrorKind::InvalidLink
        );
        for host in ["127.0.0.1:8080", "[::1]:8080", "localhost:8080"] {
            let local = link(&format!("http://{host}"), CODE);
            assert!(parse_link(&local, true).is_ok(), "{host} en debug");
            assert!(parse_link(&local, false).is_err(), "{host} en release");
        }
    }

    #[test]
    fn refuses_malformed_links() {
        for bad in [
            "pas un lien".to_owned(),
            "https://pair?u=https%3A%2F%2Fexample.org&c=abcdefghijklmnopqrst-_".to_owned(),
            "vigie://autre?u=https%3A%2F%2Fexample.org&c=abcdefghijklmnopqrst-_".to_owned(),
            "vigie://pair?c=abcdefghijklmnopqrst-_".to_owned(),
            link("https://veilleur.example.org", "court"),
            link("https://veilleur.example.org", "abcdefghijklmnopqrst+/"),
            link("ftp://veilleur.example.org", CODE),
        ] {
            assert_eq!(
                parse_link(&bad, true).expect_err(&bad).kind,
                ErrorKind::InvalidLink,
                "{bad}"
            );
        }
    }

    #[test]
    fn saves_loads_and_clears_the_device_file() {
        let dir = tempfile::tempdir().expect("dossier");
        let data = dir.path().join("données");
        assert_eq!(load(&data).expect("absent"), None);
        let stored = Stored {
            url: "https://veilleur.example.org".into(),
            token: "jeton".into(),
            device_id: 3,
            name: "poste".into(),
        };
        save(&data, &stored).expect("écrit");
        assert_eq!(load(&data).expect("relu"), Some(stored.clone()));
        assert!(!format!("{stored:?}").contains("jeton"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(path(&data))
                .expect("meta")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        clear(&data).expect("supprimé");
        clear(&data).expect("déjà absent");
        assert_eq!(load(&data).expect("absent"), None);
    }
}
