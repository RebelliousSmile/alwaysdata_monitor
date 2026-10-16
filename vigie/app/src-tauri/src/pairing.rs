//! Appairage : lecture du lien `vigie://pair?u=…&c=…` et fichier de
//! l'appareil (`device.json`) dans `app_data_dir`. Le jeton vit à part, dans
//! le `SecretStore` de la plateforme, et dans la mémoire du processus ; il
//! n'est jamais renvoyé au webview.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use url::{Host, Url};

use crate::client::{ApiError, ErrorKind};
use crate::secret::{self, SecretStore, TokenStorage};

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

/// Contenu de `device.json`. Le jeton n'y est plus : il vit dans le
/// `SecretStore` de la plateforme (`secret.rs`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stored {
    pub url: String,
    pub device_id: i64,
    pub name: String,
}

/// `device.json` tel qu'on le lit : la 0.1.1 y écrivait aussi le jeton.
/// Un fichier qui le porte encore est migré par `open`.
#[derive(Deserialize)]
struct OnDisk {
    url: String,
    #[serde(default)]
    token: Option<String>,
    device_id: i64,
    name: String,
}

/// Appareil chargé au démarrage. Le jeton ne quitte pas le processus.
pub struct Loaded {
    pub stored: Stored,
    pub token: String,
    pub storage: TokenStorage,
}

impl std::fmt::Debug for Loaded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Loaded")
            .field("stored", &self.stored)
            .field("storage", &self.storage)
            .finish_non_exhaustive()
    }
}

fn storage(message: String) -> ApiError {
    ApiError::new(ErrorKind::Storage, message)
}

fn path(dir: &Path) -> PathBuf {
    dir.join(DEVICE_FILE)
}

/// Lit `device.json`, ou `None` s'il est absent (`NotFound` seulement).
/// Message fixe sur un fichier illisible : une erreur de lecture JSON peut
/// citer la valeur fautive, et l'ancien format porte le jeton.
fn read(dir: &Path) -> Result<Option<OnDisk>, ApiError> {
    match fs::read(path(dir)) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| storage("fichier de l'appareil illisible".into())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(storage(format!(
            "fichier de l'appareil inaccessible : {err}"
        ))),
    }
}

/// Appareil enregistré, ou `None` si ce poste n'est pas appairé.
///
/// - `device.json` absent : une entrée restée dans le store (fichier effacé
///   à la main, appairage interrompu) est effacée. Jamais si le fichier est
///   seulement illisible.
/// - `device.json` 0.1.1, jeton compris : le jeton du fichier fait foi. Il
///   est rangé dans le store et relu, puis le fichier est réécrit sans lui.
///   Rejouable : un échec à n'importe quelle étape laisse le fichier
///   d'origine, et le jeton sert depuis le fichier (`file_legacy`) jusqu'au
///   lancement suivant, qui réessaie.
/// - Sinon le jeton est lu dans le store.
pub fn open(dir: &Path, secrets: &dyn SecretStore) -> Result<Option<Loaded>, ApiError> {
    let Some(disk) = read(dir)? else {
        // Rien à rendre à l'appelant : un échec laisse une entrée inerte.
        let _ = secrets.delete();
        return Ok(None);
    };
    let stored = Stored {
        url: disk.url,
        device_id: disk.device_id,
        name: disk.name,
    };
    match disk.token.filter(|token| !token.is_empty()) {
        Some(token) => {
            let storage = match migrate(dir, secrets, &stored, &token) {
                Ok(()) => secrets.storage(),
                Err(_) => TokenStorage::FileLegacy,
            };
            Ok(Some(Loaded {
                stored,
                token,
                storage,
            }))
        }
        None => {
            let token = secrets.read()?.ok_or_else(|| {
                storage("jeton de l'appareil introuvable : appairer de nouveau".into())
            })?;
            Ok(Some(Loaded {
                stored,
                token,
                storage: secrets.storage(),
            }))
        }
    }
}

/// Jeton du fichier vers le store, relu, puis fichier réécrit sans jeton.
fn migrate(
    dir: &Path,
    secrets: &dyn SecretStore,
    stored: &Stored,
    token: &str,
) -> Result<(), ApiError> {
    secret::put(secrets, token)?;
    save(dir, stored)
}

/// Écrit le fichier d'un coup (temporaire puis renommage), sans le jeton.
/// Sous unix (Android), lisible par l'application seule.
pub fn save(dir: &Path, stored: &Stored) -> Result<(), ApiError> {
    let json = serde_json::to_vec(stored).map_err(|err| storage(err.to_string()))?;
    secret::write_private(&path(dir), &json)
        .map_err(|err| storage(format!("fichier de l'appareil impossible à écrire : {err}")))
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
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::secret::MemoryStore;

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

    const TOKEN: &str = "jeton-fictif-0123456789abcdef";

    fn stored() -> Stored {
        Stored {
            url: "https://veilleur.example.org".into(),
            device_id: 3,
            name: "poste".into(),
        }
    }

    /// `device.json` tel que l'écrivait la 0.1.1.
    fn write_legacy(dir: &Path) {
        fs::create_dir_all(dir).expect("dossier");
        let json = serde_json::json!({
            "url": "https://veilleur.example.org",
            "token": TOKEN,
            "device_id": 3,
            "name": "poste",
        });
        fs::write(path(dir), serde_json::to_vec(&json).expect("json")).expect("écrit");
    }

    fn file_text(dir: &Path) -> String {
        fs::read_to_string(path(dir)).expect("relu")
    }

    #[test]
    fn saves_opens_and_clears_the_device_file_without_the_token() {
        let dir = tempfile::tempdir().expect("dossier");
        let data = dir.path().join("données");
        let secrets = MemoryStore::new();
        assert!(open(&data, &secrets).expect("absent").is_none());
        save(&data, &stored()).expect("écrit");
        secret::put(&secrets, TOKEN).expect("rangé");
        assert!(!file_text(&data).contains(TOKEN));
        let loaded = open(&data, &secrets).expect("relu").expect("appairé");
        assert_eq!(loaded.stored, stored());
        assert_eq!(loaded.token, TOKEN);
        assert_eq!(loaded.storage, TokenStorage::Keyring);
        assert!(!format!("{loaded:?}").contains(TOKEN));
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
        assert!(open(&data, &MemoryStore::new()).expect("absent").is_none());
    }

    #[test]
    fn migrates_a_legacy_device_file_into_the_store() {
        let dir = tempfile::tempdir().expect("dossier");
        write_legacy(dir.path());
        let secrets = MemoryStore::holding("ancien-jeton-du-trousseau");
        let loaded = open(dir.path(), &secrets).expect("lu").expect("appairé");
        assert_eq!(loaded.token, TOKEN, "le jeton du fichier fait foi");
        assert_eq!(loaded.storage, TokenStorage::Keyring);
        assert_eq!(secrets.secret().as_deref(), Some(TOKEN));
        let text = file_text(dir.path());
        assert!(!text.contains(TOKEN), "{text}");
        assert!(!text.contains("token"), "{text}");
        // Rejouée sur le fichier migré : rien ne change.
        let again = open(dir.path(), &secrets).expect("lu").expect("appairé");
        assert_eq!(again.token, TOKEN);
        assert_eq!(again.stored, stored());
    }

    /// Android : même migration, vers le fichier de `no_backup`.
    #[test]
    fn migrates_a_legacy_device_file_into_no_backup() {
        let dir = tempfile::tempdir().expect("dossier");
        write_legacy(dir.path());
        let secrets = secret::FileStore::new(secret::token_path(dir.path()));
        let loaded = open(dir.path(), &secrets).expect("lu").expect("appairé");
        assert_eq!(loaded.token, TOKEN);
        assert_eq!(loaded.storage, TokenStorage::PrivateFile);
        let moved = dir.path().join("no_backup").join("device-token");
        assert_eq!(fs::read_to_string(moved).expect("jeton"), TOKEN);
        assert!(!file_text(dir.path()).contains(TOKEN));
    }

    #[test]
    fn a_failed_migration_keeps_the_device_paired_from_the_file() {
        for secrets in [
            MemoryStore::failing_write(),
            MemoryStore::altered_readback(),
        ] {
            let dir = tempfile::tempdir().expect("dossier");
            write_legacy(dir.path());
            let loaded = open(dir.path(), &secrets).expect("lu").expect("appairé");
            assert_eq!(loaded.token, TOKEN);
            assert_eq!(loaded.storage, TokenStorage::FileLegacy);
            assert!(file_text(dir.path()).contains(TOKEN), "fichier intact");
            // Le lancement suivant réessaie, et réussit si le store le permet.
            secrets.fail_write.store(false, Ordering::SeqCst);
            secrets.alter_readback.store(false, Ordering::SeqCst);
            let loaded = open(dir.path(), &secrets).expect("lu").expect("appairé");
            assert_eq!(loaded.storage, TokenStorage::Keyring);
            assert!(!file_text(dir.path()).contains(TOKEN));
        }
    }

    #[test]
    fn an_orphan_entry_is_erased_only_when_the_file_is_missing() {
        let dir = tempfile::tempdir().expect("dossier");
        let secrets = MemoryStore::holding(TOKEN);
        fs::write(path(dir.path()), b"{pas du json").expect("écrit");
        let err = open(dir.path(), &secrets).expect_err("illisible");
        assert_eq!(err.kind, ErrorKind::Storage);
        assert_eq!(
            secrets.secret().as_deref(),
            Some(TOKEN),
            "fichier illisible : entrée gardée"
        );
        fs::remove_file(path(dir.path())).expect("supprimé");
        assert!(open(dir.path(), &secrets).expect("absent").is_none());
        assert_eq!(secrets.secret(), None, "fichier absent : entrée effacée");
    }

    #[test]
    fn errors_never_carry_the_token() {
        let dir = tempfile::tempdir().expect("dossier");
        // Jeton présent mais champ suivant du mauvais type : serde citerait
        // les valeurs.
        let json = format!(
            r#"{{"url":"https://veilleur.example.org","token":"{TOKEN}","device_id":"{TOKEN}","name":"poste"}}"#
        );
        fs::write(path(dir.path()), json).expect("écrit");
        let err = open(dir.path(), &MemoryStore::new()).expect_err("illisible");
        assert!(!err.message.contains(TOKEN), "{err:?}");
        // Jeton absent du fichier comme du store.
        save(dir.path(), &stored()).expect("écrit");
        let secrets = MemoryStore::new();
        let err = open(dir.path(), &secrets).expect_err("introuvable");
        assert_eq!(err.kind, ErrorKind::Storage);
        secrets.fail_read.store(true, Ordering::SeqCst);
        let err = open(dir.path(), &secrets).expect_err("illisible");
        assert!(!err.message.contains(TOKEN), "{err:?}");
    }
}
