//! Rangement du jeton de l'appareil, hors de `device.json`.
//!
//! - Windows : Credential Manager, par `windows-native-keyring-store`, store
//!   construit ici (aucun store global par défaut), persistance `Local`
//!   (jamais `Enterprise`, qui suit le profil itinérant vers d'autres
//!   postes), cible fixe `vigie-console/device`. Jamais la façade `keyring`,
//!   qui se rabat en silence sur un stockage en mémoire.
//! - Ailleurs (Android) : fichier privé de l'application (0600) dans son
//!   dossier `no_backup`, exclu de la sauvegarde et du transfert d'appareil.
//! - Tests : mémoire, avec échecs provoqués.
//!
//! Les erreurs portent des messages fixes : une erreur du trousseau peut
//! contenir les octets du secret (`BadEncoding`), elle n'est jamais citée.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;

use crate::client::{ApiError, ErrorKind};

/// Dossier exclu de la sauvegarde sous Android : `Context.getNoBackupFilesDir()`
/// vaut `<dataDir>/no_backup`, et `app_data_dir` de Tauri y vaut `dataDir`.
pub const NO_BACKUP_DIR: &str = "no_backup";
/// Fichier du jeton, dans `NO_BACKUP_DIR`.
pub const TOKEN_FILE: &str = "device-token";

/// Où vit le jeton ; affiché dans Réglages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenStorage {
    /// Credential Manager de Windows.
    Keyring,
    /// Encore dans `device.json` : la migration a échoué, elle est retentée
    /// à chaque lancement. Seul état dégradé.
    FileLegacy,
    /// Fichier privé de l'application, hors sauvegarde (Android).
    PrivateFile,
}

/// Échec du rangement du jeton. Ne porte aucune donnée : seulement un
/// message fixe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretError {
    /// Trousseau inaccessible (verrouillé, interdit par stratégie de groupe).
    Unavailable,
    Read,
    Write,
    /// Relu différent de ce qui a été écrit.
    Mismatch,
    Delete,
}

impl SecretError {
    pub fn message(self) -> &'static str {
        match self {
            Self::Unavailable => "trousseau du système inaccessible",
            Self::Read => "jeton de l'appareil illisible",
            Self::Write => "jeton de l'appareil impossible à enregistrer",
            Self::Mismatch => "jeton de l'appareil relu différent de celui enregistré",
            Self::Delete => "jeton de l'appareil impossible à supprimer",
        }
    }
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for SecretError {}

impl From<SecretError> for ApiError {
    fn from(err: SecretError) -> Self {
        ApiError::new(ErrorKind::Storage, err.message())
    }
}

/// Emplacement du jeton d'un appareil.
pub trait SecretStore: Send + Sync {
    /// `None` : aucun jeton rangé.
    fn read(&self) -> Result<Option<String>, SecretError>;
    fn write(&self, token: &str) -> Result<(), SecretError>;
    /// Absent, il n'y a rien à faire.
    fn delete(&self) -> Result<(), SecretError>;
    /// Ce que `Status.token_storage` affiche quand ce store tient le jeton.
    fn storage(&self) -> TokenStorage;
}

/// Écrit le jeton puis le relit : il n'est tenu pour rangé que relu à
/// l'identique.
pub fn put(store: &dyn SecretStore, token: &str) -> Result<(), SecretError> {
    store.write(token)?;
    match store.read()? {
        Some(read) if read == token => Ok(()),
        _ => Err(SecretError::Mismatch),
    }
}

/// Store de la plateforme : Credential Manager sous Windows, fichier privé
/// hors sauvegarde ailleurs.
pub fn platform(data_dir: &Path) -> Arc<dyn SecretStore> {
    #[cfg(windows)]
    {
        let _ = data_dir;
        Arc::new(windows::WindowsStore::new())
    }
    #[cfg(not(windows))]
    {
        Arc::new(FileStore::new(token_path(data_dir)))
    }
}

/// `<app_data_dir>/no_backup/device-token`.
pub fn token_path(data_dir: &Path) -> PathBuf {
    data_dir.join(NO_BACKUP_DIR).join(TOKEN_FILE)
}

/// Écrit `bytes` d'un coup : fichier temporaire, puis renommage. Sous unix
/// (Android), dossier et fichier lisibles par l'application seule.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("chemin sans dossier"))?;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)?;
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    let tmp = dir.join(name);
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let write = || -> std::io::Result<()> {
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)
    };
    write().inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })
}

/// Jeton dans un fichier privé de l'application.
#[derive(Debug)]
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl SecretStore for FileStore {
    fn read(&self) -> Result<Option<String>, SecretError> {
        match fs::read(&self.path) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(token) if token.is_empty() => Ok(None),
                Ok(token) => Ok(Some(token)),
                Err(_) => Err(SecretError::Read),
            },
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(SecretError::Read),
        }
    }

    fn write(&self, token: &str) -> Result<(), SecretError> {
        write_private(&self.path, token.as_bytes()).map_err(|_| SecretError::Write)
    }

    fn delete(&self) -> Result<(), SecretError> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(SecretError::Delete),
        }
    }

    fn storage(&self) -> TokenStorage {
        TokenStorage::PrivateFile
    }
}

/// Jeton en mémoire, pour les tests : chaque opération peut être mise en
/// échec, et la relecture faussée.
#[derive(Debug, Default)]
pub struct MemoryStore {
    secret: Mutex<Option<String>>,
    pub fail_read: AtomicBool,
    pub fail_write: AtomicBool,
    pub fail_delete: AtomicBool,
    /// La relecture rend autre chose que ce qui a été écrit.
    pub alter_readback: AtomicBool,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store qui tient déjà `token`.
    pub fn holding(token: &str) -> Self {
        let store = Self::new();
        *store.lock() = Some(token.to_owned());
        store
    }

    pub fn failing_write() -> Self {
        let store = Self::new();
        store.fail_write.store(true, Ordering::SeqCst);
        store
    }

    pub fn altered_readback() -> Self {
        let store = Self::new();
        store.alter_readback.store(true, Ordering::SeqCst);
        store
    }

    /// Ce que le store tient vraiment, relecture faussée ou non.
    pub fn secret(&self) -> Option<String> {
        self.lock().clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<String>> {
        self.secret.lock().unwrap_or_else(|err| err.into_inner())
    }
}

impl SecretStore for MemoryStore {
    fn read(&self) -> Result<Option<String>, SecretError> {
        if self.fail_read.load(Ordering::SeqCst) {
            return Err(SecretError::Read);
        }
        let secret = self.lock().clone();
        if self.alter_readback.load(Ordering::SeqCst) {
            return Ok(secret.map(|token| format!("{token}-altéré")));
        }
        Ok(secret)
    }

    fn write(&self, token: &str) -> Result<(), SecretError> {
        if self.fail_write.load(Ordering::SeqCst) {
            return Err(SecretError::Write);
        }
        *self.lock() = Some(token.to_owned());
        Ok(())
    }

    fn delete(&self) -> Result<(), SecretError> {
        if self.fail_delete.load(Ordering::SeqCst) {
            return Err(SecretError::Delete);
        }
        *self.lock() = None;
        Ok(())
    }

    fn storage(&self) -> TokenStorage {
        TokenStorage::Keyring
    }
}

#[cfg(windows)]
pub mod windows {
    //! Credential Manager de Windows.

    use std::collections::HashMap;

    use keyring_core::api::CredentialStoreApi;
    use keyring_core::{Entry, Error};
    use windows_native_keyring_store::Store;

    use super::{SecretError, SecretStore, TokenStorage};

    const SERVICE: &str = "vigie-console";
    const USER: &str = "device";
    /// Nom de l'identifiant dans le Credential Manager.
    pub const TARGET: &str = "vigie-console/device";
    /// Persistance de l'identifiant : ce poste seulement.
    pub const PERSISTENCE: &str = "Local";

    /// Identifiant générique du Credential Manager. `entry` vaut `None` si
    /// le store n'a pas pu être construit : chaque opération échoue alors.
    pub struct WindowsStore {
        entry: Option<Entry>,
    }

    impl WindowsStore {
        pub fn new() -> Self {
            Self::with_target(TARGET)
        }

        /// Cible donnée : les tests en prennent une à eux.
        pub fn with_target(target: &str) -> Self {
            let modifiers = HashMap::from([("target", target), ("persistence", PERSISTENCE)]);
            let entry = Store::new()
                .and_then(|store| store.build(SERVICE, USER, Some(&modifiers)))
                .ok();
            Self { entry }
        }

        fn entry(&self) -> Result<&Entry, SecretError> {
            self.entry.as_ref().ok_or(SecretError::Unavailable)
        }

        /// Persistance relue de l'identifiant (`Local` attendu).
        pub fn persistence(&self) -> Result<String, SecretError> {
            self.entry()?
                .get_attributes()
                .ok()
                .and_then(|attributes| attributes.get("persistence").cloned())
                .ok_or(SecretError::Read)
        }
    }

    impl Default for WindowsStore {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Jamais `{err}` : `BadEncoding` porte les octets du secret.
    fn fixed(err: &Error, otherwise: SecretError) -> SecretError {
        match err {
            Error::NoStorageAccess(_) => SecretError::Unavailable,
            _ => otherwise,
        }
    }

    impl SecretStore for WindowsStore {
        fn read(&self) -> Result<Option<String>, SecretError> {
            match self.entry()?.get_password() {
                Ok(token) => Ok(Some(token)),
                Err(Error::NoEntry) => Ok(None),
                Err(err) => Err(fixed(&err, SecretError::Read)),
            }
        }

        fn write(&self, token: &str) -> Result<(), SecretError> {
            self.entry()?
                .set_password(token)
                .map_err(|err| fixed(&err, SecretError::Write))
        }

        fn delete(&self) -> Result<(), SecretError> {
            match self.entry()?.delete_credential() {
                Ok(()) | Err(Error::NoEntry) => Ok(()),
                Err(err) => Err(fixed(&err, SecretError::Delete)),
            }
        }

        fn storage(&self) -> TokenStorage {
            TokenStorage::Keyring
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "jeton-fictif-0123456789abcdef";

    #[test]
    fn the_token_file_lives_in_no_backup() {
        let data = Path::new("/data/user/0/org.example.vigie");
        assert_eq!(
            token_path(data),
            Path::new("/data/user/0/org.example.vigie/no_backup/device-token")
        );
    }

    #[test]
    fn the_private_file_round_trips_and_stays_private() {
        let dir = tempfile::tempdir().expect("dossier");
        let store = FileStore::new(token_path(dir.path()));
        assert_eq!(store.read(), Ok(None));
        put(&store, TOKEN).expect("rangé");
        assert_eq!(store.read(), Ok(Some(TOKEN.into())));
        assert_eq!(store.storage(), TokenStorage::PrivateFile);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |path: &Path| fs::metadata(path).expect("meta").permissions().mode() & 0o777;
            assert_eq!(mode(store.path()), 0o600);
            assert_eq!(mode(&dir.path().join(NO_BACKUP_DIR)), 0o700);
        }
        store.delete().expect("supprimé");
        store.delete().expect("déjà absent");
        assert_eq!(store.read(), Ok(None));
    }

    #[test]
    fn put_refuses_a_different_readback() {
        let store = MemoryStore::altered_readback();
        assert_eq!(put(&store, TOKEN), Err(SecretError::Mismatch));
        let store = MemoryStore::failing_write();
        assert_eq!(put(&store, TOKEN), Err(SecretError::Write));
        assert_eq!(store.secret(), None);
    }

    #[test]
    fn errors_never_carry_the_token() {
        for err in [
            SecretError::Unavailable,
            SecretError::Read,
            SecretError::Write,
            SecretError::Mismatch,
            SecretError::Delete,
        ] {
            let api = ApiError::from(err);
            assert_eq!(api.kind, ErrorKind::Storage);
            assert!(!api.message.contains(TOKEN), "{api:?}");
        }
    }

    #[test]
    fn storage_serializes_in_snake_case() {
        let json = serde_json::to_string(&[
            TokenStorage::Keyring,
            TokenStorage::FileLegacy,
            TokenStorage::PrivateFile,
        ])
        .expect("json");
        assert_eq!(json, r#"["keyring","file_legacy","private_file"]"#);
    }

    /// Aller-retour réel dans le Credential Manager, sur une cible propre à
    /// cette exécution, effacée par `Drop` même si le test échoue.
    #[cfg(windows)]
    #[test]
    fn windows_credential_manager_round_trip() {
        use windows::WindowsStore;

        struct Cleanup(WindowsStore);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = self.0.delete();
            }
        }

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("horloge")
            .as_nanos();
        let target = format!("vigie-console-test/{}-{nanos}", std::process::id());
        let store = Cleanup(WindowsStore::with_target(&target));
        assert_eq!(store.0.read(), Ok(None));
        put(&store.0, TOKEN).expect("rangé dans le Credential Manager");
        assert_eq!(store.0.persistence().as_deref(), Ok("Local"));
        assert_eq!(store.0.storage(), TokenStorage::Keyring);
        store.0.delete().expect("supprimé");
        assert_eq!(store.0.read(), Ok(None));
        store.0.delete().expect("déjà absent");
    }
}
