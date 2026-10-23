//! Console Vigie : commandes Tauri d'appel au veilleur. Le webview ne fait
//! aucune requête réseau et ne voit jamais le jeton de l'appareil.

pub mod client;
pub mod pairing;
pub mod secret;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::{Manager, State};

use client::{
    ApiError, Client, ErrorKind, Incident, LogIps, Overview, Settings, SiteComponents, SiteDetail,
    SiteIncidents, SiteLogs, SiteVulns, VulnSources,
};
use secret::{SecretStore, TokenStorage};

/// Appareil appairé, chargé en mémoire.
struct Session {
    client: Client,
    stored: pairing::Stored,
    storage: TokenStorage,
}

/// État partagé des commandes.
pub struct Console {
    data_dir: PathBuf,
    secrets: Arc<dyn SecretStore>,
    session: Mutex<Option<Session>>,
}

/// Ce que le webview sait de l'appareil : jamais le jeton.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Status {
    pub device_id: i64,
    pub name: String,
    pub url: String,
    /// Où vit le jeton ; `file_legacy` est le seul état dégradé.
    pub token_storage: TokenStorage,
}

#[derive(Debug, Serialize)]
pub struct Unpaired {
    /// `false` : veilleur injoignable, l'appareil reste à révoquer en CLI.
    pub revoked: bool,
    pub device_id: i64,
}

impl Status {
    fn of(stored: &pairing::Stored, storage: TokenStorage) -> Self {
        Self {
            device_id: stored.device_id,
            name: stored.name.clone(),
            url: stored.url.clone(),
            token_storage: storage,
        }
    }
}

fn not_paired() -> ApiError {
    ApiError::new(ErrorKind::NotPaired, "cet appareil n'est pas appairé")
}

impl Console {
    /// Charge l'appareil enregistré, en migrant au besoin un `device.json`
    /// 0.1.1 (`pairing::open`). Un fichier illisible ou un jeton introuvable
    /// laissent la console non appairée, sans rien effacer.
    pub fn new(data_dir: PathBuf, secrets: Arc<dyn SecretStore>) -> Self {
        let session = match pairing::open(&data_dir, secrets.as_ref()) {
            Ok(Some(loaded)) => Client::new(&loaded.stored.url).ok().map(|client| Session {
                client: client.with_token(loaded.token),
                stored: loaded.stored,
                storage: loaded.storage,
            }),
            _ => None,
        };
        Self {
            data_dir,
            secrets,
            session: Mutex::new(session),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Session>> {
        // Un panic pendant que le verrou était tenu ne rend pas l'état faux :
        // il ne contient qu'un client et des identifiants.
        self.session.lock().unwrap_or_else(|err| err.into_inner())
    }

    pub fn status(&self) -> Option<Status> {
        self.lock()
            .as_ref()
            .map(|session| Status::of(&session.stored, session.storage))
    }

    /// Client de la session, cloné pour ne pas tenir le verrou pendant l'appel.
    fn client(&self) -> Result<Client, ApiError> {
        self.lock()
            .as_ref()
            .map(|session| session.client.clone())
            .ok_or_else(not_paired)
    }

    /// Efface le jeton du store **et** le fichier, même si l'un échoue.
    fn forget(&self) -> Result<(), ApiError> {
        *self.lock() = None;
        let secret = self.secrets.delete();
        let file = pairing::clear(&self.data_dir);
        file?;
        secret?;
        Ok(())
    }

    /// Range le jeton (écrit puis relu) et écrit `device.json`. En cas
    /// d'échec, rien ne reste sur l'appareil.
    fn keep(&self, stored: &pairing::Stored, token: &str) -> Result<(), ApiError> {
        secret::put(self.secrets.as_ref(), token)?;
        pairing::save(&self.data_dir, stored).inspect_err(|_| {
            let _ = self.secrets.delete();
        })
    }

    /// Appaire ce poste. Si le jeton reçu ne peut pas être rangé (trousseau
    /// interdit par stratégie de groupe, disque plein), il est révoqué
    /// aussitôt : aucun jeton valide ne reste orphelin.
    pub async fn pair(&self, link: &str, allow_loopback: bool) -> Result<Status, ApiError> {
        let link = pairing::parse_link(link, allow_loopback)?;
        let client = Client::new(&link.url)?;
        let paired = client.pair(&link.code).await?;
        let stored = pairing::Stored {
            url: link.url,
            device_id: paired.device_id,
            name: paired.name,
        };
        let client = client.with_token(paired.token.clone());
        if let Err(err) = self.keep(&stored, &paired.token) {
            let revoked = matches!(client.unpair().await, Ok(()));
            let message = if revoked {
                format!(
                    "{} : appairage annulé, le veilleur a révoqué le jeton émis",
                    err.message
                )
            } else {
                format!(
                    "{} : appairage annulé, mais le veilleur est injoignable ; sur le VPS : vigie device revoke {}",
                    err.message, stored.device_id
                )
            };
            return Err(ApiError::new(err.kind, message));
        }
        let status = Status::of(&stored, self.secrets.storage());
        *self.lock() = Some(Session {
            client,
            stored,
            storage: status.token_storage,
        });
        Ok(status)
    }

    /// Révoque l'appareil côté veilleur s'il répond, et efface toujours le
    /// jeton et le fichier locaux.
    pub async fn unpair(&self) -> Result<Unpaired, ApiError> {
        let (client, device_id) = {
            let session = self.lock();
            let session = session.as_ref().ok_or_else(not_paired)?;
            (session.client.clone(), session.stored.device_id)
        };
        let revoked = match client.unpair().await {
            Ok(()) => true,
            // Déjà révoqué côté veilleur : le résultat est le même.
            Err(err) if err.kind == ErrorKind::Unauthorized => true,
            Err(_) => false,
        };
        self.forget()?;
        Ok(Unpaired { revoked, device_id })
    }

    /// Un 401 signifie un jeton révoqué : l'appareil n'est plus appairé.
    pub async fn call<T, F>(&self, call: impl FnOnce(Client) -> F) -> Result<T, ApiError>
    where
        F: Future<Output = Result<T, ApiError>>,
    {
        let result = call(self.client()?).await;
        if let Err(err) = &result
            && err.kind == ErrorKind::Unauthorized
        {
            self.forget()?;
        }
        result
    }
}

#[tauri::command]
fn status(console: State<'_, Console>) -> Option<Status> {
    console.status()
}

#[tauri::command]
async fn pair(console: State<'_, Console>, link: String) -> Result<Status, ApiError> {
    console.pair(&link, cfg!(debug_assertions)).await
}

#[tauri::command]
async fn unpair(console: State<'_, Console>) -> Result<Unpaired, ApiError> {
    console.unpair().await
}

#[tauri::command]
async fn overview(console: State<'_, Console>) -> Result<Overview, ApiError> {
    console
        .call(|client| async move { client.overview().await })
        .await
}

#[tauri::command]
async fn site(console: State<'_, Console>, id: String) -> Result<SiteDetail, ApiError> {
    console
        .call(|client| async move { client.site(&id).await })
        .await
}

/// Une page des incidents clos ; `cursor` absent pour la première.
#[tauri::command]
async fn incidents(
    console: State<'_, Console>,
    site: String,
    cursor: Option<String>,
) -> Result<SiteIncidents, ApiError> {
    console
        .call(|client| async move { client.incidents(&site, cursor.as_deref()).await })
        .await
}

#[tauri::command]
async fn logs(console: State<'_, Console>, site: String) -> Result<SiteLogs, ApiError> {
    console
        .call(|client| async move { client.logs(&site).await })
        .await
}

/// Une page des verdicts d'IP ; `cursor` absent pour la première.
#[tauri::command]
async fn log_ips(
    console: State<'_, Console>,
    site: String,
    cursor: Option<String>,
) -> Result<LogIps, ApiError> {
    console
        .call(|client| async move { client.log_ips(&site, cursor.as_deref()).await })
        .await
}

/// Une page des composants d'un site ; `cursor` absent pour la première.
#[tauri::command]
async fn components(
    console: State<'_, Console>,
    site: String,
    cursor: Option<String>,
) -> Result<SiteComponents, ApiError> {
    console
        .call(|client| async move { client.components(&site, cursor.as_deref()).await })
        .await
}

/// Une page des failles d'un site ; `cursor` absent pour la première.
#[tauri::command]
async fn vulns(
    console: State<'_, Console>,
    site: String,
    cursor: Option<String>,
) -> Result<SiteVulns, ApiError> {
    console
        .call(|client| async move { client.vulns(&site, cursor.as_deref()).await })
        .await
}

#[tauri::command]
async fn vuln_sources(console: State<'_, Console>) -> Result<VulnSources, ApiError> {
    console
        .call(|client| async move { client.vuln_sources().await })
        .await
}

#[tauri::command]
async fn incident(console: State<'_, Console>, id: i64) -> Result<Incident, ApiError> {
    console
        .call(|client| async move { client.incident(id).await })
        .await
}

#[tauri::command]
async fn snooze(
    console: State<'_, Console>,
    id: i64,
    duration: client::Snooze,
) -> Result<Incident, ApiError> {
    console
        .call(|client| async move { client.snooze(id, duration).await })
        .await
}

#[tauri::command]
async fn ack(console: State<'_, Console>, id: i64) -> Result<Incident, ApiError> {
    console
        .call(|client| async move { client.ack(id).await })
        .await
}

#[tauri::command]
async fn settings(console: State<'_, Console>) -> Result<Settings, ApiError> {
    console
        .call(|client| async move { client.settings().await })
        .await
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default();
    #[cfg(mobile)]
    let builder = builder.plugin(tauri_plugin_barcode_scanner::init());
    builder
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            let secrets = secret::platform(&data_dir);
            app.manage(Console::new(data_dir, secrets));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            status,
            pair,
            unpair,
            overview,
            site,
            incidents,
            logs,
            log_ips,
            components,
            vulns,
            vuln_sources,
            incident,
            ack,
            snooze,
            settings
        ])
        .run(tauri::generate_context!())
        .expect("échec du lancement de la console Vigie");
}

#[cfg(test)]
mod tests {
    use super::*;
    use secret::MemoryStore;

    const TOKEN: &str = "jeton-fictif-0123456789abcdef";

    fn stored() -> pairing::Stored {
        pairing::Stored {
            url: "https://vigie.example.org".into(),
            device_id: 3,
            name: "poste de test".into(),
        }
    }

    #[test]
    fn status_never_carries_the_token() {
        let json = serde_json::to_string(&Status::of(&stored(), TokenStorage::Keyring)).unwrap();
        assert!(!json.contains(TOKEN), "{json}");
        assert_eq!(
            json,
            r#"{"device_id":3,"name":"poste de test","url":"https://vigie.example.org","token_storage":"keyring"}"#
        );
    }

    /// Console appairée sur `secrets`, dans un dossier temporaire.
    fn paired(secrets: Arc<MemoryStore>) -> (tempfile::TempDir, Console) {
        let dir = tempfile::tempdir().expect("dossier");
        pairing::save(dir.path(), &stored()).expect("écrit");
        secret::put(secrets.as_ref(), TOKEN).expect("rangé");
        let console = Console::new(dir.path().to_path_buf(), secrets);
        (dir, console)
    }

    #[test]
    fn loads_the_device_and_its_token_storage() {
        let secrets = Arc::new(MemoryStore::new());
        let (_dir, console) = paired(secrets);
        let status = console.status().expect("appairé");
        assert_eq!(status.device_id, 3);
        assert_eq!(status.token_storage, TokenStorage::Keyring);
    }

    #[test]
    fn a_missing_token_leaves_the_console_unpaired_without_erasing() {
        let dir = tempfile::tempdir().expect("dossier");
        pairing::save(dir.path(), &stored()).expect("écrit");
        let console = Console::new(dir.path().to_path_buf(), Arc::new(MemoryStore::new()));
        assert_eq!(console.status(), None);
        assert!(dir.path().join("device.json").exists());
    }

    #[test]
    fn forget_erases_both_sides_even_if_one_fails() {
        let secrets = Arc::new(MemoryStore::new());
        let (dir, console) = paired(Arc::clone(&secrets));
        secrets
            .fail_delete
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let err = console.forget().expect_err("entrée du store gardée");
        assert_eq!(err.kind, ErrorKind::Storage);
        assert!(!err.message.contains(TOKEN));
        assert!(!dir.path().join("device.json").exists(), "fichier effacé");
        assert_eq!(console.status(), None);
        secrets
            .fail_delete
            .store(false, std::sync::atomic::Ordering::SeqCst);
        console.forget().expect("effacé");
        assert_eq!(secrets.secret(), None);
    }

    /// Commandes exposées au webview : en ajouter une passe par ce test.
    #[test]
    fn the_command_list_is_frozen() {
        let source = include_str!("lib.rs");
        let start = source
            .find("generate_handler![")
            .expect("generate_handler!")
            + 18;
        let end = start + source[start..].find(']').expect("fin");
        let commands: Vec<&str> = source[start..end]
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .collect();
        assert_eq!(
            commands,
            [
                "status",
                "pair",
                "unpair",
                "overview",
                "site",
                "incidents",
                "logs",
                "log_ips",
                "components",
                "vulns",
                "vuln_sources",
                "incident",
                "ack",
                "snooze",
                "settings"
            ]
        );
        let code = &source[..source.find("#[cfg(test)]").expect("tests")];
        assert_eq!(code.matches("#[tauri::command]").count(), commands.len());
    }

    /// La console lit ; ses seules écritures sont l'acquittement et la
    /// sourdine (décision de #35). Hors `pair` et `unpair`, toute autre
    /// requête de `client.rs` est un GET.
    #[test]
    fn ack_and_snooze_are_the_only_writes_besides_pairing() {
        let source = include_str!("client.rs");
        let code = &source[..source.find("#[cfg(test)]").expect("tests")];
        let mut writes = Vec::new();
        let mut function = "";
        for line in code.lines() {
            if let Some(rest) = line.trim().strip_prefix("pub async fn ") {
                function = rest.split('(').next().unwrap_or_default();
            }
            for method in ["POST", "PUT", "PATCH", "DELETE"] {
                if line.contains(&format!("Method::{method}")) {
                    writes.push(format!("{function} {method}"));
                }
            }
            for raw in [".post(", ".put(", ".patch(", ".delete("] {
                assert!(!line.contains(raw), "requête hors de send : {line}");
            }
        }
        assert_eq!(
            writes,
            ["pair POST", "ack POST", "snooze POST", "unpair DELETE"]
        );
    }
}
