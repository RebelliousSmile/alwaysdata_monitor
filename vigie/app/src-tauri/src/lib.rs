//! Console Vigie : commandes Tauri d'appel au veilleur. Le webview ne fait
//! aucune requête réseau et ne voit jamais le jeton de l'appareil.

pub mod client;
pub mod pairing;

use std::path::PathBuf;
use std::sync::Mutex;

use serde::Serialize;
use tauri::{Manager, State};

use client::{
    ApiError, Client, ErrorKind, Incident, Overview, Settings, SiteDetail, SiteIncidents,
};

/// Appareil appairé, chargé en mémoire.
struct Session {
    client: Client,
    stored: pairing::Stored,
}

/// État partagé des commandes.
struct Console {
    data_dir: PathBuf,
    session: Mutex<Option<Session>>,
}

/// Ce que le webview sait de l'appareil : jamais le jeton.
#[derive(Debug, Serialize)]
struct Status {
    device_id: i64,
    name: String,
    url: String,
}

#[derive(Debug, Serialize)]
struct Unpaired {
    /// `false` : veilleur injoignable, l'appareil reste à révoquer en CLI.
    revoked: bool,
    device_id: i64,
}

impl Status {
    fn of(stored: &pairing::Stored) -> Self {
        Self {
            device_id: stored.device_id,
            name: stored.name.clone(),
            url: stored.url.clone(),
        }
    }
}

impl Console {
    fn new(data_dir: PathBuf) -> Self {
        let session = match pairing::load(&data_dir) {
            Ok(Some(stored)) => Client::new(&stored.url).ok().map(|client| Session {
                client: client.with_token(stored.token.clone()),
                stored,
            }),
            _ => None,
        };
        Self {
            data_dir,
            session: Mutex::new(session),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Session>> {
        // Un panic pendant que le verrou était tenu ne rend pas l'état faux :
        // il ne contient qu'un client et des identifiants.
        self.session.lock().unwrap_or_else(|err| err.into_inner())
    }

    /// Client de la session, cloné pour ne pas tenir le verrou pendant l'appel.
    fn client(&self) -> Result<Client, ApiError> {
        self.lock()
            .as_ref()
            .map(|session| session.client.clone())
            .ok_or_else(|| ApiError::new(ErrorKind::NotPaired, "cet appareil n'est pas appairé"))
    }

    fn forget(&self) -> Result<(), ApiError> {
        *self.lock() = None;
        pairing::clear(&self.data_dir)
    }

    /// Un 401 signifie un jeton révoqué : l'appareil n'est plus appairé.
    async fn call<T, F>(&self, call: impl FnOnce(Client) -> F) -> Result<T, ApiError>
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
    console
        .lock()
        .as_ref()
        .map(|session| Status::of(&session.stored))
}

#[tauri::command]
async fn pair(console: State<'_, Console>, link: String) -> Result<Status, ApiError> {
    let link = pairing::parse_link(&link, cfg!(debug_assertions))?;
    let client = Client::new(&link.url)?;
    let paired = client.pair(&link.code).await?;
    let stored = pairing::Stored {
        url: link.url,
        token: paired.token,
        device_id: paired.device_id,
        name: paired.name,
    };
    pairing::save(&console.data_dir, &stored)?;
    let status = Status::of(&stored);
    *console.lock() = Some(Session {
        client: client.with_token(stored.token.clone()),
        stored,
    });
    Ok(status)
}

/// Révoque l'appareil côté veilleur s'il répond, et efface toujours le
/// fichier local.
#[tauri::command]
async fn unpair(console: State<'_, Console>) -> Result<Unpaired, ApiError> {
    let (client, device_id) = {
        let session = console.lock();
        let session = session
            .as_ref()
            .ok_or_else(|| ApiError::new(ErrorKind::NotPaired, "cet appareil n'est pas appairé"))?;
        (session.client.clone(), session.stored.device_id)
    };
    let revoked = match client.unpair().await {
        Ok(()) => true,
        // Déjà révoqué côté veilleur : le résultat est le même.
        Err(err) if err.kind == ErrorKind::Unauthorized => true,
        Err(_) => false,
    };
    console.forget()?;
    Ok(Unpaired { revoked, device_id })
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

#[tauri::command]
async fn incidents(console: State<'_, Console>, site: String) -> Result<SiteIncidents, ApiError> {
    console
        .call(|client| async move { client.incidents(&site).await })
        .await
}

#[tauri::command]
async fn incident(console: State<'_, Console>, id: i64) -> Result<Incident, ApiError> {
    console
        .call(|client| async move { client.incident(id).await })
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
            app.manage(Console::new(data_dir));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            status, pair, unpair, overview, site, incidents, incident, ack, settings
        ])
        .run(tauri::generate_context!())
        .expect("échec du lancement de la console Vigie");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_never_carries_the_token() {
        let stored = pairing::Stored {
            url: "https://vigie.example.org".into(),
            token: "jeton-fictif-0123456789abcdef".into(),
            device_id: 3,
            name: "poste de test".into(),
        };
        let json = serde_json::to_string(&Status::of(&stored)).unwrap();
        assert!(!json.contains(&stored.token), "{json}");
        assert_eq!(
            json,
            r#"{"device_id":3,"name":"poste de test","url":"https://vigie.example.org"}"#
        );
    }
}
