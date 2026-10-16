//! Console Vigie : coquille Tauri. Les commandes d'appel au veilleur
//! s'enregistrent ici (phase 4) ; le webview ne fait aucune requête réseau.

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![])
        .run(tauri::generate_context!())
        .expect("échec du lancement de la console Vigie");
}
