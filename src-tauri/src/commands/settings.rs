use std::sync::Arc;
use std::collections::HashMap;
use crate::app_state::AppState;
use crate::security::crypto;

const PROVIDERS: &[&str] = &["virustotal", "metadefender", "hybridanalysis", "cloudmersive"];

/// Salva le API key nel keyring di sistema
#[tauri::command]
pub async fn save_api_keys(
    keys:  HashMap<String, String>,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<(), String> {
    for (id, key) in &keys {
        if !key.is_empty() {
            crypto::store_key(id, key).map_err(|e: anyhow::Error| e.to_string())?;
        }
    }
    // Aggiorna anche i mutex in memoria
    let set = |mtx: &std::sync::Arc<std::sync::Mutex<String>>, id: &str| {
        if let Some(k) = keys.get(id) {
            *mtx.lock().unwrap() = k.clone();
        }
    };
    set(&state.keys.vt, "virustotal");
    set(&state.keys.md, "metadefender");
    set(&state.keys.ha, "hybridanalysis");
    set(&state.keys.cm, "cloudmersive");
    Ok(())
}

/// Carica le API key (mascherate) per mostrarle nella UI
#[tauri::command]
pub async fn load_api_keys(
    _state: tauri::State<'_, Arc<AppState>>,
) -> Result<HashMap<String, String>, String> {
    Ok(crypto::get_all_keys(PROVIDERS))
}
