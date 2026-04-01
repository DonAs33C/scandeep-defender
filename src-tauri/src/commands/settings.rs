use std::sync::Arc;
use std::collections::HashMap;
use crate::app_state::{AppState, AppConfig};
use crate::security::crypto;
use crate::security::rules::RulesEngine;

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

/// Carica le API key per mostrarle nella UI
#[tauri::command]
pub async fn load_api_keys(
    _state: tauri::State<'_, Arc<AppState>>,
) -> Result<HashMap<String, String>, String> {
    Ok(crypto::get_all_keys(PROVIDERS))
}

/// Aggiorna le chiavi nel watcher live (senza riavvio)
#[tauri::command]
pub async fn set_watcher_keys(
    vt: String, md: String, ha: String, cm: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<(), String> {
    let set = |mtx: &std::sync::Arc<std::sync::Mutex<String>>, val: String| {
        *mtx.lock().unwrap() = val;
    };
    set(&state.keys.vt, vt);
    set(&state.keys.md, md);
    set(&state.keys.ha, ha);
    set(&state.keys.cm, cm);
    Ok(())
}

/// Attiva/disattiva il monitoraggio automatico della cartella Downloads
#[tauri::command]
pub async fn set_auto_scan(
    enabled: bool,
    state:   tauri::State<'_, Arc<AppState>>,
) -> Result<(), String> {
    *state.auto_scan.lock().unwrap() = enabled;
    Ok(())
}

/// Aggiorna provider abilitati e opzione cloud upload in AppState
#[tauri::command]
pub async fn set_config(
    allow_cloud_upload:  bool,
    enabled_providers:   Vec<String>,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<(), String> {
    let mut cfg = state.config.write().unwrap();
    cfg.allow_cloud_upload = allow_cloud_upload;
    cfg.enabled_providers  = enabled_providers;
    Ok(())
}

/// Apre un URL nel browser di sistema
#[tauri::command]
pub async fn open_browser(url: String) -> Result<(), String> {
    open::that(&url).map_err(|e| e.to_string())
}
