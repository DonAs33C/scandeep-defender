
use std::sync::Arc;
use std::path::PathBuf;
use sha2::{Digest, Sha256};
use tauri::AppHandle;
use crate::app_state::AppState;
use crate::engine::job::{ScanJob, ScanReport};
use crate::adapters::scanner_trait::ProviderResult;

#[tauri::command]
pub async fn scan_file(
    file_path: String,
    services: Vec<String>,
    state: tauri::State<'_, Arc<AppState>>,
    app: AppHandle,
) -> Result<ScanReport, String> {
    // Verifica che il file esista
    let path = PathBuf::from(&file_path);
    if !path.exists() {
        return Err(format!("File non trovato: {}", file_path));
    }

    // FIX: estrae config PRIMA dell'await — RwLockGuard non è Send
    let (providers, allow_cloud_upload) = {
        let cfg = state.config.read().map_err(|e| e.to_string())?;
        let p = if services.is_empty() {
            cfg.enabled_providers.clone()
        } else {
            services
        };
        (p, cfg.allow_cloud_upload)
    };

    if providers.is_empty() {
        return Err("Nessun provider abilitato. Controlla le impostazioni.".into());
    }

    let job = ScanJob::new(path, providers, allow_cloud_upload);

    state.pipeline
        .execute(job, &app)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn poll_result(
    provider_id: String,
    poll_id: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<ProviderResult, String> {
    let provider = state.pipeline
        .get_provider(&provider_id)
        .ok_or_else(|| format!("Provider '{}' non trovato", provider_id))?;
    Ok(provider.poll_result(&poll_id).await)
}

#[tauri::command]
pub async fn check_duplicate(
    file_path: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<Option<String>, String> {
    let bytes = tokio::fs::read(&file_path).await
        .map_err(|e| format!("Lettura file fallita: {}", e))?;
    let mut h = Sha256::new();
    h.update(&bytes);
    let hash = format!("{:x}", h.finalize());
    state.db.find_by_hash(&hash).map_err(|e| e.to_string())
}
