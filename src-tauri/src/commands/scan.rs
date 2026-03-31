
use std::sync::Arc;
use sha2::{Digest, Sha256};
use tauri::AppHandle;
use crate::app_state::AppState;
use crate::engine::job::{ScanJob, ScanReport};
use crate::adapters::scanner_trait::ProviderResult;

#[tauri::command]
pub async fn scan_file(
    file_path: String, services: Vec<String>,
    state: tauri::State<'_, Arc<AppState>>, app: AppHandle,
) -> Result<ScanReport, String> {
    // FIX: estrae i dati dal lock PRIMA dell'await, così RwLockReadGuard viene droppato
    let (providers, allow_cloud_upload) = {
        let cfg = state.config.read().unwrap();
        (
            if services.is_empty() { cfg.enabled_providers.clone() } else { services },
            cfg.allow_cloud_upload,
        )
        // cfg droppato qui — il guard NON attraversa il punto di await
    };

    let job = ScanJob::new(
        std::path::PathBuf::from(&file_path),
        providers,
        allow_cloud_upload,
    );

    state.pipeline.execute(job, &app).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn poll_result(
    provider_id: String, poll_id: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<ProviderResult, String> {
    // get_provider ora esiste su ScanPipeline
    let provider = state.pipeline.get_provider(&provider_id)
        .ok_or_else(|| format!("Provider {} non trovato", provider_id))?;
    Ok(provider.poll_result(&poll_id).await)
}

#[tauri::command]
pub async fn check_duplicate(
    file_path: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<Option<String>, String> {
    let bytes = tokio::fs::read(&file_path).await.map_err(|e| e.to_string())?;
    let mut h = Sha256::new(); h.update(&bytes);
    let hash = format!("{:x}", h.finalize());
    state.db.find_by_hash(&hash).map_err(|e| e.to_string())
}
