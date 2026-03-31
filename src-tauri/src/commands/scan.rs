
use std::sync::Arc;
use sha2::{Digest,Sha256};
use tauri::AppHandle;
use crate::app_state::AppState;
use crate::engine::{pipeline::ScanPipeline, job::{ScanJob,ScanReport}};

#[tauri::command]
pub async fn scan_file(
    file_path:String, services:Vec<String>,
    state:tauri::State<'_,Arc<AppState>>, app:AppHandle,
) -> Result<ScanReport,String> {
    let cfg = state.config.read().unwrap();
    let job = ScanJob::new(
        std::path::PathBuf::from(&file_path),
        if services.is_empty(){cfg.enabled_providers.clone()}else{services},
        cfg.allow_cloud_upload,
    );
    drop(cfg);
    state.pipeline.execute(job, &app).await.map_err(|e|e.to_string())
}

#[tauri::command]
pub async fn poll_result(
    provider_id:String, poll_id:String, state:tauri::State<'_,Arc<AppState>>,
) -> Result<crate::adapters::scanner_trait::ProviderResult,String> {
    let provider = state.pipeline.get_provider(&provider_id)
        .ok_or_else(||format!("Provider {} not found",provider_id))?;
    Ok(provider.poll_result(&poll_id).await)
}

#[tauri::command]
pub async fn check_duplicate(file_path:String, state:tauri::State<'_,Arc<AppState>>) -> Result<Option<String>,String> {
    let bytes = tokio::fs::read(&file_path).await.map_err(|e|e.to_string())?;
    let mut h = Sha256::new(); h.update(&bytes);
    let hash = format!("{:x}",h.finalize());
    state.db.find_by_hash(&hash).map_err(|e|e.to_string())
}
