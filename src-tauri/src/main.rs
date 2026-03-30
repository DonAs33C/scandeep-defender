#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod apis;
mod db;
mod file_watcher;
mod scanner;

use std::sync::Arc;
use tauri::{Manager, Emitter};
use tokio::sync::Mutex;

#[derive(serde::Deserialize)]
struct ScanRequest {
    file_path: String,
    services: Vec<String>,
    api_keys: serde_json::Value,
}

#[tauri::command]
async fn scan_file(
    req: ScanRequest,
    db: tauri::State<'_, Arc<Mutex<db::Database>>>,
) -> Result<serde_json::Value, String> {
    let result = scanner::scan_file(&req.file_path, &req.services, &req.api_keys).await?;
    let mut guard = db.lock().await;
    guard.insert_scan(&result).map_err(|e| e.to_string())?;
    Ok(result)
}

#[tauri::command]
async fn get_history(
    db: tauri::State<'_, Arc<Mutex<db::Database>>>,
) -> Result<Vec<serde_json::Value>, String> {
    let guard = db.lock().await;
    guard.get_all_scans().map_err(|e| e.to_string())
}

#[tauri::command]
async fn clear_history(
    db: tauri::State<'_, Arc<Mutex<db::Database>>>,
) -> Result<(), String> {
    let mut guard = db.lock().await;
    guard.clear_history().map_err(|e| e.to_string())
}

fn main() {
    let db = Arc::new(Mutex::new(db::Database::new().expect("db init failed")));

    tauri::Builder::default()
        .manage(db)
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .setup(|app| {
            let handle = app.handle().clone();
            let db = app.state::<Arc<Mutex<db::Database>>>().inner().clone();

            std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async move {
                    let _ = file_watcher::start_watcher(handle, db).await;
                });
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            scan_file,
            get_history,
            clear_history
        ])
        .run(tauri::generate_context!())
        .expect("error while running app");
}
