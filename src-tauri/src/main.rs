#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Arc;

mod app_state;
mod commands;
mod engine;
mod adapters;
mod persistence;
mod security;
mod watcher;
mod rate_limiter;

use app_state::{AppConfig, AppState, ApiKeys};
use engine::{pipeline::ScanPipeline, queue::JobQueue};
use persistence::database::Database;

fn main() {
    let db       = Arc::new(Database::new().expect("db init failed"));
    let keys     = Arc::new(ApiKeys::new());
    keys.load_from_keyring();

    let pipeline = Arc::new(ScanPipeline::new(keys.clone()));
    let queue    = Arc::new(JobQueue::new());   // FIX: non più tupla

    let state = Arc::new(AppState {
        db,
        pipeline,
        queue,
        keys,
        auto_scan: std::sync::Mutex::new(false),
        config:    std::sync::RwLock::new(AppConfig::default()),
    });

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            commands::scan::scan_file,
            commands::scan::poll_result,
            commands::scan::check_duplicate,
            commands::settings::save_api_keys,
            commands::settings::load_api_keys,
        ])
        .setup(|_app| Ok(()))
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
