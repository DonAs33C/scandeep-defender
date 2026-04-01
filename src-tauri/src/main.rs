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
use adapters::scanner_trait::ScanProvider;
use adapters::{
    virustotal::VirusTotalAdapter,
    metadefender::MetaDefenderAdapter,
    hybridanalysis::HybridAnalysisAdapter,
    cloudmersive::CloudmersiveAdapter,
    clamav::ClamAvAdapter,
};

fn main() {
    let db   = Arc::new(Database::new().expect("db init failed"));
    let keys = Arc::new(ApiKeys::new());
    keys.load_from_keyring();

    let providers: Vec<Arc<dyn ScanProvider>> = vec![
        Arc::new(VirusTotalAdapter::new(keys.vt.clone())),
        Arc::new(MetaDefenderAdapter::new(keys.md.clone())),
        Arc::new(HybridAnalysisAdapter::new(keys.ha.clone())),
        Arc::new(CloudmersiveAdapter::new(keys.cm.clone())),
        Arc::new(ClamAvAdapter::new()),
    ];

    let pipeline = Arc::new(ScanPipeline::new(providers, db.clone()));
    let queue    = Arc::new(JobQueue::new());

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