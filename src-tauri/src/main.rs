#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Arc;

mod adapters;
mod app_state;
mod commands;
mod engine;
mod persistence;
mod rate_limiter;
mod security;
mod watcher;

use adapters::scanner_trait::ScanProvider;
use adapters::{
    clamav::ClamAVAdapter, cloudmersive::CloudmersiveAdapter,
    hybrid_analysis::HybridAnalysisAdapter, metadefender::MetaDefenderAdapter,
    virustotal::VirusTotalAdapter,
};
use app_state::{ApiKeys, AppConfig, AppState};
use engine::{pipeline::ScanPipeline, queue::JobQueue};
use persistence::database::Database;

fn main() {
    tracing_subscriber::fmt::init();

    let db = Arc::new(Database::new().expect("db init failed"));
    let keys = Arc::new(ApiKeys::new());
    keys.load_from_keyring();

    let providers: Vec<Arc<dyn ScanProvider>> = vec![
        Arc::new(VirusTotalAdapter::new(keys.vt.clone())),
        Arc::new(MetaDefenderAdapter::new(keys.md.clone())),
        Arc::new(HybridAnalysisAdapter::new(keys.ha.clone())),
        Arc::new(CloudmersiveAdapter::new(keys.cm.clone())),
        Arc::new(ClamAVAdapter::new()),
    ];

    let pipeline = Arc::new(ScanPipeline::new(providers, db.clone()));
    let queue = Arc::new(JobQueue::new());

    let state = Arc::new(AppState {
        db,
        pipeline,
        queue: queue.clone(),
        keys,
        auto_scan: std::sync::Mutex::new(false),
        config: std::sync::RwLock::new(AppConfig::default()),
    });

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(state.clone())
        .invoke_handler(tauri::generate_handler![
            // scan
            commands::scan::scan_file,
            commands::scan::poll_result,
            commands::scan::check_duplicate,
            // settings
            commands::settings::save_api_keys,
            commands::settings::load_api_keys,
            commands::settings::set_watcher_keys,
            commands::settings::set_auto_scan,
            commands::settings::set_config,
            commands::settings::open_browser,
            // history
            commands::history::get_history,
            commands::history::clear_history,
            // quarantine
            commands::quarantine::quarantine_file,
            commands::quarantine::restore_file,
            commands::quarantine::list_quarantine,
            commands::quarantine::delete_permanently,
        ])
        .setup(move |app| {
            watcher::file_watcher::start_watcher(
                app.handle().clone(),
                state.clone(),
                queue.clone(),
            );
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
