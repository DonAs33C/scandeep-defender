
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod adapters; mod engine; mod watcher; mod persistence; mod security; mod rate_limiter; mod commands; mod app_state;

use std::sync::{Arc,RwLock,Mutex};
use app_state::{AppState,AppConfig,ApiKeys};
use engine::{queue::JobQueue,pipeline::ScanPipeline};
use persistence::database::Database;

fn main() {
    tracing_subscriber::fmt::init();

    let db   = Arc::new(Database::new().expect("DB init failed"));
    let keys = Arc::new(ApiKeys::new());
    keys.load_from_keyring();

    let providers = adapters::build_providers(
        Arc::clone(&keys.vt), Arc::clone(&keys.md),
        Arc::clone(&keys.ha), Arc::clone(&keys.cm),
    );
    let pipeline = Arc::new(ScanPipeline::new(providers, Arc::clone(&db)));
    let (queue, _rx) = JobQueue::new();
    let queue = Arc::new(queue);

    let app_state = Arc::new(AppState {
        db: Arc::clone(&db), pipeline: Arc::clone(&pipeline),
        queue: Arc::clone(&queue), keys: Arc::clone(&keys),
        auto_scan: Mutex::new(true),
        config: RwLock::new(AppConfig{ enabled_providers:vec!["virustotal".into(),"clamav".into()], allow_cloud_upload:false, ..Default::default() }),
    });

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Arc::clone(&app_state))
        .setup(move |app| {
            watcher::file_watcher::start_watcher(app.handle().clone(), Arc::clone(&app_state), Arc::clone(&queue));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::scan::scan_file,
            commands::scan::poll_result,
            commands::scan::check_duplicate,
            commands::history::get_history,
            commands::history::clear_history,
            commands::settings::save_api_keys,
            commands::settings::set_watcher_keys,
            commands::settings::load_api_keys,
            commands::settings::set_auto_scan,
            commands::settings::set_config,
            commands::quarantine::quarantine_file,
            commands::quarantine::restore_file,
            commands::quarantine::list_quarantine,
            commands::quarantine::delete_permanently,
            open_browser,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[tauri::command]
fn open_browser(url:String)->Result<(),String>{ open::that(&url).map_err(|e|e.to_string()) }
