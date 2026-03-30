use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter};

use crate::db::Database;
use crate::do_scan;

pub fn start_watcher(app: AppHandle, db: Arc<Mutex<Database>>, keys: Arc<Mutex<(String, String)>>) {
    let downloads = dirs::download_dir()
        .unwrap_or_else(|| PathBuf::from("."));

    std::thread::spawn(move || {
        let (tx, rx) = mpsc::channel::<notify::Result<Event>>();
        let mut watcher: RecommendedWatcher =
            notify::recommended_watcher(tx).expect("watcher init failed");
        watcher
            .watch(&downloads, RecursiveMode::NonRecursive)
            .expect("watch failed");

        for res in rx {
            if let Ok(event) = res {
                if matches!(event.kind, EventKind::Create(_)) {
                    for path in event.paths {
                        let ext = path.extension()
                            .and_then(|e| e.to_str())
                            .unwrap_or("");
                        // Ignora cartelle e file temporanei
                        if path.is_dir() || ext == "tmp" || ext == "part" || ext == "crdownload" {
                            continue;
                        }
                        // Attendi che il file sia completamente scritto
                        std::thread::sleep(std::time::Duration::from_secs(2));
                        if !path.exists() { continue; }

                        let fp = path.to_string_lossy().to_string();
                        let (vt, md) = { let k = keys.lock().unwrap(); (k.0.clone(), k.1.clone()) };
                        let svcs = vec!["virustotal".to_string(), "metadefender".to_string(), "clamav".to_string()];

                        let db_clone = db.clone();
                        let app_clone = app.clone();

                        let rt = tokio::runtime::Handle::current();
                        rt.spawn(async move {
                            if let Ok(result) = do_scan(fp, svcs, vt, md, db_clone).await {
                                let _ = app_clone.emit("scan-complete", &result);
                            }
                        });
                    }
                }
            }
        }
    });
}
