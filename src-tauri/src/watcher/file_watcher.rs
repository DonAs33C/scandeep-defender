
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::{mpsc, Arc};
use tauri::{AppHandle, Emitter};

use crate::app_state::AppState;
use crate::engine::job::ScanJob;
use crate::watcher::stability_checker::StabilityChecker;

pub fn start_watcher(app: AppHandle, state: Arc<AppState>, _queue: Arc<crate::engine::queue::JobQueue>) {
    let downloads = dirs::download_dir().unwrap_or_else(|| PathBuf::from("."));

    std::thread::spawn(move || {
        let (tx, rx) = mpsc::channel::<notify::Result<Event>>();
        let mut watcher: RecommendedWatcher = match notify::recommended_watcher(tx) {
            Ok(w) => w,
            Err(e) => { tracing::error!("Failed to create watcher: {}", e); return; }
        };
        if let Err(e) = watcher.watch(&downloads, RecursiveMode::NonRecursive) {
            tracing::error!("Failed to watch downloads: {}", e); return;
        }

        tracing::info!("Watching {:?} for new files", downloads);
        let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => { tracing::error!("Failed to create tokio runtime: {}", e); return; }
        };

        for res in rx {
            if !*state.auto_scan.lock().unwrap() { continue; }
            let Ok(event) = res else { continue; };
            if !matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) { continue; }

            for path in event.paths {
                if StabilityChecker::should_ignore(&path) { continue; }

                let app2 = app.clone();
                let state2 = Arc::clone(&state);
                let path2 = path.clone();

                rt.spawn(async move {
                    let size = match StabilityChecker::wait_until_stable(&path2).await {
                        Ok(s) => s,
                        Err(e) => { tracing::warn!("Stability check failed for {:?}: {}", path2, e); return; }
                    };
                    if size == 0 { return; }

                    let (providers, allow_cloud_upload, should_scan) = {
                        let cfg = state2.config.read().unwrap();
                        (
                            cfg.enabled_providers.clone(),
                            cfg.allow_cloud_upload,
                            cfg.rules.should_scan(&path2),
                        )
                    };
                    if !should_scan {
                        tracing::debug!("RulesEngine skipped {:?}", path2);
                        return;
                    }

                    let job = ScanJob::new(path2.clone(), providers, allow_cloud_upload);
                    let _ = app2.emit("job-queued", serde_json::json!({
                        "job_id": job.id,
                        "filename": job.filename,
                        "source": "downloads"
                    }));

                    match state2.pipeline.execute(job, &app2).await {
                        Ok(report) => {
                            let _ = app2.emit("scan-complete", &report);
                            tracing::info!("Background scan completed for {}", report.filename);
                        }
                        Err(e) => {
                            let _ = app2.emit("scan-error", serde_json::json!({
                                "message": e.to_string(),
                                "source": "downloads"
                            }));
                            tracing::error!("Background scan failed: {}", e);
                        }
                    }
                });
            }
        }
    });
}
