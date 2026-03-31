
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Arc;
use tauri::{AppHandle, Emitter};
use crate::AppState;
use crate::do_scan;

pub fn start_watcher(app: AppHandle, state: Arc<AppState>) {
    let downloads = dirs::download_dir().unwrap_or_else(|| PathBuf::from("."));
    std::thread::spawn(move || {
        let (tx, rx) = mpsc::channel::<notify::Result<Event>>();
        let mut watcher: RecommendedWatcher = match notify::recommended_watcher(tx){Ok(w)=>w,Err(_)=>return};
        if watcher.watch(&downloads, RecursiveMode::NonRecursive).is_err(){return;}
        let rt = tokio::runtime::Runtime::new().unwrap();
        for res in rx {
            if !*state.auto_scan.lock().unwrap() { continue; }
            if let Ok(event) = res {
                if matches!(event.kind, EventKind::Create(_)) {
                    for path in event.paths {
                        let ext=path.extension().and_then(|e|e.to_str()).unwrap_or("").to_lowercase();
                        if path.is_dir()||ext=="tmp"||ext=="part"||ext=="crdownload"||ext=="download"{continue;}
                        std::thread::sleep(std::time::Duration::from_secs(2));
                        if !path.exists(){continue;}
                        let fp=path.to_string_lossy().to_string();
                        let (vt,md,ha,cm)={let k=state.keys.lock().unwrap();(k.vt.clone(),k.md.clone(),k.ha.clone(),k.cm.clone())};
                        let svcs=vec!["virustotal".to_string(),"metadefender".to_string(),"hybridanalysis".to_string(),"clamav".to_string()];
                        let db2=state.db.clone();
                        let app2=app.clone();
                        rt.spawn(async move {
                            if let Ok(result)=do_scan(fp,svcs,vt,md,ha,cm,db2).await{
                                let _=app2.emit("scan-complete",&result);
                            }
                        });
                    }
                }
            }
        }
    });
}
