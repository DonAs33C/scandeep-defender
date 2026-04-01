
use std::sync::Arc;
use crate::app_state::AppState;
use crate::security::crypto;

const PROVIDERS: &[&str] = &["virustotal","metadefender","hybridanalysis","cloudmersive"];

#[tauri::command]
pub fn save_api_keys(vt:String,md:String,ha:String,cm:String,state:tauri::State<'_,Arc<AppState>>) -> Result<(),String> {
    let keys_map = [("virustotal",&vt),("metadefender",&md),("hybridanalysis",&ha),("cloudmersive",&cm)];
    for (id,key) in &keys_map {
        if !key.is_empty() { crypto::store_key(id,key).map_err(|e|e.to_string())?; }
    }
    *state.keys.vt.lock().unwrap() = vt.clone();
    *state.keys.md.lock().unwrap() = md.clone();
    *state.keys.ha.lock().unwrap() = ha.clone();
    *state.keys.cm.lock().unwrap() = cm.clone();
    Ok(())
}

#[tauri::command]
pub fn set_watcher_keys(vt:String,md:String,ha:String,cm:String,state:tauri::State<'_,Arc<AppState>>) -> Result<(),String> {
    *state.keys.vt.lock().unwrap() = vt;
    *state.keys.md.lock().unwrap() = md;
    *state.keys.ha.lock().unwrap() = ha;
    *state.keys.cm.lock().unwrap() = cm;
    Ok(())
}

#[tauri::command]
pub fn load_api_keys(_state:tauri::State<'_,Arc<AppState>>) -> Result<std::collections::HashMap<String,String>,String> {
    Ok(crypto::get_all_keys(PROVIDERS))
}

#[tauri::command]
pub fn set_auto_scan(enabled:bool, state:tauri::State<'_,Arc<AppState>>) -> Result<(),String> {
    *state.auto_scan.lock().unwrap() = enabled; Ok(())
}

#[tauri::command]
pub fn set_config(allow_cloud_upload:bool,enabled_providers:Vec<String>,state:tauri::State<'_,Arc<AppState>>) -> Result<(),String> {
    let mut cfg = state.config.write().unwrap();
    cfg.allow_cloud_upload = allow_cloud_upload;
    cfg.enabled_providers  = enabled_providers;
    Ok(())
}
