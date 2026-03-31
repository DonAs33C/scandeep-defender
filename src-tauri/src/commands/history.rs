
use std::sync::Arc;
use crate::app_state::AppState;
use crate::persistence::database::ScanRecord;

#[tauri::command]
pub fn get_history(state:tauri::State<'_,Arc<AppState>>) -> Result<Vec<ScanRecord>,String> {
    state.db.get_all_scans().map_err(|e|e.to_string())
}
#[tauri::command]
pub fn clear_history(state:tauri::State<'_,Arc<AppState>>) -> Result<(),String> {
    state.db.clear_history().map_err(|e|e.to_string())
}
