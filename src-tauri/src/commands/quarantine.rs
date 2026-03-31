
use std::sync::Arc;
use crate::app_state::AppState;
use crate::security::quarantine::{QuarantineManager,QuarantineRecord};

#[tauri::command]
pub fn quarantine_file(file_path:String,hash:String,scan_id:String,state:tauri::State<'_,Arc<AppState>>) -> Result<QuarantineRecord,String> {
    let qm = QuarantineManager::new().map_err(|e|e.to_string())?;
    let rec = qm.quarantine(std::path::Path::new(&file_path),&hash,&scan_id).map_err(|e|e.to_string())?;
    state.db.save_quarantine(&rec).map_err(|e|e.to_string())?;
    Ok(rec)
}
#[tauri::command]
pub fn restore_file(record:QuarantineRecord,state:tauri::State<'_,Arc<AppState>>) -> Result<(),String> {
    let qm = QuarantineManager::new().map_err(|e|e.to_string())?;
    qm.restore(&record).map_err(|e|e.to_string())?;
    state.db.remove_quarantine(&record.id).map_err(|e|e.to_string())?;
    Ok(())
}
#[tauri::command]
pub fn list_quarantine(state:tauri::State<'_,Arc<AppState>>) -> Result<Vec<QuarantineRecord>,String> {
    state.db.get_quarantine_list().map_err(|e|e.to_string())
}
#[tauri::command]
pub fn delete_permanently(record:QuarantineRecord,state:tauri::State<'_,Arc<AppState>>) -> Result<(),String> {
    let qm = QuarantineManager::new().map_err(|e|e.to_string())?;
    qm.delete_permanently(&record).map_err(|e|e.to_string())?;
    state.db.remove_quarantine(&record.id).map_err(|e|e.to_string())?;
    Ok(())
}
