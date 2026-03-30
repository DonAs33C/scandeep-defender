#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod db;
mod file_watcher;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServiceResult {
    pub status: String,
    pub detections: u32,
    pub engines: u32,
    pub verdict: String,
    pub details: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScanResult {
    pub id: String,
    pub filename: String,
    pub filepath: String,
    pub filesize: u64,
    pub filehash: String,
    pub timestamp: String,
    pub services: HashMap<String, ServiceResult>,
    pub overall_verdict: String,
}

// Logica di scansione condivisa tra comando manuale e file watcher
pub async fn do_scan(
    file_path: String,
    services: Vec<String>,
    vt_key: String,
    md_key: String,
    db: Arc<Mutex<db::Database>>,
) -> Result<ScanResult, String> {
    let meta = fs::metadata(&file_path).map_err(|e| e.to_string())?;
    let bytes = fs::read(&file_path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let hash = format!("{:x}", hasher.finalize());
    let filename = std::path::Path::new(&file_path)
        .file_name().unwrap_or_default()
        .to_string_lossy().to_string();

    let mut service_results: HashMap<String, ServiceResult> = HashMap::new();
    for svc in &services {
        let result = match svc.as_str() {
            "virustotal"   => scan_virustotal(&hash, &bytes, &filename, &vt_key).await,
            "metadefender" => scan_metadefender(&hash, &md_key).await,
            "clamav"       => scan_clamav(&file_path),
            _ => ServiceResult {
                status:"unknown".into(), detections:0, engines:0,
                verdict:"pending".into(), details:"Servizio non supportato".into(),
            },
        };
        service_results.insert(svc.clone(), result);
    }

    let overall = compute_verdict(&service_results);
    let id = uuid::Uuid::new_v4().to_string();
    let timestamp = chrono::Utc::now().to_rfc3339();
    let result = ScanResult {
        id, filename, filepath: file_path,
        filesize: meta.len(), filehash: hash, timestamp,
        services: service_results, overall_verdict: overall,
    };
    { let db = db.lock().unwrap(); let _ = db.insert_scan(&result); }
    Ok(result)
}

// ── ClamAV locale ────────────────────────────────────────────────────────────
fn scan_clamav(file_path: &str) -> ServiceResult {
    match std::process::Command::new("clamscan")
        .args(["--no-summary", "--infected", file_path])
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let infected = stdout.contains("FOUND");
            ServiceResult {
                status: "scanned".into(),
                detections: if infected { 1 } else { 0 },
                engines: 1,
                verdict: if infected { "malicious" } else { "clean" }.into(),
                details: if infected {
                    stdout.lines().find(|l| l.contains("FOUND"))
                          .unwrap_or("Malware rilevato").to_string()
                } else {
                    "Nessuna minaccia (ClamAV)".into()
                },
            }
        }
        Err(_) => ServiceResult {
            status: "not_installed".into(), detections: 0, engines: 0,
            verdict: "pending".into(),
            details: "ClamAV non installato (scarica da clamav.net)".into(),
        },
    }
}

// ── VirusTotal ───────────────────────────────────────────────────────────────
async fn scan_virustotal(hash: &str, bytes: &[u8], filename: &str, api_key: &str) -> ServiceResult {
    if api_key.is_empty() {
        return ServiceResult { status:"no_key".into(), detections:0, engines:0,
            verdict:"pending".into(), details:"API key VirusTotal non configurata".into() };
    }
    let client = reqwest::Client::new();
    let url = format!("https://www.virustotal.com/api/v3/files/{}", hash);
    match client.get(&url).header("x-apikey", api_key).send().await {
        Ok(r) if r.status().is_success() => {
            if let Ok(json) = r.json::<serde_json::Value>().await {
                let stats = &json["data"]["attributes"]["last_analysis_stats"];
                let mal = stats["malicious"].as_u64().unwrap_or(0) as u32;
                let sus = stats["suspicious"].as_u64().unwrap_or(0) as u32;
                let tot = mal + sus
                    + stats["harmless"].as_u64().unwrap_or(0) as u32
                    + stats["undetected"].as_u64().unwrap_or(0) as u32;
                let verdict = if mal>0{"malicious"}else if sus>0{"suspicious"}else{"clean"};
                return ServiceResult { status:"found".into(), detections:mal+sus,
                    engines:tot, verdict:verdict.into(),
                    details:format!("{} rilevazioni su {} engine", mal+sus, tot) };
            }
            ServiceResult { status:"error".into(), detections:0, engines:0,
                verdict:"pending".into(), details:"Risposta non valida".into() }
        },
        Ok(r) if r.status() == 404 => upload_virustotal(bytes, filename, api_key).await,
        Ok(r) => ServiceResult { status:"error".into(), detections:0, engines:0,
            verdict:"pending".into(), details:format!("HTTP {}", r.status()) },
        Err(e) => ServiceResult { status:"error".into(), detections:0, engines:0,
            verdict:"pending".into(), details:e.to_string() },
    }
}

async fn upload_virustotal(bytes: &[u8], filename: &str, api_key: &str) -> ServiceResult {
    let client = reqwest::Client::new();
    let part = reqwest::multipart::Part::bytes(bytes.to_vec()).file_name(filename.to_string());
    let form = reqwest::multipart::Form::new().part("file", part);
    match client.post("https://www.virustotal.com/api/v3/files")
        .header("x-apikey", api_key).multipart(form).send().await {
        Ok(r) if r.status().is_success() => ServiceResult {
            status:"uploaded".into(), detections:0, engines:0,
            verdict:"pending".into(), details:"File inviato, ricontrolla tra pochi minuti".into() },
        Ok(r) => ServiceResult { status:"error".into(), detections:0, engines:0,
            verdict:"pending".into(), details:format!("Upload HTTP {}", r.status()) },
        Err(e) => ServiceResult { status:"error".into(), detections:0, engines:0,
            verdict:"pending".into(), details:e.to_string() },
    }
}

// ── MetaDefender ─────────────────────────────────────────────────────────────
async fn scan_metadefender(hash: &str, api_key: &str) -> ServiceResult {
    if api_key.is_empty() {
        return ServiceResult { status:"no_key".into(), detections:0, engines:0,
            verdict:"pending".into(), details:"API key MetaDefender non configurata".into() };
    }
    let client = reqwest::Client::new();
    let url = format!("https://api.metadefender.com/v4/hash/{}", hash);
    match client.get(&url).header("apikey", api_key).send().await {
        Ok(r) if r.status().is_success() => {
            if let Ok(json) = r.json::<serde_json::Value>().await {
                let detected = json["scan_results"]["scan_all_result_i"].as_u64().unwrap_or(0);
                let tot = json["scan_results"]["total_avs"].as_u64().unwrap_or(0) as u32;
                let pos = json["scan_results"]["total_detected_avs"].as_u64().unwrap_or(0) as u32;
                let verdict = if detected > 0 { "malicious" } else { "clean" };
                return ServiceResult { status:"found".into(), detections:pos,
                    engines:tot, verdict:verdict.into(),
                    details:format!("{} rilevazioni su {} engine", pos, tot) };
            }
            ServiceResult { status:"error".into(), detections:0, engines:0,
                verdict:"pending".into(), details:"Risposta non valida".into() }
        },
        Ok(r) if r.status() == 404 => ServiceResult {
            status:"not_found".into(), detections:0, engines:0,
            verdict:"clean".into(), details:"Hash non trovato in MetaDefender".into() },
        Ok(r) => ServiceResult { status:"error".into(), detections:0, engines:0,
            verdict:"pending".into(), details:format!("HTTP {}", r.status()) },
        Err(e) => ServiceResult { status:"error".into(), detections:0, engines:0,
            verdict:"pending".into(), details:e.to_string() },
    }
}

fn compute_verdict(services: &HashMap<String, ServiceResult>) -> String {
    if services.values().any(|s| s.verdict == "malicious") { return "malicious".into(); }
    if services.values().any(|s| s.verdict == "suspicious") { return "suspicious".into(); }
    if services.values().all(|s| s.verdict == "clean") { return "clean".into(); }
    "pending".into()
}

// ── Tauri commands ────────────────────────────────────────────────────────────
#[tauri::command]
async fn scan_file(
    file_path: String, services: Vec<String>,
    vt_key: String, md_key: String,
    state: tauri::State<'_, Arc<Mutex<db::Database>>>,
) -> Result<ScanResult, String> {
    do_scan(file_path, services, vt_key, md_key, state.inner().clone()).await
}

#[tauri::command]
fn get_history(state: tauri::State<'_, Arc<Mutex<db::Database>>>) -> Result<Vec<db::ScanRecord>, String> {
    let db = state.lock().unwrap();
    db.get_all_scans().map_err(|e| e.to_string())
}

#[tauri::command]
fn clear_history(state: tauri::State<'_, Arc<Mutex<db::Database>>>) -> Result<(), String> {
    let db = state.lock().unwrap();
    db.clear_history().map_err(|e| e.to_string())
}

#[tauri::command]
fn set_watcher_keys(vt: String, md: String,
    keys: tauri::State<'_, Arc<Mutex<(String, String)>>>) -> Result<(), String> {
    let mut k = keys.lock().unwrap();
    k.0 = vt; k.1 = md;
    Ok(())
}

fn main() {
    let db   = Arc::new(Mutex::new(db::Database::new().expect("db init failed")));
    let keys = Arc::new(Mutex::new((String::new(), String::new())));

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(db.clone())
        .manage(keys.clone())
        .setup(move |app| {
            file_watcher::start_watcher(app.handle().clone(), db.clone(), keys.clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            scan_file, get_history, clear_history, set_watcher_keys
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
