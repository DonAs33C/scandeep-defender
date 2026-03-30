#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex};

mod db;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ServiceResult {
    status: String,
    detections: u32,
    engines: u32,
    verdict: String,
    details: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ScanResult {
    id: String,
    filename: String,
    filepath: String,
    filesize: u64,
    filehash: String,
    timestamp: String,
    services: HashMap<String, ServiceResult>,
    overall_verdict: String,
}

#[tauri::command]
async fn scan_file(
    file_path: String,
    services: Vec<String>,
    vt_key: String,
    md_key: String,
    state: tauri::State<'_, Arc<Mutex<db::Database>>>,
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
            "virustotal" => scan_virustotal(&hash, &bytes, &filename, &vt_key).await,
            "metadefender" => scan_metadefender(&hash, &md_key).await,
            _ => ServiceResult {
                status: "unknown".into(), detections: 0, engines: 0,
                verdict: "pending".into(), details: "Servizio non supportato".into(),
            },
        };
        service_results.insert(svc.clone(), result);
    }

    let overall = compute_verdict(&service_results);
    let id = format!("{}", uuid::Uuid::new_v4());
    let timestamp = chrono::Utc::now().to_rfc3339();

    let result = ScanResult {
        id: id.clone(),
        filename: filename.clone(),
        filepath: file_path.clone(),
        filesize: meta.len(),
        filehash: hash.clone(),
        timestamp: timestamp.clone(),
        services: service_results.clone(),
        overall_verdict: overall.clone(),
    };

    let db = state.lock().unwrap();
    let _ = db.insert_scan(&result);

    Ok(result)
}

async fn scan_virustotal(hash: &str, bytes: &[u8], filename: &str, api_key: &str) -> ServiceResult {
    if api_key.is_empty() {
        return ServiceResult {
            status: "no_key".into(), detections: 0, engines: 0,
            verdict: "pending".into(), details: "API key VirusTotal non configurata".into(),
        };
    }
    let client = reqwest::Client::new();
    let url = format!("https://www.virustotal.com/api/v3/files/{}", hash);
    match client.get(&url).header("x-apikey", api_key).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                let stats = &json["data"]["attributes"]["last_analysis_stats"];
                let malicious = stats["malicious"].as_u64().unwrap_or(0) as u32;
                let suspicious = stats["suspicious"].as_u64().unwrap_or(0) as u32;
                let total = malicious + suspicious
                    + stats["harmless"].as_u64().unwrap_or(0) as u32
                    + stats["undetected"].as_u64().unwrap_or(0) as u32;
                let verdict = if malicious > 0 { "malicious" }
                    else if suspicious > 0 { "suspicious" } else { "clean" };
                return ServiceResult {
                    status: "found".into(),
                    detections: malicious + suspicious,
                    engines: total,
                    verdict: verdict.into(),
                    details: format!("{} rilevazioni su {} engine", malicious+suspicious, total),
                };
            }
            ServiceResult { status:"error".into(), detections:0, engines:0, verdict:"pending".into(), details:"Risposta non valida".into() }
        },
        Ok(resp) if resp.status() == 404 => {
            // File non trovato, carica
            upload_virustotal(bytes, filename, api_key).await
        },
        Ok(resp) => ServiceResult {
            status: "error".into(), detections: 0, engines: 0,
            verdict: "pending".into(),
            details: format!("HTTP {}", resp.status()),
        },
        Err(e) => ServiceResult {
            status: "error".into(), detections: 0, engines: 0,
            verdict: "pending".into(), details: e.to_string(),
        },
    }
}

async fn upload_virustotal(bytes: &[u8], filename: &str, api_key: &str) -> ServiceResult {
    let client = reqwest::Client::new();
    let part = reqwest::multipart::Part::bytes(bytes.to_vec()).file_name(filename.to_string());
    let form = reqwest::multipart::Form::new().part("file", part);
    match client.post("https://www.virustotal.com/api/v3/files")
        .header("x-apikey", api_key).multipart(form).send().await {
        Ok(r) if r.status().is_success() => ServiceResult {
            status: "uploaded".into(), detections: 0, engines: 0,
            verdict: "pending".into(), details: "File inviato a VirusTotal, ricontrolla tra pochi minuti".into(),
        },
        Ok(r) => ServiceResult {
            status: "error".into(), detections: 0, engines: 0,
            verdict: "pending".into(), details: format!("Upload HTTP {}", r.status()),
        },
        Err(e) => ServiceResult {
            status: "error".into(), detections: 0, engines: 0,
            verdict: "pending".into(), details: e.to_string(),
        },
    }
}

async fn scan_metadefender(hash: &str, api_key: &str) -> ServiceResult {
    if api_key.is_empty() {
        return ServiceResult {
            status: "no_key".into(), detections: 0, engines: 0,
            verdict: "pending".into(), details: "API key MetaDefender non configurata".into(),
        };
    }
    let client = reqwest::Client::new();
    let url = format!("https://api.metadefender.com/v4/hash/{}", hash);
    match client.get(&url).header("apikey", api_key).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                let detected = json["scan_results"]["scan_all_result_i"].as_u64().unwrap_or(0);
                let total = json["scan_results"]["total_avs"].as_u64().unwrap_or(0) as u32;
                let positives = json["scan_results"]["total_detected_avs"].as_u64().unwrap_or(0) as u32;
                let verdict = if detected > 0 { "malicious" } else { "clean" };
                return ServiceResult {
                    status: "found".into(),
                    detections: positives,
                    engines: total,
                    verdict: verdict.into(),
                    details: format!("{} rilevazioni su {} engine", positives, total),
                };
            }
            ServiceResult { status:"error".into(), detections:0, engines:0, verdict:"pending".into(), details:"Risposta non valida".into() }
        },
        Ok(resp) if resp.status() == 404 => ServiceResult {
            status: "not_found".into(), detections: 0, engines: 0,
            verdict: "clean".into(), details: "Hash non trovato in MetaDefender".into(),
        },
        Ok(resp) => ServiceResult {
            status: "error".into(), detections: 0, engines: 0,
            verdict: "pending".into(), details: format!("HTTP {}", resp.status()),
        },
        Err(e) => ServiceResult {
            status: "error".into(), detections: 0, engines: 0,
            verdict: "pending".into(), details: e.to_string(),
        },
    }
}

fn compute_verdict(services: &HashMap<String, ServiceResult>) -> String {
    if services.values().any(|s| s.verdict == "malicious") { return "malicious".into(); }
    if services.values().any(|s| s.verdict == "suspicious") { return "suspicious".into(); }
    if services.values().all(|s| s.verdict == "clean") { return "clean".into(); }
    "pending".into()
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

fn main() {
    let db = Arc::new(Mutex::new(db::Database::new().expect("db init failed")));
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(db)
        .invoke_handler(tauri::generate_handler![scan_file, get_history, clear_history])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
