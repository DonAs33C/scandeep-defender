
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod db; mod file_watcher;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServiceResult { pub status:String, pub detections:u32, pub engines:u32, pub verdict:String, pub details:String }
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScanResult { pub id:String, pub filename:String, pub filepath:String, pub filesize:u64, pub filehash:String, pub timestamp:String, pub services:HashMap<String,ServiceResult>, pub overall_verdict:String }
pub struct AppState { pub db:Arc<Mutex<db::Database>>, pub keys:Arc<Mutex<ApiKeys>>, pub auto_scan:Arc<Mutex<bool>> }
pub struct ApiKeys { pub vt:String, pub md:String, pub ha:String, pub cm:String }

pub async fn do_scan(file_path:String, services:Vec<String>, vt_key:String, md_key:String, ha_key:String, cm_key:String, db:Arc<Mutex<db::Database>>) -> Result<ScanResult,String> {
    let meta=fs::metadata(&file_path).map_err(|e|e.to_string())?;
    let bytes=fs::read(&file_path).map_err(|e|e.to_string())?;
    let mut hasher=Sha256::new(); hasher.update(&bytes);
    let hash=format!("{:x}",hasher.finalize());
    let filename=std::path::Path::new(&file_path).file_name().unwrap_or_default().to_string_lossy().to_string();
    let mut svc_map:HashMap<String,ServiceResult>=HashMap::new();
    for svc in &services {
        let r=match svc.as_str() {
            "virustotal"     => scan_virustotal(&hash,&bytes,&filename,&vt_key).await,
            "metadefender"   => scan_metadefender(&hash,&md_key).await,
            "hybridanalysis" => scan_hybrid_analysis(&hash,&ha_key).await,
            "cloudmersive"   => scan_cloudmersive(&bytes,&filename,&cm_key).await,
            "clamav"         => scan_clamav(&file_path),
            _ => ServiceResult{status:"unknown".into(),detections:0,engines:0,verdict:"pending".into(),details:"Servizio non supportato".into()},
        };
        svc_map.insert(svc.clone(),r);
    }
    let overall=compute_verdict(&svc_map);
    let result=ScanResult{id:uuid::Uuid::new_v4().to_string(),filename,filepath:file_path,filesize:meta.len(),filehash:hash,timestamp:chrono::Utc::now().to_rfc3339(),services:svc_map,overall_verdict:overall};
    {let db=db.lock().unwrap();let _=db.insert_scan(&result);}
    Ok(result)
}

fn scan_clamav(file_path:&str)->ServiceResult {
    match std::process::Command::new("clamscan").args(["--no-summary","--infected",file_path]).output() {
        Ok(out)=>{let s=String::from_utf8_lossy(&out.stdout).to_string();let inf=s.contains("FOUND");ServiceResult{status:"scanned".into(),detections:if inf{1}else{0},engines:1,verdict:if inf{"malicious"}else{"clean"}.into(),details:if inf{s.lines().find(|l|l.contains("FOUND")).unwrap_or("Malware rilevato").to_string()}else{"Nessuna minaccia (ClamAV)".into()}}},
        Err(_)=>ServiceResult{status:"not_installed".into(),detections:0,engines:0,verdict:"pending".into(),details:"ClamAV non installato. Scarica da clamav.net".into()},
    }
}

async fn scan_virustotal(hash:&str,bytes:&[u8],filename:&str,api_key:&str)->ServiceResult {
    if api_key.is_empty(){return ServiceResult{status:"no_key".into(),detections:0,engines:0,verdict:"pending".into(),details:"API key VirusTotal non configurata in Impostazioni".into()};}
    let client=reqwest::Client::new();
    match client.get(format!("https://www.virustotal.com/api/v3/files/{}",hash)).header("x-apikey",api_key).send().await {
        Ok(r) if r.status().is_success()=>{if let Ok(j)=r.json::<serde_json::Value>().await{let s=&j["data"]["attributes"]["last_analysis_stats"];let mal=s["malicious"].as_u64().unwrap_or(0) as u32;let sus=s["suspicious"].as_u64().unwrap_or(0) as u32;let tot=mal+sus+s["harmless"].as_u64().unwrap_or(0) as u32+s["undetected"].as_u64().unwrap_or(0) as u32;let v=if mal>0{"malicious"}else if sus>0{"suspicious"}else{"clean"};return ServiceResult{status:"found".into(),detections:mal+sus,engines:tot,verdict:v.into(),details:format!("{} rilevazioni su {} engine",mal+sus,tot)};} ServiceResult{status:"error".into(),detections:0,engines:0,verdict:"pending".into(),details:"Risposta non valida".into()}},
        Ok(r) if r.status()==404=>upload_virustotal(bytes,filename,api_key).await,
        Ok(r)=>ServiceResult{status:"error".into(),detections:0,engines:0,verdict:"pending".into(),details:format!("HTTP {}",r.status())},
        Err(e)=>ServiceResult{status:"error".into(),detections:0,engines:0,verdict:"pending".into(),details:e.to_string()},
    }
}
async fn upload_virustotal(bytes:&[u8],filename:&str,api_key:&str)->ServiceResult {
    let client=reqwest::Client::new();
    let part=reqwest::multipart::Part::bytes(bytes.to_vec()).file_name(filename.to_string());
    let form=reqwest::multipart::Form::new().part("file",part);
    match client.post("https://www.virustotal.com/api/v3/files").header("x-apikey",api_key).multipart(form).send().await {
        Ok(r) if r.status().is_success()=>ServiceResult{status:"uploaded".into(),detections:0,engines:0,verdict:"pending".into(),details:"File inviato a VirusTotal, ricontrolla tra pochi minuti".into()},
        Ok(r)=>ServiceResult{status:"error".into(),detections:0,engines:0,verdict:"pending".into(),details:format!("Upload HTTP {}",r.status())},
        Err(e)=>ServiceResult{status:"error".into(),detections:0,engines:0,verdict:"pending".into(),details:e.to_string()},
    }
}
async fn scan_metadefender(hash:&str,api_key:&str)->ServiceResult {
    if api_key.is_empty(){return ServiceResult{status:"no_key".into(),detections:0,engines:0,verdict:"pending".into(),details:"API key MetaDefender non configurata in Impostazioni".into()};}
    let client=reqwest::Client::new();
    match client.get(format!("https://api.metadefender.com/v4/hash/{}",hash)).header("apikey",api_key).send().await {
        Ok(r) if r.status().is_success()=>{if let Ok(j)=r.json::<serde_json::Value>().await{let det=j["scan_results"]["scan_all_result_i"].as_u64().unwrap_or(0);let tot=j["scan_results"]["total_avs"].as_u64().unwrap_or(0) as u32;let pos=j["scan_results"]["total_detected_avs"].as_u64().unwrap_or(0) as u32;return ServiceResult{status:"found".into(),detections:pos,engines:tot,verdict:if det>0{"malicious"}else{"clean"}.into(),details:format!("{} rilevazioni su {} engine",pos,tot)};} ServiceResult{status:"error".into(),detections:0,engines:0,verdict:"pending".into(),details:"Risposta non valida".into()}},
        Ok(r) if r.status()==404=>ServiceResult{status:"not_found".into(),detections:0,engines:0,verdict:"clean".into(),details:"Hash non trovato in MetaDefender".into()},
        Ok(r)=>ServiceResult{status:"error".into(),detections:0,engines:0,verdict:"pending".into(),details:format!("HTTP {}",r.status())},
        Err(e)=>ServiceResult{status:"error".into(),detections:0,engines:0,verdict:"pending".into(),details:e.to_string()},
    }
}
async fn scan_hybrid_analysis(hash:&str,api_key:&str)->ServiceResult {
    if api_key.is_empty(){return ServiceResult{status:"no_key".into(),detections:0,engines:0,verdict:"pending".into(),details:"API key Hybrid Analysis non configurata in Impostazioni".into()};}
    let client=reqwest::Client::new();
    match client.get(format!("https://www.hybrid-analysis.com/api/v2/search/hash?hash={}",hash)).header("api-key",api_key).header("User-Agent","Falcon Sandbox").header("accept","application/json").send().await {
        Ok(r) if r.status().is_success()=>{if let Ok(j)=r.json::<serde_json::Value>().await{let arr=j.as_array().cloned().unwrap_or_default();if arr.is_empty(){return ServiceResult{status:"not_found".into(),detections:0,engines:0,verdict:"clean".into(),details:"Hash non trovato in Hybrid Analysis".into()};}let first=&arr[0];let ts=first["threat_score"].as_u64().unwrap_or(0);let vstr=first["verdict"].as_str().unwrap_or("no specific threat");let v=if ts>70{"malicious"}else if ts>30{"suspicious"}else{"clean"};return ServiceResult{status:"found".into(),detections:if ts>0{1}else{0},engines:arr.len() as u32,verdict:v.into(),details:format!("Threat score: {} — {}",ts,vstr)};} ServiceResult{status:"error".into(),detections:0,engines:0,verdict:"pending".into(),details:"Risposta non valida".into()}},
        Ok(r)=>ServiceResult{status:"error".into(),detections:0,engines:0,verdict:"pending".into(),details:format!("HTTP {}",r.status())},
        Err(e)=>ServiceResult{status:"error".into(),detections:0,engines:0,verdict:"pending".into(),details:e.to_string()},
    }
}
async fn scan_cloudmersive(bytes:&[u8],filename:&str,api_key:&str)->ServiceResult {
    if api_key.is_empty(){return ServiceResult{status:"no_key".into(),detections:0,engines:0,verdict:"pending".into(),details:"API key Cloudmersive non configurata in Impostazioni".into()};}
    let client=reqwest::Client::new();
    let part=reqwest::multipart::Part::bytes(bytes.to_vec()).file_name(filename.to_string());
    let form=reqwest::multipart::Form::new().part("inputFile",part);
    match client.post("https://api.cloudmersive.com/virus/scan/file").header("Apikey",api_key).multipart(form).send().await {
        Ok(r) if r.status().is_success()=>{if let Ok(j)=r.json::<serde_json::Value>().await{let clean=j["CleanResult"].as_bool().unwrap_or(true);let fv=j["FoundViruses"].as_array().cloned().unwrap_or_default();let num=fv.len() as u32;let details=if !clean && !fv.is_empty(){fv.iter().filter_map(|v|v["VirusName"].as_str()).collect::<Vec<_>>().join(", ")}else{"Nessuna minaccia (Cloudmersive)".into()};return ServiceResult{status:"scanned".into(),detections:num,engines:1,verdict:if !clean{"malicious"}else{"clean"}.into(),details};} ServiceResult{status:"error".into(),detections:0,engines:0,verdict:"pending".into(),details:"Risposta non valida".into()}},
        Ok(r)=>ServiceResult{status:"error".into(),detections:0,engines:0,verdict:"pending".into(),details:format!("HTTP {}",r.status())},
        Err(e)=>ServiceResult{status:"error".into(),detections:0,engines:0,verdict:"pending".into(),details:e.to_string()},
    }
}
fn compute_verdict(services:&HashMap<String,ServiceResult>)->String {
    if services.values().any(|s|s.verdict=="malicious") {return "malicious".into();}
    if services.values().any(|s|s.verdict=="suspicious"){return "suspicious".into();}
    if services.values().all(|s|s.verdict=="clean")     {return "clean".into();}
    "pending".into()
}

#[tauri::command]
async fn scan_file(file_path:String,services:Vec<String>,vt_key:String,md_key:String,ha_key:String,cm_key:String,state:tauri::State<'_,Arc<AppState>>)->Result<ScanResult,String> {
    do_scan(file_path,services,vt_key,md_key,ha_key,cm_key,state.db.clone()).await
}
#[tauri::command]
fn get_history(state:tauri::State<'_,Arc<AppState>>)->Result<Vec<db::ScanRecord>,String> {
    state.db.lock().unwrap().get_all_scans().map_err(|e|e.to_string())
}
#[tauri::command]
fn clear_history(state:tauri::State<'_,Arc<AppState>>)->Result<(),String> {
    state.db.lock().unwrap().clear_history().map_err(|e|e.to_string())
}
#[tauri::command]
fn set_watcher_keys(vt:String,md:String,ha:String,cm:String,state:tauri::State<'_,Arc<AppState>>)->Result<(),String> {
    let mut k=state.keys.lock().unwrap(); k.vt=vt; k.md=md; k.ha=ha; k.cm=cm; Ok(())
}
#[tauri::command]
fn set_auto_scan(enabled:bool,state:tauri::State<'_,Arc<AppState>>)->Result<(),String> {
    *state.auto_scan.lock().unwrap()=enabled; Ok(())
}

fn main() {
    let app_state=Arc::new(AppState{
        db:Arc::new(Mutex::new(db::Database::new().expect("db init failed"))),
        keys:Arc::new(Mutex::new(ApiKeys{vt:String::new(),md:String::new(),ha:String::new(),cm:String::new()})),
        auto_scan:Arc::new(Mutex::new(true)),
    });
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(app_state.clone())
        .setup(move|app|{file_watcher::start_watcher(app.handle().clone(),app_state.clone());Ok(())})
        .invoke_handler(tauri::generate_handler![scan_file,get_history,clear_history,set_watcher_keys,set_auto_scan])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
