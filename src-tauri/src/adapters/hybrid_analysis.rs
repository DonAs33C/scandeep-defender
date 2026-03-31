
use std::path::Path; use std::sync::{Arc,Mutex};
use async_trait::async_trait;
use super::scanner_trait::{ScanProvider,ProviderResult,Verdict};
pub struct HybridAnalysisAdapter{key:Arc<Mutex<String>>,client:reqwest::Client}
impl HybridAnalysisAdapter{pub fn new(k:Arc<Mutex<String>>)->Self{Self{key:k,client:reqwest::Client::new()}}}
fn k(a:&Arc<Mutex<String>>)->String{a.lock().unwrap().clone()}
#[async_trait]
impl ScanProvider for HybridAnalysisAdapter {
    fn id(&self)->&'static str{"hybridanalysis"} fn name(&self)->&'static str{"Hybrid Analysis"}
    fn is_cloud(&self)->bool{true} fn is_enabled(&self)->bool{!k(&self.key).is_empty()}
    async fn scan_hash(&self,hash:&str)->ProviderResult {
        let key=k(&self.key); if key.is_empty(){return ProviderResult::unavailable("hybridanalysis","API key non configurata");}
        match self.client.get(format!("https://www.hybrid-analysis.com/api/v2/search/hash?hash={}",hash)).header("api-key",&key).header("User-Agent","Falcon Sandbox").header("accept","application/json").send().await {
            Ok(r) if r.status().is_success()=>{if let Ok(j)=r.json::<serde_json::Value>().await{let arr=j.as_array().cloned().unwrap_or_default();if arr.is_empty(){return ProviderResult{provider_id:"hybridanalysis".into(),verdict:Verdict::Unavailable,detections:0,total_engines:0,details:"Hash non trovato".into(),poll_id:None};}let f=&arr[0];let ts=f["threat_score"].as_u64().unwrap_or(0);let vs=f["verdict"].as_str().unwrap_or("no specific threat");let v=if ts>70{Verdict::Malicious}else if ts>30{Verdict::Suspicious}else{Verdict::Clean};return ProviderResult{provider_id:"hybridanalysis".into(),verdict:v,detections:if ts>0{1}else{0},total_engines:arr.len() as u32,details:format!("Threat score: {} — {}",ts,vs),poll_id:None};}ProviderResult::error("hybridanalysis","Risposta non valida")},
            Ok(r)=>ProviderResult::error("hybridanalysis",&format!("HTTP {}",r.status())),
            Err(e)=>ProviderResult::error("hybridanalysis",&e.to_string()),
        }
    }
    async fn scan_file(&self,_p:&Path,_h:&str,_f:&str)->ProviderResult{ProviderResult::unavailable("hybridanalysis","Usa scan_hash per Hybrid Analysis")}
}
