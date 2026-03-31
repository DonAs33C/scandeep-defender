
use std::path::Path; use std::sync::{Arc,Mutex};
use async_trait::async_trait;
use super::scanner_trait::{ScanProvider,ProviderResult,Verdict};
pub struct MetaDefenderAdapter{key:Arc<Mutex<String>>,client:reqwest::Client}
impl MetaDefenderAdapter{pub fn new(k:Arc<Mutex<String>>)->Self{Self{key:k,client:reqwest::Client::new()}}}
fn k(a:&Arc<Mutex<String>>)->String{a.lock().unwrap().clone()}
#[async_trait]
impl ScanProvider for MetaDefenderAdapter {
    fn id(&self)->&'static str{"metadefender"} fn name(&self)->&'static str{"MetaDefender"}
    fn is_cloud(&self)->bool{true} fn is_enabled(&self)->bool{!k(&self.key).is_empty()}
    async fn scan_hash(&self,hash:&str)->ProviderResult {
        let key=k(&self.key); if key.is_empty(){return ProviderResult::unavailable("metadefender","API key non configurata");}
        match self.client.get(format!("https://api.metadefender.com/v4/hash/{}",hash)).header("apikey",&key).send().await {
            Ok(r) if r.status().is_success()=>{if let Ok(j)=r.json::<serde_json::Value>().await{let det=j["scan_results"]["scan_all_result_i"].as_u64().unwrap_or(0);let tot=j["scan_results"]["total_avs"].as_u64().unwrap_or(0) as u32;let pos=j["scan_results"]["total_detected_avs"].as_u64().unwrap_or(0) as u32;return ProviderResult{provider_id:"metadefender".into(),verdict:if det>0{Verdict::Malicious}else{Verdict::Clean},detections:pos,total_engines:tot,details:format!("{} rilevazioni su {} engine",pos,tot),poll_id:None};}ProviderResult::error("metadefender","Risposta non valida")},
            Ok(r) if r.status()==404=>ProviderResult{provider_id:"metadefender".into(),verdict:Verdict::Unavailable,detections:0,total_engines:0,details:"Hash non trovato".into(),poll_id:None},
            Ok(r)=>ProviderResult::error("metadefender",&format!("HTTP {}",r.status())),
            Err(e)=>ProviderResult::error("metadefender",&e.to_string()),
        }
    }
    async fn scan_file(&self,_path:&Path,_hash:&str,_fn:&str)->ProviderResult{ ProviderResult::unavailable("metadefender","Upload non supportato (piano free)") }
}
