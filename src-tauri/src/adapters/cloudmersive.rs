
use std::path::Path; use std::sync::{Arc,Mutex};
use async_trait::async_trait;
use super::scanner_trait::{ScanProvider,ProviderResult,Verdict};
pub struct CloudmersiveAdapter{key:Arc<Mutex<String>>,client:reqwest::Client}
impl CloudmersiveAdapter{pub fn new(k:Arc<Mutex<String>>)->Self{Self{key:k,client:reqwest::Client::new()}}}
fn k(a:&Arc<Mutex<String>>)->String{a.lock().unwrap().clone()}
#[async_trait]
impl ScanProvider for CloudmersiveAdapter {
    fn id(&self)->&'static str{"cloudmersive"} fn name(&self)->&'static str{"Cloudmersive"}
    fn is_cloud(&self)->bool{true} fn is_enabled(&self)->bool{!k(&self.key).is_empty()}
    async fn scan_hash(&self,_h:&str)->ProviderResult{ProviderResult::unavailable("cloudmersive","Cloudmersive richiede upload file")}
    async fn scan_file(&self,path:&Path,_hash:&str,filename:&str)->ProviderResult {
        let key=k(&self.key); if key.is_empty(){return ProviderResult::unavailable("cloudmersive","API key non configurata");}
        let bytes=match tokio::fs::read(path).await{Ok(b)=>b,Err(e)=>return ProviderResult::error("cloudmersive",&e.to_string())};
        let form=reqwest::multipart::Form::new().part("inputFile",reqwest::multipart::Part::bytes(bytes).file_name(filename.to_string()));
        match reqwest::Client::new().post("https://api.cloudmersive.com/virus/scan/file").header("Apikey",&key).multipart(form).send().await {
            Ok(r) if r.status().is_success()=>{if let Ok(j)=r.json::<serde_json::Value>().await{let clean=j["CleanResult"].as_bool().unwrap_or(true);let fv=j["FoundViruses"].as_array().cloned().unwrap_or_default();let num=fv.len() as u32;let det=if !clean&&!fv.is_empty(){fv.iter().filter_map(|v|v["VirusName"].as_str()).collect::<Vec<_>>().join(", ")}else{"Nessuna minaccia (Cloudmersive)".into()};return ProviderResult{provider_id:"cloudmersive".into(),verdict:if !clean{Verdict::Malicious}else{Verdict::Clean},detections:num,total_engines:1,details:det,poll_id:None};}ProviderResult::error("cloudmersive","Risposta non valida")},
            Ok(r)=>ProviderResult::error("cloudmersive",&format!("HTTP {}",r.status())),
            Err(e)=>ProviderResult::error("cloudmersive",&e.to_string()),
        }
    }
}
