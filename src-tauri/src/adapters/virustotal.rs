
use std::path::Path;
use std::sync::{Arc,Mutex};
use async_trait::async_trait;
use super::scanner_trait::{ScanProvider,ProviderResult,Verdict};

pub struct VirusTotalAdapter { key:Arc<Mutex<String>>, client:reqwest::Client }
impl VirusTotalAdapter { pub fn new(k:Arc<Mutex<String>>)->Self{ Self{key:k,client:reqwest::Client::new()} } }
fn k(a:&Arc<Mutex<String>>)->String{ a.lock().unwrap().clone() }

#[async_trait]
impl ScanProvider for VirusTotalAdapter {
    fn id(&self)->&'static str{"virustotal"} fn name(&self)->&'static str{"VirusTotal"}
    fn is_cloud(&self)->bool{true} fn is_enabled(&self)->bool{!k(&self.key).is_empty()}

    async fn scan_hash(&self,hash:&str)->ProviderResult {
        let key=k(&self.key); if key.is_empty(){return ProviderResult::unavailable("virustotal","API key non configurata");}
        match self.client.get(format!("https://www.virustotal.com/api/v3/files/{}",hash)).header("x-apikey",&key).send().await {
            Ok(r) if r.status().is_success() => {
                if let Ok(j)=r.json::<serde_json::Value>().await {
                    let s=&j["data"]["attributes"]["last_analysis_stats"];
                    let mal=s["malicious"].as_u64().unwrap_or(0) as u32; let sus=s["suspicious"].as_u64().unwrap_or(0) as u32;
                    let tot=mal+sus+s["harmless"].as_u64().unwrap_or(0) as u32+s["undetected"].as_u64().unwrap_or(0) as u32;
                    return ProviderResult{provider_id:"virustotal".into(),verdict:if mal>0{Verdict::Malicious}else if sus>0{Verdict::Suspicious}else{Verdict::Clean},detections:mal+sus,total_engines:tot,details:format!("{} rilevazioni su {} engine",mal+sus,tot),poll_id:None};
                } ProviderResult::error("virustotal","Risposta non valida")
            },
            Ok(r) if r.status()==404 => ProviderResult{provider_id:"virustotal".into(),verdict:Verdict::Unavailable,detections:0,total_engines:0,details:"Hash non trovato — upload richiesto".into(),poll_id:None},
            Ok(r) => ProviderResult::error("virustotal",&format!("HTTP {}",r.status())),
            Err(e)=> ProviderResult::error("virustotal",&e.to_string()),
        }
    }
    async fn scan_file(&self,path:&Path,_hash:&str,filename:&str)->ProviderResult {
        let key=k(&self.key); if key.is_empty(){return ProviderResult::unavailable("virustotal","API key non configurata");}
        let bytes=match tokio::fs::read(path).await{Ok(b)=>b,Err(e)=>return ProviderResult::error("virustotal",&e.to_string())};
        let form=reqwest::multipart::Form::new().part("file",reqwest::multipart::Part::bytes(bytes).file_name(filename.to_string()));
        match self.client.post("https://www.virustotal.com/api/v3/files").header("x-apikey",&key).multipart(form).send().await {
            Ok(r) if r.status().is_success() => {
                if let Ok(j)=r.json::<serde_json::Value>().await { let pid=j["data"]["id"].as_str().map(|s|s.to_string()); return ProviderResult::pending("virustotal",pid,"File caricato, aggiorna tra 1-2 min"); }
                ProviderResult::pending("virustotal",None,"File caricato su VirusTotal")
            },
            Ok(r)=>ProviderResult::error("virustotal",&format!("Upload HTTP {}",r.status())),
            Err(e)=>ProviderResult::error("virustotal",&e.to_string()),
        }
    }
    async fn poll_result(&self,poll_id:&str)->ProviderResult {
        let key=k(&self.key); if key.is_empty(){return ProviderResult::unavailable("virustotal","API key non configurata");}
        match self.client.get(format!("https://www.virustotal.com/api/v3/analyses/{}",poll_id)).header("x-apikey",&key).send().await {
            Ok(r) if r.status().is_success() => {
                if let Ok(j)=r.json::<serde_json::Value>().await {
                    let st=j["data"]["attributes"]["status"].as_str().unwrap_or("");
                    if st=="completed" {
                        let s=&j["data"]["attributes"]["stats"];
                        let mal=s["malicious"].as_u64().unwrap_or(0) as u32; let sus=s["suspicious"].as_u64().unwrap_or(0) as u32;
                        let tot=mal+sus+s["harmless"].as_u64().unwrap_or(0) as u32+s["undetected"].as_u64().unwrap_or(0) as u32;
                        return ProviderResult{provider_id:"virustotal".into(),verdict:if mal>0{Verdict::Malicious}else if sus>0{Verdict::Suspicious}else{Verdict::Clean},detections:mal+sus,total_engines:tot,details:format!("{} rilevazioni su {} engine",mal+sus,tot),poll_id:None};
                    }
                    return ProviderResult::pending("virustotal",Some(poll_id.to_string()),&format!("Stato: {}",st));
                } ProviderResult::error("virustotal","Risposta non valida")
            },
            Ok(r)=>ProviderResult::error("virustotal",&format!("HTTP {}",r.status())),
            Err(e)=>ProviderResult::error("virustotal",&e.to_string()),
        }
    }
}
