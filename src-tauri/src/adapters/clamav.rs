
use std::path::Path;
use async_trait::async_trait;
use super::scanner_trait::{ScanProvider,ProviderResult,Verdict};

pub struct ClamAVAdapter;
impl ClamAVAdapter { pub fn new()->Self{ Self } }

#[async_trait]
impl ScanProvider for ClamAVAdapter {
    fn id(&self)->&'static str{"clamav"} fn name(&self)->&'static str{"ClamAV (locale)"}
    fn is_cloud(&self)->bool{false}
    fn is_enabled(&self)->bool{ std::process::Command::new("clamscan").arg("--version").output().is_ok() }

    async fn scan_hash(&self,_hash:&str)->ProviderResult { ProviderResult::unavailable("clamav","ClamAV requires file path") }

    async fn scan_file(&self,path:&Path,_hash:&str,_filename:&str)->ProviderResult {
        let fp=path.to_string_lossy().to_string();
        match std::process::Command::new("clamscan").args(["--no-summary","--infected",&fp]).output() {
            Ok(out)=>{
                let s=String::from_utf8_lossy(&out.stdout).to_string();
                let infected=s.contains("FOUND");
                ProviderResult{provider_id:"clamav".into(),verdict:if infected{Verdict::Malicious}else{Verdict::Clean},detections:if infected{1}else{0},total_engines:1,
                    details:if infected{s.lines().find(|l|l.contains("FOUND")).unwrap_or("Malware rilevato").to_string()}else{"Nessuna minaccia rilevata".into()},poll_id:None}
            },
            Err(_)=>ProviderResult::unavailable("clamav","ClamAV non installato — scarica da clamav.net"),
        }
    }
}
