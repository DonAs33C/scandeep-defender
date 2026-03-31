
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug,Clone,Serialize,Deserialize,PartialEq)]
#[serde(rename_all="snake_case")]
pub enum Verdict { Clean, Suspicious, Malicious, Pending, Unavailable, Error }

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct ProviderResult {
    pub provider_id:   String,
    pub verdict:       Verdict,
    pub detections:    u32,
    pub total_engines: u32,
    pub details:       String,
    #[serde(skip_serializing_if="Option::is_none")]
    pub poll_id:       Option<String>,
}
impl ProviderResult {
    pub fn unavailable(pid:&str,msg:&str)->Self{ Self{provider_id:pid.into(),verdict:Verdict::Unavailable,detections:0,total_engines:0,details:msg.into(),poll_id:None} }
    pub fn error(pid:&str,msg:&str)->Self{ Self{provider_id:pid.into(),verdict:Verdict::Error,detections:0,total_engines:0,details:msg.into(),poll_id:None} }
    pub fn pending(pid:&str,poll_id:Option<String>,msg:&str)->Self{ Self{provider_id:pid.into(),verdict:Verdict::Pending,detections:0,total_engines:0,details:msg.into(),poll_id} }
}

#[async_trait]
pub trait ScanProvider: Send + Sync {
    fn id(&self)   -> &'static str;
    fn name(&self) -> &'static str;
    fn is_cloud(&self) -> bool;
    fn is_enabled(&self)          -> bool { true }
    fn supports_file_upload(&self)-> bool { true }   // FIX: era in ScanProviderExt

    async fn scan_hash(&self, hash: &str) -> ProviderResult;
    async fn scan_file(&self, path: &Path, hash: &str, filename: &str) -> ProviderResult;
    async fn poll_result(&self, _poll_id: &str) -> ProviderResult {
        ProviderResult::unavailable(self.id(), "Polling non supportato")
    }
}
