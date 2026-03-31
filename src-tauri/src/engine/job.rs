
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::SystemTime;
use uuid::Uuid;
use crate::adapters::scanner_trait::{ProviderResult, Verdict};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JobStatus { Pending, Hashing, Scanning, Polling, Completed, Failed }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanJob {
    pub id:                 String,
    pub file_path:          PathBuf,
    pub filename:           String,
    pub filesize:           u64,
    pub hash:               Option<String>,
    pub status:             JobStatus,
    pub requested_providers:Vec<String>,
    pub allow_cloud_upload: bool,
    pub created_at:         SystemTime,
    pub retry_count:        u32,
    pub max_retries:        u32,
}

impl ScanJob {
    pub fn new(file_path: PathBuf, providers: Vec<String>, allow_cloud_upload: bool) -> Self {
        let filename = file_path.file_name()
            .unwrap_or_default().to_string_lossy().to_string();
        let filesize = std::fs::metadata(&file_path).map(|m| m.len()).unwrap_or(0);
        Self {
            id: Uuid::new_v4().to_string(),
            file_path, filename, filesize, hash: None,
            status: JobStatus::Pending,
            requested_providers: providers,
            allow_cloud_upload,
            created_at: SystemTime::now(),
            retry_count: 0, max_retries: 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub job_id:          String,
    pub filename:        String,
    pub filepath:        String,
    pub filesize:        u64,
    pub hash:            String,
    pub timestamp:       String,
    pub results:         Vec<ProviderResult>,
    pub overall_verdict: Verdict,
    pub risk_score:      u8,  // 0–100
    pub from_cache:      bool,
}

impl ScanReport {
    pub fn compute_verdict(results: &[ProviderResult]) -> Verdict {
        if results.iter().any(|r| r.verdict == Verdict::Malicious)  { return Verdict::Malicious; }
        if results.iter().any(|r| r.verdict == Verdict::Suspicious) { return Verdict::Suspicious; }
        if results.iter().all(|r| matches!(r.verdict, Verdict::Clean | Verdict::Unavailable | Verdict::Error)) { return Verdict::Clean; }
        Verdict::Pending
    }
}
