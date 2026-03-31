
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict { Clean, Suspicious, Malicious, Pending, Unavailable, Error }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderResult {
    pub provider_id: String,
    pub verdict:      Verdict,
    pub detections:   u32,
    pub total_engines:u32,
    pub details:      String,
    pub poll_id:      Option<String>,
}

impl ProviderResult {
    pub fn unavailable(provider_id: &str, reason: &str) -> Self {
        Self { provider_id: provider_id.into(), verdict: Verdict::Unavailable,
               detections:0, total_engines:0, details: reason.into(), poll_id:None }
    }
    pub fn error(provider_id: &str, err: &str) -> Self {
        Self { provider_id: provider_id.into(), verdict: Verdict::Error,
               detections:0, total_engines:0, details: err.into(), poll_id:None }
    }
    pub fn pending(provider_id: &str, poll_id: Option<String>, msg: &str) -> Self {
        Self { provider_id: provider_id.into(), verdict: Verdict::Pending,
               detections:0, total_engines:0, details: msg.into(), poll_id }
    }
}

#[async_trait]
pub trait ScanProvider: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn is_cloud(&self) -> bool;
    fn is_enabled(&self) -> bool { true }

    /// Lookup hash only — no file upload.
    async fn scan_hash(&self, hash: &str) -> ProviderResult;

    /// Upload + scan file. Called only when hash not known and user enabled cloud upload.
    async fn scan_file(&self, path: &Path, hash: &str, filename: &str) -> ProviderResult;

    /// Poll for a deferred result (e.g. VT analysis).
    async fn poll_result(&self, _poll_id: &str) -> ProviderResult {
        ProviderResult::unavailable(self.id(), "Polling not supported")
    }
}
