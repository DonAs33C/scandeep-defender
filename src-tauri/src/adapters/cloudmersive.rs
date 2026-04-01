use async_trait::async_trait;
use std::path::Path;
use std::sync::{Arc, Mutex};
use reqwest::Client;
use serde_json::Value;

use crate::adapters::scanner_trait::{ScanProvider, ProviderResult, Verdict};

pub struct CloudmersiveAdapter {
    key:    Arc<Mutex<String>>,
    #[allow(dead_code)]          // usato nelle chiamate HTTP future
    client: Client,
}

impl CloudmersiveAdapter {
    pub fn new(key: Arc<Mutex<String>>) -> Self {
        Self { key, client: Client::new() }
    }

    fn key(&self) -> String {
        self.key.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

#[async_trait]
impl ScanProvider for CloudmersiveAdapter {
    fn id(&self)   -> &'static str { "cloudmersive" }
    fn name(&self) -> &'static str { "Cloudmersive" }
    fn is_cloud(&self) -> bool { true }
    fn is_enabled(&self) -> bool { !self.key().is_empty() }
    fn supports_file_upload(&self) -> bool { true }

    async fn scan_hash(&self, _hash: &str) -> ProviderResult {
        ProviderResult::unavailable(self.id(), "Cloudmersive non supporta lookup per hash")
    }

    async fn scan_file(&self, path: &Path, _hash: &str, filename: &str) -> ProviderResult {
        let key = self.key();
        if key.is_empty() {
            return ProviderResult::unavailable(self.id(), "Nessuna API key configurata");
        }

        let bytes = match tokio::fs::read(path).await {
            Ok(b) => b,
            Err(e) => return ProviderResult::error(self.id(), &e.to_string()),
        };

        let part = reqwest::multipart::Part::bytes(bytes)
            .file_name(filename.to_string())
            .mime_str("application/octet-stream")
            .unwrap_or_else(|_| reqwest::multipart::Part::bytes(vec![]));

        let form = reqwest::multipart::Form::new().part("inputFile", part);

        let client = Client::new();
        let resp = match client
            .post("https://api.cloudmersive.com/virus/scan/file")
            .header("Apikey", &key)
            .multipart(form)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => return ProviderResult::error(self.id(), &e.to_string()),
        };

        if !resp.status().is_success() {
            return ProviderResult::error(
                self.id(),
                &format!("HTTP {}", resp.status()),
            );
        }

        let json: Value = match resp.json().await {
            Ok(j) => j,
            Err(e) => return ProviderResult::error(self.id(), &e.to_string()),
        };

        let clean   = json["CleanResult"].as_bool().unwrap_or(false);
        let threats = json["FoundViruses"].as_array().map(|a| a.len() as u32).unwrap_or(0);

        ProviderResult {
            provider_id:   self.id().into(),
            verdict:       if clean { Verdict::Clean } else { Verdict::Malicious },
            detections:    threats,
            total_engines: 1,
            details:       if clean {
                "Nessuna minaccia rilevata".into()
            } else {
                format!("{} minacce rilevate", threats)
            },
            poll_id: None,
        }
    }

    async fn poll_result(&self, _poll_id: &str) -> ProviderResult {
        ProviderResult::unavailable(self.id(), "Cloudmersive non richiede polling")
    }
}
