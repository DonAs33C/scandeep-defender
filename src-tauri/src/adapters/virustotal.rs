use async_trait::async_trait;
use std::path::Path;
use std::sync::{Arc, Mutex};
use reqwest::{Client, multipart};
use serde_json::Value;
use tokio::time::{sleep, Duration};

use crate::adapters::scanner_trait::{ScanProvider, ProviderResult, Verdict};

const BASE: &str = "https://www.virustotal.com/api/v3";

pub struct VirusTotalAdapter {
    client:  Client,
    api_key: Arc<Mutex<String>>,
}

impl VirusTotalAdapter {
    pub fn new(api_key: Arc<Mutex<String>>) -> Self {
        Self { client: Client::new(), api_key }
    }

    fn key(&self) -> String {
        self.api_key.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

#[async_trait]
impl ScanProvider for VirusTotalAdapter {
    fn id(&self)   -> &'static str { "virustotal" }
    fn name(&self) -> &'static str { "VirusTotal" }
    fn is_cloud(&self) -> bool { true }
    fn is_enabled(&self) -> bool { !self.key().is_empty() }
    fn supports_file_upload(&self) -> bool { true }

    async fn scan_hash(&self, hash: &str) -> ProviderResult {
        let key = self.key();
        if key.is_empty() {
            return ProviderResult::unavailable(self.id(), "Nessuna API key configurata");
        }
        let url  = format!("{}/files/{}", BASE, hash);
        let resp = match self.client.get(&url).header("x-apikey", &key).send().await {
            Ok(r)  => r,
            Err(e) => return ProviderResult::error(self.id(), &e.to_string()),
        };
        match resp.status().as_u16() {
            200 => parse_vt_response(self.id(), resp.json::<Value>().await.ok()),
            404 => ProviderResult::unavailable(self.id(), "Hash non trovato — verrà caricato il file"),
            401 => ProviderResult::error(self.id(), "API key non valida"),
            429 => ProviderResult::error(self.id(), "Rate limit superato"),
            s   => ProviderResult::error(self.id(), &format!("HTTP {}", s)),
        }
    }

    async fn scan_file(&self, path: &Path, _hash: &str, filename: &str) -> ProviderResult {
        let key = self.key();
        if key.is_empty() {
            return ProviderResult::unavailable(self.id(), "Nessuna API key configurata");
        }
        let bytes = match tokio::fs::read(path).await {
            Ok(b)  => b,
            Err(e) => return ProviderResult::error(self.id(), &e.to_string()),
        };
        let part = multipart::Part::bytes(bytes)
            .file_name(filename.to_string())
            .mime_str("application/octet-stream")
            .unwrap_or_else(|_| multipart::Part::bytes(vec![]));
        let form = multipart::Form::new().part("file", part);
        let resp = match self.client
            .post(format!("{}/files", BASE))
            .header("x-apikey", &key)
            .multipart(form)
            .send().await
        {
            Ok(r)  => r,
            Err(e) => return ProviderResult::error(self.id(), &e.to_string()),
        };
        if !resp.status().is_success() {
            return ProviderResult::error(self.id(), &format!("Upload HTTP {}", resp.status()));
        }
        let json: Value = match resp.json().await {
            Ok(j)  => j,
            Err(e) => return ProviderResult::error(self.id(), &e.to_string()),
        };
        let analysis_id = json["data"]["id"].as_str().unwrap_or("").to_string();
        if analysis_id.is_empty() {
            return ProviderResult::error(self.id(), "Nessun analysis_id ricevuto da VT");
        }
        for attempt in 0..12u8 {
            sleep(Duration::from_secs(if attempt == 0 { 5 } else { 10 })).await;
            let r = self.poll_result(&analysis_id).await;
            if r.verdict != Verdict::Pending { return r; }
        }
        ProviderResult::pending(self.id(), Some(analysis_id), "Analisi in corso su VirusTotal")
    }

    async fn poll_result(&self, poll_id: &str) -> ProviderResult {
        let key = self.key();
        if key.is_empty() {
            return ProviderResult::error(self.id(), "API key mancante");
        }
        let url  = format!("{}/analyses/{}", BASE, poll_id);
        let resp = match self.client.get(&url).header("x-apikey", &key).send().await {
            Ok(r)  => r,
            Err(e) => return ProviderResult::error(self.id(), &e.to_string()),
        };
        if !resp.status().is_success() {
            return ProviderResult::error(self.id(), &format!("HTTP {}", resp.status()));
        }
        let json: Value = match resp.json().await {
            Ok(j)  => j,
            Err(e) => return ProviderResult::error(self.id(), &e.to_string()),
        };
        let status = json["data"]["attributes"]["status"].as_str().unwrap_or("");
        if status == "queued" || status == "in-progress" {
            return ProviderResult::pending(self.id(), Some(poll_id.into()), "Analisi in corso");
        }
        parse_vt_response(self.id(), Some(json))
    }
}

fn parse_vt_response(pid: &str, json: Option<Value>) -> ProviderResult {
    let json = match json {
        Some(j) => j,
        None    => return ProviderResult::error(pid, "Risposta vuota da VirusTotal"),
    };
    let stats = json["data"]["attributes"]["last_analysis_stats"]
        .as_object()
        .or_else(|| json["data"]["attributes"]["stats"].as_object());
    let stats = match stats {
        Some(s) => s,
        None    => return ProviderResult::error(pid, "Struttura risposta VT non riconosciuta"),
    };
    let malicious  = stats.get("malicious").and_then(|v| v.as_u64()).unwrap_or(0);
    let suspicious = stats.get("suspicious").and_then(|v| v.as_u64()).unwrap_or(0);
    let undetected = stats.get("undetected").and_then(|v| v.as_u64()).unwrap_or(0);
    let harmless   = stats.get("harmless").and_then(|v| v.as_u64()).unwrap_or(0);
    let total      = malicious + suspicious + undetected + harmless;
    let verdict    = if malicious > 0 { Verdict::Malicious }
                     else if suspicious > 0 { Verdict::Suspicious }
                     else if total > 0 { Verdict::Clean }
                     else { Verdict::Unavailable };
    ProviderResult {
        provider_id:   pid.into(),
        verdict,
        detections:    malicious as u32,
        total_engines: total as u32,
        details:       format!("{}/{} engine positivi", malicious, total),
        poll_id:       None,
    }
}
