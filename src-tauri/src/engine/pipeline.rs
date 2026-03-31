
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use tokio::time::{sleep, Duration};
use tauri::AppHandle;
use tauri::Emitter;

use crate::adapters::scanner_trait::{ScanProvider, ProviderResult, Verdict};
use crate::engine::job::{ScanJob, ScanReport};
use crate::engine::risk_scoring::RiskScorer;
use crate::rate_limiter::token_bucket::{TokenBucket, DailyQuota};
use crate::persistence::database::Database;

const MAX_RETRIES: u32 = 3;

pub struct ScanPipeline {
    providers:     Vec<Arc<dyn ScanProvider>>,
    rate_limiters: HashMap<&'static str, Arc<TokenBucket>>,
    daily_quotas:  HashMap<&'static str, Arc<DailyQuota>>,
    db:            Arc<Database>,
}

impl ScanPipeline {
    pub fn new(providers: Vec<Arc<dyn ScanProvider>>, db: Arc<Database>) -> Self {
        let mut rl = HashMap::new();
        let mut dq = HashMap::new();
        rl.insert("virustotal",    Arc::new(TokenBucket::new(4.0,  4.0)));
        rl.insert("metadefender",  Arc::new(TokenBucket::new(10.0, 10.0)));
        rl.insert("hybridanalysis",Arc::new(TokenBucket::new(5.0,  5.0)));
        rl.insert("cloudmersive",  Arc::new(TokenBucket::new(20.0, 20.0)));
        dq.insert("virustotal",    Arc::new(DailyQuota::new(500)));
        dq.insert("hybridanalysis",Arc::new(DailyQuota::new(200)));
        dq.insert("cloudmersive",  Arc::new(DailyQuota::new(800)));
        Self { providers, rate_limiters: rl, daily_quotas: dq, db }
    }

    /// Restituisce un provider per ID (usato da poll_result command).
    pub fn get_provider(&self, id: &str) -> Option<Arc<dyn ScanProvider>> {
        self.providers.iter().find(|p| p.id() == id).cloned()
    }

    pub async fn execute(&self, job: ScanJob, app: &AppHandle) -> Result<ScanReport> {
        // 1. hash
        emit(app, &job.id, "hashing", "Calcolo SHA-256...");
        let hash = compute_hash(&job.file_path).await?;

        // 2. cache
        if let Ok(Some(report)) = self.db.get_cached_report(&hash).await {
            emit(app, &job.id, "completed", "Caricato dalla cache");
            return Ok(ScanReport { from_cache: true, ..report });
        }

        // 3. scansione parallela
        emit(app, &job.id, "scanning", "Avvio scansione parallela...");
        let mut handles = vec![];

        for provider in &self.providers {
            if !job.requested_providers.contains(&provider.id().to_string()) { continue; }
            if !provider.is_enabled() { continue; }

            if provider.is_cloud() {
                if let Some(rl) = self.rate_limiters.get(provider.id()) {
                    if !rl.try_acquire() { continue; }  // salta se rate-limited
                }
                if let Some(dq) = self.daily_quotas.get(provider.id()) {
                    if !dq.try_consume() {
                        tracing::warn!("Quota giornaliera esaurita per {}", provider.id());
                        continue;
                    }
                }
            }

            let p   = Arc::clone(provider);
            let h   = hash.clone();
            let fp  = job.file_path.clone();
            let fn_ = job.filename.clone();
            let allow_upload = job.allow_cloud_upload;
            let app2 = app.clone();
            let pid  = job.id.clone();

            handles.push(tokio::spawn(async move {
                emit(&app2, &pid, "scanning", &format!("{}...", p.name()));
                let result = with_retry(MAX_RETRIES, || p.scan_hash(&h)).await;
                // upload solo se hash sconosciuto E upload consentito
                let result = if result.verdict == Verdict::Unavailable
                                && p.supports_file_upload()
                                && allow_upload {
                    with_retry(MAX_RETRIES, || p.scan_file(&fp, &h, &fn_)).await
                } else { result };
                emit(&app2, &pid, "done", &format!("{}: {:?}", p.name(), result.verdict));
                result
            }));
        }

        let results: Vec<ProviderResult> = futures::future::join_all(handles)
            .await.into_iter().filter_map(|r| r.ok()).collect();

        // 4. aggregazione
        let overall = ScanReport::compute_verdict(&results);
        let risk    = RiskScorer::calculate(&results, &job.file_path);

        let report = ScanReport {
            job_id: job.id, filename: job.filename,
            filepath: job.file_path.to_string_lossy().to_string(),
            filesize: job.filesize, hash: hash.clone(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            results, overall_verdict: overall, risk_score: risk, from_cache: false,
        };

        self.db.save_report(&report).await.ok();
        emit(app, &report.job_id, "completed", "Scansione completata");
        Ok(report)
    }
}

async fn compute_hash(path: &Path) -> Result<String> {
    let bytes = tokio::fs::read(path).await.context("Impossibile leggere il file")?;
    let mut h = Sha256::new(); h.update(&bytes);
    Ok(format!("{:x}", h.finalize()))
}

async fn with_retry<F, Fut>(max: u32, mut f: F) -> ProviderResult
where F: FnMut() -> Fut, Fut: std::future::Future<Output=ProviderResult> {
    for attempt in 0..max {
        let r = f().await;
        if r.verdict != Verdict::Error { return r; }
        if attempt < max - 1 { sleep(Duration::from_secs(2u64.pow(attempt))).await; }
    }
    f().await
}

fn emit(app: &AppHandle, job_id: &str, status: &str, msg: &str) {
    app.emit("scan-progress", serde_json::json!({
        "job_id": job_id, "status": status, "message": msg
    })).ok();
}
