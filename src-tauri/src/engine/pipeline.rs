
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use tokio::time::{sleep, Duration};
use tauri::AppHandle;
use tauri::Emitter;

use crate::adapters::scanner_trait::{ScanProvider, ProviderResult, Verdict};
use crate::engine::job::{ScanJob, ScanReport, JobStatus};
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
        let mut rate_limiters = HashMap::new();
        let mut daily_quotas  = HashMap::new();
        // VirusTotal: 4 req/min, 500/day
        rate_limiters.insert("virustotal", Arc::new(TokenBucket::new(4.0, 4.0)));
        daily_quotas .insert("virustotal", Arc::new(DailyQuota::new(500)));
        // MetaDefender: 10 req/min community
        rate_limiters.insert("metadefender", Arc::new(TokenBucket::new(10.0, 10.0)));
        Self { providers, rate_limiters, daily_quotas, db }
    }

    pub async fn execute(&self, mut job: ScanJob, app: &AppHandle) -> Result<ScanReport> {
        // ── Step 1: hash ────────────────────────────────────────────────────
        job.status = JobStatus::Hashing;
        emit_progress(app, &job.id, "hashing", "Computing SHA-256…");
        let hash = compute_hash(&job.file_path).await?;
        job.hash = Some(hash.clone());

        // ── Step 2: cache lookup ────────────────────────────────────────────
        if let Ok(Some(report)) = self.db.get_cached_report(&hash).await {
            emit_progress(app, &job.id, "completed", "Loaded from cache");
            return Ok(ScanReport { from_cache: true, ..report });
        }

        // ── Step 3: parallel scan across providers ──────────────────────────
        job.status = JobStatus::Scanning;
        let mut handles = vec![];

        for provider in &self.providers {
            if !job.requested_providers.contains(&provider.id().to_string()) { continue; }
            if !provider.is_enabled() { continue; }
            if provider.is_cloud() {
                if let Some(rl) = self.rate_limiters.get(provider.id()) {
                    if !rl.try_acquire() {
                        // backoff
                        let rl = rl.clone();
                        tokio::spawn(async move { rl.acquire().await });
                    }
                }
                if let Some(dq) = self.daily_quotas.get(provider.id()) {
                    if !dq.try_consume() {
                        tracing::warn!("Daily quota exhausted for {}", provider.id());
                        continue;
                    }
                }
            }

            let p   = Arc::clone(provider);
            let h   = hash.clone();
            let fp  = job.file_path.clone();
            let fn_ = job.filename.clone();
            let rl  = self.rate_limiters.get(provider.id()).cloned();
            let allow_upload = job.allow_cloud_upload;
            let app2 = app.clone();
            let pid  = job.id.clone();

            handles.push(tokio::spawn(async move {
                if let Some(rl) = &rl { rl.acquire().await; }
                emit_progress(&app2, &pid, "scanning",
                    &format!("Scanning with {}…", p.name()));

                // Hash lookup first
                let result = with_retry(MAX_RETRIES, || p.scan_hash(&h)).await;

                // If not found and upload allowed → upload
                let result = if result.verdict == Verdict::Unavailable
                                && p.supports_file_upload() && allow_upload {
                    with_retry(MAX_RETRIES, || p.scan_file(&fp, &h, &fn_)).await
                } else { result };

                emit_progress(&app2, &pid, "done",
                    &format!("{}: {:?}", p.name(), result.verdict));
                result
            }));
        }

        let results: Vec<ProviderResult> = futures::future::join_all(handles)
            .await.into_iter().filter_map(|r| r.ok()).collect();

        // ── Step 4: aggregate + risk score ──────────────────────────────────
        let overall = ScanReport::compute_verdict(&results);
        let risk    = RiskScorer::calculate(&results, &job.file_path);

        let report = ScanReport {
            job_id:          job.id.clone(),
            filename:        job.filename.clone(),
            filepath:        job.file_path.to_string_lossy().to_string(),
            filesize:        job.filesize,
            hash:            hash.clone(),
            timestamp:       chrono::Utc::now().to_rfc3339(),
            results,
            overall_verdict: overall,
            risk_score:      risk,
            from_cache:      false,
        };

        self.db.save_report(&report).await.ok();
        emit_progress(app, &job.id, "completed", "Scan complete");
        Ok(report)
    }
}

async fn compute_hash(path: &Path) -> Result<String> {
    let bytes = tokio::fs::read(path).await.context("Failed to read file")?;
    let mut h = Sha256::new(); h.update(&bytes);
    Ok(format!("{:x}", h.finalize()))
}

async fn with_retry<F, Fut>(max: u32, mut f: F) -> ProviderResult
where F: FnMut() -> Fut, Fut: std::future::Future<Output=ProviderResult> {
    for attempt in 0..max {
        let r = f().await;
        if r.verdict != Verdict::Error { return r; }
        if attempt < max - 1 {
            sleep(Duration::from_secs(2u64.pow(attempt))).await;
        }
    }
    f().await
}

fn emit_progress(app: &AppHandle, job_id: &str, status: &str, msg: &str) {
    app.emit("scan-progress", serde_json::json!({
        "job_id": job_id, "status": status, "message": msg
    })).ok();
}

// Allow ScanProvider to have no default impl (compiler needs it)
trait ScanProviderExt: ScanProvider {
    fn supports_file_upload(&self) -> bool { true }
}
impl<T: ScanProvider> ScanProviderExt for T {}
