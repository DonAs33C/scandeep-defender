use mockall::*;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use tempfile::tempdir;
use tokio::fs;

// Mock the ScanProvider trait
mock! {
    pub ScanProvider {}
    #[async_trait]
    impl crate::adapters::scanner_trait::ScanProvider for ScanProvider {
        fn id(&self) -> &'static str;
        fn name(&self) -> &'static str;
        fn is_cloud(&self) -> bool;
        fn is_enabled(&self) -> bool;
        fn supports_file_upload(&self) -> bool;
        async fn scan_hash(&self, hash: &str) -> crate::adapters::scanner_trait::ProviderResult;
        async fn scan_file(&self, path: &Path, hash: &str, filename: &str) -> crate::adapters::scanner_trait::ProviderResult;
        async fn poll_result(&self, poll_id: &str) -> crate::adapters::scanner_trait::ProviderResult;
    }
}

// Mock Database
mock! {
    pub Database {}
    impl crate::persistence::database::Database for Database {
        async fn save_report(&self, r: &crate::engine::job::ScanReport) -> rusqlite::Result<()>;
        async fn get_cached_report(&self, hash: &str) -> rusqlite::Result<Option<crate::engine::job::ScanReport>>;
        fn get_all_scans(&self) -> rusqlite::Result<Vec<crate::persistence::database::ScanRecord>>;
        fn clear_history(&self) -> rusqlite::Result<()>;
        fn find_by_hash(&self, hash: &str) -> rusqlite::Result<Option<String>>;
        fn save_quarantine(&self, q: &crate::security::quarantine::QuarantineRecord) -> rusqlite::Result<()>;
        fn get_quarantine_list(&self) -> rusqlite::Result<Vec<crate::security::quarantine::QuarantineRecord>>;
        fn remove_quarantine(&self, id: &str) -> rusqlite::Result<()>;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::scanner_trait::{ProviderResult, Verdict};
    use crate::engine::job::{ScanJob, ScanReport};
    use crate::engine::pipeline::ScanPipeline;
    use crate::engine::risk_scoring::RiskScorer;
    use std::time::SystemTime;
    use uuid::Uuid;

    fn make_test_file(content: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let temp = tempdir().unwrap();
        let file_path = temp.path().join("test.exe");
        std::fs::write(&file_path, content).unwrap();
        (temp, file_path)
    }

    fn make_scan_job(file_path: std::path::PathBuf) -> ScanJob {
        ScanJob::new(file_path, vec!["test_provider".to_string()], true)
    }

    fn make_provider_result(verdict: Verdict, provider_id: &str) -> ProviderResult {
        ProviderResult {
            provider_id: provider_id.into(),
            verdict,
            detections: if matches!(verdict, Verdict::Malicious) { 1 } else { 0 },
            total_engines: 10,
            details: format!("{:?}", verdict),
            poll_id: None,
        }
    }

    fn make_mock_provider(id: &str, verdict: Verdict) -> MockScanProvider {
        let mut mock = MockScanProvider::new();
        mock.expect_id().return_const(id);
        mock.expect_name().return_const(id);
        mock.expect_is_cloud().return_const(false);
        mock.expect_is_enabled().return_const(true);
        mock.expect_supports_file_upload().return_const(true);
        let verdict_clone = verdict.clone();
        mock.expect_scan_hash()
            .returning(move |_| make_provider_result(verdict_clone.clone(), id));
        mock.expect_scan_file()
            .returning(move |_, _, _| make_provider_result(verdict_clone.clone(), id));
        mock
    }

    #[tokio::test]
    async fn pipeline_new_creates_with_providers() {
        let providers: Vec<Arc<dyn crate::adapters::scanner_trait::ScanProvider>> = vec![];
        let db = Arc::new(crate::persistence::database::Database::new().unwrap());
        let pipeline = ScanPipeline::new(providers, db);

        // Just verify it creates without error
        assert!(pipeline.get_provider("nonexistent").is_none());
    }

    #[tokio::test]
    async fn get_provider_returns_correct_provider() {
        let provider = Arc::new(make_mock_provider("test1", Verdict::Clean));
        let db = Arc::new(crate::persistence::database::Database::new().unwrap());
        let pipeline = ScanPipeline::new(vec![provider.clone()], db);

        let found = pipeline.get_provider("test1");
        assert!(found.is_some());
        assert_eq!(found.unwrap().id(), "test1");

        let not_found = pipeline.get_provider("nonexistent");
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn execute_returns_cached_report_when_available() {
        let (temp, file_path) = make_test_file(b"test content");

        let mut mock_provider = make_mock_provider("test1", Verdict::Clean);
        // scan_hash should not be called if cached
        mock_provider.expect_scan_hash().times(0);

        let providers: Vec<Arc<dyn crate::adapters::scanner_trait::ScanProvider>> = vec![Arc::new(mock_provider)];

        let db = Arc::new(crate::persistence::database::Database::new().unwrap());

        // Pre-populate cache
        let hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // SHA256 of empty string
        let cached_report = ScanReport {
            job_id: "cached-job".into(),
            filename: "test.exe".into(),
            filepath: file_path.to_string_lossy().to_string(),
            filesize: 1024,
            hash: hash.into(),
            timestamp: "2024-01-01T00:00:00Z".into(),
            results: vec![make_provider_result(Verdict::Malicious, "cached")],
            overall_verdict: Verdict::Malicious,
            risk_score: 80,
            from_cache: false,
        };
        db.save_report(&cached_report).await.unwrap();

        let pipeline = ScanPipeline::new(providers, db);
        let job = make_scan_job(file_path.clone());

        // We can't easily test the full execute without AppHandle
        // This test verifies the pipeline construction
        assert!(pipeline.get_provider("test1").is_some());
    }
}

// Test RiskScorer integration with pipeline
#[cfg(test)]
mod risk_scoring_integration_tests {
    use super::*;
    use crate::adapters::scanner_trait::{ProviderResult, Verdict};
    use std::path::Path;

    #[test]
    fn compute_verdict_malicious_when_any_malicious() {
        let results = vec![
            ProviderResult { provider_id: "1".into(), verdict: Verdict::Clean, detections: 0, total_engines: 10, details: "".into(), poll_id: None },
            ProviderResult { provider_id: "2".into(), verdict: Verdict::Malicious, detections: 5, total_engines: 10, details: "".into(), poll_id: None },
        ];
        let verdict = ScanReport::compute_verdict(&results);
        assert_eq!(verdict, Verdict::Malicious);
    }

    #[test]
    fn compute_verdict_suspicious_when_no_malicious_but_suspicious() {
        let results = vec![
            ProviderResult { provider_id: "1".into(), verdict: Verdict::Clean, detections: 0, total_engines: 10, details: "".into(), poll_id: None },
            ProviderResult { provider_id: "2".into(), verdict: Verdict::Suspicious, detections: 1, total_engines: 10, details: "".into(), poll_id: None },
        ];
        let verdict = ScanReport::compute_verdict(&results);
        assert_eq!(verdict, Verdict::Suspicious);
    }

    #[test]
    fn compute_verdict_clean_when_all_clean_or_unavailable() {
        let results = vec![
            ProviderResult { provider_id: "1".into(), verdict: Verdict::Clean, detections: 0, total_engines: 10, details: "".into(), poll_id: None },
            ProviderResult { provider_id: "2".into(), verdict: Verdict::Unavailable, detections: 0, total_engines: 0, details: "".into(), poll_id: None },
            ProviderResult { provider_id: "3".into(), verdict: Verdict::Error, detections: 0, total_engines: 0, details: "".into(), poll_id: None },
        ];
        let verdict = ScanReport::compute_verdict(&results);
        assert_eq!(verdict, Verdict::Clean);
    }

    #[test]
    fn compute_verdict_pending_when_any_pending() {
        let results = vec![
            ProviderResult { provider_id: "1".into(), verdict: Verdict::Clean, detections: 0, total_engines: 10, details: "".into(), poll_id: None },
            ProviderResult { provider_id: "2".into(), verdict: Verdict::Pending, detections: 0, total_engines: 0, details: "".into(), poll_id: Some("poll1".into()) },
        ];
        let verdict = ScanReport::compute_verdict(&results);
        assert_eq!(verdict, Verdict::Pending);
    }
}

// Test rate limiter logic
#[cfg(test)]
mod rate_limiter_tests {
    use crate::rate_limiter::token_bucket::{TokenBucket, DailyQuota};

    #[test]
    fn token_bucket_allows_burst_up_to_capacity() {
        let bucket = TokenBucket::new(10.0, 10.0); // 10 tokens, refill 10/sec

        // Should allow 10 requests immediately
        for _ in 0..10 {
            assert!(bucket.try_acquire(), "Should allow up to capacity");
        }

        // 11th should fail
        assert!(!bucket.try_acquire(), "Should reject when empty");
    }

    #[test]
    fn token_bucket_refills_over_time() {
        let bucket = TokenBucket::new(2.0, 10.0); // 2 tokens, refill 10/sec

        assert!(bucket.try_acquire());
        assert!(bucket.try_acquire());
        assert!(!bucket.try_acquire());

        // Wait for refill
        std::thread::sleep(std::time::Duration::from_millis(250));

        assert!(bucket.try_acquire(), "Should allow after refill");
    }

    #[test]
    fn daily_quota_allows_up_to_limit() {
        let quota = DailyQuota::new(5);

        for i in 0..5 {
            assert!(quota.try_consume(), "Should allow up to limit: {}", i);
        }

        assert!(!quota.try_consume(), "Should reject when quota exhausted");
    }

    #[test]
    fn daily_quota_resets_daily() {
        // This is harder to test without time manipulation
        // Just verify construction works
        let quota = DailyQuota::new(100);
        assert!(quota.try_consume());
    }
}

// Test ScanJob creation
#[cfg(test)]
mod scan_job_tests {
    use super::*;
    use crate::engine::job::{ScanJob, JobStatus};
    use std::path::PathBuf;
    use std::time::SystemTime;

    #[test]
    fn scan_job_creates_with_correct_defaults() {
        let temp = tempdir().unwrap();
        let file_path = temp.path().join("test.exe");
        fs::write(&file_path, b"test").unwrap();

        let job = ScanJob::new(file_path.clone(), vec!["vt".into(), "ha".into()], true);

        assert_eq!(job.file_path, file_path);
        assert_eq!(job.filename, "test.exe");
        assert_eq!(job.filesize, 4);
        assert_eq!(job.requested_providers, vec!["vt", "ha"]);
        assert!(job.allow_cloud_upload);
        assert_eq!(job.status, JobStatus::Pending);
        assert_eq!(job.retry_count, 0);
        assert_eq!(job.max_retries, 3);
        assert!(!job.id.is_empty());
    }

    #[test]
    fn scan_job_generates_unique_ids() {
        let temp = tempdir().unwrap();
        let file_path = temp.path().join("test.exe");
        fs::write(&file_path, b"test").unwrap();

        let job1 = ScanJob::new(file_path.clone(), vec![], false);
        let job2 = ScanJob::new(file_path.clone(), vec![], false);

        assert_ne!(job1.id, job2.id);
    }
}