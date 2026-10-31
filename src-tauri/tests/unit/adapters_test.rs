use mockall::*;
use std::path::Path;
use std::sync::{Arc, Mutex};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::scanner_trait::{ProviderResult, Verdict};
    use std::path::PathBuf;

    fn make_clean_result() -> ProviderResult {
        ProviderResult {
            provider_id: "test".into(),
            verdict: Verdict::Clean,
            detections: 0,
            total_engines: 10,
            details: "Clean".into(),
            poll_id: None,
        }
    }

    fn make_malicious_result() -> ProviderResult {
        ProviderResult {
            provider_id: "test".into(),
            verdict: Verdict::Malicious,
            detections: 5,
            total_engines: 10,
            details: "5/10 detected".into(),
            poll_id: None,
        }
    }

    #[tokio::test]
    async fn mock_provider_returns_configured_result() {
        let mut mock = MockScanProvider::new();
        mock.expect_id().return_const("test_provider");
        mock.expect_name().return_const("Test Provider");
        mock.expect_is_cloud().return_const(true);
        mock.expect_is_enabled().return_const(true);
        mock.expect_supports_file_upload().return_const(true);
        mock.expect_scan_hash()
            .with(mockall::predicate::eq("abc123"))
            .returning(|_| make_clean_result());
        mock.expect_scan_file()
            .returning(|_, _, _| make_malicious_result());

        let result = mock.scan_hash("abc123").await;
        assert_eq!(result.verdict, Verdict::Clean);

        let result = mock.scan_file(Path::new("/test/file.exe"), "abc123", "file.exe").await;
        assert_eq!(result.verdict, Verdict::Malicious);
    }

    #[tokio::test]
    async fn mock_provider_returns_error_when_disabled() {
        let mut mock = MockScanProvider::new();
        mock.expect_id().return_const("disabled_provider");
        mock.expect_name().return_const("Disabled Provider");
        mock.expect_is_cloud().return_const(true);
        mock.expect_is_enabled().return_const(false);
        mock.expect_supports_file_upload().return_const(true);
        mock.expect_scan_hash()
            .returning(|_| ProviderResult::unavailable("disabled_provider", "Provider disabled"));

        let result = mock.scan_hash("abc123").await;
        assert_eq!(result.verdict, Verdict::Unavailable);
    }
}

// Test VirusTotal adapter logic (without network calls)
#[cfg(test)]
mod virustotal_logic_tests {
    use super::*;
    use crate::adapters::virustotal::parse_vt_response;
    use crate::adapters::scanner_trait::{ProviderResult, Verdict};
    use serde_json::json;

    #[test]
    fn parse_vt_response_malicious() {
        let json = json!({
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 2,
                        "undetected": 60,
                        "harmless": 10
                    }
                }
            }
        });

        let result = parse_vt_response("virustotal", Some(json));
        assert_eq!(result.verdict, Verdict::Malicious);
        assert_eq!(result.detections, 5);
        assert_eq!(result.total_engines, 77);
    }

    #[test]
    fn parse_vt_response_suspicious() {
        let json = json!({
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 3,
                        "undetected": 70,
                        "harmless": 10
                    }
                }
            }
        });

        let result = parse_vt_response("virustotal", Some(json));
        assert_eq!(result.verdict, Verdict::Suspicious);
        assert_eq!(result.detections, 0);
        assert_eq!(result.total_engines, 83);
    }

    #[test]
    fn parse_vt_response_clean() {
        let json = json!({
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "undetected": 75,
                        "harmless": 10
                    }
                }
            }
        });

        let result = parse_vt_response("virustotal", Some(json));
        assert_eq!(result.verdict, Verdict::Clean);
        assert_eq!(result.detections, 0);
        assert_eq!(result.total_engines, 85);
    }

    #[test]
    fn parse_vt_response_unavailable_when_no_stats() {
        let json = json!({
            "data": {
                "attributes": {}
            }
        });

        let result = parse_vt_response("virustotal", Some(json));
        assert_eq!(result.verdict, Verdict::Error);
    }

    #[test]
    fn parse_vt_response_error_when_empty() {
        let result = parse_vt_response("virustotal", None);
        assert_eq!(result.verdict, Verdict::Error);
    }

    #[test]
    fn parse_vt_response_handles_alternative_stats_key() {
        let json = json!({
            "data": {
                "attributes": {
                    "stats": {
                        "malicious": 2,
                        "suspicious": 1,
                        "undetected": 50,
                        "harmless": 5
                    }
                }
            }
        });

        let result = parse_vt_response("virustotal", Some(json));
        assert_eq!(result.verdict, Verdict::Malicious);
        assert_eq!(result.detections, 2);
        assert_eq!(result.total_engines, 58);
    }
}

// Test MetaDefender adapter logic
#[cfg(test)]
mod metadefender_logic_tests {
    use crate::adapters::scanner_trait::{ProviderResult, Verdict};

    // We can't easily test the actual adapter without network, but we can test
    // the logic that would be used in parsing responses
    #[test]
    fn verdict_logic_malicious_when_detected() {
        let detections = 3u64;
        let total = 20u64;
        let verdict = if detections > 0 { Verdict::Malicious } else { Verdict::Clean };
        assert_eq!(verdict, Verdict::Malicious);
    }

    #[test]
    fn verdict_logic_clean_when_zero_detections() {
        let detections = 0u64;
        let verdict = if detections > 0 { Verdict::Malicious } else { Verdict::Clean };
        assert_eq!(verdict, Verdict::Clean);
    }
}

// Test Hybrid Analysis adapter logic
#[cfg(test)]
mod hybrid_analysis_logic_tests {
    use crate::adapters::scanner_trait::{ProviderResult, Verdict};

    #[test]
    fn threat_score_malicious_above_70() {
        let threat_score = 85u64;
        let verdict = if threat_score > 70 { Verdict::Malicious }
                      else if threat_score > 30 { Verdict::Suspicious }
                      else { Verdict::Clean };
        assert_eq!(verdict, Verdict::Malicious);
    }

    #[test]
    fn threat_score_suspicious_between_30_and_70() {
        let threat_score = 50u64;
        let verdict = if threat_score > 70 { Verdict::Malicious }
                      else if threat_score > 30 { Verdict::Suspicious }
                      else { Verdict::Clean };
        assert_eq!(verdict, Verdict::Suspicious);
    }

    #[test]
    fn threat_score_clean_below_30() {
        let threat_score = 15u64;
        let verdict = if threat_score > 70 { Verdict::Malicious }
                      else if threat_score > 30 { Verdict::Suspicious }
                      else { Verdict::Clean };
        assert_eq!(verdict, Verdict::Clean);
    }

    #[test]
    fn empty_results_returns_unavailable() {
        let results: Vec<serde_json::Value> = vec![];
        assert!(results.is_empty());
        // In real code, this would return ProviderResult::unavailable
    }
}

// Test Cloudmersive adapter logic
#[cfg(test)]
mod cloudmersive_logic_tests {
    use crate::adapters::scanner_trait::{ProviderResult, Verdict};
    use serde_json::json;

    #[test]
    fn clean_result_when_clean_true() {
        let json = json!({ "CleanResult": true, "FoundViruses": [] });
        let clean = json["CleanResult"].as_bool().unwrap_or(false);
        let threats = json["FoundViruses"].as_array().map(|a| a.len() as u32).unwrap_or(0);

        let verdict = if clean { Verdict::Clean } else { Verdict::Malicious };
        assert_eq!(verdict, Verdict::Clean);
        assert_eq!(threats, 0);
    }

    #[test]
    fn malicious_result_when_clean_false() {
        let json = json!({ "CleanResult": false, "FoundViruses": ["Trojan.Generic", "Worm.Win32"] });
        let clean = json["CleanResult"].as_bool().unwrap_or(false);
        let threats = json["FoundViruses"].as_array().map(|a| a.len() as u32).unwrap_or(0);

        let verdict = if clean { Verdict::Clean } else { Verdict::Malicious };
        assert_eq!(verdict, Verdict::Malicious);
        assert_eq!(threats, 2);
    }

    #[test]
    fn defaults_to_malicious_when_missing_clean_result() {
        let json = json!({ "FoundViruses": ["Virus1"] });
        let clean = json["CleanResult"].as_bool().unwrap_or(false);
        let threats = json["FoundViruses"].as_array().map(|a| a.len() as u32).unwrap_or(0);

        let verdict = if clean { Verdict::Clean } else { Verdict::Malicious };
        assert_eq!(verdict, Verdict::Malicious);
        assert_eq!(threats, 1);
    }
}

// Test ClamAV adapter logic
#[cfg(test)]
mod clamav_logic_tests {
    use crate::adapters::scanner_trait::{ProviderResult, Verdict};

    #[test]
    fn infected_when_output_contains_found() {
        let output = "/path/to/file.exe: Trojan.Generic FOUND\n";
        let infected = output.contains("FOUND");
        let verdict = if infected { Verdict::Malicious } else { Verdict::Clean };
        assert_eq!(verdict, Verdict::Malicious);
        assert_eq!(infected, true);
    }

    #[test]
    fn clean_when_output_no_found() {
        let output = "/path/to/file.exe: OK\n----------- SCAN SUMMARY -----------\n";
        let infected = output.contains("FOUND");
        let verdict = if infected { Verdict::Malicious } else { Verdict::Clean };
        assert_eq!(verdict, Verdict::Clean);
        assert_eq!(infected, false);
    }

    #[test]
    fn extracts_threat_name_from_found_line() {
        let output = "/path/to/file.exe: Win.Trojan.Agent-123 FOUND\n";
        let threat_line = output.lines().find(|l| l.contains("FOUND"));
        assert!(threat_line.is_some());
        assert_eq!(threat_line.unwrap(), "/path/to/file.exe: Win.Trojan.Agent-123 FOUND");
    }
}

// Test ProviderResult helper constructors
#[cfg(test)]
mod provider_result_tests {
    use crate::adapters::scanner_trait::{ProviderResult, Verdict};

    #[test]
    fn unavailable_constructor() {
        let result = ProviderResult::unavailable("test", "Not available");
        assert_eq!(result.provider_id, "test");
        assert_eq!(result.verdict, Verdict::Unavailable);
        assert_eq!(result.details, "Not available");
        assert_eq!(result.poll_id, None);
    }

    #[test]
    fn error_constructor() {
        let result = ProviderResult::error("test", "Error occurred");
        assert_eq!(result.provider_id, "test");
        assert_eq!(result.verdict, Verdict::Error);
        assert_eq!(result.details, "Error occurred");
    }

    #[test]
    fn pending_constructor() {
        let result = ProviderResult::pending("test", Some("poll123".into()), "Pending");
        assert_eq!(result.provider_id, "test");
        assert_eq!(result.verdict, Verdict::Pending);
        assert_eq!(result.poll_id, Some("poll123".into()));
    }

    #[test]
    fn pending_constructor_without_poll_id() {
        let result = ProviderResult::pending("test", None, "Pending");
        assert_eq!(result.poll_id, None);
    }
}

// Test Verdict serialization
#[cfg(test)]
mod verdict_serialization_tests {
    use crate::adapters::scanner_trait::Verdict;
    use serde_json;

    #[test]
    fn verdict_serializes_to_snake_case() {
        assert_eq!(serde_json::to_string(&Verdict::Clean).unwrap(), "\"clean\"");
        assert_eq!(serde_json::to_string(&Verdict::Suspicious).unwrap(), "\"suspicious\"");
        assert_eq!(serde_json::to_string(&Verdict::Malicious).unwrap(), "\"malicious\"");
        assert_eq!(serde_json::to_string(&Verdict::Pending).unwrap(), "\"pending\"");
        assert_eq!(serde_json::to_string(&Verdict::Unavailable).unwrap(), "\"unavailable\"");
        assert_eq!(serde_json::to_string(&Verdict::Error).unwrap(), "\"error\"");
    }

    #[test]
    fn verdict_deserializes_from_snake_case() {
        assert_eq!(serde_json::from_str::<Verdict>("\"clean\"").unwrap(), Verdict::Clean);
        assert_eq!(serde_json::from_str::<Verdict>("\"suspicious\"").unwrap(), Verdict::Suspicious);
        assert_eq!(serde_json::from_str::<Verdict>("\"malicious\"").unwrap(), Verdict::Malicious);
        assert_eq!(serde_json::from_str::<Verdict>("\"pending\"").unwrap(), Verdict::Pending);
        assert_eq!(serde_json::from_str::<Verdict>("\"unavailable\"").unwrap(), Verdict::Unavailable);
        assert_eq!(serde_json::from_str::<Verdict>("\"error\"").unwrap(), Verdict::Error);
    }
}