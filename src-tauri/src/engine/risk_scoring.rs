use crate::adapters::scanner_trait::{ProviderResult, Verdict};
use std::path::Path;

/// High-risk file extensions
const HIGH_RISK_EXT: &[&str] = &[
    "exe", "dll", "bat", "cmd", "ps1", "vbs", "js", "jar", "msi", "scr", "pif", "com", "hta",
];
const MED_RISK_EXT: &[&str] = &[
    "zip", "rar", "7z", "iso", "dmg", "pkg", "deb", "rpm", "docm", "xlsm", "pptm",
];

pub struct RiskScorer;

impl RiskScorer {
    /// Returns a risk score 0–100.
    pub fn calculate(results: &[ProviderResult], path: &Path) -> u8 {
        let mut score: f32 = 0.0;

        // ── Detection ratio (0–60 pts) ───────────────────────────────────────
        let total_engines: u32 = results.iter().map(|r| r.total_engines).sum();
        let detections: u32 = results.iter().map(|r| r.detections).sum();
        if total_engines > 0 {
            let ratio = detections as f32 / total_engines as f32;
            score += ratio * 60.0;
        }

        // ── Malicious verdicts boost (0–20 pts) ─────────────────────────────
        let malicious_count = results
            .iter()
            .filter(|r| r.verdict == Verdict::Malicious)
            .count();
        score += (malicious_count as f32 * 5.0).min(20.0);

        // ── File type risk (0–20 pts) ────────────────────────────────────────
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        if HIGH_RISK_EXT.contains(&ext.as_str()) {
            score += 20.0;
        } else if MED_RISK_EXT.contains(&ext.as_str()) {
            score += 8.0;
        }

        score.min(100.0) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::scanner_trait::{ProviderResult, Verdict};
    use std::path::Path;

    fn make_result(verdict: Verdict, detections: u32, total_engines: u32) -> ProviderResult {
        ProviderResult {
            provider_id: "test".into(),
            verdict,
            detections,
            total_engines,
            details: "test".into(),
            poll_id: None,
        }
    }

    #[test]
    fn returns_zero_for_empty_results() {
        let score = RiskScorer::calculate(&[], Path::new("test.txt"));
        assert_eq!(score, 0);
    }

    #[test]
    fn calculates_detection_ratio_correctly() {
        // 1 detection out of 10 engines = 10% * 60 = 6 points
        let results = vec![make_result(Verdict::Clean, 1, 10)];
        let score = RiskScorer::calculate(&results, Path::new("test.txt"));
        assert_eq!(score, 6);
    }

    #[test]
    fn calculates_malicious_verdict_boost() {
        // 2 malicious results = 2 * 5 = 10 points (capped at 20)
        let results = vec![
            make_result(Verdict::Malicious, 5, 10),
            make_result(Verdict::Malicious, 3, 10),
        ];
        let score = RiskScorer::calculate(&results, Path::new("test.txt"));
        assert_eq!(score, 10 + 20); // detection ratio (80% * 60 = 48) + malicious boost (10) = 58
    }

    #[test]
    fn malicious_verdict_boost_caps_at_20() {
        // 6 malicious results = 30 points, but capped at 20
        let results = vec![
            make_result(Verdict::Malicious, 1, 1),
            make_result(Verdict::Malicious, 1, 1),
            make_result(Verdict::Malicious, 1, 1),
            make_result(Verdict::Malicious, 1, 1),
            make_result(Verdict::Malicious, 1, 1),
            make_result(Verdict::Malicious, 1, 1),
        ];
        let score = RiskScorer::calculate(&results, Path::new("test.txt"));
        // 100% detection = 60 + 20 (capped) = 80
        assert_eq!(score, 80);
    }

    #[test]
    fn adds_high_risk_extension_score() {
        let results = vec![make_result(Verdict::Clean, 0, 10)];
        let score = RiskScorer::calculate(&results, Path::new("malware.exe"));
        assert_eq!(score, 20); // 0 detection + 20 for .exe
    }

    #[test]
    fn adds_medium_risk_extension_score() {
        let results = vec![make_result(Verdict::Clean, 0, 10)];
        let score = RiskScorer::calculate(&results, Path::new("archive.zip"));
        assert_eq!(score, 8); // 0 detection + 8 for .zip
    }

    #[test]
    fn caps_score_at_100() {
        // Maximum possible: 100% detection (60) + 20 malicious boost + 20 high risk ext = 100
        let results = vec![
            make_result(Verdict::Malicious, 10, 10),
            make_result(Verdict::Malicious, 10, 10),
            make_result(Verdict::Malicious, 10, 10),
            make_result(Verdict::Malicious, 10, 10),
        ];
        let score = RiskScorer::calculate(&results, Path::new("virus.exe"));
        assert_eq!(score, 100);
    }

    #[test]
    fn case_insensitive_extension_check() {
        let results = vec![make_result(Verdict::Clean, 0, 10)];
        let score = RiskScorer::calculate(&results, Path::new("MALWARE.EXE"));
        assert_eq!(score, 20);
    }
}
