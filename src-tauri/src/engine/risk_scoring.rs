
use std::path::Path;
use crate::adapters::scanner_trait::{ProviderResult, Verdict};

/// High-risk file extensions
const HIGH_RISK_EXT: &[&str] = &["exe","dll","bat","cmd","ps1","vbs","js","jar","msi","scr","pif","com","hta"];
const MED_RISK_EXT:  &[&str] = &["zip","rar","7z","iso","dmg","pkg","deb","rpm","docm","xlsm","pptm"];

pub struct RiskScorer;

impl RiskScorer {
    /// Returns a risk score 0–100.
    pub fn calculate(results: &[ProviderResult], path: &Path) -> u8 {
        let mut score: f32 = 0.0;

        // ── Detection ratio (0–60 pts) ───────────────────────────────────────
        let total_engines: u32 = results.iter().map(|r| r.total_engines).sum();
        let detections:    u32 = results.iter().map(|r| r.detections).sum();
        if total_engines > 0 {
            let ratio = detections as f32 / total_engines as f32;
            score += ratio * 60.0;
        }

        // ── Malicious verdicts boost (0–20 pts) ─────────────────────────────
        let malicious_count = results.iter().filter(|r| r.verdict == Verdict::Malicious).count();
        score += (malicious_count as f32 * 5.0).min(20.0);

        // ── File type risk (0–20 pts) ────────────────────────────────────────
        let ext = path.extension()
            .and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
        if HIGH_RISK_EXT.contains(&ext.as_str()) { score += 20.0; }
        else if MED_RISK_EXT.contains(&ext.as_str()) { score += 8.0; }

        score.min(100.0) as u8
    }
}
