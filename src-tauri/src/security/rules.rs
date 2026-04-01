use std::path::Path;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id:          String,
    pub description: String,
    pub enabled:     bool,
    pub threshold:   u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RulesEngine {
    pub rules:            Vec<Rule>,
    pub excluded_exts:    Vec<String>,
    pub excluded_paths:   Vec<String>,
    pub min_file_size_kb: u64,
}

impl RulesEngine {
    #[allow(dead_code)]
    pub fn default_rules() -> Self {
        Self {
            rules: vec![
                Rule { id: "high-detections".into(), description: "Blocca se > 3 engine positivi".into(), enabled: true,  threshold: 3 },
                Rule { id: "any-malicious".into(),   description: "Blocca se almeno 1 malicious".into(),  enabled: true,  threshold: 1 },
                Rule { id: "suspicious-flag".into(), description: "Avvisa se suspicious".into(),          enabled: false, threshold: 1 },
            ],
            excluded_exts:    vec!["tmp".into(), "log".into(), "lnk".into()],
            excluded_paths:   vec![],
            min_file_size_kb: 0,
        }
    }

    /// Usato da file_watcher.rs
    pub fn should_scan(&self, path: &Path) -> bool {
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if self.excluded_exts.iter().any(|ex| ex.eq_ignore_ascii_case(ext)) {
                return false;
            }
        }
        let path_str = path.to_string_lossy().to_lowercase();
        if self.excluded_paths.iter().any(|ep| path_str.contains(&ep.to_lowercase())) {
            return false;
        }
        if self.min_file_size_kb > 0 {
            if let Ok(meta) = path.metadata() {
                if meta.len() < self.min_file_size_kb * 1024 {
                    return false;
                }
            }
        }
        true
    }

    pub fn evaluate(&self, detections: u32) -> bool {
        self.rules.iter()
            .filter(|r| r.enabled)
            .any(|r| detections >= r.threshold)
    }
}
