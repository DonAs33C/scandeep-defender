use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Rule {
    pub id:          String,
    pub description: String,
    pub enabled:     bool,
    pub threshold:   u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RulesEngine {
    pub rules: Vec<Rule>,
}

impl RulesEngine {
    #[allow(dead_code)]   // chiamata all'inizializzazione del DB la prima volta
    pub fn default_rules() -> Self {
        Self {
            rules: vec![
                Rule { id: "high-detections".into(), description: "Blocca se > 3 engine positivi".into(), enabled: true,  threshold: 3 },
                Rule { id: "any-malicious".into(),   description: "Blocca se almeno 1 malicious".into(),  enabled: true,  threshold: 1 },
                Rule { id: "suspicious-flag".into(), description: "Avvisa se suspicious".into(),          enabled: false, threshold: 1 },
            ],
        }
    }

    pub fn evaluate(&self, detections: u32) -> bool {
        self.rules.iter()
            .filter(|r| r.enabled)
            .any(|r| detections >= r.threshold)
    }
}
