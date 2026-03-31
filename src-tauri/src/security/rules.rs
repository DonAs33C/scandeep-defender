
use std::path::Path;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleCondition {
    FileExtension(Vec<String>),
    FileSizeAbove(u64),
    PathContains(String),
    FilenameMatcher(String),   // glob pattern
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RuleAction { Alert, AutoQuarantine, Skip, ForceScan }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id:        String,
    pub name:      String,
    pub condition: RuleCondition,
    pub action:    RuleAction,
    pub enabled:   bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RulesEngine {
    pub rules: Vec<Rule>,
}

impl RulesEngine {
    pub fn default_rules() -> Self {
        Self { rules: vec![
            Rule { id:"r1".into(), name:"Scan executables".into(), enabled:true,
                condition: RuleCondition::FileExtension(vec!["exe","dll","msi","bat","cmd","ps1","vbs","scr"].iter().map(|s|s.to_string()).collect()),
                action: RuleAction::ForceScan },
            Rule { id:"r2".into(), name:"Alert on archives".into(), enabled:true,
                condition: RuleCondition::FileExtension(vec!["zip","rar","7z","iso"].iter().map(|s|s.to_string()).collect()),
                action: RuleAction::Alert },
            Rule { id:"r3".into(), name:"Skip very small files (<1 KB)".into(), enabled:true,
                condition: RuleCondition::FileSizeAbove(0),
                action: RuleAction::Skip },
        ]}
    }

    /// Returns true if the file should be scanned.
    pub fn should_scan(&self, path: &Path) -> bool {
        let ext  = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
        let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        for rule in &self.rules {
            if !rule.enabled { continue; }
            let matches = match &rule.condition {
                RuleCondition::FileExtension(exts) => exts.iter().any(|e| e == &ext),
                RuleCondition::FileSizeAbove(n)    => size > *n,
                RuleCondition::PathContains(s)     => path.to_string_lossy().contains(s.as_str()),
                RuleCondition::FilenameMatcher(p)  => {
                    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    glob::Pattern::new(p).map(|g| g.matches(name)).unwrap_or(false)
                }
            };
            if matches {
                return rule.action != RuleAction::Skip;
            }
        }
        true // scan by default
    }
}
