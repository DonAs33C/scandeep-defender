use std::sync::{Arc, Mutex, RwLock};
use crate::engine::{pipeline::ScanPipeline, queue::JobQueue};
use crate::persistence::database::Database;
use crate::security::crypto;
use crate::security::rules::RulesEngine;

#[derive(Default)]
pub struct AppConfig {
    pub enabled_providers:  Vec<String>,
    pub allow_cloud_upload: bool,
    pub rules:              RulesEngine,
}

pub struct ApiKeys {
    pub vt: Arc<Mutex<String>>,
    pub md: Arc<Mutex<String>>,
    pub ha: Arc<Mutex<String>>,
    pub cm: Arc<Mutex<String>>,
}

impl ApiKeys {
    pub fn new() -> Self {
        Self {
            vt: Arc::new(Mutex::new(String::new())),
            md: Arc::new(Mutex::new(String::new())),
            ha: Arc::new(Mutex::new(String::new())),
            cm: Arc::new(Mutex::new(String::new())),
        }
    }

    pub fn load_from_keyring(&self) {
        let pairs = [
            ("virustotal",     &self.vt),
            ("metadefender",   &self.md),
            ("hybridanalysis", &self.ha),
            ("cloudmersive",   &self.cm),
        ];
        for (id, mtx) in &pairs {
            if let Ok(Some(k)) = crypto::get_key(id) {
                *mtx.lock().unwrap() = k;
                tracing::info!("Loaded key for {}", id);
            }
        }
    }
}

pub struct AppState {
    pub db:        Arc<Database>,
    pub pipeline:  Arc<ScanPipeline>,
    #[allow(dead_code)]          // sarà usato per lo scan asincrono in coda
    pub queue:     Arc<JobQueue>,
    pub keys:      Arc<ApiKeys>,
    pub auto_scan: Mutex<bool>,
    pub config:    RwLock<AppConfig>,
}
