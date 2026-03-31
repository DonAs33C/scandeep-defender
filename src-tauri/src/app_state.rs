
use std::sync::{Arc,Mutex,RwLock};
use crate::engine::{pipeline::ScanPipeline,queue::JobQueue};
use crate::persistence::database::Database;
use crate::security::rules::RulesEngine;

#[derive(Debug,Clone,Default)]
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
    pub fn new()->Self{
        Self{ vt:Arc::new(Mutex::new(String::new())), md:Arc::new(Mutex::new(String::new())),
              ha:Arc::new(Mutex::new(String::new())), cm:Arc::new(Mutex::new(String::new())) }
    }
    pub fn load_from_keyring(&self){
        use crate::security::crypto::get_key;
        for (k,arc) in [("virustotal",&self.vt),("metadefender",&self.md),("hybridanalysis",&self.ha),("cloudmersive",&self.cm)] {
            if let Ok(Some(v)) = get_key(k) { *arc.lock().unwrap() = v; }
        }
    }
}

pub struct AppState {
    pub db:        Arc<Database>,
    pub pipeline:  Arc<ScanPipeline>,
    pub queue:     Arc<JobQueue>,
    pub keys:      Arc<ApiKeys>,
    pub auto_scan: Mutex<bool>,
    pub config:    RwLock<AppConfig>,
}
