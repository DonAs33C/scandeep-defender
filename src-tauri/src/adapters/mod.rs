pub mod scanner_trait;
pub mod virustotal;
pub mod clamav;
pub mod metadefender;
pub mod hybrid_analysis;
pub mod cloudmersive;

use std::sync::{Arc, Mutex};
use scanner_trait::ScanProvider;

pub fn build_providers(
    vt_key: Arc<Mutex<String>>, md_key: Arc<Mutex<String>>,
    ha_key: Arc<Mutex<String>>, cm_key: Arc<Mutex<String>>,
) -> Vec<Arc<dyn ScanProvider>> {
    vec![
        Arc::new(virustotal::VirusTotalAdapter::new(vt_key)),
        Arc::new(metadefender::MetaDefenderAdapter::new(md_key)),
        Arc::new(hybrid_analysis::HybridAnalysisAdapter::new(ha_key)),
        Arc::new(cloudmersive::CloudmersiveAdapter::new(cm_key)),
        Arc::new(clamav::ClamAVAdapter::new()),
    ]
}
