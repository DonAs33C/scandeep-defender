
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct QuarantineRecord {
    pub id:            String,
    pub original_path: String,
    pub quarantine_path: String,
    pub filename:      String,
    pub hash:          String,
    pub quarantined_at:String,
    pub scan_id:       String,
}

pub struct QuarantineManager {
    quarantine_dir: PathBuf,
}

impl QuarantineManager {
    pub fn new() -> Result<Self> {
        let dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("scandeep-defender")
            .join("quarantine");
        std::fs::create_dir_all(&dir).context("Cannot create quarantine dir")?;
        Ok(Self { quarantine_dir: dir })
    }

    /// Move file to quarantine. Returns a QuarantineRecord.
    pub fn quarantine(&self, file_path: &Path, hash: &str, scan_id: &str) -> Result<QuarantineRecord> {
        let id = Uuid::new_v4().to_string();
        let filename = file_path.file_name()
            .unwrap_or_default().to_string_lossy().to_string();
        // Rename to UUID so no extension is executable in quarantine
        let qpath = self.quarantine_dir.join(format!("{}.quar", id));

        std::fs::rename(file_path, &qpath)
            .context("Failed to move file to quarantine")?;

        // Lock-down permissions (Windows: remove execute bit if on Unix it's no-op)
        #[cfg(unix)]
        { use std::os::unix::fs::PermissionsExt;
          std::fs::set_permissions(&qpath, std::fs::Permissions::from_mode(0o400))?; }

        Ok(QuarantineRecord {
            id,
            original_path: file_path.to_string_lossy().to_string(),
            quarantine_path: qpath.to_string_lossy().to_string(),
            filename,
            hash: hash.to_string(),
            quarantined_at: chrono::Utc::now().to_rfc3339(),
            scan_id: scan_id.to_string(),
        })
    }

    /// Restore a quarantined file to its original location.
    pub fn restore(&self, record: &QuarantineRecord) -> Result<()> {
        let qpath = PathBuf::from(&record.quarantine_path);
        let orig  = PathBuf::from(&record.original_path);
        if let Some(parent) = orig.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::rename(&qpath, &orig)
            .context("Failed to restore file from quarantine")
    }

    /// Permanently delete a quarantined file.
    pub fn delete_permanently(&self, record: &QuarantineRecord) -> Result<()> {
        std::fs::remove_file(&record.quarantine_path)
            .context("Failed to delete quarantined file")
    }
}
