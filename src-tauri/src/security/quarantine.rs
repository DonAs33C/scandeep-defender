use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct QuarantineRecord {
    pub id: String,
    pub original_path: String,
    pub quarantine_path: String,
    pub filename: String,
    pub hash: String,
    pub quarantined_at: String,
    pub scan_id: String,
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
        Ok(Self {
            quarantine_dir: dir,
        })
    }

    /// Computes SHA256 hash of a file in streaming fashion (memory efficient)
    async fn compute_file_hash(path: &Path) -> Result<String> {
        let mut file = File::open(path)
            .await
            .context("Cannot open file for hashing")?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 8192];
        loop {
            let n = file
                .read(&mut buffer)
                .await
                .context("Failed to read file for hashing")?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Atomically moves file to quarantine with cross-device fallback and integrity verification
    pub async fn quarantine(
        &self,
        file_path: &Path,
        expected_hash: &str,
        scan_id: &str,
    ) -> Result<QuarantineRecord> {
        let id = Uuid::new_v4().to_string();
        let filename = file_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let qpath = self.quarantine_dir.join(format!("{}.quar", id));

        // Try rename first (fast, atomic on same filesystem)
        let move_result = std::fs::rename(file_path, &qpath);

        // If rename fails (e.g., cross-device), fall back to copy + verify + remove
        if move_result.is_err() {
            // Copy file to quarantine
            tokio::fs::copy(file_path, &qpath)
                .await
                .context("Failed to copy file to quarantine (cross-device fallback)")?;

            // Verify integrity after copy
            let copied_hash = Self::compute_file_hash(&qpath).await?;
            if copied_hash != expected_hash {
                // Clean up corrupted copy
                tokio::fs::remove_file(&qpath).await.ok();
                anyhow::bail!("Integrity check failed after quarantine copy: hash mismatch");
            }

            // Remove original after successful copy and verification
            tokio::fs::remove_file(file_path)
                .await
                .context("Failed to remove original file after quarantine")?;
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&qpath, std::fs::Permissions::from_mode(0o400))?;
        }

        // Final integrity verification
        let final_hash = Self::compute_file_hash(&qpath).await?;
        if final_hash != expected_hash {
            anyhow::bail!("Final integrity check failed: quarantined file hash mismatch");
        }

        Ok(QuarantineRecord {
            id,
            original_path: file_path.to_string_lossy().to_string(),
            quarantine_path: qpath.to_string_lossy().to_string(),
            filename,
            hash: expected_hash.to_string(),
            quarantined_at: chrono::Utc::now().to_rfc3339(),
            scan_id: scan_id.to_string(),
        })
    }

    pub async fn restore(&self, record: &QuarantineRecord) -> Result<()> {
        let qpath = PathBuf::from(&record.quarantine_path);
        let orig = PathBuf::from(&record.original_path);

        // Verify integrity before restore
        let hash = Self::compute_file_hash(&qpath).await?;
        if hash != record.hash {
            anyhow::bail!("Integrity check failed: quarantined file hash mismatch before restore");
        }

        if let Some(parent) = orig.parent() {
            tokio::fs::create_dir_all(parent).await.ok();
        }

        // Try rename first
        let restore_result = tokio::fs::rename(&qpath, &orig).await;

        // Cross-device fallback: copy + verify + remove
        if restore_result.is_err() {
            tokio::fs::copy(&qpath, &orig)
                .await
                .context("Failed to copy file from quarantine (cross-device fallback)")?;

            // Verify integrity after copy
            let copied_hash = Self::compute_file_hash(&orig).await?;
            if copied_hash != record.hash {
                tokio::fs::remove_file(&orig).await.ok();
                anyhow::bail!("Integrity check failed after restore copy: hash mismatch");
            }

            tokio::fs::remove_file(&qpath)
                .await
                .context("Failed to remove quarantined file after restore")?;
        }

        Ok(())
    }

    pub async fn delete_permanently(&self, record: &QuarantineRecord) -> Result<()> {
        tokio::fs::remove_file(&record.quarantine_path)
            .await
            .context("Failed to delete quarantined file")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::tempdir;
    use tokio::fs;

    async fn create_test_file(dir: &Path, name: &str, content: &[u8]) -> std::path::PathBuf {
        let path = dir.join(name);
        fs::write(&path, content).await.unwrap();
        path
    }

    #[tokio::test]
    async fn quarantine_creates_record_with_correct_hash() {
        let temp = tempdir().unwrap();
        let file_path = create_test_file(temp.path(), "test.exe", b"malware content").await;

        let manager = QuarantineManager::new().unwrap();
        let expected_hash = manager.compute_file_hash(&file_path).await.unwrap();

        let record = manager
            .quarantine(&file_path, &expected_hash, "scan-123")
            .await
            .unwrap();

        assert_eq!(record.hash, expected_hash);
        assert_eq!(record.filename, "test.exe");
        assert_eq!(record.scan_id, "scan-123");
        assert!(record.quarantine_path.ends_with(".quar"));
        assert!(!record.id.is_empty());
    }

    #[tokio::test]
    async fn quarantine_fails_on_hash_mismatch() {
        let temp = tempdir().unwrap();
        let file_path = create_test_file(temp.path(), "test.exe", b"malware content").await;

        let manager = QuarantineManager::new().unwrap();
        let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";

        let result = manager.quarantine(&file_path, wrong_hash, "scan-123").await;

        assert!(result.is_err());
        // Original file should still exist
        assert!(file_path.exists());
    }

    #[tokio::test]
    async fn quarantine_removes_original_file() {
        let temp = tempdir().unwrap();
        let file_path = create_test_file(temp.path(), "test.exe", b"malware content").await;

        let manager = QuarantineManager::new().unwrap();
        let expected_hash = manager.compute_file_hash(&file_path).await.unwrap();

        let _record = manager
            .quarantine(&file_path, &expected_hash, "scan-123")
            .await
            .unwrap();

        // Original file should be gone
        assert!(!file_path.exists());
    }

    #[tokio::test]
    async fn restore_restores_file_to_original_location() {
        let temp = tempdir().unwrap();
        let file_path = create_test_file(temp.path(), "test.exe", b"malware content").await;

        let manager = QuarantineManager::new().unwrap();
        let expected_hash = manager.compute_file_hash(&file_path).await.unwrap();

        let record = manager
            .quarantine(&file_path, &expected_hash, "scan-123")
            .await
            .unwrap();

        // Restore
        manager.restore(&record).await.unwrap();

        // File should be back at original location
        assert!(file_path.exists());
        let content = fs::read(&file_path).await.unwrap();
        assert_eq!(content, b"malware content");
    }

    #[tokio::test]
    async fn restore_fails_on_hash_mismatch() {
        let temp = tempdir().unwrap();
        let file_path = create_test_file(temp.path(), "test.exe", b"malware content").await;

        let manager = QuarantineManager::new().unwrap();
        let expected_hash = manager.compute_file_hash(&file_path).await.unwrap();

        let record = manager
            .quarantine(&file_path, &expected_hash, "scan-123")
            .await
            .unwrap();

        // Corrupt the quarantined file
        fs::write(&record.quarantine_path, b"corrupted")
            .await
            .unwrap();

        let result = manager.restore(&record).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn delete_permanently_removes_quarantined_file() {
        let temp = tempdir().unwrap();
        let file_path = create_test_file(temp.path(), "test.exe", b"malware content").await;

        let manager = QuarantineManager::new().unwrap();
        let expected_hash = manager.compute_file_hash(&file_path).await.unwrap();

        let record = manager
            .quarantine(&file_path, &expected_hash, "scan-123")
            .await
            .unwrap();

        manager.delete_permanently(&record).await.unwrap();

        assert!(!Path::new(&record.quarantine_path).exists());
    }

    #[tokio::test]
    async fn quarantine_sets_restrictive_permissions_on_unix() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let temp = tempdir().unwrap();
            let file_path = create_test_file(temp.path(), "test.exe", b"malware content").await;

            let manager = QuarantineManager::new().unwrap();
            let expected_hash = manager.compute_file_hash(&file_path).await.unwrap();

            let record = manager
                .quarantine(&file_path, &expected_hash, "scan-123")
                .await
                .unwrap();

            let metadata = fs::metadata(&record.quarantine_path).await.unwrap();
            let perms = metadata.permissions();
            // Should be 0o400 (read-only for owner)
            assert_eq!(perms.mode() & 0o777, 0o400);
        }
    }

    #[tokio::test]
    async fn compute_file_hash_is_consistent() {
        let temp = tempdir().unwrap();
        let file_path = create_test_file(temp.path(), "test.bin", b"consistent content").await;

        let manager = QuarantineManager::new().unwrap();

        let hash1 = manager.compute_file_hash(&file_path).await.unwrap();
        let hash2 = manager.compute_file_hash(&file_path).await.unwrap();

        assert_eq!(hash1, hash2);
    }

    #[tokio::test]
    async fn compute_file_hash_different_for_different_content() {
        let temp = tempdir().unwrap();
        let file1 = create_test_file(temp.path(), "file1.bin", b"content one").await;
        let file2 = create_test_file(temp.path(), "file2.bin", b"content two").await;

        let manager = QuarantineManager::new().unwrap();

        let hash1 = manager.compute_file_hash(&file1).await.unwrap();
        let hash2 = manager.compute_file_hash(&file2).await.unwrap();

        assert_ne!(hash1, hash2);
    }
}
