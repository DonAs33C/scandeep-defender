
use std::path::Path;
use std::time::Duration;
use tokio::time::sleep;

const IGNORE_EXTENSIONS: &[&str] = &[
    "tmp","part","crdownload","download","partial","!ut","downloading","filepart","opdownload",
];
const STABILITY_CHECKS: u32 = 3;       // consecutive stable reads
const CHECK_INTERVAL_MS: u64 = 1500;   // ms between checks
const MAX_WAIT_SECS:   u64 = 120;      // give up after 2 min

pub struct StabilityChecker;

impl StabilityChecker {
    /// Returns true if we should ignore this file entirely.
    pub fn should_ignore(path: &Path) -> bool {
        if !path.is_file() { return true; }
        let ext = path.extension()
            .and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
        if IGNORE_EXTENSIONS.contains(&ext.as_str()) { return true; }
        // Ignore hidden/temp files starting with dot or tilde
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.starts_with('.') || name.starts_with('~') { return true; }
        }
        false
    }

    /// Waits until the file size is stable for N consecutive checks.
    /// Returns Ok(file_size) or Err if timed out or file disappeared.
    pub async fn wait_until_stable(path: &Path) -> Result<u64, String> {
        let deadline = tokio::time::Instant::now()
            + Duration::from_secs(MAX_WAIT_SECS);

        let mut stable_count = 0u32;
        let mut last_size = 0u64;

        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(format!("Timeout: file {:?} never stabilised", path));
            }
            if !path.exists() {
                return Err(format!("File {:?} disappeared", path));
            }
            let size = tokio::fs::metadata(path).await
                .map(|m| m.len())
                .map_err(|e| e.to_string())?;

            if size == last_size && size > 0 {
                stable_count += 1;
                if stable_count >= STABILITY_CHECKS { return Ok(size); }
            } else {
                stable_count = 0;
                last_size = size;
            }
            sleep(Duration::from_millis(CHECK_INTERVAL_MS)).await;
        }
    }
}
