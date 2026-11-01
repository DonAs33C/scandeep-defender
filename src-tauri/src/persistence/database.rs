use crate::adapters::scanner_trait::{ProviderResult, Verdict};
use crate::engine::job::ScanReport;
use crate::security::quarantine::QuarantineRecord;
use rusqlite::{params, Connection, Result};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScanRecord {
    pub id: String,
    pub filename: String,
    pub filepath: String,
    pub filesize: u64,
    pub filehash: String,
    pub timestamp: String,
    pub overall_verdict: String,
    pub risk_score: u8,
}

pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub fn new() -> Result<Self> {
        let dir = dirs::data_local_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("scandeep-defender");
        std::fs::create_dir_all(&dir).ok();
        let conn = Connection::open(dir.join("history.db"))?;
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY, filename TEXT, filepath TEXT,
                filesize INTEGER, filehash TEXT, timestamp TEXT,
                overall_verdict TEXT, risk_score INTEGER DEFAULT 0,
                results_json TEXT
            );
            CREATE TABLE IF NOT EXISTS quarantine (
                id TEXT PRIMARY KEY, original_path TEXT, quarantine_path TEXT,
                filename TEXT, hash TEXT, quarantined_at TEXT, scan_id TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_filehash ON scans(filehash);
        ",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub async fn save_report(&self, r: &ScanReport) -> Result<()> {
        let results_json = serde_json::to_string(&r.results).unwrap_or_default();
        let verdict_str = format!("{:?}", r.overall_verdict).to_lowercase();
        self.conn.lock().unwrap().execute(
            "INSERT OR REPLACE INTO scans VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                r.job_id,
                r.filename,
                r.filepath,
                r.filesize as i64,
                r.hash,
                r.timestamp,
                verdict_str,
                r.risk_score as i64,
                results_json
            ],
        )?;
        Ok(())
    }

    pub async fn get_cached_report(&self, hash: &str) -> Result<Option<ScanReport>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,filename,filepath,filesize,filehash,timestamp,overall_verdict,risk_score,results_json
             FROM scans WHERE filehash=? ORDER BY timestamp DESC LIMIT 1"
        )?;
        let row = stmt.query_row([hash], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)? as u64,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, i64>(7)? as u8,
                r.get::<_, String>(8)?,
            ))
        });
        match row {
            Ok((id, filename, filepath, filesize, filehash, timestamp, vs, risk_score, rj)) => {
                let results: Vec<ProviderResult> = serde_json::from_str(&rj).unwrap_or_default();
                let overall_verdict = match vs.as_str() {
                    "malicious" => "Malicious",
                    "suspicious" => "Suspicious",
                    "clean" => "Clean",
                    _ => "Pending",
                };
                let overall_verdict = match overall_verdict {
                    "Malicious" => Verdict::Malicious,
                    "Suspicious" => Verdict::Suspicious,
                    "Clean" => Verdict::Clean,
                    _ => Verdict::Pending,
                };
                Ok(Some(ScanReport {
                    job_id: id,
                    filename,
                    filepath,
                    filesize,
                    hash: filehash,
                    timestamp,
                    results,
                    overall_verdict,
                    risk_score,
                    from_cache: true,
                }))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn get_all_scans(&self) -> Result<Vec<ScanRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,filename,filepath,filesize,filehash,timestamp,overall_verdict,risk_score
             FROM scans ORDER BY timestamp DESC LIMIT 500",
        )?;
        // FIX: collect in variabile PRIMA che conn venga droppato
        let rows = stmt.query_map([], |r| {
            Ok(ScanRecord {
                id: r.get(0)?,
                filename: r.get(1)?,
                filepath: r.get(2)?,
                filesize: r.get::<_, i64>(3)? as u64,
                filehash: r.get(4)?,
                timestamp: r.get(5)?,
                overall_verdict: r.get(6)?,
                risk_score: r.get::<_, i64>(7)? as u8,
            })
        })?;
        let result: Vec<ScanRecord> = rows.collect::<Result<Vec<_>, _>>()?;
        Ok(result)
    }

    pub fn clear_history(&self) -> Result<()> {
        self.conn.lock().unwrap().execute("DELETE FROM scans", [])?;
        Ok(())
    }

    pub fn find_by_hash(&self, hash: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT overall_verdict FROM scans WHERE filehash=? ORDER BY timestamp DESC LIMIT 1",
        )?;
        match stmt.query_row([hash], |r| r.get::<_, String>(0)) {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn save_quarantine(&self, q: &QuarantineRecord) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT OR REPLACE INTO quarantine VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                q.id,
                q.original_path,
                q.quarantine_path,
                q.filename,
                q.hash,
                q.quarantined_at,
                q.scan_id
            ],
        )?;
        Ok(())
    }

    pub fn get_quarantine_list(&self) -> Result<Vec<QuarantineRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,original_path,quarantine_path,filename,hash,quarantined_at,scan_id
             FROM quarantine ORDER BY quarantined_at DESC",
        )?;
        // FIX: stesso pattern — collect prima del drop
        let rows = stmt.query_map([], |r| {
            Ok(QuarantineRecord {
                id: r.get(0)?,
                original_path: r.get(1)?,
                quarantine_path: r.get(2)?,
                filename: r.get(3)?,
                hash: r.get(4)?,
                quarantined_at: r.get(5)?,
                scan_id: r.get(6)?,
            })
        })?;
        let result: Vec<QuarantineRecord> = rows.collect::<Result<Vec<_>, _>>()?;
        Ok(result)
    }

    pub fn remove_quarantine(&self, id: &str) -> Result<()> {
        self.conn
            .lock()
            .unwrap()
            .execute("DELETE FROM quarantine WHERE id=?", [id])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::scanner_trait::{ProviderResult, Verdict};
    use crate::engine::job::ScanReport;
    use crate::security::quarantine::QuarantineRecord;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn make_test_db() -> Database {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test_history.db");
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY, filename TEXT, filepath TEXT,
                filesize INTEGER, filehash TEXT, timestamp TEXT,
                overall_verdict TEXT, risk_score INTEGER DEFAULT 0,
                results_json TEXT
            );
            CREATE TABLE IF NOT EXISTS quarantine (
                id TEXT PRIMARY KEY, original_path TEXT, quarantine_path TEXT,
                filename TEXT, hash TEXT, quarantined_at TEXT, scan_id TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_filehash ON scans(filehash);",
        )
        .unwrap();
        Database {
            conn: std::sync::Mutex::new(conn),
        }
    }

    fn make_report(verdict: Verdict, hash: &str) -> ScanReport {
        ScanReport {
            job_id: "test-job".into(),
            filename: "test.exe".into(),
            filepath: "/path/test.exe".into(),
            filesize: 1024,
            hash: hash.into(),
            timestamp: "2024-01-01T00:00:00Z".into(),
            results: vec![ProviderResult {
                provider_id: "test".into(),
                verdict,
                detections: 1,
                total_engines: 10,
                details: "test".into(),
                poll_id: None,
            }],
            overall_verdict: verdict,
            risk_score: 50,
            from_cache: false,
        }
    }

    #[test]
    fn save_and_get_cached_report() {
        let db = make_test_db();
        let report = make_report(Verdict::Malicious, "abc123");

        db.save_report(&report).await.unwrap();

        let cached = db.get_cached_report("abc123").await.unwrap();
        assert!(cached.is_some());
        let cached = cached.unwrap();
        assert_eq!(cached.hash, "abc123");
        assert_eq!(cached.overall_verdict, Verdict::Malicious);
        assert_eq!(cached.risk_score, 50);
        assert!(cached.from_cache);
    }

    #[test]
    fn get_cached_report_returns_none_for_unknown_hash() {
        let db = make_test_db();

        let cached = db.get_cached_report("unknown").await.unwrap();
        assert!(cached.is_none());
    }

    #[test]
    fn save_report_updates_existing() {
        let db = make_test_db();
        let mut report = make_report(Verdict::Clean, "samehash");
        db.save_report(&report).await.unwrap();

        report.overall_verdict = Verdict::Malicious;
        report.risk_score = 90;
        db.save_report(&report).await.unwrap();

        let cached = db.get_cached_report("samehash").await.unwrap().unwrap();
        assert_eq!(cached.overall_verdict, Verdict::Malicious);
        assert_eq!(cached.risk_score, 90);
    }

    #[test]
    fn get_all_scans_returns_sorted_by_timestamp() {
        let db = make_test_db();

        let mut r1 = make_report(Verdict::Clean, "hash1");
        r1.timestamp = "2024-01-01T00:00:00Z".into();
        db.save_report(&r1).await.unwrap();

        let mut r2 = make_report(Verdict::Malicious, "hash2");
        r2.timestamp = "2024-01-02T00:00:00Z".into();
        db.save_report(&r2).await.unwrap();

        let scans = db.get_all_scans().unwrap();
        assert_eq!(scans.len(), 2);
        // Most recent first
        assert_eq!(scans[0].filehash, "hash2");
        assert_eq!(scans[1].filehash, "hash1");
    }

    #[test]
    fn clear_history_removes_all_scans() {
        let db = make_test_db();
        db.save_report(&make_report(Verdict::Clean, "hash1"))
            .await
            .unwrap();
        db.save_report(&make_report(Verdict::Malicious, "hash2"))
            .await
            .unwrap();

        db.clear_history().unwrap();

        let scans = db.get_all_scans().unwrap();
        assert_eq!(scans.len(), 0);
    }

    #[test]
    fn find_by_hash_returns_verdict() {
        let db = make_test_db();
        let mut report = make_report(Verdict::Suspicious, "findme");
        db.save_report(&report).await.unwrap();

        let result = db.find_by_hash("findme").unwrap();
        assert_eq!(result, Some("suspicious".into()));
    }

    #[test]
    fn find_by_hash_returns_none_for_unknown() {
        let db = make_test_db();
        let result = db.find_by_hash("unknown").unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn save_and_get_quarantine_list() {
        let db = make_test_db();

        let q1 = QuarantineRecord {
            id: "q1".into(),
            original_path: "/orig/file1.exe".into(),
            quarantine_path: "/quar/q1.quar".into(),
            filename: "file1.exe".into(),
            hash: "hash1".into(),
            quarantined_at: "2024-01-01T00:00:00Z".into(),
            scan_id: "scan1".into(),
        };
        let q2 = QuarantineRecord {
            id: "q2".into(),
            original_path: "/orig/file2.exe".into(),
            quarantine_path: "/quar/q2.quar".into(),
            filename: "file2.exe".into(),
            hash: "hash2".into(),
            quarantined_at: "2024-01-02T00:00:00Z".into(),
            scan_id: "scan2".into(),
        };

        db.save_quarantine(&q1).unwrap();
        db.save_quarantine(&q2).unwrap();

        let list = db.get_quarantine_list().unwrap();
        assert_eq!(list.len(), 2);
        // Most recent first
        assert_eq!(list[0].id, "q2");
        assert_eq!(list[1].id, "q1");
    }

    #[test]
    fn remove_quarantine_removes_record() {
        let db = make_test_db();

        let q = QuarantineRecord {
            id: "q1".into(),
            original_path: "/orig/file.exe".into(),
            quarantine_path: "/quar/q1.quar".into(),
            filename: "file.exe".into(),
            hash: "hash1".into(),
            quarantined_at: "2024-01-01T00:00:00Z".into(),
            scan_id: "scan1".into(),
        };
        db.save_quarantine(&q).unwrap();

        db.remove_quarantine("q1").unwrap();

        let list = db.get_quarantine_list().unwrap();
        assert_eq!(list.len(), 0);
    }
}
