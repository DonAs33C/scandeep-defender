use rusqlite::{Connection, Result, params};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScanRecord {
    pub id: String,
    pub filename: String,
    pub filepath: String,
    pub filesize: u64,
    pub filehash: String,
    pub timestamp: String,
    pub overall_verdict: String,
}

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn new() -> Result<Self> {
        let dir = dirs::data_local_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("scandeep-defender");
        std::fs::create_dir_all(&dir).ok();
        let conn = Connection::open(dir.join("history.db"))?;
        conn.execute_batch("
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                filepath TEXT NOT NULL,
                filesize INTEGER NOT NULL,
                filehash TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                overall_verdict TEXT NOT NULL
            );
        ")?;
        Ok(Self { conn })
    }

    pub fn insert_scan(&self, result: &crate::ScanResult) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO scans VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                result.id, result.filename, result.filepath,
                result.filesize as i64, result.filehash,
                result.timestamp, result.overall_verdict
            ],
        )?;
        Ok(())
    }

    pub fn get_all_scans(&self) -> Result<Vec<ScanRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT id,filename,filepath,filesize,filehash,timestamp,overall_verdict
             FROM scans ORDER BY timestamp DESC LIMIT 500"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ScanRecord {
                id: row.get(0)?,
                filename: row.get(1)?,
                filepath: row.get(2)?,
                filesize: row.get::<_,i64>(3)? as u64,
                filehash: row.get(4)?,
                timestamp: row.get(5)?,
                overall_verdict: row.get(6)?,
            })
        })?;
        rows.collect()
    }

    pub fn clear_history(&self) -> Result<()> {
        self.conn.execute("DELETE FROM scans", [])?;
        Ok(())
    }
}
