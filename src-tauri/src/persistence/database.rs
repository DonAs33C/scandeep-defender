
use rusqlite::{Connection,Result,params};
use serde::{Deserialize,Serialize};
use std::sync::Mutex;
use crate::engine::job::ScanReport;
use crate::adapters::scanner_trait::{ProviderResult,Verdict};
use crate::security::quarantine::QuarantineRecord;

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct ScanRecord {
    pub id:String, pub filename:String, pub filepath:String,
    pub filesize:u64, pub filehash:String, pub timestamp:String,
    pub overall_verdict:String, pub risk_score:u8,
}

pub struct Database { conn: Mutex<Connection> }

impl Database {
    pub fn new() -> Result<Self> {
        let dir = dirs::data_local_dir().unwrap_or_else(||std::path::PathBuf::from(".")).join("scandeep-defender");
        std::fs::create_dir_all(&dir).ok();
        let conn = Connection::open(dir.join("history.db"))?;
        conn.execute_batch("
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
        ")?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    pub async fn save_report(&self, r: &ScanReport) -> Result<()> {
        let results_json = serde_json::to_string(&r.results).unwrap_or_default();
        let verdict_str = format!("{:?}", r.overall_verdict).to_lowercase();
        self.conn.lock().unwrap().execute(
            "INSERT OR REPLACE INTO scans VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![r.job_id,r.filename,r.filepath,r.filesize as i64,r.hash,
                    r.timestamp,verdict_str,r.risk_score as i64,results_json],
        )?;
        Ok(())
    }

    pub async fn get_cached_report(&self, hash: &str) -> Result<Option<ScanReport>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,filename,filepath,filesize,filehash,timestamp,overall_verdict,risk_score,results_json FROM scans WHERE filehash=? ORDER BY timestamp DESC LIMIT 1"
        )?;
        let r = stmt.query_row([hash], |row| {
            Ok((
                row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,
                row.get::<_,i64>(3)? as u64,row.get::<_,String>(4)?,row.get::<_,String>(5)?,
                row.get::<_,String>(6)?,row.get::<_,i64>(7)? as u8,row.get::<_,String>(8)?,
            ))
        });
        match r {
            Ok((id,filename,filepath,filesize,filehash,timestamp,verdict_str,risk_score,rj)) => {
                let results:Vec<ProviderResult> = serde_json::from_str(&rj).unwrap_or_default();
                let overall_verdict = match verdict_str.as_str() {
                    "malicious"=>Verdict::Malicious,"suspicious"=>Verdict::Suspicious,
                    "clean"=>Verdict::Clean,_=>Verdict::Pending
                };
                Ok(Some(ScanReport{job_id:id,filename,filepath,filesize,hash:filehash,
                    timestamp,results,overall_verdict,risk_score,from_cache:true}))
            },
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn get_all_scans(&self) -> Result<Vec<ScanRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,filename,filepath,filesize,filehash,timestamp,overall_verdict,risk_score FROM scans ORDER BY timestamp DESC LIMIT 500"
        )?;
        stmt.query_map([],|r|Ok(ScanRecord{
            id:r.get(0)?,filename:r.get(1)?,filepath:r.get(2)?,
            filesize:r.get::<_,i64>(3)? as u64,filehash:r.get(4)?,
            timestamp:r.get(5)?,overall_verdict:r.get(6)?,risk_score:r.get::<_,i64>(7)? as u8,
        }))?.collect()
    }

    pub fn clear_history(&self) -> Result<()> { self.conn.lock().unwrap().execute("DELETE FROM scans",[])?; Ok(()) }

    pub fn find_by_hash(&self, hash:&str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT overall_verdict FROM scans WHERE filehash=? ORDER BY timestamp DESC LIMIT 1")?;
        match stmt.query_row([hash],|r|r.get::<_,String>(0)) {
            Ok(v)=>Ok(Some(v)), Err(rusqlite::Error::QueryReturnedNoRows)=>Ok(None), Err(e)=>Err(e),
        }
    }

    pub fn save_quarantine(&self, q:&QuarantineRecord) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT OR REPLACE INTO quarantine VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![q.id,q.original_path,q.quarantine_path,q.filename,q.hash,q.quarantined_at,q.scan_id],
        )?; Ok(())
    }
    pub fn get_quarantine_list(&self) -> Result<Vec<QuarantineRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id,original_path,quarantine_path,filename,hash,quarantined_at,scan_id FROM quarantine ORDER BY quarantined_at DESC")?;
        stmt.query_map([],|r|Ok(QuarantineRecord{
            id:r.get(0)?,original_path:r.get(1)?,quarantine_path:r.get(2)?,
            filename:r.get(3)?,hash:r.get(4)?,quarantined_at:r.get(5)?,scan_id:r.get(6)?,
        }))?.collect()
    }
    pub fn remove_quarantine(&self, id:&str) -> Result<()> {
        self.conn.lock().unwrap().execute("DELETE FROM quarantine WHERE id=?",[id])?; Ok(())
    }
}
