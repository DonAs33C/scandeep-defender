import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface ScanRecord {
  id: string;
  filename: string;
  filepath: string;
  filesize: number;
  filehash: string;
  timestamp: string;
  overall_verdict: string;
}

export default function History() {
  const [records, setRecords] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const data = await invoke<ScanRecord[]>("get_history");
      setRecords(data);
    } catch(e) { console.error(e); }
    finally { setLoading(false); }
  };

  const clear = async () => {
    if (!confirm("Cancellare tutto lo storico?")) return;
    await invoke("clear_history");
    setRecords([]);
  };

  useEffect(()=>{ load(); }, []);

  const badge = (v: string) => `badge badge-${v}`;

  return (
    <div className="card">
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"1rem"}}>
        <h2>📋 Storico scansioni ({records.length})</h2>
        <div style={{display:"flex",gap:".5rem"}}>
          <button className="btn btn-primary" onClick={load}>↻ Aggiorna</button>
          {records.length>0 && <button className="btn btn-danger" onClick={clear}>🗑 Cancella</button>}
        </div>
      </div>

      {loading && <div className="empty">Caricamento...</div>}
      {!loading && records.length===0 && <div className="empty">Nessuna scansione ancora.</div>}

      {!loading && records.length>0 && (
        <table>
          <thead>
            <tr>
              <th>File</th>
              <th>Dimensione</th>
              <th>Risultato</th>
              <th>Data</th>
            </tr>
          </thead>
          <tbody>
            {records.map(r => (
              <tr key={r.id} title={r.filepath}>
                <td style={{maxWidth:220,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>
                  {r.filename}
                </td>
                <td>{(r.filesize/1024).toFixed(1)} KB</td>
                <td><span className={badge(r.overall_verdict)}>{r.overall_verdict.toUpperCase()}</span></td>
                <td style={{color:"#64748b"}}>{new Date(r.timestamp).toLocaleString("it-IT")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
