import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface ScanRecord {
  id:string; filename:string; filepath:string; filesize:number;
  filehash:string; timestamp:string; overall_verdict:string;
}
export default function History() {
  const [records, setRecords] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter,  setFilter]  = useState("all");

  const load = async () => {
    setLoading(true);
    try { setRecords(await invoke<ScanRecord[]>("get_history")); }
    catch(e) { console.error(e); }
    finally { setLoading(false); }
  };
  const clear = async () => {
    if (!confirm("Cancellare tutto lo storico?")) return;
    await invoke("clear_history"); setRecords([]);
  };
  useEffect(() => { load(); }, []);

  const filtered = filter==="all" ? records : records.filter(r => r.overall_verdict===filter);
  const fmt = (n:number) => n>=1024*1024 ? (n/1024/1024).toFixed(1)+" MB" : (n/1024).toFixed(1)+" KB";
  const count = (v:string) => v==="all" ? records.length : records.filter(r=>r.overall_verdict===v).length;

  return (
    <div>
      <div style={{display:"flex", gap:"0.6rem", marginBottom:"1.25rem", flexWrap:"wrap", alignItems:"center"}}>
        {(["all","malicious","suspicious","clean"] as const).map((v) => {
          const meta: Record<string,{l:string;c:string}> = {
            all:{l:"Tutti",c:"#475569"}, malicious:{l:"🚨 Malware",c:"#dc2626"},
            suspicious:{l:"⚠️ Sospetti",c:"#d97706"}, clean:{l:"✅ Puliti",c:"#16a34a"}
          };
          const { l, c } = meta[v];
          return (
            <button key={v} onClick={() => setFilter(v)} style={{
              padding:"0.4rem 1rem", border:`1.5px solid ${filter===v?c:"#334155"}`,
              borderRadius:"9999px", background:filter===v?c+"22":"#1e293b",
              color:filter===v?c:"#64748b", cursor:"pointer", fontWeight:600,
              fontSize:"0.85rem", transition:"all 0.18s"}}>
              {l} <span style={{opacity:0.7}}>({count(v)})</span>
            </button>
          );
        })}
        <div style={{marginLeft:"auto", display:"flex", gap:"0.6rem"}}>
          <button className="btn btn-sm" style={{background:"#334155",color:"#94a3b8"}} onClick={load}>↻ Aggiorna</button>
          {records.length>0 && <button className="btn btn-sm btn-danger" onClick={clear}>🗑 Cancella</button>}
        </div>
      </div>

      <div className="card" style={{padding:0, overflow:"hidden"}}>
        {loading && <div className="empty"><div className="empty-icon">⏳</div>Caricamento...</div>}
        {!loading && filtered.length===0 && (
          <div className="empty"><div className="empty-icon">📋</div>
            {filter==="all" ? "Nessuna scansione ancora." : `Nessun file ${filter}.`}
          </div>
        )}
        {!loading && filtered.length>0 && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th style={{paddingLeft:"1.5rem"}}>📄 Nome file</th>
                  <th>📏 Dim.</th>
                  <th>🔍 Risultato</th>
                  <th>🕒 Data scansione</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(r => (
                  <tr key={r.id} title={r.filepath}>
                    <td style={{paddingLeft:"1.5rem"}}>
                      <div className="col-name" title={r.filename}>{r.filename}</div>
                      <div style={{fontSize:"0.73rem",color:"#334155",marginTop:"0.15rem",
                        overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",maxWidth:260}}>
                        {r.filepath}
                      </div>
                    </td>
                    <td className="col-size">{fmt(r.filesize)}</td>
                    <td className="col-verdict">
                      <span className={`badge badge-${r.overall_verdict}`}>
                        {r.overall_verdict.toUpperCase()}
                      </span>
                    </td>
                    <td className="col-date">{new Date(r.timestamp).toLocaleString("it-IT")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
