import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useLangCtx } from "../LangContext";
import { T } from "../i18n";

interface QRecord { id:string; filename:string; original_path:string; quarantine_path:string; hash:string; quarantined_at:string; scan_id:string; }

export default function Quarantine() {
  const { lang } = useLangCtx();
  const q = T[lang].quarantine;
  const [records, setRecords] = useState<QRecord[]>([]);
  const [loading, setLoading] = useState(true);

  const load = async () => { setLoading(true); try { setRecords(await invoke<QRecord[]>("list_quarantine")); } catch(e){console.error(e);} finally{setLoading(false);} };
  useEffect(()=>{load();},[]);

  const restore = async (r:QRecord) => {
    await invoke("restore_file",{record:r}); setRecords(records.filter(x=>x.id!==r.id));
  };
  const del = async (r:QRecord) => {
    if(!confirm(q.confirmDelete)) return;
    await invoke("delete_permanently",{record:r}); setRecords(records.filter(x=>x.id!==r.id));
  };

  return (
    <div>
      <div className="card" style={{padding:0,overflow:"hidden"}}>
        {loading && <div className="empty"><div className="empty-icon">⏳</div></div>}
        {!loading && records.length===0 && <div className="empty"><div className="empty-icon">🔒</div>{q.empty}</div>}
        {!loading && records.length>0 && (
          <div className="table-wrap">
            <table>
              <thead><tr>
                <th style={{paddingLeft:"1.5rem"}}>{q.file}</th>
                <th style={{minWidth:160}}>{q.originalPath}</th>
                <th style={{minWidth:140}}>{q.date}</th>
                <th style={{minWidth:180}}>{q.action}</th>
              </tr></thead>
              <tbody>
                {records.map(r=>(
                  <tr key={r.id}>
                    <td style={{paddingLeft:"1.5rem"}}>
                      <div style={{fontWeight:600,color:"#e2e8f0"}}>{r.filename}</div>
                      <div style={{fontSize:"0.72rem",color:"#334155",fontFamily:"monospace"}}>{r.hash.slice(0,16)}…</div>
                    </td>
                    <td><div style={{fontSize:"0.78rem",color:"#64748b",maxWidth:200,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}} title={r.original_path}>{r.original_path}</div></td>
                    <td style={{color:"#64748b",fontSize:"0.82rem"}}>{new Date(r.quarantined_at).toLocaleString(lang==="it"?"it-IT":"en-US")}</td>
                    <td>
                      <div className="btn-group">
                        <button className="btn btn-sm" style={{background:"#1d4ed8",color:"#fff"}} onClick={()=>restore(r)}>{q.restore}</button>
                        <button className="btn btn-sm btn-danger" onClick={()=>del(r)}>{q.delete}</button>
                      </div>
                    </td>
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
