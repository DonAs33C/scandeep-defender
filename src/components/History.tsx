import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useLangCtx } from "../LangContext";
import { T } from "../i18n";

interface ScanRecord { id:string;filename:string;filepath:string;filesize:number;filehash:string;timestamp:string;overall_verdict:string; }

export default function History() {
  const { lang } = useLangCtx();
  const h = T[lang].history;
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
    if (!confirm(h.confirmClear)) return;
    await invoke("clear_history"); setRecords([]);
  };
  useEffect(()=>{ load(); }, []);

  const filtered = filter==="all" ? records : records.filter(r=>r.overall_verdict===filter);
  const fmt = (n:number) => n>=1024*1024?(n/1024/1024).toFixed(1)+" MB":(n/1024).toFixed(1)+" KB";
  const count = (vd:string) => vd==="all" ? records.length : records.filter(r=>r.overall_verdict===vd).length;

  const FILTERS = [
    { v:"all",        l:h.all,        c:"#475569" },
    { v:"malicious",  l:h.malicious,  c:"#dc2626" },
    { v:"suspicious", l:h.suspicious, c:"#d97706" },
    { v:"clean",      l:h.clean,      c:"#16a34a" },
  ];

  return (
    <div>
      <div style={{display:"flex",gap:"0.6rem",marginBottom:"1.25rem",flexWrap:"wrap",alignItems:"center"}}>
        {FILTERS.map(({v,l,c}) => (
          <button key={v} onClick={()=>setFilter(v)} style={{
            padding:"0.4rem 1rem",border:`1.5px solid ${filter===v?c:"#334155"}`,
            borderRadius:"9999px",background:filter===v?c+"22":"#1e293b",
            color:filter===v?c:"#64748b",cursor:"pointer",fontWeight:600,
            fontSize:"0.85rem",transition:"all 0.18s"}}>
            {l} <span style={{opacity:0.7}}>({count(v)})</span>
          </button>
        ))}
        <div style={{marginLeft:"auto",display:"flex",gap:"0.6rem"}}>
          <button className="btn btn-sm" style={{background:"#334155",color:"#94a3b8"}} onClick={load}>{h.refresh}</button>
          {records.length>0 && <button className="btn btn-sm btn-danger" onClick={clear}>{h.clear}</button>}
        </div>
      </div>
      <div className="card" style={{padding:0,overflow:"hidden"}}>
        {loading && <div className="empty"><div className="empty-icon">⏳</div></div>}
        {!loading && filtered.length===0 && (
          <div className="empty"><div className="empty-icon">📋</div>
            {filter==="all" ? h.empty : `${h.emptyFilter} ${filter}.`}
          </div>
        )}
        {!loading && filtered.length>0 && (
          <div className="table-wrap">
            <table>
              <thead><tr>
                <th style={{paddingLeft:"1.5rem"}}>{h.file}</th>
                <th>{h.size}</th><th>{h.result}</th><th>{h.date}</th>
              </tr></thead>
              <tbody>
                {filtered.map(r=>(
                  <tr key={r.id} title={r.filepath}>
                    <td style={{paddingLeft:"1.5rem"}}>
                      <div className="col-name" title={r.filename}>{r.filename}</div>
                      <div style={{fontSize:"0.73rem",color:"#334155",marginTop:"0.15rem",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",maxWidth:260}}>{r.filepath}</div>
                    </td>
                    <td className="col-size">{fmt(r.filesize)}</td>
                    <td className="col-verdict"><span className={`badge badge-${r.overall_verdict}`}>{r.overall_verdict.toUpperCase()}</span></td>
                    <td className="col-date">{new Date(r.timestamp).toLocaleString(lang==="it"?"it-IT":"en-US")}</td>
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
