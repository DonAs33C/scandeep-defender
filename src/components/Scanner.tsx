import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { listen } from "@tauri-apps/api/event";
import { useLangCtx } from "../LangContext";
import { T } from "../i18n";

const LS_SERVICES = "scandeep_services";

interface ServiceResult {
  status:string; detections:number; engines:number;
  verdict:"clean"|"suspicious"|"malicious"|"pending"|"error";
  details:string; poll_id?:string;
}
interface ScanResult {
  id:string; filename:string; filepath:string; filesize:number;
  filehash:string; timestamp:string;
  services:Record<string,ServiceResult>;
  overall_verdict:"clean"|"suspicious"|"malicious"|"pending";
}
interface ProgressEvent { service:string; status:"scanning"|"done"; verdict?:string; }

const SERVICES = [
  { id:"virustotal",     label:"VirusTotal",      sub:"70+ engine cloud",    color:"#f87171" },
  { id:"metadefender",   label:"MetaDefender",    sub:"40+ engine cloud",    color:"#fb923c" },
  { id:"hybridanalysis", label:"Hybrid Analysis", sub:"Sandbox + hash",      color:"#a78bfa" },
  { id:"cloudmersive",   label:"Cloudmersive",    sub:"Scan file avanzato",  color:"#34d399" },
  { id:"clamav",         label:"ClamAV locale",   sub:"Offline, illimitato", color:"#38bdf8" },
];

export default function Scanner() {
  const { lang } = useLangCtx();
  const s = T[lang].scanner;
  const p = T[lang].progress;
  const v = T[lang].verdict;

  const [filePath, setFilePath] = useState<string|null>(null);
  const [fileName, setFileName] = useState("");
  const [selected, setSelected] = useState<string[]>(() =>
    JSON.parse(localStorage.getItem(LS_SERVICES) || '["virustotal","clamav"]')
  );
  const [scanning,  setScanning]  = useState(false);
  const [result,    setResult]    = useState<ScanResult|null>(null);
  const [autoNotif, setAutoNotif] = useState<ScanResult|null>(null);
  const [error,     setError]     = useState<string|null>(null);
  const [dupWarning,setDupWarning]= useState<{verdict:string}|null>(null);
  const [progress,  setProgress]  = useState<Record<string,string>>({});
  const [pollCountdown, setPollCountdown] = useState<number|null>(null);
  const pollTimer = useRef<ReturnType<typeof setInterval>|null>(null);

  // Persist selected services
  useEffect(() => {
    localStorage.setItem(LS_SERVICES, JSON.stringify(selected));
  }, [selected]);

  // Listen auto-scan events
  useEffect(() => {
    const ul = listen<ScanResult>("scan-complete", e => setAutoNotif(e.payload));
    const ulP = listen<ProgressEvent>("scan-progress", e => {
      setProgress(prev => ({
        ...prev,
        [e.payload.service]: e.payload.status === "scanning" ? "scanning" : (e.payload.verdict ?? "done"),
      }));
    });
    return () => { ul.then(f=>f()); ulP.then(f=>f()); };
  }, []);

  const toggle = (id:string) =>
    setSelected(s => s.includes(id) ? s.filter(x=>x!==id) : [...s, id]);

  const pickFile = async () => {
    const path = await openDialog({ multiple:false, directory:false });
    if (typeof path === "string" && path) {
      setFilePath(path);
      setFileName(path.split(/[\\/]/).pop() ?? path);
      setResult(null); setError(null); setDupWarning(null); setProgress({});
      // Check for duplicate
      try {
        const prevVerdict = await invoke<string|null>("check_hash_in_history", { filePath: path });
        if (prevVerdict) setDupWarning({ verdict: prevVerdict });
      } catch {}
    }
  };

  const startScan = async (force = false) => {
    if (!filePath || !selected.length) return;
    if (dupWarning && !force) return;
    setScanning(true); setError(null); setResult(null);
    setDupWarning(null); setProgress({});
    try {
      const cfg = JSON.parse(localStorage.getItem("scandeep_settings") || "{}");
      await invoke("set_watcher_keys", { vt:cfg.vt_key??"", md:cfg.md_key??"", ha:cfg.ha_key??"", cm:cfg.cm_key??"" });
      const res = await invoke<ScanResult>("scan_file", {
        filePath, services:selected,
        vtKey:cfg.vt_key??"", mdKey:cfg.md_key??"",
        haKey:cfg.ha_key??"", cmKey:cfg.cm_key??"",
      });
      setResult(res);
      // Auto-poll if any pending service has poll_id
      const pendingSvcs = Object.entries(res.services).filter(([,d]) => d.verdict==="pending" && d.poll_id);
      if (pendingSvcs.length > 0) startPolling(res, pendingSvcs.map(([k])=>k));
    } catch(e) { setError(String(e)); }
    finally { setScanning(false); }
  };

  const startPolling = (baseResult: ScanResult, svcs: string[]) => {
    let countdown = 30;
    setPollCountdown(countdown);
    if (pollTimer.current) clearInterval(pollTimer.current);
    pollTimer.current = setInterval(async () => {
      countdown--;
      setPollCountdown(countdown);
      if (countdown <= 0) {
        clearInterval(pollTimer.current!);
        setPollCountdown(null);
        await refreshPending(baseResult);
      }
    }, 1000);
  };

  const refreshPending = async (currentResult?: ScanResult) => {
    const res = currentResult ?? result;
    if (!res) return;
    const cfg = JSON.parse(localStorage.getItem("scandeep_settings") || "{}");
    try {
      const updated = { ...res };
      let changed = false;
      for (const [svcName, svcData] of Object.entries(res.services)) {
        if (svcData.verdict === "pending" && svcData.poll_id) {
          const newData = await invoke<ServiceResult>("poll_vt_analysis", {
            analysisId: svcData.poll_id,
            vtKey: cfg.vt_key ?? "",
          });
          if (newData.verdict !== "pending") {
            updated.services = { ...updated.services, [svcName]: newData };
            changed = true;
          }
        }
      }
      if (changed) {
        // Recompute overall verdict
        const svcs = Object.values(updated.services);
        const overall = svcs.some(s=>s.verdict==="malicious") ? "malicious"
          : svcs.some(s=>s.verdict==="suspicious") ? "suspicious"
          : svcs.every(s=>s.verdict==="clean") ? "clean" : "pending";
        updated.overall_verdict = overall as any;
        setResult(updated);
        if (overall === "pending") startPolling(updated, []);
      } else {
        startPolling(updated, []);
      }
    } catch(e) { console.error(e); }
  };

  const statusColor = (s:string) => ({
    scanning:"#3b82f6", clean:"#4ade80", malicious:"#f87171",
    suspicious:"#fbbf24", pending:"#93c5fd", done:"#64748b"
  })[s] ?? "#64748b";

  const verdictClass = (vd:string) =>
    `verdict ${vd==="clean"?"clean":vd==="suspicious"?"suspicious":vd==="malicious"?"malicious":"pending"}`;

  return (
    <div>
      {autoNotif && (
        <div className={`notification ${verdictClass(autoNotif.overall_verdict)}`}>
          🔔 {s.autoNotif}: <strong>{autoNotif.filename}</strong> — {(v as any)[autoNotif.overall_verdict]}
          <button className="notif-close" onClick={()=>setAutoNotif(null)}>✕</button>
        </div>
      )}

      <div className="card">
        <h2>📂 {s.title}</h2>
        <div className={`upload-area ${filePath?"has-file":""}`} onClick={pickFile}
          role="button" tabIndex={0} onKeyDown={e=>e.key==="Enter"&&pickFile()}>
          <div className="icon">{filePath?"📄":"📂"}</div>
          <div>{filePath ? fileName : s.drop}</div>
          {filePath && <div style={{fontSize:"0.75rem",marginTop:"0.4rem",color:"#475569"}}>{filePath}</div>}
        </div>

        {/* Duplicate warning */}
        {dupWarning && (
          <div className="dup-warning">
            <span>⚠️ {s.dupTitle} — {s.dupMsg.replace("{verdict}",dupWarning.verdict.toUpperCase())}</span>
            <div className="btn-group" style={{marginTop:"0.5rem"}}>
              <button className="btn btn-primary btn-sm" onClick={()=>startScan(true)}>{s.dupScan}</button>
              <button className="btn btn-sm" style={{background:"#334155",color:"#94a3b8"}}
                onClick={()=>setDupWarning(null)}>{s.dupCancel}</button>
            </div>
          </div>
        )}

        <h2>🔍 {s.services}</h2>
        <p className="section-sub">{s.servicesHint}</p>
        <div className="service-list">
          {SERVICES.map(svc => (
            <label key={svc.id} className={`service-item ${selected.includes(svc.id)?"checked":""}`}>
              <input type="checkbox" checked={selected.includes(svc.id)} onChange={()=>toggle(svc.id)}/>
              <div>
                <div className="svc-label" style={{color:svc.color}}>{svc.label}</div>
                <div className="svc-sub">{svc.sub}</div>
              </div>
            </label>
          ))}
        </div>

        <div className="btn-group">
          <button className="btn btn-primary" onClick={()=>startScan(false)}
            disabled={!filePath||!selected.length||scanning||(dupWarning!=null)}>
            {scanning ? <><span className="spinner"/> {s.scanning}</> : s.scan}
          </button>
          {filePath && (
            <button className="btn" style={{background:"#334155",color:"#94a3b8"}}
              onClick={()=>{setFilePath(null);setFileName("");setResult(null);setError(null);setDupWarning(null);setProgress({});}}>
              ✕ {s.remove}
            </button>
          )}
        </div>
      </div>

      {/* Progress steps */}
      {scanning && selected.length > 0 && (
        <div className="card">
          <h2>📡 {s.step}</h2>
          <div style={{display:"flex",flexDirection:"column",gap:"0.5rem"}}>
            {selected.map(svcId => {
              const svcMeta = SERVICES.find(x=>x.id===svcId);
              const st = progress[svcId] ?? "waiting";
              return (
                <div key={svcId} className="progress-step">
                  <span className="progress-dot" style={{background:statusColor(st)}}/>
                  <span style={{color:svcMeta?.color,fontWeight:600,minWidth:120}}>{svcMeta?.label}</span>
                  <div className="progress-bar-wrap">
                    <div className="progress-bar-fill" style={{
                      width: st==="waiting"?"0%":st==="scanning"?"60%":"100%",
                      background: statusColor(st),
                      transition:"width 0.5s ease"
                    }}/>
                  </div>
                  <span style={{fontSize:"0.78rem",color:"#64748b",minWidth:80}}>
                    {st==="waiting"?p.waiting:st==="scanning"?p.analyzing:p.done}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {error && <div className="verdict malicious card">⚠️ {error}</div>}

      {result && (
        <div className="card">
          <div className={verdictClass(result.overall_verdict)} style={{marginBottom:"1rem"}}>
            {(v as any)[result.overall_verdict]}
            {pollCountdown!==null && (
              <span style={{marginLeft:"auto",fontSize:"0.82rem",fontWeight:400,opacity:0.8}}>
                Auto-refresh in {pollCountdown}s
              </span>
            )}
          </div>
          <div className="hash-box"><strong>{s.hash}:</strong> {result.filehash}</div>
          {/* Refresh button if pending */}
          {Object.values(result.services).some(d=>d.verdict==="pending") && (
            <div className="btn-group" style={{marginBottom:"1rem"}}>
              <button className="btn btn-sm btn-primary" onClick={()=>refreshPending()}>
                {s.refreshBtn}
              </button>
            </div>
          )}
          <div className="service-results">
            {Object.entries(result.services).map(([name,data])=>(
              <div className="svc-card" key={name}>
                <div className="svc-name">{name}</div>
                <div className={`svc-${data.verdict}`}>{data.verdict.toUpperCase()}</div>
                {data.detections>0 && <div className="svc-detections">{data.detections}/{data.engines} engines</div>}
                <div className="svc-details">{data.details}</div>
                {data.verdict==="pending" && <div style={{marginTop:"0.3rem"}}><span className="spinner" style={{borderTopColor:"#93c5fd",borderColor:"#334155"}}/></div>}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
