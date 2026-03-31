import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { listen } from "@tauri-apps/api/event";

interface ServiceResult {
  status: string; detections: number; engines: number;
  verdict: "clean"|"suspicious"|"malicious"|"pending"|"error"; details: string;
}
interface ScanResult {
  id: string; filename: string; filepath: string; filesize: number;
  filehash: string; timestamp: string;
  services: Record<string, ServiceResult>;
  overall_verdict: "clean"|"suspicious"|"malicious"|"pending";
}
const SERVICES = [
  { id:"virustotal",     label:"VirusTotal",      sub:"70+ engine cloud",    color:"#f87171" },
  { id:"metadefender",   label:"MetaDefender",    sub:"40+ engine cloud",    color:"#fb923c" },
  { id:"hybridanalysis", label:"Hybrid Analysis", sub:"Sandbox + hash",      color:"#a78bfa" },
  { id:"cloudmersive",   label:"Cloudmersive",    sub:"Scan file avanzato",  color:"#34d399" },
  { id:"clamav",         label:"ClamAV locale",   sub:"Offline, illimitato", color:"#38bdf8" },
];
const VERDICT_LABEL: Record<string,string> = {
  clean:"✅ Pulito — nessuna minaccia rilevata",
  suspicious:"⚠️ Sospetto — verificare manualmente",
  malicious:"🚨 MALWARE RILEVATO",
  pending:"⏳ Analisi in corso / dati insufficienti",
};
export default function Scanner() {
  const [filePath, setFilePath] = useState<string|null>(null);
  const [fileName, setFileName] = useState("");
  const [selected, setSelected] = useState<string[]>(["virustotal","clamav"]);
  const [scanning, setScanning] = useState(false);
  const [result,   setResult]   = useState<ScanResult|null>(null);
  const [autoNotif,setAutoNotif]= useState<ScanResult|null>(null);
  const [error,    setError]    = useState<string|null>(null);

  useEffect(() => {
    const ul = listen<ScanResult>("scan-complete", e => setAutoNotif(e.payload));
    return () => { ul.then(f => f()); };
  }, []);

  const pickFile = async () => {
    const path = await openDialog({ multiple: false, directory: false });
    if (typeof path === "string" && path) {
      setFilePath(path);
      setFileName(path.split(/[\\/]/).pop() ?? path);
      setResult(null); setError(null);
    }
  };
  const toggle = (id: string) =>
    setSelected(s => s.includes(id) ? s.filter(x => x !== id) : [...s, id]);

  const scan = async () => {
    if (!filePath || !selected.length) return;
    setScanning(true); setError(null); setResult(null);
    try {
      const cfg = JSON.parse(localStorage.getItem("scandeep_settings") || "{}");
      await invoke("set_watcher_keys", { vt: cfg.vt_key??"", md: cfg.md_key??"", ha: cfg.ha_key??"", cm: cfg.cm_key??"" });
      const res = await invoke<ScanResult>("scan_file", {
        filePath, services: selected,
        vtKey: cfg.vt_key??"", mdKey: cfg.md_key??"",
        haKey: cfg.ha_key??"", cmKey: cfg.cm_key??"",
      });
      setResult(res);
    } catch(e) { setError(String(e)); }
    finally { setScanning(false); }
  };

  return (
    <div>
      {autoNotif && (
        <div className={`notification verdict ${autoNotif.overall_verdict}`}>
          🔔 Auto-scan: <strong>{autoNotif.filename}</strong> — {VERDICT_LABEL[autoNotif.overall_verdict]}
          <button className="notif-close" onClick={() => setAutoNotif(null)}>✕</button>
        </div>
      )}
      <div className="card">
        <h2>📂 Seleziona file</h2>
        <div className={`upload-area ${filePath ? "has-file" : ""}`} onClick={pickFile}
          role="button" tabIndex={0} onKeyDown={e => e.key==="Enter" && pickFile()}>
          <div className="icon">{filePath ? "📄" : "📂"}</div>
          <div>{filePath ? fileName : "Clicca per sfogliare e selezionare un file"}</div>
          {filePath && <div style={{fontSize:"0.78rem",marginTop:"0.4rem",color:"#475569"}}>{filePath}</div>}
        </div>
        <h2>🔍 Servizi di scansione</h2>
        <p className="section-sub">Seleziona uno o più servizi</p>
        <div className="service-list">
          {SERVICES.map(s => (
            <label key={s.id} className={`service-item ${selected.includes(s.id)?"checked":""}`}>
              <input type="checkbox" checked={selected.includes(s.id)} onChange={() => toggle(s.id)} />
              <div>
                <div className="svc-label" style={{color:s.color}}>{s.label}</div>
                <div className="svc-sub">{s.sub}</div>
              </div>
            </label>
          ))}
        </div>
        <div className="btn-group">
          <button className="btn btn-primary" onClick={scan}
            disabled={!filePath || !selected.length || scanning}>
            {scanning ? <><span className="spinner"/> Scansione...</> : "🔍 Avvia scansione"}
          </button>
          {filePath && (
            <button className="btn" style={{background:"#334155",color:"#94a3b8"}}
              onClick={() => { setFilePath(null); setFileName(""); setResult(null); setError(null); }}>
              ✕ Rimuovi file
            </button>
          )}
        </div>
      </div>
      {error && <div className="verdict malicious card">⚠️ Errore: {error}</div>}
      {result && (
        <div className="card">
          <div className={`verdict ${result.overall_verdict}`} style={{marginBottom:"1rem"}}>
            {VERDICT_LABEL[result.overall_verdict]}
          </div>
          <div className="hash-box"><strong>SHA256:</strong> {result.filehash}</div>
          <div className="service-results">
            {Object.entries(result.services).map(([name, data]) => (
              <div className="svc-card" key={name}>
                <div className="svc-name">{name}</div>
                <div className={`svc-${data.verdict}`}>{data.verdict.toUpperCase()}</div>
                {data.detections > 0 && <div className="svc-detections">{data.detections}/{data.engines} engines</div>}
                <div className="svc-details">{data.details}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
