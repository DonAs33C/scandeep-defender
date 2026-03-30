import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
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
  { id:"virustotal",   label:"VirusTotal (70+ engine)",   color:"#f87171" },
  { id:"metadefender", label:"MetaDefender (40+ engine)", color:"#fb923c" },
  { id:"clamav",       label:"ClamAV locale",             color:"#34d399" },
];

export default function Scanner() {
  const [filePath, setFilePath] = useState<string|null>(null);
  const [fileName, setFileName] = useState<string>("");
  const [selected, setSelected] = useState<string[]>(["virustotal","clamav"]);
  const [scanning, setScanning]   = useState(false);
  const [result, setResult]       = useState<ScanResult|null>(null);
  const [autoResult, setAutoResult] = useState<ScanResult|null>(null);
  const [error, setError]         = useState<string|null>(null);

  // Ascolta scansioni automatiche dal file watcher
  useEffect(() => {
    const unlisten = listen<ScanResult>("scan-complete", (event) => {
      setAutoResult(event.payload);
    });
    return () => { unlisten.then(f => f()); };
  }, []);

  const pickFile = async () => {
    const path = await open({ multiple: false, directory: false });
    if (typeof path === "string") {
      setFilePath(path);
      setFileName(path.split(/[\\\\/]/).pop() ?? path);
      setResult(null); setError(null);
    }
  };

  const toggle = (id: string) =>
    setSelected(s => s.includes(id) ? s.filter(x=>x!==id) : [...s, id]);

  const scan = async () => {
    if (!filePath || selected.length === 0) return;
    setScanning(true); setError(null); setResult(null);
    try {
      const settings = JSON.parse(localStorage.getItem("scandeep_settings")||"{}");
      await invoke("set_watcher_keys", { vt: settings.vt_key??"", md: settings.md_key??"" });
      const res = await invoke<ScanResult>("scan_file", {
        filePath, services: selected,
        vtKey: settings.vt_key ?? "",
        mdKey: settings.md_key ?? "",
      });
      setResult(res);
    } catch(e) { setError(String(e)); }
    finally { setScanning(false); }
  };

  const verdictClass = (v: string) =>
    v==="clean"?"verdict clean":v==="suspicious"?"verdict suspicious":
    v==="malicious"?"verdict malicious":"verdict pending";

  const verdictIcon = (v: string) =>
    ({clean:"✅ Pulito",suspicious:"⚠️ Sospetto",malicious:"🚨 MALWARE",pending:"⏳ In analisi"})[v]??v;

  return (
    <div>
      {/* Notifica auto-scan */}
      {autoResult && (
        <div className={verdictClass(autoResult.overall_verdict)} style={{marginBottom:"1rem"}}>
          🔔 Auto-scan: <strong>{autoResult.filename}</strong> — {verdictIcon(autoResult.overall_verdict)}
          <button onClick={()=>setAutoResult(null)}
            style={{float:"right",background:"none",border:"none",color:"inherit",cursor:"pointer",fontSize:"1rem"}}>✕</button>
        </div>
      )}

      <div className="card">
        <h2>Seleziona file da analizzare</h2>
        <div className={`upload-area ${filePath?"has-file":""}`} onClick={pickFile}>
          {filePath
            ? <><div style={{fontSize:"2rem"}}>📄</div><div style={{marginTop:8}}>{fileName}</div></>
            : <><div style={{fontSize:"2rem"}}>📂</div><div style={{marginTop:8}}>Clicca per sfogliare e selezionare un file</div></>
          }
        </div>

        <h2 style={{marginTop:"1.2rem"}}>Servizi di scansione</h2>
        {SERVICES.map(s => (
          <label key={s.id}>
            <input type="checkbox" checked={selected.includes(s.id)} onChange={()=>toggle(s.id)} />
            <span style={{color:s.color}}>{s.label}</span>
          </label>
        ))}

        <div style={{marginTop:"1rem"}}>
          <button className="btn btn-primary"
            onClick={scan}
            disabled={!filePath || selected.length===0 || scanning}>
            {scanning ? <><span className="spinner"/>Scansione in corso...</> : "🔍 Avvia scansione"}
          </button>
        </div>
      </div>

      {error && <div className="verdict malicious">⚠️ Errore: {error}</div>}

      {result && (
        <div className="card">
          <div className={verdictClass(result.overall_verdict)} style={{marginBottom:"1rem"}}>
            {verdictIcon(result.overall_verdict)}
          </div>
          <div style={{marginBottom:".75rem",fontSize:".8rem",color:"#64748b",wordBreak:"break-all"}}>
            <strong>SHA256:</strong> {result.filehash}
          </div>
          <div className="service-results">
            {Object.entries(result.services).map(([name, data]) => (
              <div className="svc-card" key={name}>
                <div className="svc-name">{name}</div>
                <div className={`svc-${data.verdict}`}>{data.verdict.toUpperCase()}</div>
                {data.detections>0 && (
                  <div style={{color:"#f87171",marginTop:".3rem"}}>{data.detections}/{data.engines} engines</div>
                )}
                <div style={{color:"#64748b",marginTop:".3rem",fontSize:".8rem"}}>{data.details}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
'''
(out / 'Scanner.tsx').write_text(scanner_tsx, encoding='utf-8')

# ── Settings.tsx aggiornato (con toggle auto-scan) ────────────────────────────
settings_tsx = '''\
import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

interface Settings { vt_key: string; md_key: string; auto_scan: boolean; }

export default function Settings() {
  const [s, setS] = useState<Settings>({ vt_key:"", md_key:"", auto_scan:true });
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    const stored = JSON.parse(localStorage.getItem("scandeep_settings")||"{}");
    setS({
      vt_key:   stored.vt_key   ?? "",
      md_key:   stored.md_key   ?? "",
      auto_scan: stored.auto_scan !== undefined ? stored.auto_scan : true,
    });
  }, []);

  const save = async () => {
    localStorage.setItem("scandeep_settings", JSON.stringify(s));
    // Aggiorna le chiavi nel backend (per il file watcher)
    await invoke("set_watcher_keys", { vt: s.vt_key, md: s.md_key });
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div>
      <div className="card">
        <h2>⚙️ Impostazioni API</h2>
        <div className="form-group">
          <span>🔴 VirusTotal API Key <a href="https://www.virustotal.com/gui/sign-up" target="_blank" style={{color:"#60a5fa",fontSize:".8rem"}}>(ottieni gratis)</a></span>
          <input type="password" value={s.vt_key}
            placeholder="Incolla qui la tua API key"
            onChange={e=>setS({...s, vt_key:e.target.value})} />
        </div>
        <div className="form-group">
          <span>🟠 MetaDefender API Key <a href="https://www.opswat.com/metadefender-cloud" target="_blank" style={{color:"#60a5fa",fontSize:".8rem"}}>(ottieni gratis)</a></span>
          <input type="password" value={s.md_key}
            placeholder="Incolla qui la tua API key"
            onChange={e=>setS({...s, md_key:e.target.value})} />
        </div>
        <button className="btn btn-primary" onClick={save}>
          {saved ? "✅ Salvato!" : "💾 Salva impostazioni"}
        </button>
      </div>

      <div className="card">
        <h2>🔍 Scansione automatica Download</h2>
        <div style={{display:"flex",alignItems:"center",gap:"1rem",marginBottom:"1rem"}}>
          <span style={{color:"#cbd5e1"}}>Monitora cartella Downloads e scansiona automaticamente i nuovi file</span>
          {/* Toggle switch */}
          <label style={{position:"relative",display:"inline-block",width:52,height:28,flexShrink:0}}>
            <input type="checkbox" checked={s.auto_scan}
              onChange={e=>setS({...s, auto_scan:e.target.checked})}
              style={{opacity:0,width:0,height:0}} />
            <span style={{
              position:"absolute",cursor:"pointer",inset:0,
              background: s.auto_scan ? "#3b82f6":"#334155",
              borderRadius:28,transition:".3s"
            }}>
              <span style={{
                position:"absolute",content:"",height:20,width:20,
                left: s.auto_scan ? 28 : 4, bottom:4,
                background:"#fff",borderRadius:"50%",transition:".3s"
              }}/>
            </span>
          </label>
          <span style={{color: s.auto_scan?"#34d399":"#64748b",fontWeight:700}}>
            {s.auto_scan ? "ATTIVA" : "DISATTIVATA"}
          </span>
        </div>
        <div style={{fontSize:".85rem",color:"#64748b"}}>
          Quando attiva, ogni file scaricato viene scansionato in background.<br/>
          Il risultato appare come notifica nella scheda Scanner.
        </div>
      </div>

      <div className="card">
        <h2>🟢 ClamAV locale</h2>
        <div style={{fontSize:".85rem",color:"#94a3b8",lineHeight:1.7}}>
          ClamAV è un motore antivirus open-source gratuito che funziona offline.<br/>
          Se non è installato, la scansione ClamAV mostrerà un avviso.<br/>
          <a href="https://www.clamav.net/downloads" target="_blank"
            style={{color:"#60a5fa"}}>👉 Scarica ClamAV per Windows</a>
          <br/>
          <span style={{color:"#475569",fontSize:".8rem"}}>
            Dopo l'installazione assicurati che <code>clamscan</code> sia nel PATH di Windows.
          </span>
        </div>
      </div>

      <div className="card" style={{fontSize:".85rem",color:"#475569"}}>
        <strong style={{color:"#94a3b8"}}>Note limiti API:</strong><br/>
        • VirusTotal free: 500 scansioni/giorno, 4/min<br/>
        • MetaDefender free: uso community<br/>
        • ClamAV: illimitato, funziona offline<br/>
        • Le chiavi API sono salvate solo in locale
      </div>
    </div>
  );
}
