
import { useState, useRef } from "react";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { ScanReport, ProviderResult } from "../types";
import { useLangCtx } from "../LangContext";
import { T } from "../i18n";

const SERVICES = [
  { id:"virustotal",    label:"VirusTotal",      sub:"Cloud · SHA256 + upload"},
  { id:"metadefender",  label:"MetaDefender",    sub:"Cloud · multi-AV"},
  { id:"hybridanalysis",label:"Hybrid Analysis", sub:"Cloud · sandbox"},
  { id:"cloudmersive",  label:"Cloudmersive",    sub:"Cloud · ML"},
  { id:"clamav",        label:"ClamAV",          sub:"Locale · open source"},
];

type Step = {provider:string; status:string; message:string};

export default function Scan() {
  const { lang } = useLangCtx();
  const tr = T[lang].scanner;
  const [filePath, setFilePath]   = useState<string | null>(null);
  const [filename, setFilename]   = useState("");
  const [selected, setSelected]   = useState<string[]>(["virustotal"]);
  const [scanning, setScanning]   = useState(false);
  const [steps, setSteps]         = useState<Step[]>([]);
  const [report, setReport]       = useState<ScanReport | null>(null);
  const [error, setError]         = useState<string | null>(null);
  const [duplicate, setDuplicate] = useState<string | null>(null);
  const unlistenRef = useRef<(() => void) | null>(null);

  const browse = async () => {
    try {
      const result = await openDialog({
        multiple: false,
        filters: [{ name: "Tutti i file", extensions: ["*"] }],
      });
      if (typeof result === "string" && result) {
        setFilePath(result);
        setFilename(result.split(/[\\/]/).pop() ?? result);
        setReport(null);
        setError(null);
        setDuplicate(null);
        // controlla duplicati
        const dup = await invoke<string|null>("check_duplicate", { filePath: result });
        if (dup) setDuplicate(dup);
      }
    } catch (e) {
      // dialog cancellata — nessun crash
      console.info("Dialog chiusa:", e);
    }
  };

  const startScan = async () => {
    if (!filePath) return;
    if (selected.length === 0) { setError("Seleziona almeno un servizio."); return; }
    setScanning(true);
    setError(null);
    setSteps([]);
    setReport(null);

    // Ascolta i progressi
    try {
      const unlisten = await listen<{job_id:string; status:string; message:string}>(
        "scan-progress",
        ({ payload }) => {
          setSteps(prev => {
            const idx = prev.findIndex(s => s.provider === payload.status);
            const step = { provider: payload.status, status: payload.status, message: payload.message };
            return idx >= 0
              ? prev.map((s, i) => i === idx ? step : s)
              : [...prev, step];
          });
        }
      );
      unlistenRef.current = unlisten;
    } catch (_) {}

    try {
      const result = await invoke<ScanReport>("scan_file", {
        filePath,
        services: selected,
      });
      setReport(result);
    } catch (e) {
      setError(typeof e === "string" ? e : JSON.stringify(e));
    } finally {
      setScanning(false);
      unlistenRef.current?.();
      unlistenRef.current = null;
    }
  };

  const toggle = (id: string) =>
    setSelected(s => s.includes(id) ? s.filter(x => x !== id) : [...s, id]);

  const verdictClass = (v?: string) =>
    v?.toLowerCase() === "malicious"  ? "malicious"  :
    v?.toLowerCase() === "suspicious" ? "suspicious" :
    v?.toLowerCase() === "clean"      ? "clean"      : "pending";

  return (
    <div>
      {/* Scelta file */}
      <div className="card">
        <h2>📁 {tr.title}</h2>
        <div
          className={`upload-area ${filePath ? "has-file" : ""}`}
          onClick={browse}
          onKeyDown={e => e.key === "Enter" && browse()}
          role="button" tabIndex={0}
        >
          <div className="icon">{filePath ? "✅" : "📂"}</div>
          <div>{filePath ? filename : tr.dropHint}</div>
          {filePath && <div style={{fontSize:".78rem",color:"var(--text-muted)",marginTop:".3rem"}}>{filePath}</div>}
        </div>
        {duplicate && (
          <div className="dup-warning">⚠️ {tr.duplicate}: <strong>{duplicate}</strong></div>
        )}
      </div>

      {/* Selezione servizi */}
      <div className="card">
        <h2>🔬 {tr.services}</h2>
        <div className="service-list">
          {SERVICES.map(svc => (
            <div
              key={svc.id}
              className={`service-item ${selected.includes(svc.id) ? "checked" : ""}`}
              onClick={() => toggle(svc.id)}
              role="checkbox" aria-checked={selected.includes(svc.id)} tabIndex={0}
              onKeyDown={e => e.key === " " && toggle(svc.id)}
            >
              <input type="checkbox" checked={selected.includes(svc.id)} readOnly tabIndex={-1}/>
              <div>
                <div className="svc-label">{svc.label}</div>
                <div className="svc-sub">{svc.sub}</div>
              </div>
            </div>
          ))}
        </div>
        <button
          className="btn btn-primary"
          disabled={!filePath || scanning || selected.length === 0}
          onClick={startScan}
          style={{ minWidth:140 }}
        >
          {scanning ? <><span className="spinner"/>&nbsp;{tr.scanning}</> : tr.analyze}
        </button>
      </div>

      {/* Progresso */}
      {steps.length > 0 && (
        <div className="card">
          <h2>⚙️ {tr.progress}</h2>
          {steps.map((s, i) => (
            <div key={i} className="progress-step">
              <div className="progress-dot" style={{background:"var(--accent)"}}/>
              <span style={{fontSize:".85rem",color:"var(--text-2)"}}>{s.message}</span>
            </div>
          ))}
        </div>
      )}

      {/* Errore */}
      {error && (
        <div className="notification" style={{background:"rgba(244,67,54,.12)",border:"1px solid rgba(244,67,54,.3)",color:"#f44336"}}>
          ⚠️ {error}
          <button className="notif-close" onClick={() => setError(null)}>✕</button>
        </div>
      )}

      {/* Risultati */}
      {report && (
        <div className="card">
          <h2>📊 {tr.results}</h2>
          <div className={`verdict ${verdictClass(String(report.overall_verdict))}`}>
            {report.overall_verdict === "Malicious"  && "🔴"}
            {report.overall_verdict === "Suspicious" && "🟡"}
            {report.overall_verdict === "Clean"      && "🟢"}
            {report.overall_verdict === "Pending"    && "🔵"}
            &nbsp;{String(report.overall_verdict)} · Rischio {report.risk_score}/100
          </div>
          <div className="hash-box">SHA256: {report.hash}</div>
          <div className="service-results">
            {report.results.map((r: ProviderResult) => (
              <div key={r.provider_id} className="svc-card">
                <div className="svc-name">{r.provider_id}</div>
                <div className={`svc-${String(r.verdict).toLowerCase()}`}>{String(r.verdict)}</div>
                {r.detections > 0 && <div className="svc-detections">{r.detections}/{r.total_engines} rilevamenti</div>}
                {r.details && <div className="svc-details">{r.details}</div>}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
