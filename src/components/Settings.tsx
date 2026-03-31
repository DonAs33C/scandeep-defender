import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";

interface Settings { vt_key:string; md_key:string; ha_key:string; cm_key:string; auto_scan:boolean; }

const API_LINKS = [
  { label:"VirusTotal",      url:"https://www.virustotal.com/gui/sign-up",         sub:"500 req/giorno gratis" },
  { label:"MetaDefender",    url:"https://metadefender.opswat.com/account/signup", sub:"Community gratis" },
  { label:"Hybrid Analysis", url:"https://www.hybrid-analysis.com/signup",         sub:"API gratis con registrazione" },
  { label:"Cloudmersive",    url:"https://account.cloudmersive.com/signup",        sub:"800 chiamate/mese gratis" },
];
const API_FIELDS = [
  { key:"vt_key", label:"VirusTotal API Key",      color:"#f87171" },
  { key:"md_key", label:"MetaDefender API Key",    color:"#fb923c" },
  { key:"ha_key", label:"Hybrid Analysis API Key", color:"#a78bfa" },
  { key:"cm_key", label:"Cloudmersive API Key",    color:"#34d399" },
];

export default function Settings() {
  const [s, setS] = useState<Settings>({ vt_key:"", md_key:"", ha_key:"", cm_key:"", auto_scan:true });
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    const stored = JSON.parse(localStorage.getItem("scandeep_settings") || "{}");
    setS({ vt_key:stored.vt_key??"", md_key:stored.md_key??"",
           ha_key:stored.ha_key??"", cm_key:stored.cm_key??"",
           auto_scan:stored.auto_scan!==undefined ? stored.auto_scan : true });
  }, []);

  const save = async () => {
    localStorage.setItem("scandeep_settings", JSON.stringify(s));
    await invoke("set_watcher_keys", { vt:s.vt_key, md:s.md_key, ha:s.ha_key, cm:s.cm_key });
    await invoke("set_auto_scan", { enabled: s.auto_scan });
    setSaved(true);
    setTimeout(() => setSaved(false), 2200);
  };

  return (
    <div>
      <div className="card">
        <h2>🔑 Chiavi API</h2>
        {API_FIELDS.map(f => (
          <div className="form-group" key={f.key}>
            <label className="form-label" style={{color:f.color}}>{f.label}</label>
            <input className="input-field" type="password"
              placeholder={`Incolla qui la chiave ${f.label}`}
              value={(s as any)[f.key]}
              onChange={e => setS({...s, [f.key]:e.target.value})} />
          </div>
        ))}
        <div className="btn-group" style={{marginTop:"0.5rem"}}>
          <button className="btn btn-primary" onClick={save}>
            {saved ? "✅ Salvato!" : "💾 Salva impostazioni"}
          </button>
        </div>
      </div>

      <div className="card">
        <h2>📥 Scansione automatica Download</h2>
        <div className="toggle-row">
          <div className="toggle-label">
            Monitora la cartella Downloads e scansiona automaticamente i nuovi file
            <small>Il risultato appare come notifica nella scheda Scanner</small>
          </div>
          <label className="toggle">
            <input type="checkbox" checked={s.auto_scan}
              onChange={e => setS({...s, auto_scan:e.target.checked})} />
            <span className="toggle-track"/>
            <span className="toggle-thumb" style={{transform: s.auto_scan?"translateX(22px)":"translateX(0)"}}/>
          </label>
          <span style={{color:s.auto_scan?"#4ade80":"#475569", fontWeight:700, fontSize:"0.85rem", minWidth:85}}>
            {s.auto_scan ? "✅ ATTIVA" : "⛔ DISATTIVA"}
          </span>
        </div>
        <div className="divider"/>
        <div className="info-box">
          ℹ️ Ogni file scaricato viene scansionato in background. Il risultato appare come notifica nella scheda Scanner.
        </div>
        <div className="btn-group" style={{marginTop:"1rem"}}>
          <button className="btn btn-primary" onClick={save}>
            {saved ? "✅ Salvato!" : "💾 Salva impostazioni"}
          </button>
        </div>
      </div>

      <div className="card">
        <h2>🟢 ClamAV locale (offline)</h2>
        <div className="info-box">
          ClamAV è un antivirus open-source gratuito e funziona completamente offline, senza limiti di richieste.<br/>
          <br/>
          <strong>Installazione Windows:</strong><br/>
          1. Scarica da{" "}
          <button className="link-btn" onClick={() => openUrl("https://www.clamav.net/downloads")}>
            clamav.net/downloads
          </button><br/>
          2. Installa e verifica che <code style={{color:"#94a3b8"}}>clamscan</code> sia nel PATH di sistema<br/>
          3. Aggiorna le definizioni con: <code style={{color:"#94a3b8"}}>freshclam</code>
        </div>
      </div>

      <div className="card">
        <h2>🔗 Registrazione API gratuite</h2>
        <div style={{display:"grid", gridTemplateColumns:"repeat(auto-fill,minmax(200px,1fr))", gap:"0.75rem"}}>
          {API_LINKS.map(link => (
            <button key={link.url} onClick={() => openUrl(link.url)}
              style={{background:"#0f172a", border:"1px solid #334155", borderRadius:"0.5rem",
                padding:"0.85rem 1rem", textAlign:"left", cursor:"pointer", color:"inherit",
                transition:"border-color 0.18s"}}
              onMouseEnter={e => (e.currentTarget.style.borderColor="#3b82f6")}
              onMouseLeave={e => (e.currentTarget.style.borderColor="#334155")}>
              <div style={{fontWeight:700, color:"#e2e8f0", fontSize:"0.9rem"}}>{link.label}</div>
              <div style={{color:"#64748b", fontSize:"0.78rem", marginTop:"0.2rem"}}>{link.sub}</div>
              <div style={{color:"#3b82f6", fontSize:"0.78rem", marginTop:"0.4rem"}}>🔗 Vai al sito →</div>
            </button>
          ))}
        </div>
      </div>

      <div className="info-box" style={{fontSize:"0.8rem"}}>
        🔒 Tutte le chiavi API sono salvate <strong>solo localmente</strong> sul tuo PC.
      </div>
    </div>
  );
}
