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
