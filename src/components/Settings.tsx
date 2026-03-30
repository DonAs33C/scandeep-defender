import { useState, useEffect } from "react";

interface Settings { vt_key: string; md_key: string; }

export default function Settings() {
  const [s, setS] = useState<Settings>({ vt_key:"", md_key:"" });
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    const stored = JSON.parse(localStorage.getItem("scandeep_settings")||"{}");
    setS({ vt_key: stored.vt_key??"", md_key: stored.md_key??"" });
  }, []);

  const save = () => {
    localStorage.setItem("scandeep_settings", JSON.stringify(s));
    setSaved(true);
    setTimeout(()=>setSaved(false), 2000);
  };

  return (
    <div className="card">
      <h2>⚙️ Impostazioni API</h2>

      <div className="form-group">
        <span>🔴 VirusTotal API Key <a href="https://www.virustotal.com/gui/sign-up" target="_blank" style={{color:"#60a5fa",fontSize:".8rem"}}>(ottieni gratis)</a></span>
        <input type="password" value={s.vt_key} placeholder="Incolla qui la tua API key VirusTotal"
          onChange={e=>setS({...s, vt_key:e.target.value})} />
      </div>

      <div className="form-group">
        <span>🟠 MetaDefender API Key <a href="https://www.opswat.com/metadefender-cloud" target="_blank" style={{color:"#60a5fa",fontSize:".8rem"}}>(ottieni gratis)</a></span>
        <input type="password" value={s.md_key} placeholder="Incolla qui la tua API key MetaDefender"
          onChange={e=>setS({...s, md_key:e.target.value})} />
      </div>

      <button className="btn btn-primary" onClick={save} style={{marginTop:".5rem"}}>
        {saved ? "✅ Salvato!" : "💾 Salva impostazioni"}
      </button>

      <div style={{marginTop:"1.5rem",padding:"1rem",background:"#0f172a",borderRadius:".5rem",fontSize:".85rem",color:"#64748b"}}>
        <strong style={{color:"#94a3b8"}}>Note:</strong><br/>
        • VirusTotal free: 500 scansioni/giorno, 4/minuto<br/>
        • MetaDefender free: uso community limitato<br/>
        • Le chiavi API sono salvate solo in locale sul tuo PC
      </div>
    </div>
  );
}
