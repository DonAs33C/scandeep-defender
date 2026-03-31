import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useLangCtx } from "../LangContext";
import { T, type Lang } from "../i18n";

interface SettingsState { auto_scan:boolean; allow_cloud_upload:boolean; }
const API_FIELDS = [
  { key:"vt", label:"VirusTotal API Key",      color:"#f87171" },
  { key:"md", label:"MetaDefender API Key",    color:"#fb923c" },
  { key:"ha", label:"Hybrid Analysis API Key", color:"#a78bfa" },
  { key:"cm", label:"Cloudmersive API Key",    color:"#34d399" },
];
const API_LINKS = [
  { label:"VirusTotal",      url:"https://www.virustotal.com/gui/sign-up",         sub:"500 req/giorno gratis" },
  { label:"MetaDefender",    url:"https://metadefender.opswat.com/account/signup", sub:"Community gratis" },
  { label:"Hybrid Analysis", url:"https://www.hybrid-analysis.com/signup",         sub:"API gratis" },
  { label:"Cloudmersive",    url:"https://account.cloudmersive.com/signup",        sub:"800/mese gratis" },
];

export default function Settings() {
  const { lang, setLang } = useLangCtx();
  const tr = T[lang].settings;
  const [keys, setKeys] = useState<Record<string,string>>({ vt:"", md:"", ha:"", cm:"" });
  const [s, setS] = useState<SettingsState>({ auto_scan:true, allow_cloud_upload:false });
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    invoke<Record<string,string>>("load_api_keys").then(k => setKeys({
      vt:k.virustotal??"", md:k.metadefender??"", ha:k.hybridanalysis??"", cm:k.cloudmersive??""
    })).catch(console.error);
    const st = JSON.parse(localStorage.getItem("scandeep_ui") || "{}");
    setS({ auto_scan:st.auto_scan!==undefined?st.auto_scan:true, allow_cloud_upload:st.allow_cloud_upload??false });
  }, []);

  const save = async () => {
    await invoke("save_api_keys", { vt:keys.vt, md:keys.md, ha:keys.ha, cm:keys.cm });
    await invoke("set_auto_scan", { enabled:s.auto_scan });
    await invoke("set_config", { allowCloudUpload:s.allow_cloud_upload, enabledProviders:["virustotal","metadefender","hybridanalysis","cloudmersive","clamav"] });
    localStorage.setItem("scandeep_ui", JSON.stringify(s));
    setSaved(true); setTimeout(()=>setSaved(false), 2200);
  };

  const openLink = (url:string) => invoke("open_browser",{url}).catch(console.error);

  return (
    <div>
      <div className="card">
        <h2>{tr.langTitle}</h2>
        <div className="btn-group">
          {(["it","en"] as Lang[]).map(l=>(
            <button key={l} className={`btn ${lang===l?"btn-primary":""}`}
              style={lang!==l?{background:"#334155",color:"#94a3b8"}:{}} onClick={()=>setLang(l)}>
              {l==="it"?tr.langIt:tr.langEn}
            </button>
          ))}
        </div>
      </div>

      <div className="card">
        <h2>{tr.apiTitle}</h2>
        {API_FIELDS.map(f=>(
          <div className="form-group" key={f.key}>
            <label className="form-label" style={{color:f.color}}>{f.label}</label>
            <input className="input-field" type="password" placeholder={tr.placeholder}
              value={keys[f.key]} onChange={e=>setKeys({...keys,[f.key]:e.target.value})}/>
          </div>
        ))}
        <div className="info-box" style={{marginTop:"0.5rem",fontSize:"0.82rem"}}>{tr.privacy}</div>
        <div className="btn-group" style={{marginTop:"1rem"}}><button className="btn btn-primary" onClick={save}>{saved?tr.saved:tr.save}</button></div>
      </div>

      <div className="card">
        <h2>{tr.autoTitle}</h2>
        <div className="toggle-row">
          <div className="toggle-label">{tr.autoDesc}<small>{tr.autoHint}</small></div>
          <label className="toggle">
            <input type="checkbox" checked={s.auto_scan} onChange={e=>setS({...s,auto_scan:e.target.checked})}/>
            <span className="toggle-track"/><span className="toggle-thumb" style={{transform:s.auto_scan?"translateX(22px)":"translateX(0)"}}/>
          </label>
          <span style={{color:s.auto_scan?"#4ade80":"#475569",fontWeight:700,fontSize:"0.85rem",minWidth:85}}>{s.auto_scan?tr.active:tr.inactive}</span>
        </div>
        <div className="divider"/>
        <h2 style={{marginTop:"0.5rem"}}>{tr.cloudTitle}</h2>
        <div className="toggle-row">
          <div className="toggle-label">{tr.cloudDesc}<small style={{color:"#f87171"}}>{tr.cloudWarning}</small></div>
          <label className="toggle">
            <input type="checkbox" checked={s.allow_cloud_upload} onChange={e=>setS({...s,allow_cloud_upload:e.target.checked})}/>
            <span className="toggle-track" style={{background:s.allow_cloud_upload?"#dc2626":"#334155"}}/><span className="toggle-thumb" style={{transform:s.allow_cloud_upload?"translateX(22px)":"translateX(0)"}}/>
          </label>
          <span style={{color:s.allow_cloud_upload?"#f87171":"#475569",fontWeight:700,fontSize:"0.85rem",minWidth:85}}>{s.allow_cloud_upload?"⚠️ ATTIVO":"🔒 OFF"}</span>
        </div>
        <div className="btn-group" style={{marginTop:"1rem"}}><button className="btn btn-primary" onClick={save}>{saved?tr.saved:tr.save}</button></div>
      </div>

      <div className="card">
        <h2>{tr.clamTitle}</h2>
        <div className="info-box">
          {tr.clamDesc}<br/><br/>
          {tr.clamStep1} <button className="link-btn" onClick={()=>openLink("https://www.clamav.net/downloads")}>clamav.net/downloads</button><br/>
          {tr.clamStep2} <code style={{color:"#94a3b8"}}>clamscan</code> {tr.clamStep3}<br/>
          {tr.clamStep4} <code style={{color:"#94a3b8"}}>freshclam</code>
        </div>
      </div>

      <div className="card">
        <h2>{tr.linksTitle}</h2>
        <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(200px,1fr))",gap:"0.75rem"}}>
          {API_LINKS.map(link=>(
            <button key={link.url} onClick={()=>openLink(link.url)}
              style={{background:"#0f172a",border:"1px solid #334155",borderRadius:"0.5rem",padding:"0.85rem 1rem",textAlign:"left",cursor:"pointer",color:"inherit",transition:"border-color 0.18s"}}
              onMouseEnter={e=>e.currentTarget.style.borderColor="#3b82f6"} onMouseLeave={e=>e.currentTarget.style.borderColor="#334155"}>
              <div style={{fontWeight:700,color:"#e2e8f0"}}>{link.label}</div>
              <div style={{color:"#64748b",fontSize:"0.78rem",marginTop:"0.2rem"}}>{link.sub}</div>
              <div style={{color:"#3b82f6",fontSize:"0.78rem",marginTop:"0.4rem"}}>🔗 Apri →</div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
