export type Lang = "it" | "en";
export const T = {
  it: {
    nav: { scanner:"🔍 Scanner", history:"📋 Storico", quarantine:"🔒 Quarantena", settings:"⚙️ Impostazioni" },
    scanner: {
      title:"Seleziona file", drop:"Clicca per sfogliare e selezionare un file",
      services:"Servizi di scansione", servicesHint:"Seleziona uno o più servizi",
      scan:"Avvia scansione", remove:"Rimuovi file", scanning:"Scansione in corso...",
      dupTitle:"File già analizzato",
      dupMsg:"Questo file è già presente nello storico con risultato: {verdict}. Scansionare di nuovo?",
      dupScan:"Scansiona di nuovo", dupCancel:"Annulla",
      refreshBtn:"🔄 Aggiorna risultati", hash:"SHA256", autoNotif:"Auto-scan", step:"Analisi",
      quarantineBtn:"🔒 Metti in quarantena", cloudWarning:"⚠️ Upload cloud DISABILITATO di default — attivare in Impostazioni",
    },
    progress:{ sending:"Invio...", analyzing:"Analisi...", done:"Completato", waiting:"In attesa" },
    verdict:{ clean:"✅ Pulito", suspicious:"⚠️ Sospetto", malicious:"🚨 MALWARE RILEVATO", pending:"⏳ In attesa" },
    history:{ title:"Storico", all:"Tutti", malicious:"🚨 Malware", suspicious:"⚠️ Sospetti",
      clean:"✅ Puliti", refresh:"↻ Aggiorna", clear:"🗑 Cancella", empty:"Nessuna scansione.",
      emptyFilter:"Nessun file", file:"📄 File", size:"📏 Dim.", result:"🔍 Risultato",
      date:"🕒 Data", risk:"⚡ Rischio", confirmClear:"Cancellare tutto lo storico?" },
    quarantine:{ title:"File in quarantena", empty:"Nessun file in quarantena.", restore:"♻️ Ripristina",
      delete:"🗑 Elimina", confirmDelete:"Eliminare definitivamente il file? Azione irreversibile.", file:"📄 File",
      date:"🕒 Data", originalPath:"📁 Percorso originale", action:"⚙️ Azioni" },
    settings:{ apiTitle:"🔑 Chiavi API", save:"💾 Salva", saved:"✅ Salvato!",
      autoTitle:"📥 Scansione automatica Downloads",
      autoDesc:"Monitora la cartella Downloads e scansiona i nuovi file",
      autoHint:"Il risultato appare come notifica nella scheda Scanner",
      active:"✅ ATTIVA", inactive:"⛔ DISATTIVA",
      cloudTitle:"☁️ Upload cloud", cloudDesc:"Carica file su servizi cloud se non trovati tramite hash",
      cloudWarning:"I file verranno inviati a servizi terzi. Attivare solo se necessario.",
      clamTitle:"🟢 ClamAV locale", clamDesc:"Antivirus offline gratuito, nessun limite di richieste.",
      clamStep1:"1. Scarica da", clamStep2:"2. Verifica che",
      clamStep3:"sia nel PATH", clamStep4:"3. Aggiorna:",
      linksTitle:"🔗 Registrazione API gratuite",
      langTitle:"🌐 Lingua / Language", langIt:"🇮🇹 Italiano", langEn:"🇬🇧 English",
      privacy:"🔒 Le chiavi API sono salvate nel Windows Credential Manager, mai in chiaro.",
      placeholder:"Incolla qui la chiave" },
  },
  en: {
    nav:{ scanner:"🔍 Scanner", history:"📋 History", quarantine:"🔒 Quarantine", settings:"⚙️ Settings" },
    scanner:{ title:"Select file", drop:"Click to browse and select a file",
      services:"Scan services", servicesHint:"Select one or more services",
      scan:"Start scan", remove:"Remove file", scanning:"Scanning...",
      dupTitle:"File already scanned",
      dupMsg:"This file is already in history with result: {verdict}. Scan again?",
      dupScan:"Scan again", dupCancel:"Cancel",
      refreshBtn:"🔄 Refresh results", hash:"SHA256", autoNotif:"Auto-scan", step:"Analyzing",
      quarantineBtn:"🔒 Quarantine file", cloudWarning:"⚠️ Cloud upload DISABLED by default — enable in Settings",
    },
    progress:{ sending:"Sending...", analyzing:"Analyzing...", done:"Done", waiting:"Waiting" },
    verdict:{ clean:"✅ Clean", suspicious:"⚠️ Suspicious", malicious:"🚨 MALWARE DETECTED", pending:"⏳ Pending" },
    history:{ title:"History", all:"All", malicious:"🚨 Malware", suspicious:"⚠️ Suspicious",
      clean:"✅ Clean", refresh:"↻ Refresh", clear:"🗑 Clear", empty:"No scans yet.",
      emptyFilter:"No files", file:"📄 File", size:"📏 Size", result:"🔍 Result",
      date:"🕒 Date", risk:"⚡ Risk", confirmClear:"Clear all history?" },
    quarantine:{ title:"Quarantined files", empty:"No quarantined files.", restore:"♻️ Restore",
      delete:"🗑 Delete", confirmDelete:"Permanently delete the file? This cannot be undone.",
      file:"📄 File", date:"🕒 Date", originalPath:"📁 Original path", action:"⚙️ Actions" },
    settings:{ apiTitle:"🔑 API Keys", save:"💾 Save", saved:"✅ Saved!",
      autoTitle:"📥 Auto-scan Downloads",
      autoDesc:"Monitor the Downloads folder and scan new files automatically",
      autoHint:"Result appears as notification in the Scanner tab",
      active:"✅ ACTIVE", inactive:"⛔ INACTIVE",
      cloudTitle:"☁️ Cloud upload", cloudDesc:"Upload files to cloud services if not found by hash",
      cloudWarning:"Files will be sent to third-party services. Enable only if needed.",
      clamTitle:"🟢 ClamAV local", clamDesc:"Free offline antivirus, no request limits.",
      clamStep1:"1. Download from", clamStep2:"2. Make sure",
      clamStep3:"is in PATH", clamStep4:"3. Update:",
      linksTitle:"🔗 Free API registration",
      langTitle:"🌐 Lingua / Language", langIt:"🇮🇹 Italiano", langEn:"🇬🇧 English",
      privacy:"🔒 API keys are stored in Windows Credential Manager, never in plain text.",
      placeholder:"Paste your key here" },
  },
};
export function useLang() {
  const lang = ((typeof window!=="undefined" ? localStorage.getItem("lang") : null) ?? "it") as Lang;
  const t = T[lang] as typeof T["it"];
  const tr = (key:string, vars?:Record<string,string>) => {
    const parts=key.split("."); let val:any=t;
    for(const p of parts) val=val?.[p];
    if(typeof val!=="string") return key;
    if(vars) Object.entries(vars).forEach(([k,v])=>{val=val.replace(`{${k}}`,v);});
    return val as string;
  };
  return {lang,tr};
}
