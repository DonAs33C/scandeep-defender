import { useState } from "react";
import { LangProvider, useLangCtx } from "./LangContext";
import { T } from "./i18n";
import SplashScreen from "./components/SplashScreen";
import Scanner      from "./components/Scanner";
import History      from "./components/History";
import Quarantine   from "./components/Quarantine";
import Settings     from "./components/Settings";
import "./App.css";

type Tab = "scanner" | "history" | "quarantine" | "settings";

function AppInner() {
  const [tab,    setTab]    = useState<Tab>("scanner");
  const [splash, setSplash] = useState(true);
  const { lang } = useLangCtx();
  const n = T[lang].nav;

  if (splash) return <SplashScreen onDone={() => setSplash(false)} />;

  return (
    <div className="app">
      <header>
        <span className="logo">🛡️ ScanDeep Defender</span>
        <nav>
          {(["scanner","history","quarantine","settings"] as Tab[]).map(t => (
            <button key={t} className={tab===t?"active":""} onClick={()=>setTab(t)}>
              {t==="scanner"?n.scanner:t==="history"?n.history:t==="quarantine"?n.quarantine:n.settings}
            </button>
          ))}
        </nav>
      </header>
      <main>
        {tab==="scanner"    && <Scanner />}
        {tab==="history"    && <History />}
        {tab==="quarantine" && <Quarantine />}
        {tab==="settings"   && <Settings />}
      </main>
    </div>
  );
}

export default function App() {
  return <LangProvider><AppInner /></LangProvider>;
}
