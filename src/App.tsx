import { useState } from "react";
import { LangProvider, useLangCtx } from "./LangContext";
import { T } from "./i18n";
import SplashScreen from "./components/SplashScreen";
import Scan from "./components/Scan";
import History from "./components/History";
import Quarantine from "./components/Quarantine";
import Settings from "./components/Settings";
import iconImg from "./assets/icon.png";
import "./App.css";

type Tab = "scanner" | "history" | "quarantine" | "settings";

function AppInner() {
  const [tab, setTab] = useState<Tab>("scanner");
  const [splash, setSplash] = useState(true);
  const { lang } = useLangCtx();
  const n = T[lang].nav;

  if (splash) return <SplashScreen onDone={() => setSplash(false)} />;

  return (
    <div className="app">
      <header>
        <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
          <img src={iconImg} alt="ScanDeep" width={28} height={28}
            style={{ borderRadius: "6px", flexShrink: 0 }} />
          <span className="logo">ScanDeep Defender</span>
        </div>
        <nav>
          {(["scanner", "history", "quarantine", "settings"] as Tab[]).map(t => (
            <button key={t} className={tab === t ? "active" : ""} onClick={() => setTab(t)}>
              {t === "scanner" ? n.scanner : t === "history" ? n.history : t === "quarantine" ? n.quarantine : n.settings}
            </button>
          ))}
        </nav>
      </header>
      <main>
        {tab === "scanner" && <Scan />}
        {tab === "history" && <History />}
        {tab === "quarantine" && <Quarantine />}
        {tab === "settings" && <Settings />}
      </main>
    </div>
  );
}

export default function App() {
  return <LangProvider><AppInner /></LangProvider>;
}
