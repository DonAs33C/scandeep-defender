import { useState } from "react";
import Scanner from "./components/Scanner";
import History from "./components/History";
import Settings from "./components/Settings";
import "./App.css";

type Tab = "scanner" | "history" | "settings";

export default function App() {
  const [tab, setTab] = useState<Tab>("scanner");
  return (
    <div className="app">
      <header>
        <span className="logo">🛡️ ScanDeep Defender</span>
        <nav>
          {(["scanner","history","settings"] as Tab[]).map(t => (
            <button key={t} className={tab===t?"active":""} onClick={()=>setTab(t)}>
              {t==="scanner"?"🔍 Scanner":t==="history"?"📋 Storico":"⚙️ Impostazioni"}
            </button>
          ))}
        </nav>
      </header>
      <main>
        {tab==="scanner"  && <Scanner />}
        {tab==="history"  && <History />}
        {tab==="settings" && <Settings />}
      </main>
    </div>
  );
}
