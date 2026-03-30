import React, { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useStore } from "../hooks/useStore";

const services = [
  { id: "virustotal", label: "VirusTotal" },
  { id: "metadefender", label: "MetaDefender" },
  { id: "clamav", label: "ClamAV locale" },
] as const;

export default function Scanner() {
  const [file, setFile] = useState<File | null>(null);
  const { selectedServices, toggleService } = useStore();
  const [result, setResult] = useState<any>(null);

  const scan = async () => {
    if (!file) return;
    const res = await invoke("scan_file", {
      req: {
        file_path: (file as any).path ?? file.name,
        services: selectedServices,
        api_keys: {
          virustotal: localStorage.getItem("vt_key") ?? "",
          metadefender: localStorage.getItem("md_key") ?? ""
        }
      }
    });
    setResult(res);
  };

  return (
    <div className="card">
      <h2>ScanDeep Defender</h2>
      <input type="file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
      <div style={{ display: "grid", gap: 8, marginTop: 16 }}>
        {services.map((s) => (
          <label key={s.id}>
            <input
              type="checkbox"
              checked={selectedServices.includes(s.id as any)}
              onChange={() => toggleService(s.id as any)}
            />
            {" "}{s.label}
          </label>
        ))}
      </div>
      <button className="button" onClick={scan} style={{ marginTop: 16 }}>
        Avvia scansione
      </button>
      {result && <pre>{JSON.stringify(result, null, 2)}</pre>}
    </div>
  );
}
