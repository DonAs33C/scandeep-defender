import { useEffect, useState } from "react";
import splashImg from "../assets/splash.png";

interface Props { onDone: () => void; }

export default function SplashScreen({ onDone }: Props) {
  const [progress, setProgress] = useState(0);
  const [fading,  setFading]  = useState(false);

  useEffect(() => {
    // Simula caricamento progressivo
    const steps = [10, 25, 45, 60, 75, 90, 100];
    let i = 0;
    const iv = setInterval(() => {
      if (i < steps.length) { setProgress(steps[i]); i++; }
      else {
        clearInterval(iv);
        setTimeout(() => {
          setFading(true);
          setTimeout(onDone, 600);
        }, 400);
      }
    }, 260);
    return () => clearInterval(iv);
  }, []);

  return (
    <div className={`splash-root ${fading ? "splash-out" : ""}`}>
      <img src={splashImg} className="splash-bg" alt="ScanDeep Defender" />
      <div className="splash-overlay" />
      <div className="splash-content">
        <div className="splash-bar-wrap">
          <div className="splash-bar" style={{ width: `${progress}%` }} />
        </div>
        <div className="splash-label">
          {progress < 100 ? `Inizializzazione... ${progress}%` : "✅ Pronto"}
        </div>
      </div>
    </div>
  );
}
