import { useEffect, useState } from "react";
import splashImg from "../assets/splash.jpg";

interface Props { onDone: () => void; }

export default function SplashScreen({ onDone }: Props) {
  const [progress, setProgress] = useState(0);
  const [fading, setFading] = useState(false);

  useEffect(() => {
    const steps = [8, 18, 32, 48, 64, 78, 92, 100];
    let i = 0;
    const iv = setInterval(() => {
      if (i < steps.length) {
        setProgress(steps[i]);
        i++;
      } else {
        clearInterval(iv);
        setTimeout(() => {
          setFading(true);
          setTimeout(onDone, 520);
        }, 350);
      }
    }, 220);
    return () => clearInterval(iv);
  }, [onDone]);

  return (
    <div className={`splash-root ${fading ? "splash-out" : ""}`}>
      <div className="splash-stage">
        <img src={splashImg} className="splash-bg" alt="ScanDeep Defender" />
      </div>
      <div className="splash-overlay" />
      <div className="splash-content">
        <div className="splash-bar-wrap">
          <div className="splash-bar" style={{ width: `${progress}%` }} />
        </div>
        <div className="splash-label">{progress < 100 ? `Inizializzazione... ${progress}%` : "✅ Pronto"}</div>
      </div>
    </div>
  );
}
