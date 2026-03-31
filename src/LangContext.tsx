import { createContext, useContext, useState, useEffect, ReactNode } from "react";
import type { Lang } from "./i18n";

interface LangCtx { lang: Lang; setLang: (l: Lang) => void; }
export const LangContext = createContext<LangCtx>({ lang:"it", setLang:()=>{} });
export const useLangCtx = () => useContext(LangContext);

export function LangProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(() =>
    (localStorage.getItem("lang") as Lang) ?? "it"
  );
  const setLang = (l: Lang) => { localStorage.setItem("lang", l); setLangState(l); };
  useEffect(() => { document.documentElement.lang = lang; }, [lang]);
  return <LangContext.Provider value={{ lang, setLang }}>{children}</LangContext.Provider>;
}
