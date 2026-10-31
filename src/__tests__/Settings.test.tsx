import { render, screen, fireEvent, waitFor, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { vi, describe, it, expect, beforeEach } from "vitest";
import Settings from "../components/Settings";
import { LangProvider } from "../LangContext";
import { invoke } from "@tauri-apps/api/core";

const mockInvoke = invoke as vi.Mock;

const renderSettings = (props = {}) => {
  // Set up localStorage with default values
  localStorage.setItem("scandeep_ui", JSON.stringify({ auto_scan: true, allow_cloud_upload: false }));
  return render(
    <LangProvider>
      <Settings {...props} />
    </LangProvider>
  );
};

describe("Settings Component", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    localStorage.setItem("scandeep_ui", JSON.stringify({ auto_scan: true, allow_cloud_upload: false }));
    mockInvoke.mockResolvedValue(undefined);
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "load_api_keys") {
        return Promise.resolve({ virustotal: "vt-key", metadefender: "md-key", hybridanalysis: "ha-key", cloudmersive: "cm-key" });
      }
      return Promise.resolve(undefined);
    });
  });

  describe("Initial render and loading", () => {
    it("loads API keys on mount", async () => {
      renderSettings();
      await waitFor(() => expect(mockInvoke).toHaveBeenCalledWith("load_api_keys"));
    });

    it("loads UI settings from localStorage on mount", async () => {
      renderSettings();
      await waitFor(() => {
        expect(screen.getByRole("checkbox", { name: /Monitora la cartella Downloads/i })).toBeChecked();
        expect(screen.getByRole("checkbox", { name: /Carica file su servizi cloud/i })).not.toBeChecked();
      });
    });

    it("displays API key fields with loaded values", async () => {
      renderSettings();
      await waitFor(() => {
        expect(screen.getByPlaceholderText("Incolla qui la chiave")).toHaveValue("vt-key");
        expect(screen.getAllByPlaceholderText("Incolla qui la chiave")[1]).toHaveValue("md-key");
        expect(screen.getAllByPlaceholderText("Incolla qui la chiave")[2]).toHaveValue("ha-key");
        expect(screen.getAllByPlaceholderText("Incolla qui la chiave")[3]).toHaveValue("cm-key");
      });
    });

    it("displays language selector with Italian selected by default", async () => {
      renderSettings();
      await waitFor(() => {
        expect(screen.getByText("🇮🇹 Italiano")).toBeInTheDocument();
        expect(screen.getByText("🇬🇧 English")).toBeInTheDocument();
      });
    });
  });

  describe("Language selection", () => {
    it("changes language when English button is clicked", async () => {
      renderSettings();
      await waitFor(() => expect(screen.getByText("🇮🇹 Italiano")).toBeInTheDocument());

      await userEvent.click(screen.getByText("🇬🇧 English"));

      await waitFor(() => expect(localStorage.setItem).toHaveBeenCalledWith("lang", "en"));
    });

    it("changes language when Italian button is clicked", async () => {
      localStorage.setItem("lang", "en");
      renderSettings();
      await waitFor(() => expect(screen.getByText("🇬🇧 English")).toBeInTheDocument());

      await userEvent.click(screen.getByText("🇮🇹 Italiano"));

      await waitFor(() => expect(localStorage.setItem).toHaveBeenCalledWith("lang", "it"));
    });

    it("highlights selected language button", async () => {
      renderSettings();
      await waitFor(() => {
        const itButton = screen.getByText("🇮🇹 Italiano");
        expect(itButton).toHaveClass("btn-primary");
      });

      await userEvent.click(screen.getByText("🇬🇧 English"));

      await waitFor(() => {
        const enButton = screen.getByText("🇬🇧 English");
        expect(enButton).toHaveClass("btn-primary");
      });
    });
  });

  describe("API Keys", () => {
    it("updates API key state when input changes", async () => {
      renderSettings();
      await waitFor(() => expect(screen.getByPlaceholderText("Incolla qui la chiave")).toHaveValue("vt-key"));

      await userEvent.clear(screen.getByPlaceholderText("Incolla qui la chiave"));
      await userEvent.type(screen.getByPlaceholderText("Incolla qui la chiave"), "new-vt-key");

      expect(screen.getByPlaceholderText("Incolla qui la chiave")).toHaveValue("new-vt-key");
    });

    it("saves API keys when save button is clicked", async () => {
      renderSettings();
      await waitFor(() => expect(screen.getByText("💾 Salva")).toBeInTheDocument());

      await userEvent.click(screen.getByText("💾 Salva"));

      await waitFor(() => expect(mockInvoke).toHaveBeenCalledWith("save_api_keys", {
        vt: "vt-key", md: "md-key", ha: "ha-key", cm: "cm-key"
      }));
      await waitFor(() => expect(mockInvoke).toHaveBeenCalledWith("set_watcher_keys", {
        vt: "vt-key", md: "md-key", ha: "ha-key", cm: "cm-key"
      }));
    });

    it("shows saved state temporarily after saving", async () => {
      renderSettings();
      await waitFor(() => expect(screen.getByText("💾 Salva")).toBeInTheDocument());

      await userEvent.click(screen.getByText("💾 Salva"));

      await waitFor(() => expect(screen.getByText("✅ Salvato!")).toBeInTheDocument());
      // Wait for timeout
      await act(async () => { await new Promise(resolve => setTimeout(resolve, 2300)); });
      await waitFor(() => expect(screen.getByText("💾 Salva")).toBeInTheDocument());
    });

    it("shows privacy notice", async () => {
      renderSettings();
      await waitFor(() => expect(screen.getByText("🔒 Le chiavi API sono salvate nel Windows Credential Manager, mai in chiaro.")).toBeInTheDocument());
    });
  });

  describe("Auto-scan toggle", () => {
    it("toggles auto-scan when checkbox is clicked", async () => {
      renderSettings();
      await waitFor(() => expect(screen.getByRole("checkbox", { name: /Monitora la cartella Downloads/i })).toBeChecked());

      await userEvent.click(screen.getByRole("checkbox", { name: /Monitora la cartella Downloads/i }));

      expect(screen.getByRole("checkbox", { name: /Monitora la cartella Downloads/i })).not.toBeChecked();
      expect(screen.getByText("⛔ DISATTIVA")).toBeInTheDocument();
    });

    it("shows active state when enabled", async () => {
      renderSettings();
      await waitFor(() => expect(screen.getByText("✅ ATTIVA")).toBeInTheDocument());
    });

    it("shows hint text", async () => {
      renderSettings();
      await waitFor(() => expect(screen.getByText("Il risultato appare come notifica nella scheda Scanner")).toBeInTheDocument());
    });
  });

  describe("Cloud upload toggle", () => {
    it("toggles cloud upload when checkbox is clicked", async () => {
      renderSettings();
      await waitFor(() => expect(screen.getByRole("checkbox", { name: /Carica file su servizi cloud/i })).not.toBeChecked());

      await userEvent.click(screen.getByRole("checkbox", { name: /Carica file su servizi cloud/i }));

      expect(screen.getByRole("checkbox", { name: /Carica file su servizi cloud/i })).toBeChecked();
      expect(screen.getByText("⚠️ ATTIVO")).toBeInTheDocument();
    });

    it("shows warning text when enabled", async () => {
      renderSettings();
      await userEvent.click(screen.getByRole("checkbox", { name: /Carica file su servizi cloud/i }));

      await waitFor(() => expect(screen.getByText("I file verranno inviati a servizi terzi. Attivare solo se necessario.")).toBeInTheDocument());
    });

    it("shows OFF state when disabled", async () => {
      renderSettings();
      await waitFor(() => expect(screen.getByText("🔒 OFF")).toBeInTheDocument());
    });
  });

  describe("Save configuration", () => {
    it("saves config when save button is clicked", async () => {
      renderSettings();
      await waitFor(() => expect(screen.getAllByText("💾 Salva")[1]).toBeInTheDocument());

      await userEvent.click(screen.getAllByText("💾 Salva")[1]);

      await waitFor(() => expect(mockInvoke).toHaveBeenCalledWith("set_auto_scan", { enabled: true }));
      await waitFor(() => expect(mockInvoke).toHaveBeenCalledWith("set_config", {
        allowCloudUpload: false,
        enabledProviders: ["virustotal", "metadefender", "hybridanalysis", "cloudmersive", "clamav"]
      }));
    });

    it("saves to localStorage", async () => {
      renderSettings();
      await waitFor(() => expect(screen.getAllByText("💾 Salva")[1]).toBeInTheDocument());

      await userEvent.click(screen.getAllByText("💾 Salva")[1]);

      await waitFor(() => expect(localStorage.setItem).toHaveBeenCalledWith("scandeep_ui", expect.stringContaining("auto_scan")));
    });

    it("shows saved state temporarily after saving config", async () => {
      renderSettings();
      await waitFor(() => expect(screen.getAllByText("💾 Salva")[1]).toBeInTheDocument());

      await userEvent.click(screen.getAllByText("💾 Salva")[1]);

      await waitFor(() => expect(screen.getByText("✅ Salvato!")).toBeInTheDocument());
    });

    it("uses current toggle states when saving", async () => {
      renderSettings();
      await waitFor(() => expect(screen.getByRole("checkbox", { name: /Monitora la cartella Downloads/i })).toBeChecked());

      // Disable auto-scan
      await userEvent.click(screen.getByRole("checkbox", { name: /Monitora la cartella Downloads/i }));
      // Enable cloud upload
      await userEvent.click(screen.getByRole("checkbox", { name: /Carica file su servizi cloud/i }));

      await userEvent.click(screen.getAllByText("💾 Salva")[1]);

      await waitFor(() => expect(mockInvoke).toHaveBeenCalledWith("set_auto_scan", { enabled: false }));
      await waitFor(() => expect(mockInvoke).toHaveBeenCalledWith("set_config", {
        allowCloudUpload: true,
        enabledProviders: ["virustotal", "metadefender", "hybridanalysis", "cloudmersive", "clamav"]
      }));
    });
  });

  describe("ClamAV info", () => {
    it("displays ClamAV installation instructions", async () => {
      renderSettings();
      await waitFor(() => {
        expect(screen.getByText("Antivirus offline gratuito, nessun limite di richieste.")).toBeInTheDocument();
        expect(screen.getByText("1. Scarica da")).toBeInTheDocument();
        expect(screen.getByText("clamav.net/downloads")).toBeInTheDocument();
        expect(screen.getByText("2. Verifica che")).toBeInTheDocument();
        expect(screen.getByText("clamscan")).toBeInTheDocument();
        expect(screen.getByText("sia nel PATH")).toBeInTheDocument();
        expect(screen.getByText("3. Aggiorna:")).toBeInTheDocument();
        expect(screen.getByText("freshclam")).toBeInTheDocument();
      });
    });

    it("shows app icon info", async () => {
      renderSettings();
      await waitFor(() => expect(screen.getByText("Icone app:")).toBeInTheDocument());
      expect(screen.getByText("32x32.png")).toBeInTheDocument();
      expect(screen.getByText("128x128.png")).toBeInTheDocument();
      expect(screen.getByText("icon.ico")).toBeInTheDocument();
    });
  });

  describe("API registration links", () => {
    it("displays all API registration links", async () => {
      renderSettings();
      await waitFor(() => {
        expect(screen.getByText("VirusTotal")).toBeInTheDocument();
        expect(screen.getByText("MetaDefender")).toBeInTheDocument();
        expect(screen.getByText("Hybrid Analysis")).toBeInTheDocument();
        expect(screen.getByText("Cloudmersive")).toBeInTheDocument();
      });
    });

    it("opens link in browser when clicked", async () => {
      renderSettings();
      await waitFor(() => expect(screen.getByText("VirusTotal")).toBeInTheDocument());

      await userEvent.click(screen.getByText("VirusTotal"));

      await waitFor(() => expect(mockInvoke).toHaveBeenCalledWith("open_browser", { url: "https://www.virustotal.com/gui/sign-up" }));
    });

    it("shows subscription info for each service", async () => {
      renderSettings();
      await waitFor(() => {
        expect(screen.getByText("500 req/giorno gratis")).toBeInTheDocument();
        expect(screen.getByText("Community gratis")).toBeInTheDocument();
        expect(screen.getByText("API gratis")).toBeInTheDocument();
        expect(screen.getByText("800/mese gratis")).toBeInTheDocument();
      });
    });
  });

  describe("Error handling", () => {
    it("handles load_api_keys error gracefully", async () => {
      mockInvoke.mockImplementation((cmd: string) => {
        if (cmd === "load_api_keys") return Promise.reject(new Error("Failed to load"));
        return Promise.resolve(undefined);
      });

      renderSettings();
      await waitFor(() => {
        // Should not crash, inputs should be empty
        expect(screen.getByPlaceholderText("Incolla qui la chiave")).toHaveValue("");
      });
    });

    it("handles save_api_keys error gracefully", async () => {
      mockInvoke.mockImplementation((cmd: string) => {
        if (cmd === "save_api_keys") return Promise.reject(new Error("Save failed"));
        return Promise.resolve(undefined);
      });

      renderSettings();
      await waitFor(() => expect(screen.getByText("💾 Salva")).toBeInTheDocument());

      await userEvent.click(screen.getByText("💾 Salva"));

      // Should not crash
      await waitFor(() => expect(screen.getByText("💾 Salva")).toBeInTheDocument());
    });
  });
});