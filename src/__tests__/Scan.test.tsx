import { render, screen, fireEvent, waitFor, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { vi, describe, it, expect, beforeEach } from "vitest";
import Scan from "../components/Scan";
import { LangProvider } from "../LangContext";
import { invoke } from "@tauri-apps/api/core";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { listen } from "@tauri-apps/api/event";

const mockInvoke = invoke as vi.Mock;
const mockOpenDialog = openDialog as vi.Mock;
const mockListen = listen as vi.Mock;

const renderScan = (props = {}) => {
  return render(
    <LangProvider>
      <Scan {...props} />
    </LangProvider>
  );
};

describe("Scan Component", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockOpenDialog.mockResolvedValue(null);
    mockInvoke.mockResolvedValue(undefined);
    mockListen.mockResolvedValue(vi.fn());
  });

  describe("Initial render", () => {
    it("renders the file upload area with drop text", () => {
      renderScan();
      expect(screen.getByText("Clicca per sfogliare e selezionare un file")).toBeInTheDocument();
    });

    it("renders service checkboxes with default VirusTotal selected", () => {
      renderScan();
      expect(screen.getByLabelText("VirusTotal")).toBeChecked();
      expect(screen.getByLabelText("MetaDefender")).not.toBeChecked();
      expect(screen.getByLabelText("Hybrid Analysis")).not.toBeChecked();
      expect(screen.getByLabelText("Cloudmersive")).not.toBeChecked();
      expect(screen.getByLabelText("ClamAV")).not.toBeChecked();
    });

    it("disables scan button when no file selected", () => {
      renderScan();
      const scanButton = screen.getByRole("button", { name: /Avvia scansione/i });
      expect(scanButton).toBeDisabled();
    });

    it("disables scan button when no services selected", () => {
      renderScan();
      // Uncheck VirusTotal
      fireEvent.click(screen.getByLabelText("VirusTotal"));
      const scanButton = screen.getByRole("button", { name: /Avvia scansione/i });
      expect(scanButton).toBeDisabled();
    });
  });

  describe("File selection", () => {
    it("opens file dialog when upload area is clicked", async () => {
      mockOpenDialog.mockResolvedValue("/path/to/test.exe");
      renderScan();

      await userEvent.click(screen.getByText("Clicca per sfogliare e selezionare un file"));

      expect(mockOpenDialog).toHaveBeenCalledWith({
        multiple: false,
        filters: [{ name: "Tutti i file", extensions: ["*"] }],
      });
    });

    it("sets file path and filename when file is selected", async () => {
      mockOpenDialog.mockResolvedValue("/path/to/test.exe");
      mockInvoke.mockResolvedValue(null); // check_duplicate returns null
      renderScan();

      await userEvent.click(screen.getByText("Clicca per sfogliare e selezionare un file"));

      expect(screen.getByText("test.exe")).toBeInTheDocument();
      expect(screen.getByText("/path/to/test.exe")).toBeInTheDocument();
    });

    it("checks for duplicate file when file is selected", async () => {
      mockOpenDialog.mockResolvedValue("/path/to/test.exe");
      mockInvoke.mockResolvedValue("existing-scan-id");
      renderScan();

      await userEvent.click(screen.getByText("Clicca per sfogliare e selezionare un file"));

      expect(mockInvoke).toHaveBeenCalledWith("check_duplicate", { filePath: "/path/to/test.exe" });
      expect(screen.getByText("File già analizzato")).toBeInTheDocument();
      expect(screen.getByText("existing-scan-id")).toBeInTheDocument();
    });

    it("enables scan button when file and service are selected", async () => {
      mockOpenDialog.mockResolvedValue("/path/to/test.exe");
      mockInvoke.mockResolvedValue(null);
      renderScan();

      await userEvent.click(screen.getByText("Clicca per sfogliare e selezionare un file"));

      const scanButton = screen.getByRole("button", { name: /Avvia scansione/i });
      expect(scanButton).not.toBeDisabled();
    });

    it("handles dialog cancellation gracefully", async () => {
      mockOpenDialog.mockResolvedValue(null);
      renderScan();

      await userEvent.click(screen.getByText("Clicca per sfogliare e selezionare un file"));

      expect(screen.getByText("Clicca per sfogliare e selezionare un file")).toBeInTheDocument();
    });

    it("supports keyboard activation (Enter key)", async () => {
      mockOpenDialog.mockResolvedValue("/path/to/test.exe");
      mockInvoke.mockResolvedValue(null);
      renderScan();

      const uploadArea = screen.getByText("Clicca per sfogliare e selezionare un file");
      await userEvent.keyboard("{Enter}", { target: uploadArea });

      expect(mockOpenDialog).toHaveBeenCalled();
    });
  });

  describe("Service selection", () => {
    it("toggles service selection when checkbox is clicked", () => {
      renderScan();

      // VirusTotal is selected by default
      expect(screen.getByLabelText("VirusTotal")).toBeChecked();

      // Click MetaDefender to select it
      fireEvent.click(screen.getByLabelText("MetaDefender"));
      expect(screen.getByLabelText("MetaDefender")).toBeChecked();

      // Click VirusTotal to deselect it
      fireEvent.click(screen.getByLabelText("VirusTotal"));
      expect(screen.getByLabelText("VirusTotal")).not.toBeChecked();
    });

    it("supports keyboard activation (Space key) for service checkboxes", () => {
      renderScan();

      const metaDefenderCheckbox = screen.getByLabelText("MetaDefender");
      fireEvent.keyDown(metaDefenderCheckbox, { key: " " });
      fireEvent.keyUp(metaDefenderCheckbox, { key: " " });

      expect(mockInvoke).not.toHaveBeenCalled(); // No scan started
    });

    it("shows error when scan started with no services selected", async () => {
      mockOpenDialog.mockResolvedValue("/path/to/test.exe");
      mockInvoke.mockResolvedValue(null);
      renderScan();

      await userEvent.click(screen.getByText("Clicca per sfogliare e selezionare un file"));
      // Uncheck the default service
      fireEvent.click(screen.getByLabelText("VirusTotal"));

      const scanButton = screen.getByRole("button", { name: /Avvia scansione/i });
      await userEvent.click(scanButton);

      expect(screen.getByText("Seleziona almeno un servizio.")).toBeInTheDocument();
    });
  });

  describe("Scanning", () => {
    it("starts scan when button is clicked with file and services", async () => {
      mockOpenDialog.mockResolvedValue("/path/to/test.exe");
      mockInvoke
        .mockResolvedValueOnce(null) // check_duplicate
        .mockResolvedValueOnce({ // scan_file result
          overall_verdict: "Clean",
          risk_score: 0,
          hash: "abc123",
          results: [],
        });
      mockListen.mockResolvedValue(vi.fn());

      renderScan();
      await userEvent.click(screen.getByText("Clicca per sfogliare e selezionare un file"));
      await userEvent.click(screen.getByRole("button", { name: /Avvia scansione/i }));

      expect(mockInvoke).toHaveBeenCalledWith("scan_file", {
        filePath: "/path/to/test.exe",
        services: ["virustotal"],
      });
    });

    it("shows scanning state during scan", async () => {
      mockOpenDialog.mockResolvedValue("/path/to/test.exe");
      let resolveScan: (value: any) => void;
      const scanPromise = new Promise((resolve) => { resolveScan = resolve; });
      mockInvoke
        .mockResolvedValueOnce(null)
        .mockImplementationOnce(() => scanPromise);
      mockListen.mockResolvedValue(vi.fn());

      renderScan();
      await userEvent.click(screen.getByText("Clicca per sfogliare e selezionare un file"));
      await userEvent.click(screen.getByRole("button", { name: /Avvia scansione/i }));

      expect(screen.getByText("Scansione in corso...")).toBeInTheDocument();
      expect(screen.getByRole("button", { name: /Scansione in corso/i })).toBeDisabled();

      act(() => { resolveScan!({ overall_verdict: "Clean", risk_score: 0, hash: "abc123", results: [] }); });
      await waitFor(() => expect(screen.queryByText("Scansione in corso...")).not.toBeInTheDocument());
    });

    it("listens for scan progress events", async () => {
      let progressCallback: (event: any) => void;
      mockListen.mockImplementation((_event, callback) => {
        progressCallback = callback;
        return Promise.resolve(vi.fn());
      });
      mockOpenDialog.mockResolvedValue("/path/to/test.exe");
      mockInvoke
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce({ overall_verdict: "Clean", risk_score: 0, hash: "abc123", results: [] });

      renderScan();
      await userEvent.click(screen.getByText("Clicca per sfogliare e selezionare un file"));
      await userEvent.click(screen.getByRole("button", { name: /Avvia scansione/i }));

      expect(mockListen).toHaveBeenCalledWith("scan-progress", expect.any(Function));

      // Simulate progress event
      act(() => {
        progressCallback!({ payload: { status: "virustotal", message: "Analisi in corso..." } });
      });

      expect(screen.getByText("Analisi in corso...")).toBeInTheDocument();
    });

    it("displays scan results when scan completes", async () => {
      mockOpenDialog.mockResolvedValue("/path/to/test.exe");
      mockInvoke
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce({
          overall_verdict: "Malicious",
          risk_score: 85,
          hash: "abc123",
          results: [
            { provider_id: "virustotal", verdict: "Malicious", detections: 15, total_engines: 70, details: "Trojan detected" },
          ],
        });
      mockListen.mockResolvedValue(vi.fn());

      renderScan();
      await userEvent.click(screen.getByText("Clicca per sfogliare e selezionare un file"));
      await userEvent.click(screen.getByRole("button", { name: /Avvia scansione/i }));

      await waitFor(() => expect(screen.getByText("MALWARE RILEVATO")).toBeInTheDocument());
      expect(screen.getByText("SHA256: abc123")).toBeInTheDocument();
      expect(screen.getByText("virustotal")).toBeInTheDocument();
      expect(screen.getByText("15/70 rilevamenti")).toBeInTheDocument();
      expect(screen.getByText("Trojan detected")).toBeInTheDocument();
    });

    it("displays error when scan fails", async () => {
      mockOpenDialog.mockResolvedValue("/path/to/test.exe");
      mockInvoke
        .mockResolvedValueOnce(null)
        .mockRejectedValueOnce(new Error("Network error"));
      mockListen.mockResolvedValue(vi.fn());

      renderScan();
      await userEvent.click(screen.getByText("Clicca per sfogliare e selezionare un file"));
      await userEvent.click(screen.getByRole("button", { name: /Avvia scansione/i }));

      await waitFor(() => expect(screen.getByText("Network error")).toBeInTheDocument());
    });

    it("clears error when close button is clicked", async () => {
      mockOpenDialog.mockResolvedValue("/path/to/test.exe");
      mockInvoke
        .mockResolvedValueOnce(null)
        .mockRejectedValueOnce("Scan failed");
      mockListen.mockResolvedValue(vi.fn());

      renderScan();
      await userEvent.click(screen.getByText("Clicca per sfogliare e selezionare un file"));
      await userEvent.click(screen.getByRole("button", { name: /Avvia scansione/i }));

      await waitFor(() => expect(screen.getByText("Scan failed")).toBeInTheDocument());
      await userEvent.click(screen.getByRole("button", { name: /✕/i }));
      expect(screen.queryByText("Scan failed")).not.toBeInTheDocument();
    });

    it("shows different verdict styles for different results", async () => {
      const verdicts = [
        { verdict: "Clean", icon: "🟢", text: "Pulito" },
        { verdict: "Suspicious", icon: "🟡", text: "Sospetto" },
        { verdict: "Malicious", icon: "🔴", text: "MALWARE RILEVATO" },
        { verdict: "Pending", icon: "🔵", text: "In attesa" },
      ];

      for (const v of verdicts) {
        mockOpenDialog.mockResolvedValue("/path/to/test.exe");
        mockInvoke
          .mockResolvedValueOnce(null)
          .mockResolvedValueOnce({ overall_verdict: v.verdict, risk_score: 50, hash: "abc123", results: [] });
        mockListen.mockResolvedValue(vi.fn());

        const { unmount } = renderScan();
        await userEvent.click(screen.getByText("Clicca per sfogliare e selezionare un file"));
        await userEvent.click(screen.getByRole("button", { name: /Avvia scansione/i }));

        await waitFor(() => expect(screen.getByText(v.icon)).toBeInTheDocument());
        expect(screen.getByText(v.text)).toBeInTheDocument();

        unmount();
        vi.clearAllMocks();
      }
    });
  });

  describe("Progress steps", () => {
    it("displays progress steps during scan", async () => {
      let progressCallback: (event: any) => void;
      mockListen.mockImplementation((_event, callback) => {
        progressCallback = callback;
        return Promise.resolve(vi.fn());
      });
      mockOpenDialog.mockResolvedValue("/path/to/test.exe");
      mockInvoke
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce({ overall_verdict: "Clean", risk_score: 0, hash: "abc123", results: [] });

      renderScan();
      await userEvent.click(screen.getByText("Clicca per sfogliare e selezionare un file"));
      await userEvent.click(screen.getByRole("button", { name: /Avvia scansione/i }));

      act(() => {
        progressCallback!({ payload: { status: "virustotal", message: "Invio file..." } });
        progressCallback!({ payload: { status: "metadefender", message: "Analisi sandbox..." } });
      });

      expect(screen.getByText("Invio file...")).toBeInTheDocument();
      expect(screen.getByText("Analisi sandbox...")).toBeInTheDocument();
    });

    it("updates existing progress step instead of duplicating", async () => {
      let progressCallback: (event: any) => void;
      mockListen.mockImplementation((_event, callback) => {
        progressCallback = callback;
        return Promise.resolve(vi.fn());
      });
      mockOpenDialog.mockResolvedValue("/path/to/test.exe");
      mockInvoke
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce({ overall_verdict: "Clean", risk_score: 0, hash: "abc123", results: [] });

      renderScan();
      await userEvent.click(screen.getByText("Clicca per sfogliare e selezionare un file"));
      await userEvent.click(screen.getByRole("button", { name: /Avvia scansione/i }));

      act(() => {
        progressCallback!({ payload: { status: "virustotal", message: "Invio..." } });
        progressCallback!({ payload: { status: "virustotal", message: "Analisi..." } });
      });

      // Should only have one step for virustotal
      const steps = screen.getAllByText("Analisi...");
      expect(steps.length).toBe(1);
    });
  });
});