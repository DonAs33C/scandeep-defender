import { render, screen, fireEvent, waitFor, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { vi, describe, it, expect, beforeEach } from "vitest";
import History from "../components/History";
import { LangProvider } from "../LangContext";
import { invoke } from "@tauri-apps/api/core";

const mockInvoke = invoke as vi.Mock;

const mockRecords = [
  {
    id: "1",
    filename: "test.exe",
    filepath: "/path/to/test.exe",
    filesize: 1024 * 1024,
    filehash: "abc123",
    timestamp: "2024-01-15T10:30:00Z",
    overall_verdict: "Clean",
  },
  {
    id: "2",
    filename: "malware.exe",
    filepath: "/path/to/malware.exe",
    filesize: 2 * 1024 * 1024,
    filehash: "def456",
    timestamp: "2024-01-16T14:45:00Z",
    overall_verdict: "Malicious",
  },
  {
    id: "3",
    filename: "suspicious.exe",
    filepath: "/path/to/suspicious.exe",
    filesize: 512 * 1024,
    filehash: "ghi789",
    timestamp: "2024-01-17T09:15:00Z",
    overall_verdict: "Suspicious",
  },
];

const renderHistory = (props = {}) => {
  return render(
    <LangProvider>
      <History {...props} />
    </LangProvider>
  );
};

describe("History Component", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockInvoke.mockResolvedValue(mockRecords);
    vi.spyOn(window, "confirm").mockReturnValue(true);
  });

  describe("Initial render and loading", () => {
    it("shows loading indicator initially", () => {
      let resolveLoad: (value: any) => void;
      mockInvoke.mockImplementation(() => new Promise((resolve) => { resolveLoad = resolve; }));

      renderHistory();

      expect(screen.getByText("⏳")).toBeInTheDocument();
      act(() => { resolveLoad!(mockRecords); });
    });

    it("loads history on mount", async () => {
      renderHistory();
      await waitFor(() => expect(mockInvoke).toHaveBeenCalledWith("get_history"));
    });

    it("displays records in table after loading", async () => {
      renderHistory();
      await waitFor(() => expect(screen.getByText("test.exe")).toBeInTheDocument());
      expect(screen.getByText("malware.exe")).toBeInTheDocument();
      expect(screen.getByText("suspicious.exe")).toBeInTheDocument();
    });

    it("formats file sizes correctly", async () => {
      renderHistory();
      await waitFor(() => expect(screen.getByText("1.0 MB")).toBeInTheDocument());
      expect(screen.getByText("2.0 MB")).toBeInTheDocument();
      expect(screen.getByText("512.0 KB")).toBeInTheDocument();
    });

    it("displays verdict badges with correct styling", async () => {
      renderHistory();
      await waitFor(() => {
        expect(screen.getByText("CLEAN")).toBeInTheDocument();
        expect(screen.getByText("MALICIOUS")).toBeInTheDocument();
        expect(screen.getByText("SUSPICIOUS")).toBeInTheDocument();
      });
    });

    it("formats dates according to locale", async () => {
      renderHistory();
      await waitFor(() => {
        // Italian locale formatting
        expect(screen.getByText(/15\/01\/2024/)).toBeInTheDocument();
        expect(screen.getByText(/16\/01\/2024/)).toBeInTheDocument();
        expect(screen.getByText(/17\/01\/2024/)).toBeInTheDocument();
      });
    });
  });

  describe("Filtering", () => {
    it("shows all records when 'Tutti' filter is selected", async () => {
      renderHistory();
      await waitFor(() => expect(screen.getByText("test.exe")).toBeInTheDocument());
      expect(screen.getByText("malware.exe")).toBeInTheDocument();
      expect(screen.getByText("suspicious.exe")).toBeInTheDocument();
    });

    it("filters to show only malicious records", async () => {
      renderHistory();
      await waitFor(() => expect(screen.getByText("malware.exe")).toBeInTheDocument());

      await userEvent.click(screen.getByText("🚨 Malware"));

      expect(screen.getByText("malware.exe")).toBeInTheDocument();
      expect(screen.queryByText("test.exe")).not.toBeInTheDocument();
      expect(screen.queryByText("suspicious.exe")).not.toBeInTheDocument();
    });

    it("filters to show only suspicious records", async () => {
      renderHistory();
      await waitFor(() => expect(screen.getByText("suspicious.exe")).toBeInTheDocument());

      await userEvent.click(screen.getByText("⚠️ Sospetti"));

      expect(screen.getByText("suspicious.exe")).toBeInTheDocument();
      expect(screen.queryByText("test.exe")).not.toBeInTheDocument();
      expect(screen.queryByText("malware.exe")).not.toBeInTheDocument();
    });

    it("filters to show only clean records", async () => {
      renderHistory();
      await waitFor(() => expect(screen.getByText("test.exe")).toBeInTheDocument());

      await userEvent.click(screen.getByText("✅ Puliti"));

      expect(screen.getByText("test.exe")).toBeInTheDocument();
      expect(screen.queryByText("malware.exe")).not.toBeInTheDocument();
      expect(screen.queryByText("suspicious.exe")).not.toBeInTheDocument();
    });

    it("shows correct count in filter buttons", async () => {
      renderHistory();
      await waitFor(() => {
        expect(screen.getByText("Tutti (3)")).toBeInTheDocument();
        expect(screen.getByText("🚨 Malware (1)")).toBeInTheDocument();
        expect(screen.getByText("⚠️ Sospetti (1)")).toBeInTheDocument();
        expect(screen.getByText("✅ Puliti (1)")).toBeInTheDocument();
      });
    });

    it("highlights active filter button", async () => {
      renderHistory();
      await waitFor(() => {
        const allButton = screen.getByText("Tutti (3)");
        expect(allButton).toHaveStyle({ borderColor: expect.stringContaining("#475569") });
      });

      await userEvent.click(screen.getByText("🚨 Malware"));

      await waitFor(() => {
        const malwareButton = screen.getByText("🚨 Malware (1)");
        expect(malwareButton).toHaveStyle({ borderColor: expect.stringContaining("#dc2626") });
      });
    });
  });

  describe("Refresh", () => {
    it("reloads history when refresh button is clicked", async () => {
      renderHistory();
      await waitFor(() => expect(mockInvoke).toHaveBeenCalledTimes(1));

      await userEvent.click(screen.getByText("↻ Aggiorna"));

      await waitFor(() => expect(mockInvoke).toHaveBeenCalledTimes(2));
    });

    it("shows loading indicator during refresh", async () => {
      let resolveLoad: (value: any) => void;
      mockInvoke
        .mockResolvedValueOnce(mockRecords)
        .mockImplementationOnce(() => new Promise((resolve) => { resolveLoad = resolve; }));

      renderHistory();
      await waitFor(() => expect(screen.getByText("test.exe")).toBeInTheDocument());

      await userEvent.click(screen.getByText("↻ Aggiorna"));

      expect(screen.getByText("⏳")).toBeInTheDocument();
      act(() => { resolveLoad!(mockRecords); });
    });
  });

  describe("Clear history", () => {
    it("shows confirmation dialog when clear is clicked", async () => {
      renderHistory();
      await waitFor(() => expect(screen.getByText("test.exe")).toBeInTheDocument());

      await userEvent.click(screen.getByText("🗑 Cancella"));

      expect(window.confirm).toHaveBeenCalledWith("Cancellare tutto lo storico?");
    });

    it("clears history when confirmed", async () => {
      mockInvoke.mockResolvedValue(mockRecords);
      renderHistory();
      await waitFor(() => expect(screen.getByText("test.exe")).toBeInTheDocument());

      mockInvoke.mockResolvedValue(undefined);
      await userEvent.click(screen.getByText("🗑 Cancella"));

      await waitFor(() => expect(mockInvoke).toHaveBeenCalledWith("clear_history"));
      await waitFor(() => expect(screen.queryByText("test.exe")).not.toBeInTheDocument());
    });

    it("does not clear history when cancelled", async () => {
      vi.spyOn(window, "confirm").mockReturnValue(false);
      renderHistory();
      await waitFor(() => expect(screen.getByText("test.exe")).toBeInTheDocument());

      await userEvent.click(screen.getByText("🗑 Cancella"));

      expect(mockInvoke).not.toHaveBeenCalledWith("clear_history");
      expect(screen.getByText("test.exe")).toBeInTheDocument();
    });

    it("hides clear button when no records", async () => {
      mockInvoke.mockResolvedValue([]);
      renderHistory();
      await waitFor(() => expect(screen.getByText("Nessuna scansione.")).toBeInTheDocument());

      expect(screen.queryByText("🗑 Cancella")).not.toBeInTheDocument();
    });
  });

  describe("Empty states", () => {
    it("shows empty message when no records", async () => {
      mockInvoke.mockResolvedValue([]);
      renderHistory();
      await waitFor(() => expect(screen.getByText("Nessuna scansione.")).toBeInTheDocument());
    });

    it("shows filtered empty message when filter has no results", async () => {
      renderHistory();
      await waitFor(() => expect(screen.getByText("malware.exe")).toBeInTheDocument());

      await userEvent.click(screen.getByText("✅ Puliti"));

      await waitFor(() => expect(screen.getByText("Nessun file Puliti.")).toBeInTheDocument());
    });
  });

  describe("Error handling", () => {
    it("handles load error gracefully", async () => {
      mockInvoke.mockRejectedValue(new Error("Database error"));
      renderHistory();

      await waitFor(() => expect(screen.getByText("⏳")).not.toBeInTheDocument());
      // Should not crash, just show empty state
      expect(screen.getByText("Nessuna scansione.")).toBeInTheDocument();
    });
  });
});