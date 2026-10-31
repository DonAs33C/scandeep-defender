import { render, screen, fireEvent, waitFor, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { vi, describe, it, expect, beforeEach } from "vitest";
import Quarantine from "../components/Quarantine";
import { LangProvider } from "../LangContext";
import { invoke } from "@tauri-apps/api/core";

const mockInvoke = invoke as vi.Mock;

const mockRecords = [
  {
    id: "1",
    filename: "malware.exe",
    original_path: "/Downloads/malware.exe",
    quarantine_path: "/quarantine/malware_abc123.exe",
    hash: "abc123def456",
    quarantined_at: "2024-01-15T10:30:00Z",
    scan_id: "scan-1",
  },
  {
    id: "2",
    filename: "trojan.dll",
    original_path: "/Temp/trojan.dll",
    quarantine_path: "/quarantine/trojan_def456.dll",
    hash: "def456ghi789",
    quarantined_at: "2024-01-16T14:45:00Z",
    scan_id: "scan-2",
  },
];

const renderQuarantine = (props = {}) => {
  return render(
    <LangProvider>
      <Quarantine {...props} />
    </LangProvider>
  );
};

describe("Quarantine Component", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockInvoke.mockResolvedValue(mockRecords);
    vi.spyOn(window, "confirm").mockReturnValue(true);
  });

  describe("Initial render and loading", () => {
    it("shows loading indicator initially", () => {
      let resolveLoad: (value: any) => void;
      mockInvoke.mockImplementation(() => new Promise((resolve) => { resolveLoad = resolve; }));

      renderQuarantine();

      expect(screen.getByText("⏳")).toBeInTheDocument();
      act(() => { resolveLoad!(mockRecords); });
    });

    it("loads quarantine list on mount", async () => {
      renderQuarantine();
      await waitFor(() => expect(mockInvoke).toHaveBeenCalledWith("list_quarantine"));
    });

    it("displays records in table after loading", async () => {
      renderQuarantine();
      await waitFor(() => expect(screen.getByText("malware.exe")).toBeInTheDocument());
      expect(screen.getByText("trojan.dll")).toBeInTheDocument();
    });

    it("displays truncated hash", async () => {
      renderQuarantine();
      await waitFor(() => {
        expect(screen.getByText("abc123de…")).toBeInTheDocument();
        expect(screen.getByText("def456gh…")).toBeInTheDocument();
      });
    });

    it("displays original path with tooltip", async () => {
      renderQuarantine();
      await waitFor(() => {
        const pathElement = screen.getByText("/Downloads/malware.exe");
        expect(pathElement).toHaveAttribute("title", "/Downloads/malware.exe");
      });
    });

    it("formats dates according to locale", async () => {
      renderQuarantine();
      await waitFor(() => {
        expect(screen.getByText(/15\/01\/2024/)).toBeInTheDocument();
        expect(screen.getByText(/16\/01\/2024/)).toBeInTheDocument();
      });
    });
  });

  describe("Restore file", () => {
    it("calls restore_file when restore button is clicked", async () => {
      renderQuarantine();
      await waitFor(() => expect(screen.getByText("♻️ Ripristina")).toBeInTheDocument());

      await userEvent.click(screen.getAllByText("♻️ Ripristina")[0]);

      await waitFor(() => expect(mockInvoke).toHaveBeenCalledWith("restore_file", { record: mockRecords[0] }));
    });

    it("removes record from list after restore", async () => {
      renderQuarantine();
      await waitFor(() => expect(screen.getByText("malware.exe")).toBeInTheDocument());

      await userEvent.click(screen.getAllByText("♻️ Ripristina")[0]);

      await waitFor(() => expect(screen.queryByText("malware.exe")).not.toBeInTheDocument());
      expect(screen.getByText("trojan.dll")).toBeInTheDocument();
    });
  });

  describe("Delete permanently", () => {
    it("shows confirmation dialog when delete is clicked", async () => {
      renderQuarantine();
      await waitFor(() => expect(screen.getByText("🗑 Elimina")).toBeInTheDocument());

      await userEvent.click(screen.getAllByText("🗑 Elimina")[0]);

      expect(window.confirm).toHaveBeenCalledWith("Eliminare definitivamente il file? Azione irreversibile.");
    });

    it("calls delete_permanently when confirmed", async () => {
      renderQuarantine();
      await waitFor(() => expect(screen.getByText("trojan.dll")).toBeInTheDocument());

      await userEvent.click(screen.getAllByText("🗑 Elimina")[1]);

      await waitFor(() => expect(mockInvoke).toHaveBeenCalledWith("delete_permanently", { record: mockRecords[1] }));
    });

    it("removes record from list after delete", async () => {
      renderQuarantine();
      await waitFor(() => expect(screen.getByText("trojan.dll")).toBeInTheDocument());

      await userEvent.click(screen.getAllByText("🗑 Elimina")[1]);

      await waitFor(() => expect(screen.queryByText("trojan.dll")).not.toBeInTheDocument());
      expect(screen.getByText("malware.exe")).toBeInTheDocument();
    });

    it("does not delete when cancelled", async () => {
      vi.spyOn(window, "confirm").mockReturnValue(false);
      renderQuarantine();
      await waitFor(() => expect(screen.getByText("malware.exe")).toBeInTheDocument());

      await userEvent.click(screen.getAllByText("🗑 Elimina")[0]);

      expect(mockInvoke).not.toHaveBeenCalledWith("delete_permanently", expect.any(Object));
      expect(screen.getByText("malware.exe")).toBeInTheDocument();
    });
  });

  describe("Empty state", () => {
    it("shows empty message when no quarantined files", async () => {
      mockInvoke.mockResolvedValue([]);
      renderQuarantine();
      await waitFor(() => expect(screen.getByText("Nessun file in quarantena.")).toBeInTheDocument());
    });
  });

  describe("Error handling", () => {
    it("handles load error gracefully", async () => {
      mockInvoke.mockRejectedValue(new Error("Database error"));
      renderQuarantine();

      await waitFor(() => expect(screen.getByText("⏳")).not.toBeInTheDocument());
      expect(screen.getByText("Nessun file in quarantena.")).toBeInTheDocument();
    });

    it("handles restore error gracefully", async () => {
      renderQuarantine();
      await waitFor(() => expect(screen.getByText("malware.exe")).toBeInTheDocument());

      mockInvoke.mockRejectedValueOnce(new Error("Restore failed"));
      await userEvent.click(screen.getAllByText("♻️ Ripristina")[0]);

      // Record should still be in list if restore fails
      expect(screen.getByText("malware.exe")).toBeInTheDocument();
    });

    it("handles delete error gracefully", async () => {
      renderQuarantine();
      await waitFor(() => expect(screen.getByText("trojan.dll")).toBeInTheDocument());

      mockInvoke.mockRejectedValueOnce(new Error("Delete failed"));
      await userEvent.click(screen.getAllByText("🗑 Elimina")[1]);

      // Record should still be in list if delete fails
      expect(screen.getByText("trojan.dll")).toBeInTheDocument();
    });
  });
});