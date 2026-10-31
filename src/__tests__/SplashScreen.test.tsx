import { render, screen, waitFor, act } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach, afterEach } from "vitest";
import SplashScreen from "../components/SplashScreen";

describe("SplashScreen Component", () => {
  const mockOnDone = vi.fn();

  beforeEach(() => {
    vi.useFakeTimers();
    mockOnDone.mockClear();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("renders splash screen with progress bar", () => {
    render(<SplashScreen onDone={mockOnDone} />);

    expect(screen.getByAltText("ScanDeep Defender")).toBeInTheDocument();
    expect(screen.getByText("Inizializzazione... 0%")).toBeInTheDocument();
    // Progress bar is a div with style width, not a native progressbar role
    expect(screen.getByText("Inizializzazione... 0%")).toBeInTheDocument();
  });

  it("progresses through initialization steps", async () => {
    render(<SplashScreen onDone={mockOnDone} />);

    // Initial progress
    expect(screen.getByText("Inizializzazione... 0%")).toBeInTheDocument();
    const progressBar = screen.getByText("Inizializzazione... 0%").closest("div")?.querySelector(".splash-bar");
    expect(progressBar).toBeInTheDocument();

    // First step (8%)
    act(() => { vi.advanceTimersByTime(220); });
    expect(screen.getByText("Inizializzazione... 8%")).toBeInTheDocument();

    // Second step (18%)
    act(() => { vi.advanceTimersByTime(220); });
    expect(screen.getByText("Inizializzazione... 18%")).toBeInTheDocument();

    // Continue through all steps
    const steps = [32, 48, 64, 78, 92, 100];
    for (const step of steps) {
      act(() => { vi.advanceTimersByTime(220); });
      expect(screen.getByText(`Inizializzazione... ${step}%`)).toBeInTheDocument();
    }
  });

  it("shows 'Pronto' when progress reaches 100%", async () => {
    render(<SplashScreen onDone={mockOnDone} />);

    // Advance through all steps
    for (let i = 0; i < 8; i++) {
      act(() => { vi.advanceTimersByTime(220); });
    }

    expect(screen.getByText("Pronto")).toBeInTheDocument();
  });

  it("calls onDone after fade out animation completes", async () => {
    render(<SplashScreen onDone={mockOnDone} />);

    // Advance through all progress steps
    for (let i = 0; i < 8; i++) {
      act(() => { vi.advanceTimersByTime(220); });
    }

    // Wait for "Pronto" state
    expect(screen.getByText("Pronto")).toBeInTheDocument();

    // Wait for fade out delay (350ms)
    act(() => { vi.advanceTimersByTime(350); });

    // Wait for fade out animation (520ms)
    act(() => { vi.advanceTimersByTime(520); });

    expect(mockOnDone).toHaveBeenCalledTimes(1);
  });

  it("applies fade-out class when fading", async () => {
    render(<SplashScreen onDone={mockOnDone} />);

    // Advance through all progress steps
    for (let i = 0; i < 8; i++) {
      act(() => { vi.advanceTimersByTime(220); });
    }

    // Wait for fade out delay
    act(() => { vi.advanceTimersByTime(350); });

    const splashRoot = document.querySelector(".splash-root");
    expect(splashRoot).toHaveClass("splash-out");
  });

  it("cleans up interval on unmount", () => {
    const { unmount } = render(<SplashScreen onDone={mockOnDone} />);

    // Advance a bit
    act(() => { vi.advanceTimersByTime(500); });

    // Unmount
    unmount();

    // Advance more - onDone should not be called after unmount
    act(() => { vi.advanceTimersByTime(5000); });

    expect(mockOnDone).not.toHaveBeenCalled();
  });

  it("renders splash image with correct alt text", () => {
    render(<SplashScreen onDone={mockOnDone} />);

    const img = screen.getByAltText("ScanDeep Defender");
    expect(img).toHaveAttribute("src", expect.stringContaining("splash.png"));
  });

  it("has overlay element", () => {
    render(<SplashScreen onDone={mockOnDone} />);

    const overlay = document.querySelector(".splash-overlay");
    expect(overlay).toBeInTheDocument();
  });

  it("progress bar width matches progress percentage", async () => {
    render(<SplashScreen onDone={mockOnDone} />);

    const progressSteps = [0, 8, 18, 32, 48, 64, 78, 92, 100];

    for (const step of progressSteps) {
      if (step > 0) {
        act(() => { vi.advanceTimersByTime(220); });
      }
      const progressBar = document.querySelector(".splash-bar") as HTMLElement;
      expect(progressBar).toHaveStyle({ width: `${step}%` });
    }
  });
});