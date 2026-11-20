import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { ScoreBenchmark } from "./ScoreBenchmark";

describe("ScoreBenchmark", () => {
  beforeEach(() => {
    vi.unstubAllGlobals();
  });

  it("shows how the scan compares, with the session token", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ benchmark: { betterThanPercent: 40, groupSize: 80, windowDays: 90, kind: "scan" } }) });
    vi.stubGlobal("fetch", fetchMock);
    render(<ScoreBenchmark scanId="s1" token="tok" />);
    expect(await screen.findByText("Better than 40% of the 80 sites scanned with Hebrides Cyber in the last 90 days.")).toBeInTheDocument();
    expect(screen.getByText(/your own sites aren't included/)).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith("/api/scans/s1/benchmark", { headers: { Authorization: "Bearer tok" } });
  });

  it("renders nothing while the feature is off, on an error status, or when the request fails", async () => {
    for (const impl of [
      () => Promise.resolve({ ok: true, json: async () => ({ benchmark: null }) }),
      () => Promise.resolve({ ok: false, json: async () => ({}) }),
      () => Promise.reject(new Error("offline")),
    ]) {
      const fetchMock = vi.fn(impl);
      vi.stubGlobal("fetch", fetchMock);
      const { container, unmount } = render(<ScoreBenchmark scanId="s1" token="tok" />);
      await waitFor(() => expect(fetchMock).toHaveBeenCalled());
      expect(container).toBeEmptyDOMElement();
      unmount();
    }
  });
});
