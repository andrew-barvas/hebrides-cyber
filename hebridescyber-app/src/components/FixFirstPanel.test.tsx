import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import FixFirstPanel from "./FixFirstPanel";

const fetchMock = vi.fn();
const ok = (body: unknown) => ({ ok: true, status: 200, json: async () => body });

const item = (rank: number, over: Record<string, unknown> = {}) => ({
  key: `h${rank}`, host: "shop.example", checkId: "nuclei.cve-1", checkBase: "nuclei.cve-1", category: "nuclei", severity: "high",
  title: `Finding ${rank}`, detail: null, firstSeenAt: "2026-10-01T00:00:00Z", ageDays: 3, slaState: null, slaDueAt: null,
  knownExploited: true, ransomware: false, epss: null, cvssScore: null, cveIds: [], scanId: "s1", triage: null,
  priority: { rank, score: 33.8, base: 22.5, factors: [], reason: "High severity, KEV listed, on a high-criticality site" },
  ...over,
});

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("FixFirstPanel", () => {
  it("lists the top of the ranked list with each reason and a link to the full list", async () => {
    fetchMock.mockResolvedValue(ok({ available: true, priorityComplete: true, truncated: false, totalFindings: 12, items: [item(1), item(2, { scanId: null })] }));
    render(<FixFirstPanel token="tok" />);
    expect(await screen.findByRole("link", { name: "Finding 1" })).toHaveAttribute("href", "/dashboard/scans/s1");
    expect(screen.getByText("Finding 2")).toBeInTheDocument();
    expect(screen.getAllByText("Why here: High severity, KEV listed, on a high-criticality site")).toHaveLength(2);
    expect(screen.getByRole("link", { name: "See all 12" })).toHaveAttribute("href", "/dashboard/findings?sort=priority");
    expect(fetchMock).toHaveBeenCalledWith("/api/findings?sort=priority&view=rows&pageSize=5", { headers: { Authorization: "Bearer tok" } });
    expect(screen.queryByText(/may be incomplete/)).toBeNull();
  });

  it("flags a partial ranking", async () => {
    fetchMock.mockResolvedValue(ok({ available: true, priorityComplete: false, totalFindings: 1, items: [item(1)] }));
    render(<FixFirstPanel token="tok" />);
    expect(await screen.findByText(/this ranking may be incomplete/)).toBeInTheDocument();
  });

  it("says when there is nothing to fix", async () => {
    fetchMock.mockResolvedValue(ok({ available: true, totalFindings: 0, items: [] }));
    render(<FixFirstPanel token="tok" />);
    expect(await screen.findByText("Nothing open to fix across your sites.")).toBeInTheDocument();
  });

  it("reports a failed load instead of an empty list", async () => {
    fetchMock.mockResolvedValue({ ok: false, status: 500, json: async () => ({}) });
    render(<FixFirstPanel token="tok" />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Couldn't load your priority list");
    fetchMock.mockRejectedValue(new Error("offline"));
    render(<FixFirstPanel token="tok2" />);
    await waitFor(() => expect(screen.getAllByRole("alert")).toHaveLength(2));
  });

  it("renders nothing before the lifecycle migration, or without a token", async () => {
    fetchMock.mockResolvedValue(ok({ available: false }));
    const { container } = render(<FixFirstPanel token="tok" />);
    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
    const { container: noToken } = render(<FixFirstPanel token={null} />);
    expect(noToken).toBeEmptyDOMElement();
  });
});
