import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import EmergingThreatsPanel, { type EmergingThreatAlert } from "./EmergingThreatsPanel";

const fetchMock = vi.fn();
const ok = (body: unknown) => ({ ok: true, status: 200, json: async () => body });

const alert = (over: Partial<EmergingThreatAlert> = {}): EmergingThreatAlert => ({
  id: "a1", target_host: "shop.example", cve_id: "CVE-2021-41773", confidence: "affected", product: "Apache HTTP Server",
  detected_version: "2.4.49", kev_date_added: "2026-09-30", scan_id: "s1", matched_at: "2026-10-01T06:40:00Z", notified_at: null, ...over,
});

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => vi.unstubAllGlobals());

describe("EmergingThreatsPanel", () => {
  it("lists alerts with their evidence tier and a link to the report", async () => {
    fetchMock.mockResolvedValue(ok({ available: true, alerts: [alert(), alert({ id: "a2", confidence: "possibly_affected", detected_version: null, cve_id: "CVE-2026-0001" })] }));
    render(<EmergingThreatsPanel token="tok" paidPlan />);
    expect(await screen.findByText("CVE-2021-41773")).toBeInTheDocument();
    expect(screen.getByText("Affected")).toBeInTheDocument();
    expect(screen.getByText("Check version")).toBeInTheDocument();
    expect(screen.getByText("(version not visible)")).toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: "latest report" })[0]).toHaveAttribute("href", "/dashboard/scans/s1");
    expect(fetchMock).toHaveBeenCalledWith("/api/emerging-threats", { headers: { Authorization: "Bearer tok" } });
  });

  it("says so when nothing has matched, for a paid plan", async () => {
    fetchMock.mockResolvedValue(ok({ available: true, alerts: [] }));
    render(<EmergingThreatsPanel token="tok" paidPlan />);
    expect(await screen.findByText("No newly exploited vulnerability has matched your sites.")).toBeInTheDocument();
  });

  it("renders nothing without a paid plan and no alerts, or before the migration", async () => {
    fetchMock.mockResolvedValue(ok({ available: true, alerts: [] }));
    const { container, rerender } = render(<EmergingThreatsPanel token="tok" paidPlan={false} />);
    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();

    fetchMock.mockResolvedValue(ok({ available: false, alerts: [] }));
    rerender(<EmergingThreatsPanel token="tok2" paidPlan />);
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    expect(container).toBeEmptyDOMElement();
  });

  it("waits for a session token", () => {
    render(<EmergingThreatsPanel token={null} paidPlan />);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
