import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import DmarcReports, { type DmarcReport } from "./DmarcReports";

const fetchMock = vi.fn();
const ok = (body: unknown) => ({ ok: true, status: 200, json: async () => body });

// Routes the panel's two GETs (reports + ingest token) by URL.
function route(reportsBody: unknown, tokenBody: unknown) {
  fetchMock.mockImplementation((url: string) => {
    if (url === "/api/dmarc/reports") return Promise.resolve(ok(reportsBody));
    if (url === "/api/account/dmarc-ingest-token") return Promise.resolve(ok(tokenBody));
    return Promise.resolve({ ok: false, status: 404, json: async () => ({}) });
  });
}

const report = (over: Partial<DmarcReport> = {}): DmarcReport => ({
  id: "r1",
  domain: "example.com",
  org_name: "google.com",
  date_begin: "2026-10-01T00:00:00Z",
  date_end: "2026-10-02T00:00:00Z",
  total_messages: 100,
  passing_messages: 98,
  failing_messages: 2,
  rows: [],
  received_at: "2026-10-02T06:00:00Z",
  ...over,
});

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => vi.unstubAllGlobals());

describe("DmarcReports", () => {
  it("shows the ingest URL and lists reports with an alignment badge", async () => {
    route({ available: true, reports: [report()] }, { ingestUrl: "https://www.hebridescyber.co.uk/api/dmarc/ingest?token=dmarc_x" });
    render(<DmarcReports token="tok" paidPlan />);
    expect(await screen.findByText("example.com")).toBeInTheDocument();
    expect(screen.getByText("98% aligned")).toBeInTheDocument();
    expect(screen.getByText("https://www.hebridescyber.co.uk/api/dmarc/ingest?token=dmarc_x")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith("/api/dmarc/reports", { headers: { Authorization: "Bearer tok" } });
  });

  it("offers to generate an ingest URL when none exists, and prompts for reports", async () => {
    route({ available: true, reports: [] }, { ingestUrl: null });
    render(<DmarcReports token="tok" paidPlan />);
    expect(await screen.findByRole("button", { name: "Generate ingest URL" })).toBeInTheDocument();
    expect(screen.getByText(/No reports received yet/)).toBeInTheDocument();
  });

  it("renders nothing before migration 060 (available:false)", async () => {
    route({ available: false, reports: [] }, { ingestUrl: null });
    const { container } = render(<DmarcReports token="tok" paidPlan />);
    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });

  it("renders nothing for a free account with no ingest URL and no reports", async () => {
    route({ available: true, reports: [] }, { ingestUrl: null });
    const { container } = render(<DmarcReports token="tok" paidPlan={false} />);
    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });
});
