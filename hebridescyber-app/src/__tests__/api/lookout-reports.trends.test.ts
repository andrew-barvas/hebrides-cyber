import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks, type RequestMethod } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock, state } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  state: { report: null as Record<string, unknown> | null, updates: [] as unknown[] },
}));

function builder(table: string) {
  const b: Record<string, unknown> = {
    select: () => b,
    eq: () => b,
    in: () => b,
    lte: () => b,
    limit: () => b,
    order: () => (table === "lookout_report_items" ? Promise.resolve({ data: [{ id: "i1", title: "Weak TLS" }], error: null }) : b),
    maybeSingle: async () => (table === "scans" ? { data: { id: "scan-9" }, error: null } : { data: state.report, error: null }),
    update: (row: unknown) => {
      state.updates.push(row);
      const u: Record<string, unknown> = { eq: () => u, then: (r: (v: unknown) => void) => r({ error: null }) };
      return u;
    },
  };
  return b;
}

vi.mock("@/lib/apiAuth", () => ({ authenticateApiRequest: authenticateApiRequestMock, supabaseAdmin: { from: (t: string) => builder(t) } }));
vi.mock("@/lib/audit", () => ({ logAuditEvent: vi.fn() }));
vi.mock("@/lib/lookoutLookalikes", () => ({ loadReportLookalikes: async () => ({ available: false, newInPeriod: [], totalKnown: 0 }) }));
vi.mock("@/lib/lookoutBreaches", () => ({ loadReportBreaches: async () => ({ available: false, sites: [] }) }));
vi.mock("@/lib/reportTrends", () => ({ loadReportTrends: async () => ({ available: true, sites: [{ host: "a.example", start: 50, end: 70, change: 20 }], average: [] }) }));

import handler from "@/pages/api/lookout/reports/[id]";

async function call(method: RequestMethod, body?: Record<string, unknown>) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method, query: { id: "r1" }, body });
  await handler(req, res);
  return res;
}

const report = (status: string, customer = "cust-1") => ({ id: "r1", customer, period_start: "2026-10-15", period_end: "2026-11-14", status, summary: "s", published_at: "2026-11-14T00:00:00Z", acknowledged_at: null });

describe("/api/lookout/reports/[id]: trends and methods", () => {
  beforeEach(() => {
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: "cust-1", via: "session" });
    state.report = report("published");
    state.updates = [];
  });

  it("includes the score trend for the report's period", async () => {
    const res = await call("GET");
    expect((res._getJSONData() as { trends: unknown }).trends).toMatchObject({ available: true, sites: [{ host: "a.example", change: 20 }] });
  });

  it("refuses other methods", async () => {
    const res = await call("DELETE");
    expect(res._getStatusCode()).toBe(405);
    expect(res.getHeader("Allow")).toBe("GET, POST");
  });
});
