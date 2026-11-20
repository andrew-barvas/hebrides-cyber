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

import handler from "@/pages/api/lookout/reports/[id]";

async function call(method: RequestMethod, body?: Record<string, unknown>) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method, query: { id: "r1" }, body });
  await handler(req, res);
  return res;
}

const report = (status: string, customer = "cust-1") => ({ id: "r1", customer, period_start: "2026-10-15", period_end: "2026-11-14", status, summary: "s", published_at: "2026-11-14T00:00:00Z", acknowledged_at: null });

describe("/api/lookout/reports/[id] (customer)", () => {
  beforeEach(() => {
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: "cust-1", via: "session" });
    state.report = report("published");
    state.updates = [];
  });

  it("shows a published report and its included items, without the customer id", async () => {
    const res = await call("GET");
    expect(res._getStatusCode()).toBe(200);
    const body = res._getJSONData() as { report: Record<string, unknown>; items: unknown[] };
    expect(body.report.customer).toBeUndefined();
    expect(body.items).toHaveLength(1);
    // The scan whose host screenshots form the report's estate gallery.
    expect((body as { galleryScanId?: string }).galleryScanId).toBe("scan-9");
  });

  it("hides drafts and other customers' reports behind a 404", async () => {
    state.report = report("draft");
    expect((await call("GET"))._getStatusCode()).toBe(404);
    state.report = report("published", "cust-2");
    expect((await call("GET"))._getStatusCode()).toBe(404);
  });

  it("records the acknowledgement once, from a session only", async () => {
    const res = await call("POST", { action: "acknowledge" });
    expect(res._getStatusCode()).toBe(200);
    expect(state.updates).toEqual([expect.objectContaining({ status: "acknowledged", acknowledged_by: "cust-1" })]);

    state.report = report("acknowledged");
    expect(((await call("POST", { action: "acknowledge" }))._getJSONData() as { acknowledged: boolean }).acknowledged).toBe(true);
    expect(state.updates).toHaveLength(1);

    authenticateApiRequestMock.mockResolvedValue({ ownerId: "cust-1", via: "api_key" });
    state.report = report("published");
    expect((await call("POST", { action: "acknowledge" }))._getStatusCode()).toBe(403);
  });
});
