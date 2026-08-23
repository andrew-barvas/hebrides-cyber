import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";
import { makeAdminSupabaseMock } from "./_supabaseQueueMock";

const { requireAdminMock } = vi.hoisted(() => ({ requireAdminMock: vi.fn() }));
const mock = makeAdminSupabaseMock();

vi.mock("@/lib/adminAuth", () => ({
  requireAdmin: requireAdminMock,
  supabaseAdmin: { from: (table: string) => mock.supabaseAdmin.from(table) },
}));

import handler from "@/pages/api/admin/metrics";

function mockReqRes() {
  return createMocks<NextApiRequest, NextApiResponse>({ method: "GET", headers: { authorization: "Bearer t" } });
}

describe("GET /api/admin/metrics", () => {
  beforeEach(() => {
    mock.reset();
    requireAdminMock.mockReset();
  });

  it("rejects non-GET methods with 405", async () => {
    const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "POST" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });

  it("returns 403 when the caller is not an admin", async () => {
    requireAdminMock.mockResolvedValue(null);
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  // Regression test for a real pricing-drift bug found while writing this
  // suite: PLAN_PRICE here was { basic: 19, pro: 49, agency: 99 }, stale
  // against the real prices on /pricing and dashboard.tsx's PLAN_LABELS
  // (£20/£35/£75) — silently understating MRR on every admin panel load.
  it("computes MRR using the real plan prices (£20/£35/£75), not stale ones", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({
      users: [{ count: 3 }, { data: [] }], // head-count query, then recentSignups
      subscriptions: [{ data: [{ plan: "basic", status: "active" }, { plan: "pro", status: "active" }, { plan: "agency", status: "active" }] }],
      scans: [{ data: [] }],
    });
    const { req, res } = mockReqRes();

    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect((res._getJSONData() as { mrrUsd: number }).mrrUsd).toBe(20 + 35 + 75);
  });

  it("ignores non-active subscriptions in MRR and plan breakdown", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({
      users: [{ count: 1 }, { data: [] }],
      subscriptions: [{ data: [{ plan: "agency", status: "cancelled" }, { plan: "pro", status: "active" }] }],
      scans: [{ data: [] }],
    });
    const { req, res } = mockReqRes();

    await handler(req, res);

    const body = res._getJSONData() as { mrrUsd: number; activeSubscriptions: number };
    expect(body.mrrUsd).toBe(35);
    expect(body.activeSubscriptions).toBe(1);
  });

  it("counts scans in the last 30 days separately from the total", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    const now = Date.now();
    mock.setQueues({
      users: [{ count: 0 }, { data: [] }],
      subscriptions: [{ data: [] }],
      scans: [{
        data: [
          { status: "completed", created_at: new Date(now - 5 * 86_400_000).toISOString() },
          { status: "completed", created_at: new Date(now - 60 * 86_400_000).toISOString() },
          { status: "failed", created_at: new Date(now - 1 * 86_400_000).toISOString() },
        ],
      }],
    });
    const { req, res } = mockReqRes();

    await handler(req, res);

    const body = res._getJSONData() as { totalScans: number; scansLast30d: number; scansByStatus: Record<string, number> };
    expect(body.totalScans).toBe(3);
    expect(body.scansLast30d).toBe(2);
    expect(body.scansByStatus).toEqual({ completed: 2, failed: 1 });
  });

  it("returns zeroed defaults when every query comes back null", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({
      users: [{ count: null }, { data: null }],
      subscriptions: [{ data: null }],
      scans: [{ data: null }],
    });
    const { req, res } = mockReqRes();

    await handler(req, res);

    expect(res._getJSONData()).toMatchObject({ totalCustomers: 0, activeSubscriptions: 0, totalScans: 0, mrrUsd: 0, recentSignups: [] });
  });
});
