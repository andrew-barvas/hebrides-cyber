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
  // scans queue order matches metrics.ts's own Promise.all construction
  // order: total head-count, then one head-count per SCAN_STATUSES entry
  // (pending, running, completed, failed), then the last-30-days head-count.
  function scansQueue(byStatus: Partial<Record<"pending" | "running" | "completed" | "failed", number>>, last30d: number) {
    const total = Object.values(byStatus).reduce((sum, n) => sum + (n ?? 0), 0);
    return [
      { count: total },
      { count: byStatus.pending ?? 0 },
      { count: byStatus.running ?? 0 },
      { count: byStatus.completed ?? 0 },
      { count: byStatus.failed ?? 0 },
      { count: last30d },
    ];
  }

  it("computes MRR using the real plan prices (£20/£35/£75), not stale ones", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({
      users: [{ count: 3 }, { data: [] }], // head-count query, then recentSignups
      subscriptions: [{ data: [{ plan: "basic", status: "active" }, { plan: "pro", status: "active" }, { plan: "agency", status: "active" }] }],
      scans: scansQueue({}, 0),
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
      scans: scansQueue({}, 0),
    });
    const { req, res } = mockReqRes();

    await handler(req, res);

    const body = res._getJSONData() as { mrrUsd: number; activeSubscriptions: number };
    expect(body.mrrUsd).toBe(35);
    expect(body.activeSubscriptions).toBe(1);
  });

  it("counts scans in the last 30 days separately from the total, using exact counts not a sampled fetch", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({
      users: [{ count: 0 }, { data: [] }],
      subscriptions: [{ data: [] }],
      scans: scansQueue({ completed: 2, failed: 1 }, 2),
    });
    const { req, res } = mockReqRes();

    await handler(req, res);

    const body = res._getJSONData() as { totalScans: number; scansLast30d: number; scansByStatus: Record<string, number> };
    expect(body.totalScans).toBe(3);
    expect(body.scansLast30d).toBe(2);
    expect(body.scansByStatus).toEqual({ completed: 2, failed: 1 });
  });

  it("totalScans reflects an exact count past the old 500-row sample cap", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({
      users: [{ count: 0 }, { data: [] }],
      subscriptions: [{ data: [] }],
      scans: scansQueue({ completed: 750 }, 10),
    });
    const { req, res } = mockReqRes();

    await handler(req, res);

    expect((res._getJSONData() as { totalScans: number }).totalScans).toBe(750);
  });

  it("returns zeroed defaults when every query comes back null", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({
      users: [{ count: null }, { data: null }],
      subscriptions: [{ data: null }],
      scans: [
        { count: null },
        { count: null },
        { count: null },
        { count: null },
        { count: null },
        { count: null },
      ],
    });
    const { req, res } = mockReqRes();

    await handler(req, res);

    expect(res._getJSONData()).toMatchObject({ totalCustomers: 0, activeSubscriptions: 0, totalScans: 0, mrrUsd: 0, recentSignups: [] });
  });
});
