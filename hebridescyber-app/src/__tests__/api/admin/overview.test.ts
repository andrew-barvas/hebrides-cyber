import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";
import { makeAdminSupabaseMock } from "./_supabaseQueueMock";

const { getUserMock } = vi.hoisted(() => ({ getUserMock: vi.fn() }));
const mock = makeAdminSupabaseMock();

vi.mock("@/lib/supabaseAdmin", () => ({
  supabaseAdmin: {
    auth: { getUser: getUserMock },
    from: (table: string) => mock.supabaseAdmin.from(table),
  },
}));

import handler from "@/pages/api/admin/overview";

function mockReqRes(overrides: Partial<Parameters<typeof createMocks>[0]> = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({ method: "GET", headers: { authorization: "Bearer t" }, ...overrides });
}

describe("GET /api/admin/overview", () => {
  beforeEach(() => {
    mock.reset();
    getUserMock.mockReset();
  });

  it("rejects non-GET methods with 405", async () => {
    const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "POST" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });

  it("returns 401 when there is no Authorization header", async () => {
    const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "GET" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(401);
  });

  it("returns 401 when the session is invalid", async () => {
    getUserMock.mockResolvedValue({ data: { user: null }, error: { message: "invalid" } });
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(401);
  });

  it("returns 401 (not 500) when the auth call throws", async () => {
    getUserMock.mockRejectedValue(new Error("network error"));
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(401);
  });

  it("returns 403 when the caller is authenticated but not an admin", async () => {
    getUserMock.mockResolvedValue({ data: { user: { id: "u1" } }, error: null });
    mock.setQueues({ users: [{ data: { is_admin: false } }] });
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("builds the enriched customer list and totals for an admin caller", async () => {
    getUserMock.mockResolvedValue({ data: { user: { id: "admin-1" } }, error: null });
    mock.setQueues({
      users: [
        { data: { is_admin: true } }, // the caller's own profile check
        {
          data: [
            { id: "u1", email: "a@example.com", company_name: "Acme", is_admin: false, created_at: "2026-01-01" },
            { id: "u2", email: "b@example.com", company_name: null, is_admin: false, created_at: "2026-01-02" },
          ],
        },
      ],
      subscriptions: [{ data: [{ owner: "u1", plan: "agency", status: "active" }, { owner: "u2", plan: "basic", status: "past_due" }] }],
      scans: [{ data: [{ id: "s1", owner: "u1" }, { id: "s2", owner: "u1" }] }],
    });
    const { req, res } = mockReqRes();

    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    const body = res._getJSONData() as {
      customers: Array<Record<string, unknown>>;
      totals: { customers: number; activeSubscriptions: number; totalScans: number };
    };
    expect(body.customers).toEqual([
      { id: "u1", email: "a@example.com", companyName: "Acme", isAdmin: false, plan: "agency", subscriptionStatus: "active", scanCount: 2, createdAt: "2026-01-01" },
      // past_due (not active) reports plan "none" — subscriptionStatus still reflects the real status.
      { id: "u2", email: "b@example.com", companyName: null, isAdmin: false, plan: "none", subscriptionStatus: "past_due", scanCount: 0, createdAt: "2026-01-02" },
    ]);
    expect(body.totals).toEqual({ customers: 2, activeSubscriptions: 1, totalScans: 2 });
  });
});
