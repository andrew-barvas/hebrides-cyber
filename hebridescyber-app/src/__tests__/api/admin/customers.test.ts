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

import handler from "@/pages/api/admin/customers";

function mockReqRes(query: Record<string, string> = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({ method: "GET", query, headers: { authorization: "Bearer t" } });
}

describe("GET /api/admin/customers", () => {
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

  it("returns 500 when the users query errors", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({ users: [{ data: null, error: { message: "db down" }, count: null }] });
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(500);
  });

  it("enriches each customer with plan, subscription status, and scan count", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({
      users: [
        {
          data: [
            { id: "u1", email: "a@example.com", company_name: "Acme", is_admin: false, created_at: "2026-01-01" },
            { id: "u2", email: "b@example.com", company_name: null, is_admin: false, created_at: "2026-01-02" },
          ],
          error: null,
          count: 2,
        },
      ],
      subscriptions: [{ data: [{ owner: "u1", plan: "pro", status: "active" }] }],
      scans: [{ data: [{ owner: "u1" }, { owner: "u1" }, { owner: "u2" }] }],
    });
    const { req, res } = mockReqRes();

    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    const body = res._getJSONData() as { customers: Array<Record<string, unknown>>; total: number };
    expect(body.customers).toEqual([
      { id: "u1", email: "a@example.com", company_name: "Acme", is_admin: false, plan: "pro", subscription_status: "active", scan_count: 2, created_at: "2026-01-01" },
      { id: "u2", email: "b@example.com", company_name: null, is_admin: false, plan: null, subscription_status: null, scan_count: 1, created_at: "2026-01-02" },
    ]);
    expect(body.total).toBe(2);
  });

  it("handles zero customers without erroring", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({
      users: [{ data: [], error: null, count: 0 }],
      subscriptions: [{ data: [] }],
      scans: [{ data: [] }],
    });
    const { req, res } = mockReqRes();

    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(res._getJSONData()).toMatchObject({ customers: [], total: 0 });
  });
});
