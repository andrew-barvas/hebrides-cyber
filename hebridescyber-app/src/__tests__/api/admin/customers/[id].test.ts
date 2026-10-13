import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";
import { makeAdminSupabaseMock } from "../_supabaseQueueMock";

const { requireAdminMock, logAuditEventMock } = vi.hoisted(() => ({
  requireAdminMock: vi.fn(),
  logAuditEventMock: vi.fn(),
}));
const mock = makeAdminSupabaseMock();

vi.mock("@/lib/adminAuth", () => ({
  requireAdmin: requireAdminMock,
  supabaseAdmin: {
    from: (table: string) => mock.supabaseAdmin.from(table),
    rpc: (fn: string) => mock.supabaseAdmin.rpc(fn),
  },
}));

vi.mock("@/lib/audit", () => ({ logAuditEvent: logAuditEventMock }));

import handler from "@/pages/api/admin/customers/[id]";

function mockReqRes(overrides: Partial<Parameters<typeof createMocks>[0]> = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({
    method: "GET",
    headers: { authorization: "Bearer t" },
    query: { id: "owner-1" },
    ...overrides,
  });
}

describe("/api/admin/customers/[id]", () => {
  beforeEach(() => {
    mock.reset();
    requireAdminMock.mockReset();
    logAuditEventMock.mockReset().mockResolvedValue(undefined);
  });

  it("returns 403 when the caller is not an admin", async () => {
    requireAdminMock.mockResolvedValue(null);
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("rejects other methods with 405", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    const { req, res } = mockReqRes({ method: "PATCH" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });

  it("returns 400 when id is missing", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    const { req, res } = mockReqRes({ query: {} });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
  });

  it("returns 404 when the customer does not exist", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({ users: [{ data: null, error: null }] });
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(404);
  });

  it("returns 500 when the user lookup errors", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({ users: [{ data: null, error: { message: "db down" } }] });
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(500);
  });

  it("returns profile, subscription, flattened recent scans and usage, and logs an audit event", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({
      users: [{ data: { id: "owner-1", email: "a@example.com", company_name: "Acme", is_admin: false, created_at: "2026-01-01" }, error: null }],
      subscriptions: [{ data: { plan: "pro", status: "active", source: "stripe", granted_by: null, grant_reason: null, stripe_customer_id: "cus_1", updated_at: "2026-01-02" }, error: null }],
      scans: [
        { data: [{ id: "s1", target_url: "https://example.com", status: "completed", created_at: "2026-01-03", scan_results: [{ score: 91 }] }], error: null },
        { count: 7, error: null },
        { count: 6, error: null },
      ],
      monitored_targets: [{ count: 2, error: null }],
      teams: [{ data: { id: "team-1" }, error: null }],
      team_members: [{ count: 4, error: null }],
    });
    mock.setRpcQueues({ monitored_targets_cap: [{ data: 3, error: null }] });
    const { req, res } = mockReqRes();

    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    const body = res._getJSONData() as {
      user: { email: string };
      subscription: { plan: string };
      scans: Array<{ id: string; score: number | null }>;
      scanCount: number;
      usage: {
        monitoredTargets: { count: number; cap: number | null };
        teamMembers: { count: number; cap: number } | null;
        freeScans: { count: number; allowed: number } | null;
      };
    };
    expect(body.user.email).toBe("a@example.com");
    expect(body.subscription.plan).toBe("pro");
    expect(body.scans[0]).toMatchObject({ id: "s1", score: 91 });
    expect(body.scanCount).toBe(7);
    // An active subscription means the free-tier cap no longer applies.
    expect(body.usage).toEqual({
      monitoredTargets: { count: 2, cap: 3 },
      teamMembers: { count: 4, cap: 25 },
      freeScans: null,
    });
    expect(logAuditEventMock).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ actorId: "admin-1", action: "admin.customer_viewed", resourceType: "user", resourceId: "owner-1" })
    );
  });

  it("returns null subscription when the customer has none, and reports free-tier usage", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({
      users: [{ data: { id: "owner-1", email: "a@example.com", company_name: null, is_admin: false, created_at: "2026-01-01" }, error: null }],
      subscriptions: [{ data: null, error: null }],
      scans: [{ data: [], error: null }, { count: 1, error: null }, { count: 1, error: null }],
      monitored_targets: [{ count: 0, error: null }],
      teams: [{ data: null, error: null }],
    });
    mock.setRpcQueues({ monitored_targets_cap: [{ data: 0, error: null }] });
    const { req, res } = mockReqRes();

    await handler(req, res);

    const body = res._getJSONData() as {
      subscription: null;
      usage: { teamMembers: null; freeScans: { count: number; allowed: number } | null };
    };
    expect(body.subscription).toBeNull();
    expect(body.usage.teamMembers).toBeNull();
    expect(body.usage.freeScans).toEqual({ count: 1, allowed: 1 });
  });

  it("never reports free-tier usage for an admin account, even with no subscription", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({
      users: [{ data: { id: "owner-1", email: "admin@example.com", company_name: null, is_admin: true, created_at: "2026-01-01" }, error: null }],
      subscriptions: [{ data: null, error: null }],
      scans: [{ data: [], error: null }, { count: 0, error: null }, { count: 0, error: null }],
      monitored_targets: [{ count: 0, error: null }],
      teams: [{ data: null, error: null }],
    });
    mock.setRpcQueues({ monitored_targets_cap: [{ data: 0, error: null }] });
    const { req, res } = mockReqRes();

    await handler(req, res);

    const body = res._getJSONData() as { usage: { freeScans: null } };
    expect(body.usage.freeScans).toBeNull();
  });
});
