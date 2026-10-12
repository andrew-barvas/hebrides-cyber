import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";
import { makeAdminSupabaseMock } from "./_supabaseQueueMock";

const { requireAdminMock, logAuditEventMock } = vi.hoisted(() => ({
  requireAdminMock: vi.fn(),
  logAuditEventMock: vi.fn(),
}));
const mock = makeAdminSupabaseMock();

vi.mock("@/lib/adminAuth", () => ({
  requireAdmin: requireAdminMock,
  supabaseAdmin: { from: (table: string) => mock.supabaseAdmin.from(table) },
}));

vi.mock("@/lib/audit", () => ({ logAuditEvent: logAuditEventMock }));

import handler from "@/pages/api/admin/subscription";

function mockReqRes(overrides: Partial<Parameters<typeof createMocks>[0]> = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({ method: "PATCH", headers: { authorization: "Bearer t" }, ...overrides });
}

describe("/api/admin/subscription", () => {
  beforeEach(() => {
    mock.reset();
    requireAdminMock.mockReset();
    logAuditEventMock.mockReset().mockResolvedValue(undefined);
  });

  it("returns 403 when the caller is not an admin", async () => {
    requireAdminMock.mockResolvedValue(null);
    const { req, res } = mockReqRes({ body: { ownerId: "11111111-1111-4111-8111-111111111111", plan: "pro", status: "active", reason: "pilot" } });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("rejects other methods with 405", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    const { req, res } = mockReqRes({ method: "GET" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });

  it("returns 400 when the body fails validation", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    const { req, res } = mockReqRes({ body: { ownerId: "not-a-uuid", plan: "pro", status: "active", reason: "pilot" } });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
  });

  it("returns 400 when reason is blank", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    const { req, res } = mockReqRes({ body: { ownerId: "11111111-1111-4111-8111-111111111111", plan: "pro", status: "active", reason: "   " } });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
  });

  it("returns 404 when the owner does not exist", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({ users: [{ data: null, error: null }] });
    const { req, res } = mockReqRes({ body: { ownerId: "11111111-1111-4111-8111-111111111111", plan: "pro", status: "active", reason: "pilot" } });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(404);
  });

  it("returns 500 when the owner lookup errors", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({ users: [{ data: null, error: { message: "db down" } }] });
    const { req, res } = mockReqRes({ body: { ownerId: "11111111-1111-4111-8111-111111111111", plan: "pro", status: "active", reason: "pilot" } });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(500);
  });

  it("returns 500 when the upsert errors", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({
      users: [{ data: { id: "11111111-1111-4111-8111-111111111111" }, error: null }],
      subscriptions: [{ data: null, error: { message: "constraint violation" } }],
    });
    const { req, res } = mockReqRes({ body: { ownerId: "11111111-1111-4111-8111-111111111111", plan: "pro", status: "active", reason: "pilot" } });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(500);
  });

  it("upserts the subscription tagged source=admin and logs an audit event", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({
      users: [{ data: { id: "11111111-1111-4111-8111-111111111111" }, error: null }],
      subscriptions: [{ error: null }],
    });
    const { req, res } = mockReqRes({
      body: { ownerId: "11111111-1111-4111-8111-111111111111", plan: "agency", status: "active", reason: "support pilot" },
    });

    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(mock.upserted).toEqual([
      {
        table: "subscriptions",
        payload: expect.objectContaining({
          owner: "11111111-1111-4111-8111-111111111111",
          plan: "agency",
          status: "active",
          source: "admin",
          granted_by: "admin-1",
          grant_reason: "support pilot",
        }),
        opts: { onConflict: "owner" },
      },
    ]);
    expect(logAuditEventMock).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({
        actorId: "admin-1",
        action: "admin.subscription_overridden",
        resourceType: "subscription",
        resourceId: "11111111-1111-4111-8111-111111111111",
        metadata: { plan: "agency", status: "active", reason: "support pilot" },
      })
    );
  });
});
