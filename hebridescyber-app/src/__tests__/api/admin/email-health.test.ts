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

import handler from "@/pages/api/admin/email-health";

function mockReqRes(method: "GET" | "POST" = "GET") {
  return createMocks<NextApiRequest, NextApiResponse>({ method, headers: { authorization: "Bearer t" } });
}

describe("GET /api/admin/email-health", () => {
  beforeEach(() => {
    mock.reset();
    requireAdminMock.mockReset();
  });

  it("rejects non-GET with 405", async () => {
    const { req, res } = mockReqRes("POST");
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });

  it("returns 403 when not an admin", async () => {
    requireAdminMock.mockResolvedValue(null);
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("returns 500 when the query errors", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({ email_events: [{ data: null, error: { message: "db down" } }] });
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(500);
  });

  it("summarises recent send outcomes into counts and a failure rate", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    const at = new Date().toISOString();
    mock.setQueues({
      email_events: [
        {
          data: [
            { status: "sent", subject: "a", recipient_domain: "acme.com", error: null, created_at: at },
            { status: "failed", subject: "b", recipient_domain: "acme.com", error: "550 blocked", created_at: at },
          ],
          error: null,
        },
      ],
    });
    const { req, res } = mockReqRes();
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    const body = res._getJSONData() as { total: number; sent: number; failed: number; failureRatePct: number; recentFailures: unknown[] };
    expect(body).toMatchObject({ total: 2, sent: 1, failed: 1, failureRatePct: 50 });
    expect(body.recentFailures).toHaveLength(1);
  });

  it("reports a null failure rate when there are no events", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({ email_events: [{ data: [], error: null }] });
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect((res._getJSONData() as { failureRatePct: number | null }).failureRatePct).toBeNull();
  });
});
