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
  supabaseAdmin: { from: (table: string) => mock.supabaseAdmin.from(table), rpc: (fn: string) => mock.supabaseAdmin.rpc(fn) },
}));

vi.mock("@/lib/audit", () => ({ logAuditEvent: logAuditEventMock }));

import handler from "@/pages/api/admin/queue";

function mockReqRes(overrides: Partial<Parameters<typeof createMocks>[0]> = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({ method: "GET", headers: { authorization: "Bearer t" }, ...overrides });
}

describe("GET /api/admin/queue", () => {
  beforeEach(() => {
    mock.reset();
    requireAdminMock.mockReset();
    logAuditEventMock.mockReset().mockResolvedValue(undefined);
  });

  it("rejects other methods with 405", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    const { req, res } = mockReqRes({ method: "DELETE" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });

  it("returns 403 before checking the method when the caller is not an admin", async () => {
    requireAdminMock.mockResolvedValue(null);
    const { req, res } = mockReqRes({ method: "DELETE" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("returns 403 when the caller is not an admin", async () => {
    requireAdminMock.mockResolvedValue(null);
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("buckets recent jobs by status and reports counts", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    // countByStatus() is called 4 times against "scan_jobs" (pending/running/
    // completed/failed), then one more .from("scan_jobs") call for the
    // recent-jobs list — 5 queue entries total, in that order.
    mock.setQueues({
      scan_jobs: [
        { count: 2 }, // pending
        { count: 1 }, // running
        { count: 10 }, // completed
        { count: 3 }, // failed
        {
          data: [
            { id: "j1", scan_id: "s1", target_url: "https://a.com", status: "running", created_at: "2026-01-01T00:00:00Z", claimed_at: "2026-01-01T00:01:00Z" },
            { id: "j2", scan_id: "s2", target_url: "https://b.com", status: "pending", created_at: "2026-01-01T00:02:00Z", claimed_at: null },
            { id: "j3", scan_id: "s3", target_url: "https://c.com", status: "failed", created_at: "2026-01-01T00:03:00Z", claimed_at: "2026-01-01T00:04:00Z" },
          ],
        },
      ],
    });
    const { req, res } = mockReqRes();

    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    const body = res._getJSONData() as {
      stats: Record<string, number>;
      jobs: Record<string, Array<{ id: string; startedAt: number | null; progress: number }>>;
    };
    expect(body.stats).toEqual({ waiting: 2, active: 1, completed: 10, failed: 3, delayed: 0 });
    expect(body.jobs.active.map((j) => j.id)).toEqual(["j1"]);
    expect(body.jobs.waiting.map((j) => j.id)).toEqual(["j2"]);
    expect(body.jobs.failed.map((j) => j.id)).toEqual(["j3"]);
    expect(body.jobs.active[0].startedAt).not.toBeNull();
    expect(body.jobs.waiting[0].startedAt).toBeNull();
    expect(body.jobs.failed[0].progress).toBe(100);
  });

  it("treats a null count as zero for every status bucket", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    mock.setQueues({
      scan_jobs: [{ count: null }, { count: null }, { count: null }, { count: null }, { data: [] }],
    });
    const { req, res } = mockReqRes();

    await handler(req, res);

    expect((res._getJSONData() as { stats: Record<string, number> }).stats).toEqual({
      waiting: 0,
      active: 0,
      completed: 0,
      failed: 0,
      delayed: 0,
    });
  });

  describe("PATCH — recover stuck jobs", () => {
    it("returns 500 when the RPC errors", async () => {
      requireAdminMock.mockResolvedValue("admin-1");
      mock.setRpcQueues({ reset_stale_scan_jobs: [{ data: null, error: { message: "db down" } }] });
      const { req, res } = mockReqRes({ method: "PATCH" });
      await handler(req, res);
      expect(res._getStatusCode()).toBe(500);
    });

    it("recovers stale jobs and logs an audit event with the count", async () => {
      requireAdminMock.mockResolvedValue("admin-1");
      mock.setRpcQueues({ reset_stale_scan_jobs: [{ data: 3, error: null }] });
      const { req, res } = mockReqRes({ method: "PATCH" });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
      expect(res._getJSONData()).toEqual({ ok: true, resetCount: 3 });
      expect(logAuditEventMock).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ actorId: "admin-1", action: "admin.stale_jobs_recovered", metadata: { count: 3 } })
      );
    });

    it("reports zero when nothing was stuck", async () => {
      requireAdminMock.mockResolvedValue("admin-1");
      mock.setRpcQueues({ reset_stale_scan_jobs: [{ data: 0, error: null }] });
      const { req, res } = mockReqRes({ method: "PATCH" });

      await handler(req, res);

      expect(res._getJSONData()).toEqual({ ok: true, resetCount: 0 });
    });
  });
});
