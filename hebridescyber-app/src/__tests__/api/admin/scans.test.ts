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

import handler from "@/pages/api/admin/scans";

function mockReqRes(overrides: Partial<Parameters<typeof createMocks>[0]> = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({ method: "GET", headers: { authorization: "Bearer t" }, ...overrides });
}

describe("/api/admin/scans", () => {
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

  describe("GET", () => {
    it("returns 500 when the scans query errors", async () => {
      requireAdminMock.mockResolvedValue("admin-1");
      mock.setQueues({ scans: [{ data: null, error: { message: "db down" } }] });
      const { req, res } = mockReqRes();
      await handler(req, res);
      expect(res._getStatusCode()).toBe(500);
    });

    it("enriches scans with owner email/company and flattens the joined scan_results", async () => {
      requireAdminMock.mockResolvedValue("admin-1");
      mock.setQueues({
        scans: [
          {
            data: [
              {
                id: "s1",
                owner: "u1",
                target_url: "https://example.com",
                status: "completed",
                created_at: "2026-01-01",
                owner_verified: true,
                job_id: "j1",
                scan_results: [{ score: 87, summary: { findingsCount: 3 } }],
              },
            ],
            error: null,
          },
        ],
        users: [{ data: [{ id: "u1", email: "a@example.com", company_name: "Acme" }] }],
      });
      const { req, res } = mockReqRes();

      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
      const body = res._getJSONData() as { scans: Array<Record<string, unknown>> };
      expect(body.scans[0]).toMatchObject({
        id: "s1",
        ownerEmail: "a@example.com",
        ownerCompany: "Acme",
        score: 87,
        summary: { findingsCount: 3 },
      });
    });

    it("falls back to the raw owner id when no matching user profile is found", async () => {
      requireAdminMock.mockResolvedValue("admin-1");
      mock.setQueues({
        scans: [{ data: [{ id: "s1", owner: "orphan-owner", target_url: "https://x.com", status: "failed", created_at: "2026-01-01", owner_verified: false, job_id: null, scan_results: [] }], error: null }],
        users: [{ data: [] }],
      });
      const { req, res } = mockReqRes();

      await handler(req, res);

      const body = res._getJSONData() as { scans: Array<{ ownerEmail: string; score: number | null }> };
      expect(body.scans[0].ownerEmail).toBe("orphan-owner");
      expect(body.scans[0].score).toBeNull();
    });
  });

  describe("PATCH", () => {
    it("returns 400 when scanId or action is missing", async () => {
      requireAdminMock.mockResolvedValue("admin-1");
      const { req, res } = mockReqRes({ method: "PATCH", body: { scanId: "s1" } });
      await handler(req, res);
      expect(res._getStatusCode()).toBe(400);
    });

    it("returns 400 for an unknown action", async () => {
      requireAdminMock.mockResolvedValue("admin-1");
      const { req, res } = mockReqRes({ method: "PATCH", body: { scanId: "s1", action: "explode" } });
      await handler(req, res);
      expect(res._getStatusCode()).toBe(400);
    });

    it("cancel: sets status failed and logs an audit event", async () => {
      requireAdminMock.mockResolvedValue("admin-1");
      const { req, res } = mockReqRes({ method: "PATCH", body: { scanId: "s1", action: "cancel" } });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
      expect(mock.updated).toEqual([{ table: "scans", payload: { status: "failed" } }]);
      expect(logAuditEventMock).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ action: "admin.scan_cancelled", resourceId: "s1", actorId: "admin-1" })
      );
    });

    it("retry: sets status pending and logs an audit event", async () => {
      requireAdminMock.mockResolvedValue("admin-1");
      const { req, res } = mockReqRes({ method: "PATCH", body: { scanId: "s1", action: "retry" } });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
      expect(mock.updated).toEqual([{ table: "scans", payload: { status: "queued" } }]);
      expect(logAuditEventMock).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ action: "admin.scan_retried" })
      );
    });
  });

  it("rejects other methods with 405", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    const { req, res } = mockReqRes({ method: "DELETE" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });
});
