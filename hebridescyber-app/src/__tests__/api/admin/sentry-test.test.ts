import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { requireAdminMock, logAuditEventMock, getClientMock, captureExceptionMock, flushMock } = vi.hoisted(() => ({
  requireAdminMock: vi.fn(),
  logAuditEventMock: vi.fn(),
  getClientMock: vi.fn(),
  captureExceptionMock: vi.fn(),
  flushMock: vi.fn(),
}));

vi.mock("@/lib/adminAuth", () => ({ requireAdmin: requireAdminMock, supabaseAdmin: {} }));
vi.mock("@/lib/audit", () => ({ logAuditEvent: logAuditEventMock }));
vi.mock("@sentry/nextjs", () => ({
  getClient: getClientMock,
  captureException: captureExceptionMock,
  flush: flushMock,
}));

import handler from "@/pages/api/admin/sentry-test";

function mockReqRes(method: "GET" | "POST" = "POST") {
  return createMocks<NextApiRequest, NextApiResponse>({ method, headers: { authorization: "Bearer t" } });
}

describe("POST /api/admin/sentry-test", () => {
  beforeEach(() => {
    requireAdminMock.mockReset();
    logAuditEventMock.mockReset();
    getClientMock.mockReset();
    captureExceptionMock.mockReset();
    flushMock.mockReset();
  });

  it("rejects non-POST with 405", async () => {
    const { req, res } = mockReqRes("GET");
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
    expect(requireAdminMock).not.toHaveBeenCalled();
  });

  it("returns 403 when not an admin, and sends nothing", async () => {
    requireAdminMock.mockResolvedValue(null);
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
    expect(captureExceptionMock).not.toHaveBeenCalled();
  });

  it("says not configured, rather than claiming a send, when no DSN is set", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    getClientMock.mockReturnValue({ getDsn: () => undefined });
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(200);
    expect(res._getJSONData()).toEqual({ configured: false, eventId: null, delivered: false });
    expect(captureExceptionMock).not.toHaveBeenCalled();
  });

  it("treats a missing client as not configured", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    getClientMock.mockReturnValue(undefined);
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getJSONData().configured).toBe(false);
  });

  it("captures a tagged test error, flushes, audits and returns the event id", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    getClientMock.mockReturnValue({ getDsn: () => ({ host: "o1.ingest.sentry.io" }) });
    captureExceptionMock.mockReturnValue("evt-123");
    flushMock.mockResolvedValue(true);
    const { req, res } = mockReqRes();
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(res._getJSONData()).toEqual({ configured: true, eventId: "evt-123", delivered: true });
    const [error, context] = captureExceptionMock.mock.calls[0];
    expect(error).toBeInstanceOf(Error);
    expect(context.tags).toEqual({ sentry_test: "true" });
    expect(logAuditEventMock).toHaveBeenCalledWith(
      {},
      expect.objectContaining({ actorId: "admin-1", action: "admin.sentry_test_sent", metadata: { eventId: "evt-123", delivered: true } }),
    );
  });

  it("reports delivered:false when the flush times out", async () => {
    requireAdminMock.mockResolvedValue("admin-1");
    getClientMock.mockReturnValue({ getDsn: () => ({ host: "x" }) });
    captureExceptionMock.mockReturnValue("evt-9");
    flushMock.mockResolvedValue(false);
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getJSONData()).toEqual({ configured: true, eventId: "evt-9", delivered: false });
  });
});
