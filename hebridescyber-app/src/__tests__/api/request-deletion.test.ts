import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock, logAuditEventMock, sendEmailMock } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  logAuditEventMock: vi.fn(),
  sendEmailMock: vi.fn(),
}));

type QueueMap = Record<string, unknown[]>;
let queues: QueueMap = {};

function makeBuilder(table: string) {
  const next = () => Promise.resolve(queues[table]?.shift() ?? { data: null, error: null });
  const builder: Record<string, unknown> = {
    select: () => builder,
    eq: () => builder,
    maybeSingle: next,
    then: (resolve: (v: unknown) => void) => next().then(resolve),
  };
  return builder;
}

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: { from: (table: string) => makeBuilder(table) },
}));

vi.mock("@/lib/audit", () => ({ logAuditEvent: logAuditEventMock }));

vi.mock("@/lib/email", () => ({
  sendEmail: sendEmailMock,
  escapeHtml: (s: string) => s,
}));

import handler from "@/pages/api/account/request-deletion";

const OWNER_ID = "33333333-3333-3333-3333-333333333333";

function mockReqRes(method: "GET" | "POST" = "POST") {
  return createMocks<NextApiRequest, NextApiResponse>({ method });
}

describe("POST /api/account/request-deletion", () => {
  beforeEach(() => {
    queues = {};
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: OWNER_ID, via: "session" });
    logAuditEventMock.mockReset().mockResolvedValue(undefined);
    sendEmailMock.mockReset().mockResolvedValue({ ok: true });
  });

  it("rejects non-POST methods with 405", async () => {
    const { req, res } = mockReqRes("GET");
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });

  it("rejects an unauthenticated caller with 401", async () => {
    authenticateApiRequestMock.mockResolvedValue(null);
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(401);
  });

  it("logs an audit event and notifies the owner on a valid request", async () => {
    queues.users = [{ data: { email: "jo@example.com", full_name: "Jo Smith" }, error: null }];

    const { req, res } = mockReqRes();
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(JSON.parse(res._getData())).toEqual({ ok: true });

    expect(logAuditEventMock).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({
        actorId: OWNER_ID,
        actorEmail: "jo@example.com",
        action: "account.deletion_requested",
        resourceType: "user",
        resourceId: OWNER_ID,
      })
    );

    expect(sendEmailMock).toHaveBeenCalledWith(
      expect.objectContaining({
        subject: expect.stringContaining("jo@example.com"),
      })
    );
  });

  it("still succeeds when the notification email fails to send", async () => {
    queues.users = [{ data: { email: "jo@example.com", full_name: null }, error: null }];
    sendEmailMock.mockResolvedValue({ ok: false, error: "Resend responded 500" });

    const { req, res } = mockReqRes();
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
  });

  it("still logs and responds ok even when the user profile lookup returns nothing", async () => {
    queues.users = [{ data: null, error: null }];

    const { req, res } = mockReqRes();
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(logAuditEventMock).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ actorEmail: null })
    );
  });
});
