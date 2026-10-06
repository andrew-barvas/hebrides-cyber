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
let inserts: { table: string; row: unknown }[] = [];

function makeBuilder(table: string) {
  const next = () => Promise.resolve(queues[table]?.shift() ?? { data: null, error: null });
  const builder: Record<string, unknown> = {
    select: () => builder,
    eq: () => builder,
    insert: (row: unknown) => {
      inserts.push({ table, row });
      return builder;
    },
    single: next,
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
    inserts = [];
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

  it("refuses an API-key caller: a key in a CI system must not be able to erase the account", async () => {
    authenticateApiRequestMock.mockResolvedValue({ ownerId: OWNER_ID, via: "key" });
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
    expect(inserts).toHaveLength(0);
    expect(sendEmailMock).not.toHaveBeenCalled();
  });

  it("records the request with its 30-day deadline, logs an audit event and notifies the operator", async () => {
    queues.deletion_requests = [
      { data: null, error: null }, // nothing pending yet
      { data: { requested_at: "2026-10-06T00:00:00Z", due_at: "2026-11-05T00:00:00Z" }, error: null },
    ];
    queues.users = [{ data: { email: "jo@example.com", full_name: "Jo Smith" }, error: null }];

    const { req, res } = mockReqRes();
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(JSON.parse(res._getData())).toEqual({ ok: true, requestedAt: "2026-10-06T00:00:00Z", dueAt: "2026-11-05T00:00:00Z", alreadyRequested: false });
    expect(inserts).toEqual([{ table: "deletion_requests", row: { owner: OWNER_ID } }]);
    expect(logAuditEventMock).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ actorId: OWNER_ID, actorEmail: "jo@example.com", action: "account.deletion_requested", resourceType: "user", resourceId: OWNER_ID })
    );
    const mail = sendEmailMock.mock.calls[0][0] as { subject: string; html: string };
    expect(mail.subject).toContain("jo@example.com");
    expect(mail.html).toContain("2026-11-05");
    // The suggested command takes the user id, which the erase script accepts.
    expect(mail.html).toContain(`npm run account:erase -- ${OWNER_ID}`);
  });

  it("returns the existing deadline for a repeat request, without a second email or audit row", async () => {
    queues.deletion_requests = [{ data: { requested_at: "2026-10-01T00:00:00Z", due_at: "2026-10-31T00:00:00Z" }, error: null }];

    const { req, res } = mockReqRes();
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(JSON.parse(res._getData())).toMatchObject({ dueAt: "2026-10-31T00:00:00Z", alreadyRequested: true });
    expect(inserts).toHaveLength(0);
    expect(sendEmailMock).not.toHaveBeenCalled();
    expect(logAuditEventMock).not.toHaveBeenCalled();
  });

  it("falls back to the audit row and email before migration 048", async () => {
    queues.deletion_requests = [{ data: null, error: { code: "PGRST205", message: "relation not found" } }];
    queues.users = [{ data: { email: "jo@example.com", full_name: null }, error: null }];

    const { req, res } = mockReqRes();
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(JSON.parse(res._getData())).toMatchObject({ ok: true, dueAt: null });
    expect(logAuditEventMock).toHaveBeenCalled();
    expect(sendEmailMock).toHaveBeenCalled();
  });

  it("answers 500, and tells no one it was received, when the request can't be recorded", async () => {
    queues.deletion_requests = [{ data: null, error: { code: "08006", message: "connection failure" } }];
    const log = vi.spyOn(console, "error").mockImplementation(() => undefined);

    const { req, res } = mockReqRes();
    await handler(req, res);

    expect(res._getStatusCode()).toBe(500);
    expect(logAuditEventMock).not.toHaveBeenCalled();
    expect(sendEmailMock).not.toHaveBeenCalled();
    log.mockRestore();
  });

  it("still succeeds when the notification email fails to send", async () => {
    queues.users = [{ data: { email: "jo@example.com", full_name: null }, error: null }];
    queues.deletion_requests = [{ data: null, error: null }, { data: { requested_at: "2026-10-06T00:00:00Z", due_at: "2026-11-05T00:00:00Z" }, error: null }];
    sendEmailMock.mockResolvedValue({ ok: false, error: "Resend responded 500" });
    const log = vi.spyOn(console, "error").mockImplementation(() => undefined);

    const { req, res } = mockReqRes();
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    log.mockRestore();
  });

  it("still logs and responds ok even when the user profile lookup returns nothing", async () => {
    queues.users = [{ data: null, error: null }];
    queues.deletion_requests = [{ data: null, error: null }, { data: { requested_at: "2026-10-06T00:00:00Z", due_at: "2026-11-05T00:00:00Z" }, error: null }];

    const { req, res } = mockReqRes();
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(logAuditEventMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ actorEmail: null }));
  });
});
