import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks, type RequestMethod } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock, checkRateLimitMock, logAuditEventMock, recordLoginMock } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  checkRateLimitMock: vi.fn(),
  logAuditEventMock: vi.fn(),
  recordLoginMock: vi.fn(),
}));

// 32 bytes, base64 — a throwaway test key, not a real secret.
const TEST_KEY = Buffer.alloc(32, 7).toString("base64");
let upserts: Array<Record<string, unknown>> = [];

type QueueMap = Record<string, unknown[]>;
let queues: QueueMap = {};

function makeBuilder(table: string) {
  const next = () => Promise.resolve(queues[table]?.shift() ?? { data: null, error: null });
  const builder: Record<string, unknown> = {
    select: () => builder,
    eq: () => builder,
    upsert: (row: Record<string, unknown>) => {
      upserts.push(row);
      return next();
    },
    maybeSingle: next,
  };
  return builder;
}

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: { from: (table: string) => makeBuilder(table) },
}));
vi.mock("@/lib/rateLimit", () => ({ checkRateLimit: checkRateLimitMock }));
vi.mock("@/lib/audit", () => ({ logAuditEvent: logAuditEventMock }));
vi.mock("@/lib/scanners/loginRecorder", () => ({ recordLogin: recordLoginMock, playwrightLoginRun: vi.fn() }));

import handler from "@/pages/api/account/record-login";
import { decryptSecret, isEncryptedSecret } from "@/lib/credentialEncryption";

const TARGET_ID = "11111111-1111-1111-1111-111111111111";
const OWNER_ID = "22222222-2222-2222-2222-222222222222";

function mockReqRes(method: RequestMethod, body: Record<string, unknown> = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({ method, body });
}

function validBody(over: Record<string, unknown> = {}) {
  return {
    monitoredTargetId: TARGET_ID,
    loginUrl: "https://app.example.com/login",
    username: "test-account",
    password: "s3cret",
    acknowledged: true,
    ...over,
  };
}

describe("POST /api/account/record-login", () => {
  beforeEach(() => {
    process.env.CREDENTIALS_ENC_KEY = TEST_KEY;
    upserts = [];
    queues = {};
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: OWNER_ID, via: "session" });
    checkRateLimitMock.mockReset().mockResolvedValue({ allowed: true });
    logAuditEventMock.mockReset().mockResolvedValue(undefined);
    recordLoginMock.mockReset();
  });

  it("rejects non-POST methods with 405", async () => {
    const { req, res } = mockReqRes("GET");
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });

  it("returns 401 when the caller is not authenticated", async () => {
    authenticateApiRequestMock.mockResolvedValue(null);
    const { req, res } = mockReqRes("POST", validBody());
    await handler(req, res);
    expect(res._getStatusCode()).toBe(401);
  });

  it("rejects an API-key caller — this credential is too sensitive to be scriptable", async () => {
    authenticateApiRequestMock.mockResolvedValue({ ownerId: OWNER_ID, via: "api_key" });
    const { req, res } = mockReqRes("POST", validBody());
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("rejects a request without acknowledged: true, before touching the database", async () => {
    const { req, res } = mockReqRes("POST", validBody({ acknowledged: false }));
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
    expect(recordLoginMock).not.toHaveBeenCalled();
  });

  it("returns 404 for a missing target and 403 for someone else's", async () => {
    queues.monitored_targets = [{ data: null, error: null }];
    let { req, res } = mockReqRes("POST", validBody());
    await handler(req, res);
    expect(res._getStatusCode()).toBe(404);

    queues.monitored_targets = [{ data: { id: TARGET_ID, owner: "someone-else", target_url: "https://app.example.com" }, error: null }];
    ({ req, res } = mockReqRes("POST", validBody()));
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("rejects a non-Agency plan with 403, before running the browser", async () => {
    queues.monitored_targets = [{ data: { id: TARGET_ID, owner: OWNER_ID, target_url: "https://app.example.com" }, error: null }];
    queues.subscriptions = [{ data: { plan: "pro", status: "active" }, error: null }];
    const { req, res } = mockReqRes("POST", validBody());
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
    expect(recordLoginMock).not.toHaveBeenCalled();
  });

  it("rejects a loginUrl on a different host than the monitored target", async () => {
    queues.monitored_targets = [{ data: { id: TARGET_ID, owner: OWNER_ID, target_url: "https://app.example.com" }, error: null }];
    queues.subscriptions = [{ data: { plan: "agency", status: "active" }, error: null }];
    const { req, res } = mockReqRes("POST", validBody({ loginUrl: "https://evil.example.net/login" }));
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
    expect(recordLoginMock).not.toHaveBeenCalled();
  });

  it("allows a subdomain of the monitored target's host", async () => {
    queues.monitored_targets = [{ data: { id: TARGET_ID, owner: OWNER_ID, target_url: "https://example.com" }, error: null }];
    queues.subscriptions = [{ data: { plan: "agency", status: "active" }, error: null }];
    queues.target_auth_credentials = [{ data: null, error: null }];
    recordLoginMock.mockResolvedValue({ status: "recorded", cookieValue: "session=abc" });
    const { req, res } = mockReqRes("POST", validBody({ loginUrl: "https://app.example.com/login" }));
    await handler(req, res);
    expect(res._getStatusCode()).toBe(200);
  });

  it("returns 429 when rate limited, before running the browser", async () => {
    queues.monitored_targets = [{ data: { id: TARGET_ID, owner: OWNER_ID, target_url: "https://app.example.com" }, error: null }];
    queues.subscriptions = [{ data: { plan: "agency", status: "active" }, error: null }];
    checkRateLimitMock.mockResolvedValue({ allowed: false, retryAfterSeconds: 60 });
    const { req, res } = mockReqRes("POST", validBody());
    await handler(req, res);
    expect(res._getStatusCode()).toBe(429);
    expect(recordLoginMock).not.toHaveBeenCalled();
  });

  it("422s and audits a failed login without saving anything or echoing the password", async () => {
    queues.monitored_targets = [{ data: { id: TARGET_ID, owner: OWNER_ID, target_url: "https://app.example.com" }, error: null }];
    queues.subscriptions = [{ data: { plan: "agency", status: "active" }, error: null }];
    recordLoginMock.mockResolvedValue({ status: "error", note: "Login did not appear to succeed." });
    const { req, res } = mockReqRes("POST", validBody());
    await handler(req, res);
    expect(res._getStatusCode()).toBe(422);
    expect(res._getData()).not.toContain("s3cret");
    expect(logAuditEventMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ action: "login_recorder.failed" }));
    const auditCall = logAuditEventMock.mock.calls[0][1] as { metadata?: Record<string, unknown> };
    expect(JSON.stringify(auditCall)).not.toContain("s3cret");
  });

  it("saves the recorded cookie on success and audits it", async () => {
    queues.monitored_targets = [{ data: { id: TARGET_ID, owner: OWNER_ID, target_url: "https://app.example.com" }, error: null }];
    queues.subscriptions = [{ data: { plan: "agency", status: "active" }, error: null }];
    queues.target_auth_credentials = [{ data: null, error: null }];
    recordLoginMock.mockResolvedValue({ status: "recorded", cookieValue: "session=abc123" });
    const { req, res } = mockReqRes("POST", validBody());
    await handler(req, res);
    expect(res._getStatusCode()).toBe(200);
    expect(logAuditEventMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ action: "login_recorder.succeeded" }));
    // The session cookie is stored encrypted, and decrypts back to what was recorded.
    expect(upserts).toHaveLength(1);
    expect(isEncryptedSecret(upserts[0].cookie_value)).toBe(true);
    expect(upserts[0].cookie_value).not.toContain("abc123");
    expect(decryptSecret(upserts[0].cookie_value as string)).toBe("session=abc123");
  });

  it("503s without running the browser when no encryption key is configured", async () => {
    delete process.env.CREDENTIALS_ENC_KEY;
    queues.monitored_targets = [{ data: { id: TARGET_ID, owner: OWNER_ID, target_url: "https://app.example.com" }, error: null }];
    queues.subscriptions = [{ data: { plan: "agency", status: "active" }, error: null }];
    const { req, res } = mockReqRes("POST", validBody());
    await handler(req, res);
    expect(res._getStatusCode()).toBe(503);
    expect(recordLoginMock).not.toHaveBeenCalled();
    expect(upserts).toHaveLength(0);
  });
});
