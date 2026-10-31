import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks, type RequestMethod } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock, checkRateLimitMock, logAuditEventMock, recordLoginMock, isDomainVerifiedMock } = vi.hoisted(() => ({
  isDomainVerifiedMock: vi.fn(),
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
vi.mock("@/lib/ownership", () => ({ isDomainVerified: isDomainVerifiedMock }));
vi.mock("@/lib/scanners/loginRecorder", () => ({ recordLogin: recordLoginMock, playwrightLoginRun: vi.fn() }));

import handler from "@/pages/api/account/record-login";
import { decryptSecret, isEncryptedSecret, sealSecrets } from "@/lib/credentialEncryption";

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
    isDomainVerifiedMock.mockReset().mockResolvedValue(true);
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

  describe("TOTP secret", () => {
    const SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    function agencyTarget() {
      queues.monitored_targets = [{ data: { id: TARGET_ID, owner: OWNER_ID, target_url: "https://app.example.com" }, error: null }];
      queues.subscriptions = [{ data: { plan: "agency", status: "active" }, error: null }];
    }

    it("400s an invalid secret before running the browser, without echoing it", async () => {
      agencyTarget();
      const { req, res } = mockReqRes("POST", validBody({ totpSecret: "bad secret!" }));
      await handler(req, res);
      expect(res._getStatusCode()).toBe(400);
      expect(res._getData()).not.toContain("bad secret!");
      expect(recordLoginMock).not.toHaveBeenCalled();
    });

    it("403s when the domain is not verified, before running the browser", async () => {
      agencyTarget();
      isDomainVerifiedMock.mockResolvedValue(false);
      const { req, res } = mockReqRes("POST", validBody({ totpSecret: SECRET }));
      await handler(req, res);
      expect(res._getStatusCode()).toBe(403);
      expect(recordLoginMock).not.toHaveBeenCalled();
      expect(upserts).toHaveLength(0);
    });

    it("passes the secret to the recorder, stores it encrypted, and never returns or audits it", async () => {
      agencyTarget();
      queues.target_auth_credentials = [{ data: null, error: null }];
      recordLoginMock.mockResolvedValue({ status: "recorded", cookieValue: "session=abc123" });
      const { req, res } = mockReqRes("POST", validBody({ totpSecret: SECRET }));
      await handler(req, res);
      expect(res._getStatusCode()).toBe(200);
      expect(recordLoginMock.mock.calls[0][0]).toMatchObject({ totpSecret: SECRET });
      expect(isEncryptedSecret(upserts[0].totp_secret)).toBe(true);
      expect(JSON.stringify(upserts[0].totp_secret)).not.toContain(SECRET);
      expect(decryptSecret(upserts[0].totp_secret as string)).toBe(SECRET);
      expect(res._getData()).not.toContain(SECRET);
      expect(JSON.stringify(logAuditEventMock.mock.calls)).not.toContain(SECRET);
    });

    it("422s a failed MFA login without saving or leaking the secret", async () => {
      agencyTarget();
      recordLoginMock.mockResolvedValue({ status: "error", note: "The MFA step did not complete." });
      const { req, res } = mockReqRes("POST", validBody({ totpSecret: SECRET }));
      await handler(req, res);
      expect(res._getStatusCode()).toBe(422);
      expect(res._getData()).not.toContain(SECRET);
      expect(upserts).toHaveLength(0);
      expect(JSON.stringify(logAuditEventMock.mock.calls)).not.toContain(SECRET);
    });

    it("reuses a stored secret when none is supplied", async () => {
      agencyTarget();
      const sealed = sealSecrets({ totp_secret: SECRET }, ["totp_secret"]);
      queues.target_auth_credentials = [{ data: { totp_secret: sealed.totp_secret }, error: null }];
      recordLoginMock.mockResolvedValue({ status: "recorded", cookieValue: "session=abc123" });
      const { req, res } = mockReqRes("POST", validBody());
      await handler(req, res);
      expect(res._getStatusCode()).toBe(200);
      expect(recordLoginMock.mock.calls[0][0]).toMatchObject({ totpSecret: SECRET });
    });

    it("500s, not a silent no-MFA attempt, when the stored secret cannot be decrypted", async () => {
      agencyTarget();
      const sealed = sealSecrets({ totp_secret: SECRET }, ["totp_secret"]);
      queues.target_auth_credentials = [{ data: { totp_secret: sealed.totp_secret }, error: null }];
      process.env.CREDENTIALS_ENC_KEY = Buffer.alloc(32, 9).toString("base64");
      const { req, res } = mockReqRes("POST", validBody());
      await handler(req, res);
      expect(res._getStatusCode()).toBe(500);
      expect(recordLoginMock).not.toHaveBeenCalled();
    });
  });
});
