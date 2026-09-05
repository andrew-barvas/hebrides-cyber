import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock, verifyDomainMock, logAuditEventMock, checkRateLimitMock } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  verifyDomainMock: vi.fn(),
  logAuditEventMock: vi.fn(),
  checkRateLimitMock: vi.fn(),
}));

// E-12 (docs/ENHANCEMENTS.md): this route is now rate-limited. Mocked so
// this suite's many test cases — all keyed to the same owner — don't
// accumulate against one shared in-process bucket and start failing each
// other with 429s.
vi.mock("@/lib/rateLimit", () => ({ checkRateLimit: checkRateLimitMock }));

// Call-order-consumed queue per table, same pattern as run-scan.test.ts /
// stripe/webhook.test.ts.
type QueueMap = Record<string, unknown[]>;
let queues: QueueMap = {};
const inserted: Array<{ table: string; payload: unknown }> = [];
const updated: Array<{ table: string; payload: unknown }> = [];

function makeBuilder(table: string) {
  const next = () => Promise.resolve(queues[table]?.shift() ?? { data: null, error: null });
  const builder: Record<string, unknown> = {
    select: () => builder,
    eq: () => builder,
    insert: (payload: unknown) => {
      inserted.push({ table, payload });
      return builder;
    },
    update: (payload: unknown) => {
      updated.push({ table, payload });
      return builder;
    },
    maybeSingle: next,
    then: (resolve: (v: unknown) => void) => next().then(resolve),
  };
  return builder;
}

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: { from: (table: string) => makeBuilder(table) },
}));

vi.mock("@/lib/ownership", async (importOriginal) => {
  // ownership.ts is a plain user module (not a Node built-in), so
  // importOriginal works fine here — only real hostnameFromUrl/constants
  // are reused; verifyDomain (the one that would do a real network/DNS
  // check) is replaced.
  const actual = await importOriginal<typeof import("@/lib/ownership")>();
  return { ...actual, verifyDomain: verifyDomainMock };
});

vi.mock("@/lib/audit", () => ({ logAuditEvent: logAuditEventMock }));

import handler from "@/pages/api/verify-ownership";

function mockReqRes(body: Record<string, unknown>) {
  return createMocks<NextApiRequest, NextApiResponse>({ method: "POST", body });
}

describe("POST /api/verify-ownership", () => {
  beforeEach(() => {
    queues = {};
    inserted.length = 0;
    updated.length = 0;
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: "owner-1", via: "session" });
    checkRateLimitMock.mockReset().mockResolvedValue({ allowed: true, retryAfterSeconds: 0 });
    verifyDomainMock.mockReset();
    logAuditEventMock.mockReset().mockResolvedValue(undefined);
  });

  it("rejects non-POST methods with 405", async () => {
    const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "GET" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });

  it("returns 401 when not authenticated", async () => {
    authenticateApiRequestMock.mockResolvedValue(null);
    const { req, res } = mockReqRes({ targetUrl: "https://example.com" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(401);
  });

  it("returns 429 when the caller is rate-limited, before any DNS/HTTP check", async () => {
    checkRateLimitMock.mockResolvedValue({ allowed: false, retryAfterSeconds: 17 });
    const { req, res } = mockReqRes({ targetUrl: "https://example.com" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(429);
    expect(res._getHeaders()["retry-after"]).toBe("17");
    expect(verifyDomainMock).not.toHaveBeenCalled();
  });

  it("returns 403 for an API-key caller (session-only route)", async () => {
    authenticateApiRequestMock.mockResolvedValue({ ownerId: "owner-1", via: "key" });
    const { req, res } = mockReqRes({ targetUrl: "https://example.com" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("returns 400 when targetUrl is missing", async () => {
    const { req, res } = mockReqRes({});
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
  });

  it("returns 400 when targetUrl is not a valid URL", async () => {
    const { req, res } = mockReqRes({ targetUrl: "not a url" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
  });

  describe("action: start (default)", () => {
    it("creates a new verification token when none exists yet", async () => {
      queues.verifications = [{ data: null, error: null }, { error: null }]; // fetch existing -> insert
      const { req, res } = mockReqRes({ targetUrl: "https://example.com" });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
      const body = res._getJSONData() as { domain: string; token: string; verified: boolean; dnsRecord: { name: string; value: string } };
      expect(body.domain).toBe("example.com");
      expect(body.verified).toBe(false);
      expect(body.token).toMatch(/^[0-9a-f]{32}$/);
      expect(body.dnsRecord.name).toBe("example.com");
      expect(inserted).toHaveLength(1);
      expect(inserted[0].table).toBe("verifications");
    });

    it("returns the existing token without inserting a duplicate row", async () => {
      queues.verifications = [{ data: { token: "existing-token-abc", verified_at: null }, error: null }];
      const { req, res } = mockReqRes({ targetUrl: "https://example.com" });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
      expect((res._getJSONData() as { token: string }).token).toBe("existing-token-abc");
      expect(inserted).toHaveLength(0);
    });

    it("reports verified:true when the domain was already verified previously", async () => {
      queues.verifications = [{ data: { token: "tok", verified_at: "2026-01-01T00:00:00Z" }, error: null }];
      const { req, res } = mockReqRes({ targetUrl: "https://example.com" });

      await handler(req, res);

      expect((res._getJSONData() as { verified: boolean }).verified).toBe(true);
    });

    it("returns 500 when the insert fails", async () => {
      queues.verifications = [{ data: null, error: null }, { error: { message: "db down" } }];
      const { req, res } = mockReqRes({ targetUrl: "https://example.com" });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(500);
    });
  });

  describe("action: check", () => {
    it("returns 404 when there is no pending verification for the domain", async () => {
      queues.verifications = [{ data: null, error: null }];
      const { req, res } = mockReqRes({ action: "check", targetUrl: "https://example.com" });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(404);
    });

    it("short-circuits to verified:true, alreadyVerified:true, without re-checking DNS", async () => {
      queues.verifications = [{ data: { id: "v1", token: "tok", verified_at: "2026-01-01T00:00:00Z" }, error: null }];
      const { req, res } = mockReqRes({ action: "check", targetUrl: "https://example.com" });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
      expect(res._getJSONData()).toEqual({ verified: true, alreadyVerified: true });
      expect(verifyDomainMock).not.toHaveBeenCalled();
    });

    it("marks the verification verified and logs a success audit event on a real successful check", async () => {
      queues.verifications = [{ data: { id: "v1", token: "tok", verified_at: null }, error: null }];
      verifyDomainMock.mockResolvedValue({ verified: true, method: "dns" });
      const { req, res } = mockReqRes({ action: "check", targetUrl: "https://example.com" });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
      expect(res._getJSONData()).toEqual({ verified: true, method: "dns" });
      expect(updated).toHaveLength(1);
      expect(updated[0].payload).toMatchObject({ method: "dns" });
      expect(logAuditEventMock).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ action: "domain_verification.succeeded" })
      );
    });

    it("does not update the row and logs a failure audit event when verification fails", async () => {
      queues.verifications = [{ data: { id: "v1", token: "tok", verified_at: null }, error: null }];
      verifyDomainMock.mockResolvedValue({ verified: false, method: null });
      const { req, res } = mockReqRes({ action: "check", targetUrl: "https://example.com" });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
      expect(res._getJSONData()).toEqual({ verified: false, method: null });
      expect(updated).toHaveLength(0);
      expect(logAuditEventMock).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ action: "domain_verification.failed" })
      );
    });
  });
});
