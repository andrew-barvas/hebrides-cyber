import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const {
  authenticateApiRequestMock,
  checkRateLimitMock,
  isFreeTierExhaustedMock,
  validateNoSsrfMock,
  isDomainVerifiedMock,
  triggerOnDemandWorkflowMock,
} = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  checkRateLimitMock: vi.fn(),
  isFreeTierExhaustedMock: vi.fn(),
  validateNoSsrfMock: vi.fn(),
  isDomainVerifiedMock: vi.fn(),
  triggerOnDemandWorkflowMock: vi.fn(),
}));

// Records every from()/insert()/update()/select()/eq() call and resolves
// each table's chain from a per-table queue, consumed in call order — lets
// one test configure "the first .from('scans') call returns X, the second
// returns Y" to match run-scan.ts's re-use of the same table across a
// fetch-then-update sequence within a single request.
type QueueMap = Record<string, unknown[]>;
let queues: QueueMap = {};

function makeBuilder(table: string) {
  const next = () => Promise.resolve(queues[table]?.shift() ?? { data: null, error: null });
  const builder: Record<string, unknown> = {
    select: () => builder,
    insert: () => builder,
    update: () => builder,
    eq: () => builder,
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

vi.mock("@/lib/rateLimit", () => ({ checkRateLimit: checkRateLimitMock }));

vi.mock("@/lib/freeTier", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/freeTier")>();
  return { ...actual, isFreeTierExhausted: isFreeTierExhaustedMock };
});

vi.mock("@/lib/ownership", () => ({
  validateNoSsrf: validateNoSsrfMock,
  isDomainVerified: isDomainVerifiedMock,
}));

vi.mock("@/lib/onDemandScanTrigger", () => ({ triggerOnDemandWorkflow: triggerOnDemandWorkflowMock }));

import handler from "@/pages/api/run-scan";
import { FREE_TIER_EXHAUSTED_MESSAGE } from "@/lib/freeTier";

function mockReqRes(body: Record<string, unknown> = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({ method: "POST", body });
}

describe("POST /api/run-scan", () => {
  beforeEach(() => {
    queues = {};
    authenticateApiRequestMock.mockReset();
    checkRateLimitMock.mockReset().mockResolvedValue({ allowed: true });
    isFreeTierExhaustedMock.mockReset().mockResolvedValue(false);
    validateNoSsrfMock.mockReset().mockResolvedValue(undefined);
    isDomainVerifiedMock.mockReset().mockResolvedValue(true);
    triggerOnDemandWorkflowMock.mockReset().mockResolvedValue(undefined);
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

  it("returns 403 for an API-key caller (session-only route)", async () => {
    authenticateApiRequestMock.mockResolvedValue({ ownerId: "owner-1", via: "key" });
    const { req, res } = mockReqRes({ targetUrl: "https://example.com" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("returns 429 with Retry-After when rate limited", async () => {
    authenticateApiRequestMock.mockResolvedValue({ ownerId: "owner-1", via: "session" });
    checkRateLimitMock.mockResolvedValue({ allowed: false, retryAfterSeconds: 42 });
    const { req, res } = mockReqRes({ targetUrl: "https://example.com" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(429);
    expect(res.getHeader("Retry-After")).toBe("42");
  });

  describe("step 1 — create a scan", () => {
    beforeEach(() => {
      authenticateApiRequestMock.mockResolvedValue({ ownerId: "owner-1", via: "session" });
    });

    it("returns 400 when targetUrl is missing", async () => {
      const { req, res } = mockReqRes({});
      await handler(req, res);
      expect(res._getStatusCode()).toBe(400);
    });

    it("returns 402 when the free tier is exhausted", async () => {
      isFreeTierExhaustedMock.mockResolvedValue(true);
      const { req, res } = mockReqRes({ targetUrl: "https://example.com" });
      await handler(req, res);
      expect(res._getStatusCode()).toBe(402);
      expect(res._getJSONData()).toEqual({ error: FREE_TIER_EXHAUSTED_MESSAGE, code: "free_tier_exhausted" });
    });

    it("returns 400 when the target fails SSRF validation", async () => {
      validateNoSsrfMock.mockRejectedValue(new Error("resolves to a private IP"));
      const { req, res } = mockReqRes({ targetUrl: "http://169.254.169.254/" });
      await handler(req, res);
      expect(res._getStatusCode()).toBe(400);
      expect((res._getJSONData() as { error: string }).error).toContain("resolves to a private IP");
    });

    it("returns 500 when the insert fails", async () => {
      queues.scans = [{ data: null, error: { message: "db down" } }];
      const { req, res } = mockReqRes({ targetUrl: "https://example.com" });
      await handler(req, res);
      expect(res._getStatusCode()).toBe(500);
    });

    it("creates the scan and returns a proof token on success", async () => {
      queues.scans = [{ data: { id: "new-scan-id" }, error: null }];
      const { req, res } = mockReqRes({ targetUrl: "https://example.com" });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
      const body = res._getJSONData() as { scanId: string; status: string; proofToken: string };
      expect(body.scanId).toBe("new-scan-id");
      expect(body.status).toBe("awaiting_verification");
      expect(body.proofToken).toMatch(/^[0-9a-f]{32}$/);
    });
  });

  describe("step 2 — verify and run", () => {
    beforeEach(() => {
      authenticateApiRequestMock.mockResolvedValue({ ownerId: "owner-1", via: "session" });
    });

    it("returns 404 when the scan does not exist", async () => {
      queues.scans = [{ data: null, error: null }];
      const { req, res } = mockReqRes({ scanId: "missing" });
      await handler(req, res);
      expect(res._getStatusCode()).toBe(404);
    });

    it("returns 403 when the caller does not own the scan", async () => {
      queues.scans = [{ data: { id: "scan-1", owner: "someone-else", target_url: "https://example.com", status: "pending" }, error: null }];
      const { req, res } = mockReqRes({ scanId: "scan-1" });
      await handler(req, res);
      expect(res._getStatusCode()).toBe(403);
    });

    // Regression test for a real production bug: the dashboard polls this
    // route with { scanId } every 4s for up to ~3 minutes while a scan is
    // running (see startScan() in src/app/dashboard/page.tsx) — up to 45
    // calls, all against a MAX_REQUESTS=10/hr limiter. When the rate-limit
    // check covered the whole handler, a scan's own status polling
    // exhausted the limit before the scan finished, and the user saw
    // "Rate limit exceeded" on a request that only asked "is it done yet."
    it("never rate-limits step 2 (status polling), even when the limiter would deny a new scan", async () => {
      checkRateLimitMock.mockResolvedValue({ allowed: false, retryAfterSeconds: 42 });
      queues.scans = [{ data: { id: "scan-1", owner: "owner-1", target_url: "https://example.com", status: "running" }, error: null }];
      const { req, res } = mockReqRes({ scanId: "scan-1" });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(202);
      expect(res._getStatusCode()).not.toBe(429);
    });

    it("replays a cached result for an already-completed scan without re-verifying or re-queuing", async () => {
      queues.scans = [{ data: { id: "scan-1", owner: "owner-1", target_url: "https://example.com", status: "completed" }, error: null }];
      queues.scan_results = [{ data: { score: 87, summary: { findingsCount: 3 } }, error: null }];
      const { req, res } = mockReqRes({ scanId: "scan-1" });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
      expect(res._getJSONData()).toEqual({ ok: true, scanId: "scan-1", status: "completed", score: 87, summary: { findingsCount: 3 } });
      expect(isDomainVerifiedMock).not.toHaveBeenCalled();
      expect(triggerOnDemandWorkflowMock).not.toHaveBeenCalled();
    });

    it("reports a failed scan as ok:false without re-queuing", async () => {
      queues.scans = [{ data: { id: "scan-1", owner: "owner-1", target_url: "https://example.com", status: "failed" }, error: null }];
      const { req, res } = mockReqRes({ scanId: "scan-1" });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
      expect(res._getJSONData()).toMatchObject({ ok: false, status: "failed" });
      expect(triggerOnDemandWorkflowMock).not.toHaveBeenCalled();
    });

    it("returns 202 for a scan already running, without re-queuing", async () => {
      queues.scans = [{ data: { id: "scan-1", owner: "owner-1", target_url: "https://example.com", status: "running" }, error: null }];
      const { req, res } = mockReqRes({ scanId: "scan-1" });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(202);
      expect(triggerOnDemandWorkflowMock).not.toHaveBeenCalled();
    });

    it("returns 401 domain_not_verified for a pending scan whose domain isn't verified", async () => {
      queues.scans = [{ data: { id: "scan-1", owner: "owner-1", target_url: "https://example.com", status: "pending" }, error: null }];
      isDomainVerifiedMock.mockResolvedValue(false);
      const { req, res } = mockReqRes({ scanId: "scan-1" });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(401);
      expect((res._getJSONData() as { code: string }).code).toBe("domain_not_verified");
    });

    it("marks the scan failed and returns 400 when SSRF validation fails after verification", async () => {
      queues.scans = [{ data: { id: "scan-1", owner: "owner-1", target_url: "https://example.com", status: "pending" }, error: null }, {}];
      validateNoSsrfMock.mockRejectedValue(new Error("now resolves to a private IP"));
      const { req, res } = mockReqRes({ scanId: "scan-1" });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(400);
    });

    it("returns 500 and marks the scan failed when queuing the scan job fails", async () => {
      queues.scans = [
        { data: { id: "scan-1", owner: "owner-1", target_url: "https://example.com", status: "pending" }, error: null },
        {}, // status -> running update
        {}, // status -> failed update after the job insert fails
      ];
      queues.scan_jobs = [{ error: { message: "queue insert failed" } }];
      const { req, res } = mockReqRes({ scanId: "scan-1" });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(500);
      expect(triggerOnDemandWorkflowMock).not.toHaveBeenCalled();
    });

    it("verifies, marks running, queues the job, and dispatches the workflow on the happy path", async () => {
      queues.scans = [
        { data: { id: "scan-1", owner: "owner-1", target_url: "https://example.com", status: "pending" }, error: null },
        {}, // status -> running update
      ];
      queues.scan_jobs = [{ error: null }];
      const { req, res } = mockReqRes({ scanId: "scan-1" });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(202);
      expect(res._getJSONData()).toMatchObject({ ok: true, scanId: "scan-1", status: "queued" });
      expect(triggerOnDemandWorkflowMock).toHaveBeenCalledTimes(1);
    });
  });

  it("returns 500 (not an unhandled rejection) when an unexpected error is thrown mid-request", async () => {
    authenticateApiRequestMock.mockRejectedValue(new Error("boom"));
    const { req, res } = mockReqRes({ targetUrl: "https://example.com" });

    await handler(req, res);

    expect(res._getStatusCode()).toBe(500);
    expect((res._getJSONData() as { error: string }).error).toBe("boom");
  });
});
