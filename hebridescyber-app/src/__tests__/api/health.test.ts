import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks, type RequestMethod } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { balanceRetrieveMock } = vi.hoisted(() => ({ balanceRetrieveMock: vi.fn() }));

type QueueMap = Record<string, unknown>;
let responses: QueueMap = {};

vi.mock("@/lib/supabaseAdmin", () => ({
  supabaseAdmin: {
    from: (table: string) => ({
      select: () => ({
        limit: () => Promise.resolve(responses[`${table}.select`] ?? { data: [], error: null }),
        // The queue check: pending count plus the oldest pending row.
        eq: () => ({
          order: () => ({
            limit: () => Promise.resolve(responses[`${table}.count`] ?? { data: [], count: 0, error: null }),
          }),
        }),
      }),
    }),
  },
}));

vi.mock("@/lib/stripeClient", () => ({
  getStripe: () => ({ balance: { retrieve: balanceRetrieveMock } }),
}));

import handler from "@/pages/api/health";

function mockReqRes(method: RequestMethod = "GET") {
  return createMocks<NextApiRequest, NextApiResponse>({ method });
}

type HealthBody = {
  status: "ok" | "degraded";
  checks: {
    supabase: { ok: boolean };
    stripe: { ok: boolean };
    queue: { ok: boolean; depth: number | null; oldestWaitSeconds: number | null; waitExceeded: boolean };
  };
};

describe("GET /api/health", () => {
  beforeEach(() => {
    responses = {};
    balanceRetrieveMock.mockReset().mockResolvedValue({ available: [] });
    vi.unstubAllEnvs();
  });

  it("answers HEAD with the same status as GET, so HEAD-only monitors work", async () => {
    responses["users.select"] = { data: [{ id: "u1" }], error: null };
    const ok = mockReqRes("HEAD");
    await handler(ok.req, ok.res);
    expect(ok.res._getStatusCode()).toBe(200);

    balanceRetrieveMock.mockRejectedValue(new Error("stripe down"));
    const degraded = mockReqRes("HEAD");
    await handler(degraded.req, degraded.res);
    expect(degraded.res._getStatusCode()).toBe(503);
  });

  it("rejects methods other than GET and HEAD with 405", async () => {
    const { req, res } = mockReqRes("POST");
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });

  it("returns 200 'ok' when every sub-check succeeds", async () => {
    responses["users.select"] = { data: [{ id: "u1" }], error: null };
    responses["scan_jobs.count"] = { data: [], count: 3, error: null };

    const { req, res } = mockReqRes();
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    const body = res._getJSONData() as HealthBody;
    expect(body.status).toBe("ok");
    expect(body.checks.supabase.ok).toBe(true);
    expect(body.checks.stripe.ok).toBe(true);
    expect(body.checks.queue).toEqual({ ok: true, depth: 3, oldestWaitSeconds: 0, waitExceeded: false });
  });

  it("returns 503 'degraded' when the Supabase check fails", async () => {
    responses["users.select"] = { data: null, error: { message: "connection refused" } };

    const { req, res } = mockReqRes();
    await handler(req, res);

    expect(res._getStatusCode()).toBe(503);
    const body = res._getJSONData() as HealthBody;
    expect(body.status).toBe("degraded");
    expect(body.checks.supabase.ok).toBe(false);
  });

  it("returns 503 'degraded' when the Stripe check fails", async () => {
    balanceRetrieveMock.mockRejectedValue(new Error("Invalid API Key provided"));

    const { req, res } = mockReqRes();
    await handler(req, res);

    expect(res._getStatusCode()).toBe(503);
    expect((res._getJSONData() as HealthBody).checks.stripe.ok).toBe(false);
  });

  it("never leaks a raw error message — only booleans and counts", async () => {
    balanceRetrieveMock.mockRejectedValue(new Error("sk_live_abc123 rejected"));
    responses["users.select"] = { data: null, error: { message: "some internal detail" } };

    const { req, res } = mockReqRes();
    await handler(req, res);

    const raw = res._getData();
    expect(raw).not.toContain("sk_live_abc123");
    expect(raw).not.toContain("some internal detail");
  });

  it("reports queue depth as informational and doesn't fail health on a large backlog", async () => {
    responses["users.select"] = { data: [{ id: "u1" }], error: null };
    responses["scan_jobs.count"] = { data: [], count: 5000, error: null };

    const { req, res } = mockReqRes();
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect((res._getJSONData() as HealthBody).checks.queue.depth).toBe(5000);
  });

  it("degrades health when the queue count query itself errors, not just when depth is high", async () => {
    responses["users.select"] = { data: [{ id: "u1" }], error: null };
    responses["scan_jobs.count"] = { count: null, error: { message: "table missing" } };

    const { req, res } = mockReqRes();
    await handler(req, res);

    expect(res._getStatusCode()).toBe(503);
    expect((res._getJSONData() as HealthBody).checks.queue).toEqual({
      ok: false,
      depth: null,
      oldestWaitSeconds: null,
      waitExceeded: false,
    });
  });

  describe("queue wait (oldest pending job)", () => {
    const hoursAgo = (h: number) => new Date(Date.now() - h * 60 * 60 * 1000).toISOString();

    beforeEach(() => {
      responses["users.select"] = { data: [{ id: "u1" }], error: null };
    });

    it("reports the oldest pending job's wait in seconds", async () => {
      responses["scan_jobs.count"] = { data: [{ created_at: hoursAgo(1) }], count: 4, error: null };

      const { req, res } = mockReqRes();
      await handler(req, res);

      const queue = (res._getJSONData() as HealthBody).checks.queue;
      expect(queue.depth).toBe(4);
      expect(queue.oldestWaitSeconds).toBeGreaterThanOrEqual(3599);
      expect(queue.oldestWaitSeconds).toBeLessThanOrEqual(3601);
      expect(queue.waitExceeded).toBe(false);
    });

    it("degrades health past two hours once SCAN_QUEUE_WAIT_ALERT=1 — the 503 is what pages on-call", async () => {
      vi.stubEnv("SCAN_QUEUE_WAIT_ALERT", "1");
      responses["scan_jobs.count"] = { data: [{ created_at: hoursAgo(3) }], count: 1, error: null };

      const { req, res } = mockReqRes();
      await handler(req, res);

      expect(res._getStatusCode()).toBe(503);
      const body = res._getJSONData() as HealthBody;
      expect(body.status).toBe("degraded");
      expect(body.checks.queue.ok).toBe(true);
      expect(body.checks.queue.waitExceeded).toBe(true);
    });

    it("stays healthy under two hours with the alert on", async () => {
      vi.stubEnv("SCAN_QUEUE_WAIT_ALERT", "1");
      responses["scan_jobs.count"] = { data: [{ created_at: hoursAgo(1.5) }], count: 1, error: null };

      const { req, res } = mockReqRes();
      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
    });

    it("only reports a long wait while the alert is off (the daily Actions fallback leaves jobs overnight)", async () => {
      responses["scan_jobs.count"] = { data: [{ created_at: hoursAgo(20) }], count: 60, error: null };

      const { req, res } = mockReqRes();
      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
      expect((res._getJSONData() as HealthBody).checks.queue.waitExceeded).toBe(false);
    });

    it("fails the queue check on a created_at that doesn't parse rather than reading it as an empty queue", async () => {
      responses["scan_jobs.count"] = { data: [{ created_at: "garbage" }], count: 1, error: null };

      const { req, res } = mockReqRes();
      await handler(req, res);

      expect(res._getStatusCode()).toBe(503);
      expect((res._getJSONData() as HealthBody).checks.queue.ok).toBe(false);
    });
  });
});
