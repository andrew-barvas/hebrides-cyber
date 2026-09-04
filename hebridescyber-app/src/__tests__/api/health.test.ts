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
        eq: () => Promise.resolve(responses[`${table}.count`] ?? { count: 0, error: null }),
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
    queue: { ok: boolean; depth: number | null };
  };
};

describe("GET /api/health", () => {
  beforeEach(() => {
    responses = {};
    balanceRetrieveMock.mockReset().mockResolvedValue({ available: [] });
  });

  it("rejects non-GET methods with 405", async () => {
    const { req, res } = mockReqRes("POST");
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });

  it("returns 200 'ok' when every sub-check succeeds", async () => {
    responses["users.select"] = { data: [{ id: "u1" }], error: null };
    responses["scan_jobs.count"] = { count: 3, error: null };

    const { req, res } = mockReqRes();
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    const body = res._getJSONData() as HealthBody;
    expect(body.status).toBe("ok");
    expect(body.checks.supabase.ok).toBe(true);
    expect(body.checks.stripe.ok).toBe(true);
    expect(body.checks.queue).toEqual({ ok: true, depth: 3 });
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
    responses["scan_jobs.count"] = { count: 5000, error: null };

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
    expect((res._getJSONData() as HealthBody).checks.queue).toEqual({ ok: false, depth: null });
  });
});
