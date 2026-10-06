// The partner portal is Agency-only, decided server-side by planAccess.ts:
// a subscription the Stripe webhook marked cancelled or past due keeps its
// `plan`, so the gate has to look at `status` too.
import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock } = vi.hoisted(() => ({ authenticateApiRequestMock: vi.fn() }));

let queues: Record<string, unknown[]> = {};

function makeBuilder(table: string) {
  const next = () => Promise.resolve(queues[table]?.shift() ?? { data: null, error: null, count: 0 });
  const builder: Record<string, unknown> = {
    select: () => builder,
    eq: () => builder,
    order: () => builder,
    limit: () => next(),
    maybeSingle: next,
    then: (resolve: (v: unknown) => void) => next().then(resolve),
  };
  return builder;
}

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: { from: (table: string) => makeBuilder(table) },
}));

import handler from "@/pages/api/account/partner-portal";

function get() {
  return createMocks<NextApiRequest, NextApiResponse>({ method: "GET" });
}

describe("GET /api/account/partner-portal", () => {
  beforeEach(() => {
    queues = {};
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: "owner-1", via: "session" });
  });

  it("answers 405 for other methods and 401 without a caller", async () => {
    const post = createMocks<NextApiRequest, NextApiResponse>({ method: "POST" });
    await handler(post.req, post.res);
    expect(post.res._getStatusCode()).toBe(405);

    authenticateApiRequestMock.mockResolvedValue(null);
    const anon = get();
    await handler(anon.req, anon.res);
    expect(anon.res._getStatusCode()).toBe(401);
  });

  it.each([
    ["Pro", { plan: "pro", status: "active" }],
    ["a cancelled Agency", { plan: "agency", status: "cancelled" }],
    ["no", null],
  ])("refuses %s subscription", async (_label, row) => {
    queues.subscriptions = [{ data: row, error: null }];
    const { req, res } = get();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("answers 500 when the plan can't be read", async () => {
    queues.subscriptions = [{ data: null, error: { message: "down" } }];
    const { req, res } = get();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(500);
  });

  it("returns the portal stats for an active Agency subscription", async () => {
    queues.subscriptions = [
      { data: { plan: "agency", status: "active" }, error: null },
      { data: { brand_name: "Acme", brand_logo_url: null }, error: null },
    ];
    queues.monitored_targets = [{ count: 4, error: null }];
    queues.scans = [{ count: 2, error: null }];
    queues.scan_results = [{ data: [{ score: 90 }, { score: 70 }, { score: null }], error: null }];
    const { req, res } = get();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(200);
    expect(JSON.parse(res._getData())).toEqual({ brandName: "Acme", brandLogoUrl: null, monitoredTargetCount: 4, totalScans: 2, latestScore: 90, avgScore: 80 });
  });
});
