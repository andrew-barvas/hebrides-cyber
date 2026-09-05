// Focused coverage added alongside E-12 (docs/ENHANCEMENTS.md): this route
// had no test file at all before its rate limit was added. Covers only the
// auth/rate-limit gates — the PDF-rendering path (Playwright/Chromium) is
// out of scope for a unit test and isn't touched by either gate.
import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock, checkRateLimitMock } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  checkRateLimitMock: vi.fn(),
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
vi.mock("@/lib/rateLimit", () => ({ checkRateLimit: checkRateLimitMock }));

import handler from "@/pages/api/generate-report";

function mockReqRes(query: Record<string, string> = { scan_id: "scan-1" }) {
  return createMocks<NextApiRequest, NextApiResponse>({ method: "GET", query });
}

describe("GET /api/generate-report", () => {
  beforeEach(() => {
    queues = {};
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: "owner-1", via: "session" });
    checkRateLimitMock.mockReset().mockResolvedValue({ allowed: true, retryAfterSeconds: 0 });
  });

  it("returns 405 for non-GET", async () => {
    const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "POST" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });

  it("returns 401 when unauthenticated", async () => {
    authenticateApiRequestMock.mockResolvedValue(null);
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(401);
  });

  it("returns 429 when the caller is rate-limited, before ever querying the scan", async () => {
    checkRateLimitMock.mockResolvedValue({ allowed: false, retryAfterSeconds: 55 });
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(429);
    expect(res._getHeaders()["retry-after"]).toBe("55");
    expect(queues.scan_results).toBeUndefined();
  });

  it("returns 400 when scan_id is missing", async () => {
    const { req, res } = mockReqRes({});
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
  });
});
