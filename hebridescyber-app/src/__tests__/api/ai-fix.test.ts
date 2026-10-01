// Focused coverage added alongside E-12 (docs/ENHANCEMENTS.md): this route
// had no test file at all before its rate limit was added. Covers the
// auth/rate-limit gates rather than attempting full happy-path coverage of
// generateAiRemediation (Azure OpenAI-backed, out of this fix's scope).
import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock, checkRateLimitMock, generateAiRemediationMock } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  checkRateLimitMock: vi.fn(),
  generateAiRemediationMock: vi.fn(),
}));

type QueueMap = Record<string, unknown[]>;
let queues: QueueMap = {};

function makeBuilder(table: string) {
  const next = () => Promise.resolve(queues[table]?.shift() ?? { data: null, error: null });
  const builder: Record<string, unknown> = {
    select: () => builder,
    eq: () => builder,
    order: () => builder,
    limit: () => builder,
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
vi.mock("@/lib/aiRemediation", () => ({ generateAiRemediation: generateAiRemediationMock }));

import handler from "@/pages/api/scans/[id]/ai-fix";

const OWNER_ID = "owner-1";

function mockReqRes(body: Record<string, unknown> = { checkId: "headers.missing" }) {
  return createMocks<NextApiRequest, NextApiResponse>({ method: "POST", query: { id: "scan-1" }, body });
}

describe("POST /api/scans/[id]/ai-fix", () => {
  beforeEach(() => {
    queues = {};
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: OWNER_ID, via: "session" });
    checkRateLimitMock.mockReset().mockResolvedValue({ allowed: true, retryAfterSeconds: 0 });
    generateAiRemediationMock.mockReset();
  });

  it("returns 405 for non-POST", async () => {
    const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "GET" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });

  it("returns 401 when unauthenticated", async () => {
    authenticateApiRequestMock.mockResolvedValue(null);
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(401);
  });

  it("returns 429 when the caller is rate-limited, before touching the scan or Azure OpenAI", async () => {
    checkRateLimitMock.mockResolvedValue({ allowed: false, retryAfterSeconds: 30 });
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(429);
    expect(res._getHeaders()["retry-after"]).toBe("30");
    expect(generateAiRemediationMock).not.toHaveBeenCalled();
  });

  it("returns 403 when the caller does not own the scan", async () => {
    queues.scans = [{ data: { id: "scan-1", owner: "someone-else" } }];
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("returns 200 with guidance on a valid, owned scan and finding", async () => {
    queues.scans = [{ data: { id: "scan-1", owner: OWNER_ID } }];
    queues.scan_results = [{ data: { results: { findings: [{ checkId: "headers.missing", severity: "medium", title: "t", detail: "d" }] } } }];
    generateAiRemediationMock.mockResolvedValue({ status: "ok", guidance: "Add the header." });

    const { req, res } = mockReqRes();
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(res._getJSONData()).toEqual({ guidance: "Add the header." });
  });
});
