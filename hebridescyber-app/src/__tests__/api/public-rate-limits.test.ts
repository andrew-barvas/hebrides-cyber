// The three public, unauthenticated read routes each rate-limit by client IP
// with a budget sized to their traffic — see LIVE-1 and rate-limit-coverage.test.ts.
import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { checkRateLimitMock, fromMock } = vi.hoisted(() => ({
  checkRateLimitMock: vi.fn(),
  fromMock: vi.fn(),
}));

vi.mock("@/lib/rateLimit", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/rateLimit")>()),
  checkRateLimit: checkRateLimitMock,
}));
vi.mock("@/lib/supabaseAdmin", () => ({ supabaseAdmin: { from: fromMock } }));
vi.mock("@/lib/stripeClient", () => ({ getStripe: () => ({ balance: { retrieve: vi.fn().mockResolvedValue({}) } }) }));
vi.mock("@/lib/audit", () => ({ logAuditEvent: vi.fn() }));

import badgeHandler from "@/pages/api/badge/[scanId]";
import reportHandler from "@/pages/api/reports/[token]";
import healthHandler from "@/pages/api/health";

function mockReq(query: Record<string, string> = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({
    method: "GET",
    query,
    headers: { "x-forwarded-for": "203.0.113.9" },
  });
}

beforeEach(() => {
  checkRateLimitMock.mockReset().mockResolvedValue({ allowed: true, retryAfterSeconds: 0 });
  // Every query resolves to "no row" — enough to exercise the handlers'
  // not-rate-limited paths without modelling the data.
  const builder: Record<string, unknown> = {};
  for (const m of ["select", "eq", "limit", "update", "in", "order"]) builder[m] = () => builder;
  builder.maybeSingle = () => Promise.resolve({ data: null, error: null });
  builder.then = (resolve: (v: unknown) => void) => resolve({ data: [], error: null, count: 0 });
  fromMock.mockReset().mockReturnValue(builder);
});

describe.each([
  ["badge", badgeHandler, { scanId: "abc.svg" }, "badge", 600],
  ["shared report", reportHandler, { token: "tok" }, "shared-report", 120],
  ["health", healthHandler, {}, "health", 120],
] as const)("%s", (_name, handler, query, namespace, max) => {
  it(`is keyed on the client IP in its own "${namespace}" bucket (${max}/h)`, async () => {
    const { req, res } = mockReq(query);
    await handler(req, res);
    expect(checkRateLimitMock).toHaveBeenCalledWith("203.0.113.9", namespace, { max, windowSeconds: 3600 });
    expect(res._getStatusCode()).not.toBe(429);
  });

  it("returns 429 with Retry-After and does no database work when over budget", async () => {
    checkRateLimitMock.mockResolvedValue({ allowed: false, retryAfterSeconds: 42 });
    const { req, res } = mockReq(query);
    await handler(req, res);
    expect(res._getStatusCode()).toBe(429);
    expect(res.getHeader("Retry-After")).toBe("42");
    expect(fromMock).not.toHaveBeenCalled();
  });
});
