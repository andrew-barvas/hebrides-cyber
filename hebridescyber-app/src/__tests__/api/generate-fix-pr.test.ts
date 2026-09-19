// Focused coverage added alongside E-12 (docs/ENHANCEMENTS.md): this route
// had no test file at all before its rate limit was added. Covers only the
// auth/rate-limit gates — the GitHub PR-creation path is out of scope for a
// unit test and isn't touched by either gate.
import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock, checkRateLimitMock, resolveGithubAuthMock } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  checkRateLimitMock: vi.fn(),
  resolveGithubAuthMock: vi.fn(),
}));

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: { from: () => ({}) },
}));
vi.mock("@/lib/rateLimit", () => ({ checkRateLimit: checkRateLimitMock }));
vi.mock("@/lib/githubApp", () => ({ resolveGithubAuth: resolveGithubAuthMock }));

import handler, { mapWithConcurrency } from "@/pages/api/generate-fix-pr";

function mockReqRes(body: Record<string, unknown> = { scanId: "scan-1", githubRepo: "owner/repo" }) {
  return createMocks<NextApiRequest, NextApiResponse>({ method: "POST", body });
}

describe("POST /api/generate-fix-pr", () => {
  beforeEach(() => {
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: "owner-1", via: "session" });
    checkRateLimitMock.mockReset().mockResolvedValue({ allowed: true, retryAfterSeconds: 0 });
    resolveGithubAuthMock.mockReset().mockResolvedValue({ token: null });
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

  it("returns 403 for an API-key caller (session-only route)", async () => {
    authenticateApiRequestMock.mockResolvedValue({ ownerId: "owner-1", via: "key" });
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("returns 429 when the caller is rate-limited, before resolving GitHub access", async () => {
    checkRateLimitMock.mockResolvedValue({ allowed: false, retryAfterSeconds: 12 });
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(429);
    expect(res._getHeaders()["retry-after"]).toBe("12");
    expect(resolveGithubAuthMock).not.toHaveBeenCalled();
  });

  it("returns 400 when githubRepo doesn't look like owner/repo", async () => {
    const { req, res } = mockReqRes({ scanId: "scan-1", githubRepo: "not-valid" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
  });
});

// Regression coverage for the 2026-09-19 incident: this whole request runs
// synchronously in one Azure Static Web Apps Function invocation, and the
// dependency-bump flow's OSV.dev lookups (one real network call per
// package, no batching) had no bound on TOTAL wall-clock time — only a
// per-call timeout. A real repo's package.json could push the whole
// invocation past the platform's own execution ceiling, which kills the
// function before the route's own try/catch ever runs (surfacing as a bare
// 502 with no JSON body). mapWithConcurrency's deadline/fallback params fix
// that by making the query phase itself best-effort in time.
describe("mapWithConcurrency deadline", () => {
  it("processes items normally while under the deadline", async () => {
    const fn = vi.fn(async (n: number) => `real-${n}`);
    const results = await mapWithConcurrency([1, 2, 3], 1, fn, Date.now() + 60_000, (n) => `fallback-${n}`);
    expect(results).toEqual(["real-1", "real-2", "real-3"]);
    expect(fn).toHaveBeenCalledTimes(3);
  });

  it("falls back for items not yet started once the deadline has passed, preserving each item's own data", async () => {
    let now = 1_000;
    vi.spyOn(Date, "now").mockImplementation(() => now);

    const fn = vi.fn(async (n: number) => {
      now += 100; // simulate each real call taking 100ms of wall-clock time
      return `real-${n}`;
    });
    const fallback = vi.fn((n: number) => `fallback-${n}`);

    // Concurrency 1 makes this fully sequential/deterministic: items are
    // claimed and their deadline checked one at a time, no worker-interleaving
    // ambiguity to reason about.
    const results = await mapWithConcurrency([1, 2, 3, 4, 5], 1, fn, 1_000 + 250, fallback);

    // now: 1000 -> fn(1) -> 1100 -> fn(2) -> 1200 -> fn(3) -> 1300 (still <= 1250 when checked at 1200)
    // then 1300 > 1250: fallback(4), fallback(5)
    expect(results).toEqual(["real-1", "real-2", "real-3", "fallback-4", "fallback-5"]);
    expect(fn).toHaveBeenCalledTimes(3);
    expect(fallback).toHaveBeenCalledTimes(2);

    vi.restoreAllMocks();
  });

  it("never calls fn at all once already past the deadline before starting", async () => {
    vi.spyOn(Date, "now").mockReturnValue(2_000);
    const fn = vi.fn(async (n: number) => `real-${n}`);
    const results = await mapWithConcurrency([1, 2], 2, fn, 1_000, (n) => `fallback-${n}`);
    expect(results).toEqual(["fallback-1", "fallback-2"]);
    expect(fn).not.toHaveBeenCalled();
    vi.restoreAllMocks();
  });

  it("with no deadline given, ignores it entirely (existing callers unaffected)", async () => {
    const fn = vi.fn(async (n: number) => `real-${n}`);
    const results = await mapWithConcurrency([1, 2, 3], 2, fn);
    expect(results).toEqual(["real-1", "real-2", "real-3"]);
  });
});
