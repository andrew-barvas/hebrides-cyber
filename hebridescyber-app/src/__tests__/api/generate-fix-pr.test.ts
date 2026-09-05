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

import handler from "@/pages/api/generate-fix-pr";

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
