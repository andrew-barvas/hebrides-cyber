import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authMock, proMock, rateMock, diffMock } = vi.hoisted(() => ({ authMock: vi.fn(), proMock: vi.fn(), rateMock: vi.fn(), diffMock: vi.fn() }));
vi.mock("@/lib/apiAuth", () => ({ authenticateApiRequest: authMock, supabaseAdmin: {} }));
vi.mock("@/lib/planAccess", () => ({ hasProAccess: proMock }));
vi.mock("@/lib/rateLimit", () => ({ checkRateLimit: rateMock }));
vi.mock("@/lib/dependencyDiff", async (orig) => ({ ...(await orig<typeof import("@/lib/dependencyDiff")>()), computeDependencyDiff: diffMock }));

import handler from "@/pages/api/v1/dependency-diff";

function call(body: unknown, method = "POST") {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: method as "POST", body: body as Record<string, unknown>, headers: { authorization: "Bearer k" } });
  return { req, res };
}
const valid = { files: [{ name: "package-lock.json", base: "{}", head: "{}" }] };

beforeEach(() => {
  authMock.mockReset().mockResolvedValue({ ownerId: "o1", via: "key" });
  proMock.mockReset().mockResolvedValue(true);
  rateMock.mockReset().mockResolvedValue({ allowed: true });
  diffMock.mockReset().mockResolvedValue({ status: "completed", complete: true, notes: [], files: [], packages_added: 0, vulnerabilities: [], counts: { critical: 0, high: 0, medium: 0, low: 0 } });
});

describe("POST /api/v1/dependency-diff", () => {
  it("rejects other methods and unauthenticated callers", async () => {
    const get = call(valid, "GET");
    await handler(get.req, get.res);
    expect(get.res._getStatusCode()).toBe(405);

    authMock.mockResolvedValue(null);
    const anon = call(valid);
    await handler(anon.req, anon.res);
    expect(anon.res._getStatusCode()).toBe(401);
  });

  it("requires a Pro or Agency plan", async () => {
    proMock.mockResolvedValue(false);
    const { req, res } = call(valid);
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
    expect((res._getJSONData() as { code?: string; status?: string }).code).toBe("plan_required");
    expect(diffMock).not.toHaveBeenCalled();
  });

  it("rate limits with Retry-After", async () => {
    rateMock.mockResolvedValue({ allowed: false, retryAfterSeconds: 30 });
    const { req, res } = call(valid);
    await handler(req, res);
    expect(res._getStatusCode()).toBe(429);
    expect(res.getHeader("Retry-After")).toBe("30");
    rateMock.mockResolvedValue({ allowed: false });
    const again = call(valid);
    await handler(again.req, again.res);
    expect(again.res.getHeader("Retry-After")).toBe("60");
  });

  it("validates the body", async () => {
    for (const body of [{}, { files: [] }, { files: Array.from({ length: 21 }, () => valid.files[0]) }, { files: [{ name: "" }] }]) {
      const { req, res } = call(body);
      await handler(req, res);
      expect(res._getStatusCode()).toBe(400);
    }
    expect(diffMock).not.toHaveBeenCalled();
  });

  it("rejects lockfile contents over the total size cap", async () => {
    const big = "x".repeat(4_900_000);
    const files = Array.from({ length: 5 }, (_, i) => ({ name: `p${i}/package-lock.json`, base: big, head: big }));
    const { req, res } = call({ files });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
    expect((res._getJSONData() as { error: string }).error).toContain("MB");
    expect(diffMock).not.toHaveBeenCalled();
  });

  it("returns the diff, defaulting absent contents to null", async () => {
    const { req, res } = call({ files: [{ name: "Cargo.lock", head: "x" }] });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(200);
    expect(diffMock).toHaveBeenCalledWith([{ name: "Cargo.lock", base: null, head: "x", base_companion: null, head_companion: null }]);
    expect((res._getJSONData() as { code?: string; status?: string }).status).toBe("completed");
  });

  it("treats an absent head as a deleted lockfile", async () => {
    const { req, res } = call({ files: [{ name: "Cargo.lock", base: "x" }] });
    await handler(req, res);
    expect(diffMock).toHaveBeenCalledWith([{ name: "Cargo.lock", base: "x", head: null, base_companion: null, head_companion: null }]);
  });

  it("passes through every supplied file content", async () => {
    const { req, res } = call({ files: [{ name: "package-lock.json", base: "b", head: "h", base_companion: "bc", head_companion: "hc" }] });
    await handler(req, res);
    expect(diffMock).toHaveBeenCalledWith([{ name: "package-lock.json", base: "b", head: "h", base_companion: "bc", head_companion: "hc" }]);
  });

  it("answers 502 when the vulnerability lookup fails, never a clean result", async () => {
    diffMock.mockResolvedValue({ status: "error", error: "OSV.dev querybatch returned HTTP 503" });
    const { req, res } = call(valid);
    await handler(req, res);
    expect(res._getStatusCode()).toBe(502);
    expect((res._getJSONData() as { code?: string; status?: string }).code).toBe("lookup_failed");
  });
});
