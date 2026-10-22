import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { rateLimit } = vi.hoisted(() => ({ rateLimit: vi.fn() }));
vi.mock("@/lib/rateLimit", () => ({ checkRateLimit: rateLimit, getClientIp: () => "1.2.3.4" }));

import handler from "@/pages/api/v1/openapi.json";

function call(method = "GET") {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: method as "GET" });
  return handler(req, res).then(() => res);
}

beforeEach(() => {
  rateLimit.mockReset().mockResolvedValue({ allowed: true });
});

describe("GET /api/v1/openapi.json", () => {
  it("serves the OpenAPI document without authentication, cacheable", async () => {
    const res = await call();
    expect(res.statusCode).toBe(200);
    const body = res._getJSONData() as { openapi: string; paths: Record<string, unknown>; servers: Array<{ url: string }> };
    expect(body.openapi).toBe("3.1.0");
    expect(Object.keys(body.paths)).toContain("/scans");
    expect(body.servers[0].url).toMatch(/\/api\/v1$/);
    expect(res.getHeader("Cache-Control")).toContain("max-age");
  });

  it("rate-limits by client IP and tells the caller when to retry", async () => {
    rateLimit.mockResolvedValue({ allowed: false, retryAfterSeconds: 30 });
    const res = await call();
    expect(res.statusCode).toBe(429);
    expect(res.getHeader("Retry-After")).toBe("30");
    expect(rateLimit).toHaveBeenCalledWith("1.2.3.4", "openapi-spec", expect.anything());
  });

  it("405s non-GET", async () => {
    const res = await call("POST");
    expect(res.statusCode).toBe(405);
    expect(res.getHeader("Allow")).toBe("GET");
  });
});
