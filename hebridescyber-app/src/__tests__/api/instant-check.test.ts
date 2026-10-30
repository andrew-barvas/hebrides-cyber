import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { limit, shared, run } = vi.hoisted(() => ({ limit: vi.fn(), shared: vi.fn(), run: vi.fn() }));
vi.mock("@/lib/rateLimit", () => ({ checkRateLimit: limit, getClientIp: () => "203.0.113.9", hasSharedRateLimitStore: shared }));
vi.mock("@/lib/instantCheck", async (orig) => ({ ...(await orig<typeof import("@/lib/instantCheck")>()), runInstantCheck: run }));

import handler from "@/pages/api/instant-check";
import { InstantCheckError } from "@/lib/instantCheck";

const call = async (body: unknown, method = "POST") => {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: method as "POST", body: body as never });
  await handler(req, res);
  return res;
};

describe("POST /api/instant-check", () => {
  beforeEach(() => {
    limit.mockReset().mockResolvedValue({ allowed: true, retryAfterSeconds: 0 });
    shared.mockReset().mockReturnValue(true);
    run.mockReset().mockResolvedValue({ target: "https://example.com", score: 80 });
  });
  afterEach(() => vi.unstubAllEnvs());

  it("only accepts POST", async () => expect((await call({}, "GET")).statusCode).toBe(405));

  it("is switched off in production until a shared rate-limit store exists, and does not scan", async () => {
    vi.stubEnv("NODE_ENV", "production");
    shared.mockReturnValue(false);
    expect((await call({ url: "example.com" })).statusCode).toBe(503);
    expect(run).not.toHaveBeenCalled();
  });

  it("rejects a malformed body and an unusable address with 400, before spending any rate limit", async () => {
    expect((await call({})).statusCode).toBe(400);
    expect((await call({ url: "localhost" })).statusCode).toBe(400);
    expect(limit).not.toHaveBeenCalled();
  });

  it("limits per IP and per target, both failing closed", async () => {
    await call({ url: "example.com" });
    expect(limit.mock.calls.map((c) => [c[1], c[0], c[3]])).toEqual([
      ["instant-check-ip", "203.0.113.9", { failClosed: true }],
      ["instant-check-target", "example.com", { failClosed: true }],
    ]);
  });

  it("answers 429 with Retry-After when either limit is hit, and does not scan", async () => {
    limit.mockResolvedValueOnce({ allowed: true, retryAfterSeconds: 0 }).mockResolvedValueOnce({ allowed: false, retryAfterSeconds: 120 });
    const res = await call({ url: "example.com" });
    expect(res.statusCode).toBe(429);
    expect(res.getHeader("Retry-After")).toBe("120");
    expect(run).not.toHaveBeenCalled();
  });

  it("returns the result uncached", async () => {
    const res = await call({ url: "https://example.com/x" });
    expect(res.statusCode).toBe(200);
    expect(res.getHeader("Cache-Control")).toBe("no-store");
    expect(run).toHaveBeenCalledWith("https://example.com");
  });

  it("maps a visitor-facing failure to 422 and anything else to a generic 500", async () => {
    run.mockRejectedValueOnce(new InstantCheckError("We could not reach that site."));
    expect((await call({ url: "example.com" })).statusCode).toBe(422);
    run.mockRejectedValueOnce(new Error("secret internal detail"));
    const res = await call({ url: "example.com" });
    expect(res.statusCode).toBe(500);
    expect(res._getData()).not.toMatch(/secret internal/);
  });
});
