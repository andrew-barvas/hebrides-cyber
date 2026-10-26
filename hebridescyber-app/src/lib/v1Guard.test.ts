import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { auth, rate } = vi.hoisted(() => ({ auth: vi.fn(), rate: vi.fn() }));
vi.mock("./apiAuth", () => ({ authenticateApiRequest: auth }));
vi.mock("./rateLimit", () => ({ checkRateLimit: rate, getClientIp: () => "9.9.9.9" }));

import { guardV1, API_VERSION, AUTH_FAILURE_LIMIT, READ_RATE_LIMIT } from "./v1Guard";

function run(scope: "scans:read" | "scans:write" = "scans:read", options?: { rateLimit?: boolean }) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "GET" });
  return guardV1(req, res, scope, options).then((caller) => ({ caller, res }));
}

beforeEach(() => {
  auth.mockReset().mockResolvedValue({ ownerId: "owner-1", via: "key", scopes: ["scans:read", "scans:write"] });
  rate.mockReset().mockResolvedValue({ allowed: true, retryAfterSeconds: 0 });
});

describe("guardV1", () => {
  it("returns the caller and stamps the version and no-store headers", async () => {
    const { caller, res } = await run();
    expect(caller).toMatchObject({ ownerId: "owner-1" });
    expect(res.getHeader("X-API-Version")).toBe(API_VERSION);
    expect(res.getHeader("Cache-Control")).toBe("no-store");
  });

  it("401s with a machine-readable code, and still sets the headers on the error", async () => {
    auth.mockResolvedValue(null);
    const { caller, res } = await run();
    expect(caller).toBeNull();
    expect(res.statusCode).toBe(401);
    expect(res._getJSONData()).toMatchObject({ code: "unauthorized" });
    expect(res.getHeader("X-API-Version")).toBe(API_VERSION);
    expect(res.getHeader("Cache-Control")).toBe("no-store");
  });

  it("charges only failed authentication to the per-IP failure budget", async () => {
    await run();
    expect(rate).not.toHaveBeenCalledWith("9.9.9.9", "v1-auth-failure", expect.anything());
    auth.mockResolvedValue(null);
    await run();
    expect(rate).toHaveBeenCalledWith("9.9.9.9", "v1-auth-failure", AUTH_FAILURE_LIMIT);
  });

  it("throttles repeated bad credentials with 429 and Retry-After", async () => {
    auth.mockResolvedValue(null);
    rate.mockResolvedValue({ allowed: false, retryAfterSeconds: 120 });
    const { caller, res } = await run();
    expect(caller).toBeNull();
    expect(res.statusCode).toBe(429);
    expect(res.getHeader("Retry-After")).toBe("120");
    expect(res._getJSONData()).toMatchObject({ code: "rate_limited", retry_after_seconds: 120 });
  });

  it("403s a key without the scope before spending the account budget", async () => {
    auth.mockResolvedValue({ ownerId: "owner-1", via: "key", scopes: ["scans:read"] });
    const { caller, res } = await run("scans:write");
    expect(caller).toBeNull();
    expect(res.statusCode).toBe(403);
    expect(res._getJSONData()).toMatchObject({ code: "insufficient_scope", required_scope: "scans:write" });
    expect(rate).not.toHaveBeenCalled();
  });

  it("applies the shared per-account read budget, keyed on the owner", async () => {
    await run();
    expect(rate).toHaveBeenCalledWith("owner-1", "v1-read", READ_RATE_LIMIT);
  });

  it("429s an account over its budget", async () => {
    rate.mockResolvedValue({ allowed: false, retryAfterSeconds: 33 });
    const { caller, res } = await run();
    expect(caller).toBeNull();
    expect(res.statusCode).toBe(429);
    expect(res.getHeader("Retry-After")).toBe("33");
  });

  it("skips the shared budget for routes that enforce their own", async () => {
    const { caller } = await run("scans:write", { rateLimit: false });
    expect(caller).not.toBeNull();
    expect(rate).not.toHaveBeenCalled();
  });

  it("treats a session (no scopes) as unscoped", async () => {
    auth.mockResolvedValue({ ownerId: "owner-1", via: "session" });
    const { caller } = await run("scans:write");
    expect(caller).toMatchObject({ via: "session" });
  });
});
