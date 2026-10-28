import { beforeEach, describe, expect, it, vi } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const m = vi.hoisted(() => ({
  auth: vi.fn(),
  planGate: vi.fn(),
  rate: vi.fn(),
  audit: vi.fn(),
  load: vi.fn(),
  create: vi.fn(),
}));

vi.mock("@/lib/apiAuth", () => ({ authenticateApiRequest: m.auth, supabaseAdmin: {} }));
vi.mock("@/lib/planAccess", () => ({ planGate: m.planGate }));
vi.mock("@/lib/rateLimit", () => ({ checkRateLimit: m.rate }));
vi.mock("@/lib/audit", () => ({ logAuditEvent: m.audit }));
vi.mock("@/lib/uptimeService", async (orig) => ({ ...(await orig<typeof import("@/lib/uptimeService")>()), loadUptimeProvider: m.load, createMonitorsForTargets: m.create }));

import handler from "@/pages/api/uptime/monitors";

function call(method: string, body?: unknown) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: method as "POST", body: body as Record<string, unknown> });
  return handler(req, res).then(() => res);
}
const body = { targetUrls: ["https://shop.example.co.uk"] };

beforeEach(() => {
  m.auth.mockReset().mockResolvedValue({ ownerId: "owner-1", via: "session" });
  m.planGate.mockReset().mockResolvedValue("ok");
  m.rate.mockReset().mockResolvedValue({ allowed: true, retryAfterSeconds: 0 });
  m.audit.mockReset();
  m.load.mockReset().mockResolvedValue({ status: "ok", id: "i1", provider: { id: "uptimerobot" }, lastSyncAt: null });
  m.create.mockReset().mockResolvedValue([{ targetUrl: "https://shop.example.co.uk", result: "created" }]);
});

describe("POST /api/uptime/monitors", () => {
  it("rejects other methods, anonymous callers and API keys", async () => {
    expect((await call("GET")).statusCode).toBe(405);
    m.auth.mockResolvedValue(null);
    expect((await call("POST", body)).statusCode).toBe(401);
    m.auth.mockResolvedValue({ ownerId: "o", via: "api_key" });
    expect((await call("POST", body)).statusCode).toBe(403);
  });

  it("validates the body", async () => {
    expect((await call("POST", {})).statusCode).toBe(400);
    expect((await call("POST", { targetUrls: [] })).statusCode).toBe(400);
    expect((await call("POST", { targetUrls: Array(40).fill("https://a.example") })).statusCode).toBe(400);
  });

  it("is Pro and above", async () => {
    m.planGate.mockResolvedValue("denied");
    expect((await call("POST", body)).statusCode).toBe(403);
    m.planGate.mockResolvedValue("error");
    expect((await call("POST", body)).statusCode).toBe(500);
    expect(m.create).not.toHaveBeenCalled();
  });

  it("is rate limited", async () => {
    m.rate.mockResolvedValue({ allowed: false, retryAfterSeconds: 30 });
    const res = await call("POST", body);
    expect(res.statusCode).toBe(429);
    expect(res.getHeader("Retry-After")).toBe("30");
  });

  it("needs a connected, readable UptimeRobot key", async () => {
    m.load.mockResolvedValue({ status: "none" });
    expect((await call("POST", body)).statusCode).toBe(400);
    m.load.mockResolvedValue({ status: "undecryptable" });
    expect((await call("POST", body)).statusCode).toBe(409);
    m.load.mockResolvedValue({ status: "error", error: "db" });
    expect((await call("POST", body)).statusCode).toBe(500);
    expect(m.create).not.toHaveBeenCalled();
  });

  it("returns per-target results and audits only when something was created", async () => {
    const res = await call("POST", body);
    expect(res.statusCode).toBe(200);
    expect((res._getJSONData() as { results: unknown[] }).results).toEqual([{ targetUrl: "https://shop.example.co.uk", result: "created" }]);
    expect(m.audit).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ action: "uptime.monitor_created", metadata: expect.objectContaining({ count: 1 }) }));

    m.audit.mockReset();
    m.create.mockResolvedValue([{ targetUrl: "https://shop.example.co.uk", result: "exists" }]);
    await call("POST", body);
    expect(m.audit).not.toHaveBeenCalled();
  });
});
