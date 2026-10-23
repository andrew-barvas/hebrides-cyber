import { beforeEach, describe, expect, it, vi } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const m = vi.hoisted(() => ({
  auth: vi.fn(),
  planGate: vi.fn(),
  rate: vi.fn(),
  load: vi.fn(),
  sync: vi.fn(),
  alert: vi.fn(),
  tables: {} as Record<string, unknown[]>,
}));

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: m.auth,
  supabaseAdmin: {
    from: (table: string) => {
      const b: Record<string, unknown> = {};
      b.select = () => b;
      b.eq = () => b;
      b.order = () => b;
      b.maybeSingle = () => Promise.resolve({ data: (m.tables[table] ?? [])[0] ?? null });
      b.then = (resolve: (v: unknown) => void) => resolve({ data: m.tables[table] ?? [] });
      return b;
    },
  },
}));
vi.mock("@/lib/planAccess", () => ({ planGate: m.planGate }));
vi.mock("@/lib/rateLimit", () => ({ checkRateLimit: m.rate }));
vi.mock("@/lib/uptimeAlerts", () => ({ sendUptimeAlert: m.alert }));
vi.mock("@/lib/uptimeService", async (orig) => ({ ...(await orig<typeof import("@/lib/uptimeService")>()), loadUptimeProvider: m.load, syncOwnerMonitors: m.sync }));

import handler from "@/pages/api/uptime/status";

function call(method = "GET") {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: method as "GET" });
  return handler(req, res).then(() => res);
}

const minutesAgo = (n: number) => new Date(Date.now() - n * 60_000).toISOString();

beforeEach(() => {
  m.auth.mockReset().mockResolvedValue({ ownerId: "owner-1", via: "session" });
  m.planGate.mockReset().mockResolvedValue("ok");
  m.rate.mockReset().mockResolvedValue({ allowed: true, retryAfterSeconds: 0 });
  m.load.mockReset().mockResolvedValue({ status: "ok", id: "i1", provider: {}, lastSyncAt: minutesAgo(1) });
  m.sync.mockReset().mockResolvedValue({ ok: true, alerts: [], missing: [], updated: 1 });
  m.alert.mockReset();
  m.tables = {
    uptime_monitors: [{ target_url: "https://shop.example.co.uk", last_status: "up" }],
    monitored_targets: [{ target_url: "https://shop.example.co.uk" }, { target_url: "https://blog.example.co.uk/" }],
    uptime_integrations: [{ last_sync_at: minutesAgo(1), last_error: null }],
  };
});

describe("GET /api/uptime/status", () => {
  it("rejects other methods, anonymous callers and API keys", async () => {
    expect((await call("POST")).statusCode).toBe(405);
    m.auth.mockResolvedValue(null);
    expect((await call()).statusCode).toBe(401);
    m.auth.mockResolvedValue({ ownerId: "o", via: "api_key" });
    expect((await call()).statusCode).toBe(403);
  });

  it("tells a non-Pro caller the feature is not allowed, without touching the provider", async () => {
    m.planGate.mockResolvedValue("denied");
    const res = await call();
    expect(res._getJSONData()).toMatchObject({ allowed: false, connected: false });
    expect(m.load).not.toHaveBeenCalled();
  });

  it("reports not connected when there is no integration", async () => {
    m.load.mockResolvedValue({ status: "none" });
    expect((await call())._getJSONData()).toMatchObject({ allowed: true, connected: false, monitors: [] });
  });

  it("returns cached monitors and the targets that still have none, without refreshing a fresh cache", async () => {
    const data = (await call())._getJSONData();
    expect(data.connected).toBe(true);
    expect(data.monitors).toHaveLength(1);
    expect(data.unmonitored).toEqual(["https://blog.example.co.uk/"]);
    expect(m.sync).not.toHaveBeenCalled();
  });

  it("refreshes a stale cache, and sends the alerts that refresh found", async () => {
    m.load.mockResolvedValue({ status: "ok", id: "i1", provider: {}, lastSyncAt: minutesAgo(30) });
    m.sync.mockResolvedValue({ ok: true, alerts: [{ kind: "down", targetUrl: "https://shop.example.co.uk" }], missing: [], updated: 1 });
    await call();
    expect(m.sync).toHaveBeenCalledTimes(1);
    expect(m.alert).toHaveBeenCalledWith(expect.anything(), "owner-1", "down", "https://shop.example.co.uk");
  });

  it("does not refresh when the per-owner limit is spent", async () => {
    m.load.mockResolvedValue({ status: "ok", id: "i1", provider: {}, lastSyncAt: null });
    m.rate.mockResolvedValue({ allowed: false, retryAfterSeconds: 10 });
    const res = await call();
    expect(res.statusCode).toBe(200);
    expect(m.sync).not.toHaveBeenCalled();
  });

  it("returns the cached rows plus refreshError when the refresh fails", async () => {
    m.load.mockResolvedValue({ status: "ok", id: "i1", provider: {}, lastSyncAt: null });
    m.sync.mockResolvedValue({ ok: false, kind: "unavailable", error: "UptimeRobot returned 503." });
    const data = (await call())._getJSONData();
    expect(data.refreshError).toBe("UptimeRobot returned 503.");
    expect(data.monitors).toHaveLength(1);
    expect(m.alert).not.toHaveBeenCalled();
  });

  it("explains an unreadable saved key", async () => {
    m.load.mockResolvedValue({ status: "undecryptable" });
    const data = (await call())._getJSONData();
    expect(data.refreshError).toMatch(/no longer be read/);
    expect(m.sync).not.toHaveBeenCalled();
  });

  it("never includes a key or ciphertext in the response", async () => {
    m.tables.uptime_integrations = [{ last_sync_at: null, last_error: null, api_key: "SECRET-CIPHERTEXT" }];
    expect(JSON.stringify((await call())._getJSONData())).not.toContain("SECRET-CIPHERTEXT");
  });
});
