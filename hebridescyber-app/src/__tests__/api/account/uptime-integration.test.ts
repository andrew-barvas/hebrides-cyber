import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const m = vi.hoisted(() => ({
  auth: vi.fn(),
  planGate: vi.fn(),
  rate: vi.fn(),
  audit: vi.fn(),
  validate: vi.fn(),
  upsert: vi.fn(),
  deletes: [] as string[],
}));

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: m.auth,
  supabaseAdmin: {
    from: (table: string) => {
      const b: Record<string, unknown> = {};
      b.upsert = (row: unknown, opts: unknown) => m.upsert(row, opts);
      b.delete = () => (m.deletes.push(table), b);
      b.eq = () => b;
      b.then = (resolve: (v: unknown) => void) => resolve({ error: null });
      return b;
    },
  },
}));
vi.mock("@/lib/planAccess", () => ({ planGate: m.planGate }));
vi.mock("@/lib/rateLimit", () => ({ checkRateLimit: m.rate }));
vi.mock("@/lib/audit", () => ({ logAuditEvent: m.audit }));
vi.mock("@/lib/uptimeRobot", () => ({ uptimeRobotProvider: () => ({ validate: m.validate }) }));

import handler from "@/pages/api/account/uptime-integration";
import { decryptSecret, isEncryptedSecret } from "@/lib/credentialEncryption";

const TEST_KEY = Buffer.alloc(32, 7).toString("base64");
const original = process.env.CREDENTIALS_ENC_KEY;

function call(method: string, body?: unknown) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: method as "POST", body: body as Record<string, unknown> });
  return handler(req, res).then(() => res);
}

beforeEach(() => {
  process.env.CREDENTIALS_ENC_KEY = TEST_KEY;
  m.auth.mockReset().mockResolvedValue({ ownerId: "owner-1", via: "session" });
  m.planGate.mockReset().mockResolvedValue("ok");
  m.rate.mockReset().mockResolvedValue({ allowed: true, retryAfterSeconds: 0 });
  m.audit.mockReset();
  m.validate.mockReset().mockResolvedValue({ ok: true, value: true });
  m.upsert.mockReset().mockResolvedValue({ error: null });
  m.deletes.length = 0;
});
afterEach(() => {
  if (original === undefined) delete process.env.CREDENTIALS_ENC_KEY;
  else process.env.CREDENTIALS_ENC_KEY = original;
});

describe("/api/account/uptime-integration", () => {
  it("rejects other methods", async () => {
    expect((await call("GET")).statusCode).toBe(405);
  });

  it("requires authentication, and a session rather than an API key", async () => {
    m.auth.mockResolvedValue(null);
    expect((await call("POST", { apiKey: "a-long-enough-key" })).statusCode).toBe(401);
    m.auth.mockResolvedValue({ ownerId: "owner-1", via: "api_key" });
    expect((await call("POST", { apiKey: "a-long-enough-key" })).statusCode).toBe(403);
  });

  it("rejects a missing or tiny key", async () => {
    expect((await call("POST", {})).statusCode).toBe(400);
    expect((await call("POST", { apiKey: "x" })).statusCode).toBe(400);
  });

  it("is Pro and above: a denied plan gets 403, a gate error 500, and nothing is saved", async () => {
    m.planGate.mockResolvedValue("denied");
    expect((await call("POST", { apiKey: "a-long-enough-key" })).statusCode).toBe(403);
    m.planGate.mockResolvedValue("error");
    expect((await call("POST", { apiKey: "a-long-enough-key" })).statusCode).toBe(500);
    expect(m.upsert).not.toHaveBeenCalled();
    expect(m.validate).not.toHaveBeenCalled();
  });

  it("returns 503 without an encryption key and never stores plaintext", async () => {
    delete process.env.CREDENTIALS_ENC_KEY;
    expect((await call("POST", { apiKey: "a-long-enough-key" })).statusCode).toBe(503);
    expect(m.upsert).not.toHaveBeenCalled();
  });

  it("rate limits connection attempts", async () => {
    m.rate.mockResolvedValue({ allowed: false, retryAfterSeconds: 90 });
    const res = await call("POST", { apiKey: "a-long-enough-key" });
    expect(res.statusCode).toBe(429);
    expect(res.getHeader("Retry-After")).toBe("90");
    expect(m.validate).not.toHaveBeenCalled();
  });

  it("rejects a key UptimeRobot refuses, without saving it", async () => {
    m.validate.mockResolvedValue({ ok: false, kind: "auth", error: "UptimeRobot rejected this API key." });
    const res = await call("POST", { apiKey: "a-long-enough-key" });
    expect(res.statusCode).toBe(400);
    expect(m.upsert).not.toHaveBeenCalled();
  });

  it("maps provider outages and rate limits to 502 and 429", async () => {
    m.validate.mockResolvedValue({ ok: false, kind: "unavailable", error: "down" });
    expect((await call("POST", { apiKey: "a-long-enough-key" })).statusCode).toBe(502);
    m.validate.mockResolvedValue({ ok: false, kind: "rate_limited", error: "slow" });
    expect((await call("POST", { apiKey: "a-long-enough-key" })).statusCode).toBe(429);
  });

  it("stores the key encrypted, audits the connection and never echoes the key", async () => {
    const res = await call("POST", { apiKey: "a-long-enough-key" });
    expect(res.statusCode).toBe(200);
    expect(JSON.stringify(res._getJSONData())).not.toContain("a-long-enough-key");
    const [row, opts] = m.upsert.mock.calls[0];
    expect(opts).toEqual({ onConflict: "owner,provider" });
    expect(row).toMatchObject({ owner: "owner-1", provider: "uptimerobot" });
    expect(isEncryptedSecret(row.api_key)).toBe(true);
    expect(decryptSecret(row.api_key)).toBe("a-long-enough-key");
    expect(m.audit).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ action: "uptime.connected", actorId: "owner-1" }));
    expect(JSON.stringify(m.audit.mock.calls)).not.toContain("a-long-enough-key");
  });

  it("DELETE removes the connection and the monitor records (not the monitors in their account) and audits it", async () => {
    const res = await call("DELETE");
    expect(res.statusCode).toBe(200);
    expect(m.deletes.sort()).toEqual(["uptime_integrations", "uptime_monitors"]);
    expect(m.audit).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ action: "uptime.disconnected" }));
  });

  it("DELETE stays available on any plan", async () => {
    m.planGate.mockResolvedValue("denied");
    expect((await call("DELETE")).statusCode).toBe(200);
  });
});
