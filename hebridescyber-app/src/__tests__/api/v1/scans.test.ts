import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const m = vi.hoisted(() => ({
  auth: vi.fn(),
  rateLimit: vi.fn(),
  freeTier: vi.fn(),
  ssrf: vi.fn(),
  verified: vi.fn(),
  trigger: vi.fn(),
  scansInserts: [] as unknown[],
  jobInserts: [] as unknown[],
  scanUpdates: [] as unknown[],
  list: { data: [] as unknown[], error: null as unknown },
  inflight: { data: null as unknown },
  insertScan: { data: { id: "scan-new" } as unknown, error: null as unknown },
  insertJob: { error: null as unknown },
  eqCalls: [] as string[],
  limitCalls: [] as number[],
}));

vi.mock("@/lib/ownership", () => ({
  validateNoSsrf: m.ssrf,
  isDomainVerified: m.verified,
  hostnameFromUrl: (u: string) => new URL(u).hostname,
}));
vi.mock("@/lib/rateLimit", () => ({ checkRateLimit: m.rateLimit, getClientIp: () => "1.2.3.4" }));
vi.mock("@/lib/freeTier", () => ({ isFreeTierExhausted: m.freeTier, FREE_TIER_EXHAUSTED_MESSAGE: "free tier used" }));
vi.mock("@/lib/onDemandScanTrigger", () => ({ triggerOnDemandWorkflow: m.trigger }));
vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: m.auth,
  supabaseAdmin: {
    from: (table: string) => {
      const b: Record<string, unknown> = {};
      let op = "select";
      for (const name of ["select", "order", "in", "gt"]) b[name] = () => b;
      b.eq = (col: string, val: unknown) => {
        m.eqCalls.push(`${col}=${String(val)}`);
        return b;
      };
      b.limit = (n: number) => {
        m.limitCalls.push(n);
        return b;
      };
      b.insert = (row: unknown) => {
        op = "insert";
        (table === "scans" ? m.scansInserts : m.jobInserts).push(row);
        return b;
      };
      b.update = (row: unknown) => {
        m.scanUpdates.push(row);
        return b;
      };
      b.single = () => Promise.resolve(m.insertScan);
      b.maybeSingle = () => Promise.resolve(m.inflight);
      b.then = (resolve: (v: unknown) => void) => resolve(op === "insert" && table === "scan_jobs" ? m.insertJob : m.list);
      return b;
    },
  },
}));

import handler from "@/pages/api/v1/scans";

const TARGET = "https://shop.example.com";

function call(method: string, opts: { body?: unknown; query?: Record<string, string> } = {}) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: method as "GET", body: opts.body as Record<string, unknown>, query: opts.query });
  return handler(req, res).then(() => res as Omit<typeof res, "_getJSONData"> & { _getJSONData(): any }); // eslint-disable-line @typescript-eslint/no-explicit-any
}

beforeEach(() => {
  m.auth.mockReset().mockResolvedValue({ ownerId: "owner-1", via: "api_key" });
  m.rateLimit.mockReset().mockResolvedValue({ allowed: true });
  m.freeTier.mockReset().mockResolvedValue(false);
  m.ssrf.mockReset().mockResolvedValue(undefined);
  m.verified.mockReset().mockResolvedValue(true);
  m.trigger.mockReset().mockResolvedValue(undefined);
  m.scansInserts.length = 0;
  m.jobInserts.length = 0;
  m.scanUpdates.length = 0;
  m.eqCalls.length = 0;
  m.limitCalls.length = 0;
  m.list = { data: [], error: null };
  m.inflight = { data: null };
  m.insertScan = { data: { id: "scan-new" }, error: null };
  m.insertJob = { error: null };
});

describe("/api/v1/scans", () => {
  it("401s without valid credentials", async () => {
    m.auth.mockResolvedValue(null);
    expect((await call("GET")).statusCode).toBe(401);
  });

  it("405s on an unsupported method", async () => {
    expect((await call("DELETE")).statusCode).toBe(405);
  });

  describe("scopes", () => {
    it("lets a read-only key list scans but not queue one", async () => {
      m.auth.mockResolvedValue({ ownerId: "owner-1", via: "key", scopes: ["scans:read"] });
      expect((await call("GET")).statusCode).toBe(200);
      const res = await call("POST", { body: { target_url: TARGET } });
      expect(res.statusCode).toBe(403);
      expect(res._getJSONData()).toMatchObject({ code: "insufficient_scope", required_scope: "scans:write" });
      expect(m.scansInserts).toEqual([]);
    });

    it("stops a write-only key reading scans", async () => {
      m.auth.mockResolvedValue({ ownerId: "owner-1", via: "key", scopes: ["scans:write"] });
      const res = await call("GET");
      expect(res.statusCode).toBe(403);
      expect(res._getJSONData().required_scope).toBe("scans:read");
    });
  });

  describe("GET", () => {
    it("flattens the nested score/summary and scopes to the caller", async () => {
      m.list = {
        data: [
          { id: "s1", target_url: TARGET, status: "completed", created_at: "t", scan_results: [{ score: 93, summary: "ok" }] },
          { id: "s2", target_url: TARGET, status: "queued", created_at: "t", scan_results: null },
        ],
        error: null,
      };
      const res = await call("GET");
      expect(res._getJSONData()).toEqual({
        count: 2,
        scans: [
          { scan_id: "s1", target_url: TARGET, status: "completed", created_at: "t", score: 93, summary: "ok" },
          { scan_id: "s2", target_url: TARGET, status: "queued", created_at: "t", score: null, summary: null },
        ],
      });
      expect(m.eqCalls).toContain("owner=owner-1");
    });

    it("defaults the page size to 20 and caps it at 100", async () => {
      await call("GET");
      await call("GET", { query: { limit: "5000" } });
      expect(m.limitCalls).toEqual([20, 100]);
    });

    it("filters by target_url when given, and 500s on a database error", async () => {
      await call("GET", { query: { target_url: TARGET } });
      expect(m.eqCalls).toContain(`target_url=${TARGET}`);
      m.list = { data: [], error: { message: "db" } };
      expect((await call("GET")).statusCode).toBe(500);
    });
  });

  describe("POST", () => {
    const post = (body: unknown = { target_url: TARGET }) => call("POST", { body });

    it("400s on a missing or malformed target_url", async () => {
      expect((await post({})).statusCode).toBe(400);
      expect((await post({ target_url: "not a url" })).statusCode).toBe(400);
    });

    it("429s with Retry-After when rate limited, before touching the database", async () => {
      m.rateLimit.mockResolvedValue({ allowed: false, retryAfterSeconds: 42 });
      const res = await post();
      expect(res.statusCode).toBe(429);
      expect(res.getHeader("Retry-After")).toBe("42");
      expect(m.scansInserts).toEqual([]);
    });

    it("402s when the free tier is used up", async () => {
      m.freeTier.mockResolvedValue(true);
      const res = await post();
      expect(res.statusCode).toBe(402);
      expect(res._getJSONData().code).toBe("free_tier_exhausted");
    });

    it("400s on an SSRF-blocked target", async () => {
      m.ssrf.mockRejectedValue(new Error("private address"));
      const res = await post({ target_url: "http://127.0.0.1" });
      expect(res.statusCode).toBe(400);
      expect(res._getJSONData().error).toContain("private address");
    });

    it("403s for a domain the account hasn't verified, naming the domain", async () => {
      m.verified.mockResolvedValue(false);
      const res = await post();
      expect(res.statusCode).toBe(403);
      expect(res._getJSONData().domain).toBe("shop.example.com");
      expect(m.scansInserts).toEqual([]);
    });

    it("returns the in-flight scan instead of stacking a duplicate", async () => {
      m.inflight = { data: { id: "scan-old", status: "running" } };
      const res = await post();
      expect(res.statusCode).toBe(202);
      expect(res._getJSONData()).toMatchObject({ scan_id: "scan-old", status: "running", deduped: true });
      expect(m.scansInserts).toEqual([]);
      expect(m.trigger).not.toHaveBeenCalled();
    });

    it("creates the scan, enqueues a job pointing at it, kicks the workflow and answers 202", async () => {
      const res = await post();
      expect(res.statusCode).toBe(202);
      expect(res._getJSONData()).toMatchObject({ scan_id: "scan-new", status: "queued" });
      expect(m.scansInserts[0]).toMatchObject({ owner: "owner-1", target_url: TARGET, status: "queued", owner_verified: true });
      expect(m.jobInserts[0]).toMatchObject({ owner: "owner-1", scan_id: "scan-new", status: "pending" });
      expect(m.trigger).toHaveBeenCalledTimes(1);
    });

    it("500s when the scan row can't be created", async () => {
      m.insertScan = { data: null, error: { message: "boom" } };
      expect((await post()).statusCode).toBe(500);
      expect(m.jobInserts).toEqual([]);
    });

    it("marks the scan failed, and does not dispatch, when queueing the job fails", async () => {
      m.insertJob = { error: { message: "queue down" } };
      const res = await post();
      expect(res.statusCode).toBe(500);
      expect(res._getJSONData().error).toContain("queue down");
      expect(m.scanUpdates).toContainEqual({ status: "failed" });
      expect(m.trigger).not.toHaveBeenCalled();
    });
  });
});
