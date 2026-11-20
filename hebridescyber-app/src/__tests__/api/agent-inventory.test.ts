import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";
import { mintDeviceToken } from "@/lib/deviceAgent/tokens";
import { windowsInventory } from "@/lib/deviceAgent/testFixtures";

const { checkRateLimitMock, planGateMock } = vi.hoisted(() => ({ checkRateLimitMock: vi.fn(), planGateMock: vi.fn() }));

type Result = { data: unknown; error: { code?: string; message: string } | null };
let deviceLookup: Result;
let insertResult: Result;
let updateResult: Result;
let trimRows: Result;
let trimThrows = false;
const writes: Array<{ table: string; op: string; values?: unknown; filters: Array<[string, unknown]> }> = [];

function builder(table: string) {
  const filters: Array<[string, unknown]> = [];
  let op = "select";
  let values: unknown;
  const b: Record<string, unknown> = {
    select: () => b,
    eq: (c: string, v: unknown) => (filters.push([c, v]), b),
    is: (c: string, v: unknown) => {
      filters.push([c, v]);
      if (op === "update") {
        writes.push({ table, op, values, filters: [...filters] });
        return Promise.resolve(updateResult);
      }
      return b;
    },
    order: () => b,
    range: () => (trimThrows ? Promise.reject(new Error("timeout")) : Promise.resolve(trimRows)),
    in: (c: string, v: unknown) => {
      filters.push([c, v]);
      writes.push({ table, op, filters: [...filters] });
      return Promise.resolve({ error: null });
    },
    maybeSingle: () => Promise.resolve(deviceLookup),
    insert: (v: unknown) => {
      writes.push({ table, op: "insert", values: v, filters: [] });
      return Promise.resolve(insertResult);
    },
    update: (v: unknown) => {
      op = "update";
      values = v;
      return b;
    },
    delete: () => {
      op = "delete";
      return b;
    },
  };
  return b;
}

vi.mock("@/lib/supabaseAdmin", () => ({ supabaseAdmin: { from: (t: string) => builder(t) } }));
vi.mock("@/lib/rateLimit", () => ({ checkRateLimit: checkRateLimitMock, getClientIp: () => "203.0.113.9" }));
vi.mock("@/lib/deviceAgent/access", () => ({ deviceAgentGate: planGateMock }));

import handler, { IP_POLICY, TOKEN_POLICY, KEEP_INVENTORIES, config } from "@/pages/api/agent/inventory";

const token = mintDeviceToken();

function call(opts: { method?: string; auth?: string | null; body?: unknown; contentType?: string } = {}) {
  const headers: Record<string, string> = { "content-type": opts.contentType ?? "application/json" };
  if (opts.auth !== null) headers.authorization = opts.auth ?? `Bearer ${token.plaintext}`;
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: (opts.method ?? "POST") as "POST", headers, body: (opts.body ?? windowsInventory()) as Record<string, unknown> });
  return handler(req, res).then(() => res);
}

describe("POST /api/agent/inventory", () => {
  beforeEach(() => {
    checkRateLimitMock.mockReset().mockResolvedValue({ allowed: true, retryAfterSeconds: 0 });
    planGateMock.mockReset().mockResolvedValue("ok");
    deviceLookup = { data: { id: "dev-1", owner: "owner-1", name: "PC", token_hash: token.token_hash, revoked_at: null, pending_first_seen: {}, last_match: null, matched_at: null }, error: null };
    insertResult = { data: null, error: null };
    updateResult = { data: null, error: null };
    trimRows = { data: [], error: null };
    trimThrows = false;
    writes.length = 0;
    // The 14-day arithmetic depends on today; pin it.
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-11-20T09:00:00Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("caps the body at 2 MB through Next's body parser", () => {
    expect(config.api.bodyParser.sizeLimit).toBe("2mb");
  });

  it("only accepts POST", async () => {
    const res = await call({ method: "GET" });
    expect(res._getStatusCode()).toBe(405);
    expect(res.getHeader("Allow")).toBe("POST");
  });

  it("rate-limits by IP before reading the token", async () => {
    checkRateLimitMock.mockResolvedValueOnce({ allowed: false, retryAfterSeconds: 120 });
    const res = await call();
    expect(res._getStatusCode()).toBe(429);
    expect(res.getHeader("Retry-After")).toBe("120");
    expect(checkRateLimitMock).toHaveBeenCalledWith("203.0.113.9", "agent-inventory-ip", IP_POLICY);
    expect(writes).toEqual([]);
  });

  it("refuses a missing or malformed token without touching the database", async () => {
    for (const auth of [null, "Bearer nope", `Bearer hc_live_${"a".repeat(43)}`]) {
      const res = await call({ auth });
      expect(res._getStatusCode()).toBe(401);
    }
    expect(checkRateLimitMock).toHaveBeenCalledTimes(3); // the IP limit only
  });

  it("rate-limits per token, keyed on its hash, before the lookup", async () => {
    checkRateLimitMock.mockResolvedValueOnce({ allowed: true, retryAfterSeconds: 0 }).mockResolvedValueOnce({ allowed: false, retryAfterSeconds: 3000 });
    const res = await call();
    expect(res._getStatusCode()).toBe(429);
    expect(checkRateLimitMock).toHaveBeenLastCalledWith(token.token_hash.slice(0, 32), "agent-inventory-token", TOKEN_POLICY);
    expect(JSON.stringify(checkRateLimitMock.mock.calls)).not.toContain(token.plaintext);
  });

  it("wants JSON", async () => {
    expect((await call({ contentType: "text/plain" }))._getStatusCode()).toBe(415);
  });

  it("answers revoked and unknown tokens with the same 401", async () => {
    deviceLookup = { data: { ...(deviceLookup.data as object), revoked_at: "2026-11-01" }, error: null };
    const revoked = await call();
    deviceLookup = { data: null, error: null };
    const unknown = await call();
    expect(revoked._getStatusCode()).toBe(401);
    expect(unknown._getJSONData()).toEqual(revoked._getJSONData());
  });

  it("says 503 before the migration and hides other database errors", async () => {
    deviceLookup = { data: null, error: { code: "42P01", message: 'relation "agent_devices" does not exist' } };
    expect((await call())._getStatusCode()).toBe(503);
    deviceLookup = { data: null, error: { code: "XX000", message: "agent_devices exploded" } };
    const res = await call();
    expect(res._getStatusCode()).toBe(500);
    expect(JSON.stringify(res._getJSONData())).not.toContain("agent_devices");
  });

  it("refuses an account whose plan doesn't include it, and 503s when the plan can't be read", async () => {
    planGateMock.mockResolvedValueOnce("denied");
    const denied = await call();
    expect(denied._getStatusCode()).toBe(403);
    expect(planGateMock).toHaveBeenCalledWith(expect.anything(), "owner-1");
    planGateMock.mockResolvedValueOnce("error");
    expect((await call())._getStatusCode()).toBe(503);
    expect(writes).toEqual([]);
  });

  it("validates the body and names the bad field", async () => {
    const res = await call({ body: { ...windowsInventory(), software: [{ name: "x".repeat(500), version: "1", source: "registry" }] } });
    expect(res._getStatusCode()).toBe(400);
    expect((res._getJSONData() as { error: string }).error).toMatch(/^software\.0\.name:/);
    expect(writes).toEqual([]);
    expect((await call({ body: "not json" }))._getStatusCode()).toBe(400);
  });

  it("stores the validated report, updates the device and answers with the 14-day status", async () => {
    const res = await call({ body: { ...windowsInventory(), smuggled: "x" } });
    expect(res._getStatusCode()).toBe(200);
    expect(res._getJSONData()).toMatchObject({ device_id: "dev-1", patch_status: "at_risk" });

    const insert = writes.find((w) => w.op === "insert")!;
    expect(insert.table).toBe("agent_inventories");
    expect(insert.values).toMatchObject({ device_id: "dev-1", owner: "owner-1", collected_at: "2026-11-20T09:00:00Z" });
    expect((insert.values as { inventory: object }).inventory).not.toHaveProperty("smuggled");

    const update = writes.find((w) => w.op === "update")!;
    expect(update.table).toBe("agent_devices");
    expect(update.filters).toEqual([["id", "dev-1"], ["revoked_at", null]]);
    expect(update.values).toMatchObject({ hostname: "RECEPTION-PC", os_family: "windows", os_version: "10.0.22631.3447", agent_version: "0.1.0", patch_status: "at_risk", last_match: null });
    expect((update.values as { pending_first_seen: object }).pending_first_seen).toHaveProperty(["windows-update:KB5036893"]);
    expect((update.values as { evaluation: object }).evaluation).not.toHaveProperty("pendingFirstSeen");
  });

  it("carries the previous match forward, minus CVEs for software since upgraded", async () => {
    const lastMatch = {
      status: "checked",
      matchedAt: "2026-11-19T00:00:00Z",
      osEol: null,
      notes: [],
      coverage: { softwareTotal: 3, softwareChecked: 2 },
      cves: [
        { id: "CVE-OLD", advisoryId: "CVE-OLD", source: "nvd", software: "Google Chrome", version: "122.0.0.0", cvssScore: 9.8, severity: "critical", fixAvailable: true, fixedVersion: "123", publishedAt: "2026-01-01T00:00:00Z", summary: null },
        { id: "CVE-NOW", advisoryId: "CVE-NOW", source: "nvd", software: "7-Zip 23.01 (x64)", version: "23.01", cvssScore: 7.8, severity: "high", fixAvailable: true, fixedVersion: "24.07", publishedAt: "2026-01-01T00:00:00Z", summary: null },
      ],
    };
    deviceLookup = { data: { ...(deviceLookup.data as object), last_match: lastMatch }, error: null };
    const res = await call();
    expect((res._getJSONData() as { patch_status: string }).patch_status).toBe("fails");
    const update = writes.find((w) => w.op === "update")!;
    expect((update.values as { last_match: { cves: Array<{ id: string }> } }).last_match.cves.map((c) => c.id)).toEqual(["CVE-NOW"]);
  });

  it("deletes reports beyond the newest few", async () => {
    trimRows = { data: [{ id: 11 }, { id: 12 }], error: null };
    await call();
    const del = writes.find((w) => w.op === "delete")!;
    expect(del.filters).toContainEqual(["id", [11, 12]]);
    expect(KEEP_INVENTORIES).toBe(10);
  });

  it("a failed trim doesn't fail the upload", async () => {
    trimThrows = true;
    const res = await call();
    expect(res._getStatusCode()).toBe(200);
  });

  it("hides insert and update failures behind the generic 500", async () => {
    insertResult = { data: null, error: { code: "23514", message: "agent_inventories_inventory_check" } };
    const res = await call();
    expect(res._getStatusCode()).toBe(500);
    expect(JSON.stringify(res._getJSONData())).not.toContain("agent_inventories");
    insertResult = { data: null, error: null };
    updateResult = { data: null, error: { message: "agent_devices update failed" } };
    expect((await call())._getStatusCode()).toBe(500);
  });
});
