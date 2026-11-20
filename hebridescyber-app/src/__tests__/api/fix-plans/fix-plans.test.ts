import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authMock, gateMock, canActMock, auditMock, tables, inserts } = vi.hoisted(() => ({
  authMock: vi.fn(),
  gateMock: vi.fn(),
  canActMock: vi.fn(),
  auditMock: vi.fn(),
  tables: {} as Record<string, { single?: unknown; list?: unknown[] }>,
  inserts: [] as Array<{ table: string; row: unknown }>,
}));

function builder(table: string) {
  const q: Record<string, unknown> = {};
  for (const m of ["select", "eq", "order", "limit", "in", "is"]) q[m] = () => q;
  q.maybeSingle = async () => ({ data: tables[table]?.single ?? null, error: null });
  q.single = async () => ({ data: { id: "plan-1" }, error: null });
  q.insert = (row: unknown) => {
    inserts.push({ table, row });
    return table === "fix_plans" ? q : Promise.resolve({ error: null });
  };
  q.delete = () => q;
  q.then = (r: (v: unknown) => void) => r({ data: tables[table]?.list ?? [], error: null });
  return q;
}

vi.mock("@/lib/apiAuth", () => ({ authenticateApiRequest: authMock, supabaseAdmin: { from: (t: string) => builder(t) } }));
vi.mock("@/lib/planAccess", () => ({ planGate: gateMock }));
vi.mock("@/lib/teamAccess", () => ({ callerCanActFor: canActMock }));
vi.mock("@/lib/audit", () => ({ logAuditEvent: auditMock }));

import handler from "@/pages/api/fix-plans/index";

const SCAN = "11111111-1111-4111-8111-111111111111";
const call = async (method: "GET" | "POST" | "PUT", body?: unknown, query: Record<string, string> = {}) => {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method, body: body as never, query, headers: { authorization: "Bearer t" } });
  await handler(req, res);
  return res;
};

describe("/api/fix-plans", () => {
  beforeEach(() => {
    authMock.mockReset().mockResolvedValue({ ownerId: "o1", via: "session" });
    gateMock.mockReset().mockResolvedValue("ok");
    canActMock.mockReset().mockResolvedValue(false);
    auditMock.mockReset();
    inserts.length = 0;
    for (const k of Object.keys(tables)) delete tables[k];
    tables.scans = { single: { id: SCAN, owner: "o1", target_url: "https://shop.example.com/" } };
    tables.scan_results = {
      single: { results: { findings: [{ checkId: "headers.hsts", severity: "medium", title: "Missing HSTS", remediation: "Add the header." }, { checkId: "tls.old", severity: "high", title: "Old TLS" }] } },
    };
  });

  it("401 unauthenticated, 405 other methods, 403 below Agency", async () => {
    authMock.mockResolvedValueOnce(null);
    expect((await call("GET"))._getStatusCode()).toBe(401);
    expect((await call("PUT"))._getStatusCode()).toBe(405);
    gateMock.mockResolvedValue("denied");
    expect((await call("GET"))._getStatusCode()).toBe(403);
    expect((await call("POST", { scanId: SCAN, checkIds: ["headers.hsts"] }))._getStatusCode()).toBe(403);
  });

  it("creates a plan from the scan's findings, snapshotting the fix text, and returns the link once", async () => {
    const res = await call("POST", { scanId: SCAN, checkIds: ["tls.old", "headers.hsts", "tls.old"], title: "Before go-live", expiresInDays: 30 });
    expect(res._getStatusCode()).toBe(201);
    const body = res._getJSONData() as { id: string; url: string; expiresAt: string };
    expect(body.url).toMatch(/\/plan\/[A-Za-z0-9_-]{43}$/);
    const plan = inserts.find((i) => i.table === "fix_plans")?.row as Record<string, string>;
    expect(plan).toMatchObject({ owner: "o1", target_host: "shop.example.com", title: "Before go-live" });
    expect(plan.token_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(body.url).not.toContain(plan.token_hash);
    const items = inserts.find((i) => i.table === "fix_plan_items")?.row as Array<Record<string, unknown>>;
    expect(items.map((i) => [i.check_id, i.position, i.remediation])).toEqual([
      ["tls.old", 1, ""],
      ["headers.hsts", 2, "Add the header."],
    ]);
    expect(auditMock.mock.calls[0][1]).toMatchObject({ action: "fix_plan.created" });
  });

  it("refuses findings that aren't on the scan, and someone else's scan", async () => {
    let res = await call("POST", { scanId: SCAN, checkIds: ["nope"] });
    expect(res._getStatusCode()).toBe(400);
    tables.scans = { single: { id: SCAN, owner: "someone-else", target_url: "https://x.example" } };
    res = await call("POST", { scanId: SCAN, checkIds: ["headers.hsts"] });
    expect(res._getStatusCode()).toBe(403);
    expect(inserts).toEqual([]);
  });

  it("lists the owner's plans with progress", async () => {
    tables.fix_plans = { list: [{ id: "p1", owner: "o1", target_host: "shop.example.com", title: "", created_at: "2026-11-01T00:00:00Z", expires_at: "2027-01-01T00:00:00Z", revoked_at: null }] };
    tables.fix_plan_items = { list: [{ check_id: "headers.hsts", position: 1, severity: "medium", title: "Missing HSTS", remediation: "", client_done_at: null, client_note: "" }] };
    tables.finding_lifecycle = { list: [{ check_id: "headers.hsts", resolved_at: "2026-11-03T00:00:00Z" }] };
    const res = await call("GET", undefined, { host: "shop.example.com" });
    expect(res._getStatusCode()).toBe(200);
    expect((res._getJSONData() as { plans: Array<{ progress: unknown }> }).plans[0].progress).toEqual({ fixed: 1, markedDone: 0, open: 0, total: 1 });
  });
});
