import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock, triageStates } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  triageStates: new Map<string, string>(),
}));

function makeQueryBuilder(result: unknown) {
  const builder: Record<string, unknown> = {
    select: () => builder,
    eq: () => builder,
    order: () => builder,
    limit: () => builder,
    maybeSingle: () => Promise.resolve(result),
  };
  return builder;
}

let supabaseTables: Record<string, unknown> = {};

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: { from: (table: string) => makeQueryBuilder(supabaseTables[table]) },
}));
vi.mock("@/lib/findingTriage", async (orig) => ({
  ...(await orig<typeof import("@/lib/findingTriage")>()),
  loadTriageIndexForTarget: async () => ({ host: "example.com", index: { get: () => null } }),
  applyTriage: <F extends { checkId?: string }>(findings: F[]) =>
    findings.map((f) => ({ ...f, triage: f.checkId && triageStates.has(f.checkId) ? { state: triageStates.get(f.checkId), reason: "x", expiresAt: null } : null })),
}));

import handler from "@/pages/api/v1/scans/[id]/plan";

const req = (query: Record<string, string>, method: "GET" | "POST" = "GET") =>
  createMocks<NextApiRequest, NextApiResponse>({ method, query, headers: { authorization: "Bearer t" } });

// 100 - 30 - 15 - 7 = 48
const findings = [
  { checkId: "crit", severity: "critical", title: "Critical thing", detail: "" },
  { checkId: "high", severity: "high", title: "High thing", detail: "" },
  { checkId: "med", severity: "medium", title: "Medium thing", detail: "" },
];

function ownScan(score: number | null = 48) {
  authenticateApiRequestMock.mockResolvedValue({ ownerId: "owner-1", via: "api_key" });
  supabaseTables.scans = { data: { id: "scan-1", owner: "owner-1", target_url: "https://example.com" } };
  supabaseTables.scan_results = { data: { score, results: { findings } } };
}

describe("GET /api/v1/scans/[id]/plan", () => {
  beforeEach(() => {
    authenticateApiRequestMock.mockReset();
    supabaseTables = {};
    triageStates.clear();
  });

  it("405 for non-GET, 401 unauthenticated, 400 for a bad target or too many ids", async () => {
    let r = req({ id: "scan-1" }, "POST");
    await handler(r.req, r.res);
    expect(r.res._getStatusCode()).toBe(405);

    authenticateApiRequestMock.mockResolvedValue(null);
    r = req({ id: "scan-1" });
    await handler(r.req, r.res);
    expect(r.res._getStatusCode()).toBe(401);

    authenticateApiRequestMock.mockResolvedValue({ ownerId: "owner-1", via: "session" });
    r = req({ id: "scan-1", target: "excellent" });
    await handler(r.req, r.res);
    expect(r.res._getStatusCode()).toBe(400);

    r = req({ id: "scan-1", fixed: Array.from({ length: 201 }, (_, i) => `c${i}`).join(",") });
    await handler(r.req, r.res);
    expect(r.res._getStatusCode()).toBe(400);
  });

  it("404 for a missing scan or result, 403 for someone else's, 409 with no score", async () => {
    authenticateApiRequestMock.mockResolvedValue({ ownerId: "owner-1", via: "session" });
    supabaseTables.scans = { data: null };
    let r = req({ id: "x" });
    await handler(r.req, r.res);
    expect(r.res._getStatusCode()).toBe(404);

    supabaseTables.scans = { data: { id: "scan-1", owner: "other", target_url: "https://example.com" } };
    r = req({ id: "scan-1" });
    await handler(r.req, r.res);
    expect(r.res._getStatusCode()).toBe(403);

    ownScan(null);
    r = req({ id: "scan-1" });
    await handler(r.req, r.res);
    expect(r.res._getStatusCode()).toBe(409);
  });

  it("defaults to the next rating and returns the fewest fixes", async () => {
    ownScan();
    const r = req({ id: "scan-1" });
    await handler(r.req, r.res);
    const body = r.res._getJSONData();
    expect(body).toMatchObject({ score: 48, rating: "At risk", estimate: true, target: { rating: "Needs attention", minScore: 50 }, candidates: 3 });
    expect(body.plan.fixes.map((f: { checkId: string }) => f.checkId)).toEqual(["crit"]);
    expect(body.plan).toMatchObject({ reachable: true, projected: 78, projectedRating: "Good" });
  });

  it("plans to a named target, projects given fixes, and never proposes triaged findings", async () => {
    ownScan();
    triageStates.set("crit", "accepted");
    const r = req({ id: "scan-1", target: "strong", fixed: "med,unknown" });
    await handler(r.req, r.res);
    const body = r.res._getJSONData();
    expect(body.target).toEqual({ rating: "Strong", minScore: 90 });
    expect(body.plan.fixes.map((f: { checkId: string }) => f.checkId)).toEqual(["high", "med"]);
    expect(body.plan.reachable).toBe(false);
    expect(body.ifFixed).toEqual({ checkIds: ["med"], projected: 55, projectedRating: "Needs attention" });
  });
});
