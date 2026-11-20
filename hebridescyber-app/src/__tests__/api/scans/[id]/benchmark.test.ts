import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authMock, canActMock, rpcMock, tables } = vi.hoisted(() => ({
  authMock: vi.fn(),
  canActMock: vi.fn(),
  rpcMock: vi.fn(),
  tables: {} as Record<string, unknown>,
}));

function builder(table: string) {
  const q: Record<string, unknown> = {};
  for (const m of ["select", "eq", "order", "limit"]) q[m] = () => q;
  q.maybeSingle = async () => ({ data: tables[table] ?? null, error: null });
  return q;
}

vi.mock("@/lib/apiAuth", () => ({ authenticateApiRequest: authMock, supabaseAdmin: { from: (t: string) => builder(t), rpc: rpcMock } }));
vi.mock("@/lib/teamAccess", () => ({ callerCanActFor: canActMock }));

import handler from "@/pages/api/scans/[id]/benchmark";

const call = async (method: "GET" | "POST" = "GET") => {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method, query: { id: "scan-1" }, headers: { authorization: "Bearer t" } });
  await handler(req, res);
  return res;
};

describe("GET /api/scans/[id]/benchmark", () => {
  beforeEach(() => {
    authMock.mockReset().mockResolvedValue({ ownerId: "o1", via: "session" });
    canActMock.mockReset().mockResolvedValue(false);
    rpcMock.mockReset().mockResolvedValue({ data: [{ total: 120, lower: 30 }], error: null });
    tables.scans = { id: "scan-1", owner: "o1" };
    tables.scan_results = { score: 72 };
  });
  afterEach(() => vi.unstubAllEnvs());

  it("405 / 401 as usual", async () => {
    expect((await call("POST"))._getStatusCode()).toBe(405);
    authMock.mockResolvedValueOnce(null);
    expect((await call())._getStatusCode()).toBe(401);
  });

  it("answers null without touching the database while the feature is off", async () => {
    const res = await call();
    expect(res._getJSONData()).toEqual({ benchmark: null });
    expect(rpcMock).not.toHaveBeenCalled();
  });

  it("when on, compares the scan's score with other owners' sites", async () => {
    vi.stubEnv("SCORE_BENCHMARK_ENABLED", "true");
    const res = await call();
    expect((res._getJSONData() as { benchmark: unknown }).benchmark).toEqual({ betterThanPercent: 25, groupSize: 120, windowDays: 90, kind: "scan" });
    expect(rpcMock).toHaveBeenCalledWith("scan_score_counts", { p_score: 72, p_days: 90, p_exclude_owner: "o1" });
  });

  it("when on, refuses someone else's scan", async () => {
    vi.stubEnv("SCORE_BENCHMARK_ENABLED", "true");
    tables.scans = { id: "scan-1", owner: "other" };
    expect((await call())._getStatusCode()).toBe(403);
    expect(rpcMock).not.toHaveBeenCalled();
  });
});
