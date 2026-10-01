import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks, type RequestMethod } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock } = vi.hoisted(() => ({ authenticateApiRequestMock: vi.fn() }));

type Result = { data: unknown; error: { code?: string; message: string } | null };
let result: Result;
let filters: unknown[][];

function builder() {
  const b: Record<string, unknown> = {};
  for (const m of ["select", "eq", "order", "limit"]) {
    b[m] = (...args: unknown[]) => {
      filters.push([m, ...args]);
      return b;
    };
  }
  b.then = (resolve: (v: unknown) => unknown) => Promise.resolve(result).then(resolve);
  return b;
}

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: { from: (t: string) => (filters.push(["from", t]), builder()) },
}));

import handler from "@/pages/api/emerging-threats";

function call(method: RequestMethod = "GET") {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method });
  return handler(req, res).then(() => res);
}

const row = {
  id: "a1", target_host: "shop.example", cve_id: "CVE-2021-41773", confidence: "affected", product: "Apache HTTP Server",
  detected_version: "2.4.49", kev_date_added: "2026-09-30", scan_id: "s1", matched_at: "2026-10-01T06:40:00Z", notified_at: "2026-10-01T06:41:00Z",
};

describe("/api/emerging-threats", () => {
  beforeEach(() => {
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: "o1", via: "session" });
    result = { data: [row], error: null };
    filters = [];
  });

  it("requires authentication", async () => {
    authenticateApiRequestMock.mockResolvedValue(null);
    expect((await call())._getStatusCode()).toBe(401);
  });

  it("only allows GET", async () => {
    expect((await call("POST"))._getStatusCode()).toBe(405);
  });

  it("returns the caller's own rows, newest first", async () => {
    const res = await call();
    expect(res._getStatusCode()).toBe(200);
    expect(res._getJSONData()).toEqual({ available: true, alerts: [row] });
    expect(filters).toContainEqual(["from", "emerging_threat_alerts"]);
    expect(filters).toContainEqual(["eq", "owner", "o1"]);
    expect(filters).toContainEqual(["order", "matched_at", { ascending: false }]);
  });

  it("returns an empty list with a note before migration 045", async () => {
    result = { data: null, error: { code: "42P01", message: "relation does not exist" } };
    const res = await call();
    expect(res._getStatusCode()).toBe(200);
    expect(res._getJSONData()).toMatchObject({ available: false, alerts: [], note: expect.stringContaining("045") });
  });

  it("500s on any other database error", async () => {
    result = { data: null, error: { code: "XX000", message: "boom" } };
    expect((await call())._getStatusCode()).toBe(500);
  });
});
