import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authMock, loadMock } = vi.hoisted(() => ({ authMock: vi.fn(), loadMock: vi.fn() }));
vi.mock("@/lib/apiAuth", () => ({ authenticateApiRequest: authMock, supabaseAdmin: { tag: "admin" } }));
vi.mock("@/lib/estateMap", () => ({ loadEstateMap: loadMock }));

import handler from "@/pages/api/estate/map";

async function call(method = "GET") {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: method as "GET" });
  await handler(req, res);
  return res;
}

describe("GET /api/estate/map", () => {
  beforeEach(() => {
    authMock.mockReset().mockResolvedValue({ ownerId: "o1", via: "session" });
    loadMock.mockReset().mockResolvedValue({ ok: true, map: { domains: [], totals: { hosts: 0, live: 0, certificatesExpiringSoon: 0, withCriticalOrHigh: 0 } } });
  });

  it("returns the caller's own map", async () => {
    const res = await call();
    expect(res._getStatusCode()).toBe(200);
    expect(loadMock).toHaveBeenCalledWith({ tag: "admin" }, "o1");
  });

  it("needs a caller and GET, and hides database errors", async () => {
    expect((await call("POST"))._getStatusCode()).toBe(405);
    authMock.mockResolvedValue(null);
    expect((await call())._getStatusCode()).toBe(401);
    authMock.mockResolvedValue({ ownerId: "o1", via: "session" });
    loadMock.mockResolvedValue({ ok: false, error: 'relation "asset_inventory" does not exist' });
    const res = await call();
    expect(res._getStatusCode()).toBe(500);
    expect(res._getData()).not.toContain("asset_inventory");
  });
});
