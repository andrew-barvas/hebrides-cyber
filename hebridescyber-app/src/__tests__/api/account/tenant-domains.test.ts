import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authMock, gateMock, loadMock } = vi.hoisted(() => ({ authMock: vi.fn(), gateMock: vi.fn(), loadMock: vi.fn() }));

vi.mock("@/lib/apiAuth", () => ({ authenticateApiRequest: authMock, supabaseAdmin: {} }));
vi.mock("@/lib/planAccess", () => ({ planGate: gateMock }));
vi.mock("@/lib/tenantDomains", () => ({ loadTenantDomains: loadMock }));

import handler from "@/pages/api/account/tenant-domains";

const call = async (method: "GET" | "POST" = "GET") => {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method, headers: { authorization: "Bearer t" } });
  await handler(req, res);
  return res;
};

describe("GET /api/account/tenant-domains", () => {
  beforeEach(() => {
    authMock.mockReset().mockResolvedValue({ ownerId: "o1", via: "session" });
    gateMock.mockReset().mockResolvedValue("ok");
    loadMock.mockReset().mockResolvedValue({ status: "ok", source: "m365", truncated: false, domains: [{ domain: "example.com", monitored: false }] });
  });

  it("405 for other methods and 401 unauthenticated", async () => {
    expect((await call("POST"))._getStatusCode()).toBe(405);
    authMock.mockResolvedValue(null);
    expect((await call())._getStatusCode()).toBe(401);
  });

  it("403 below Pro, 500 when the plan can't be read", async () => {
    gateMock.mockResolvedValue("denied");
    expect((await call())._getStatusCode()).toBe(403);
    gateMock.mockResolvedValue("error");
    expect((await call())._getStatusCode()).toBe(500);
    expect(loadMock).not.toHaveBeenCalled();
  });

  it("returns the suggestions for the caller, uncached", async () => {
    const res = await call();
    expect(res._getStatusCode()).toBe(200);
    expect((res._getJSONData() as { domains: unknown }).domains).toEqual([{ domain: "example.com", monitored: false }]);
    expect(res.getHeader("Cache-Control")).toBe("private, no-store");
    expect(loadMock).toHaveBeenCalledWith(expect.anything(), "o1");
  });
});
