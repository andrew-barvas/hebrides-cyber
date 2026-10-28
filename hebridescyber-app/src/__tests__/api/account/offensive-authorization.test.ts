import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authMock, gateMock, recordMock, revokeMock, target } = vi.hoisted(() => ({
  authMock: vi.fn(),
  gateMock: vi.fn(),
  recordMock: vi.fn(),
  revokeMock: vi.fn(),
  target: { current: { data: { id: "t1", owner: "owner-1" }, error: null } as { data: unknown; error: unknown } },
}));

vi.mock("@/lib/apiAuth", () => {
  const b: Record<string, unknown> = {};
  for (const m of ["select", "eq"]) b[m] = () => b;
  b.maybeSingle = () => Promise.resolve(target.current);
  return { authenticateApiRequest: authMock, supabaseAdmin: { from: () => b } };
});
vi.mock("@/lib/planAccess", () => ({ planGate: gateMock }));
vi.mock("@/lib/offensiveAuthorization", () => ({ recordOffensiveAuthorization: recordMock, revokeOffensiveAuthorization: revokeMock }));

import handler from "@/pages/api/account/offensive-authorization";

const URL_OK = "https://shop.example.com";

function call(method: string, body?: unknown) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: method as "POST", body: body as Record<string, unknown> });
  return handler(req, res).then(() => res);
}

beforeEach(() => {
  authMock.mockReset().mockResolvedValue({ ownerId: "owner-1", via: "session" });
  gateMock.mockReset().mockResolvedValue("ok");
  recordMock.mockReset().mockResolvedValue({ ok: true, host: "shop.example.com" });
  revokeMock.mockReset().mockResolvedValue({ ok: true });
  target.current = { data: { id: "t1", owner: "owner-1" }, error: null };
});

describe("/api/account/offensive-authorization", () => {
  it("only allows POST and DELETE", async () => {
    const res = await call("GET");
    expect(res.statusCode).toBe(405);
    expect(res.getHeader("Allow")).toBe("POST, DELETE");
  });

  it("401s when unauthenticated", async () => {
    authMock.mockResolvedValue(null);
    expect((await call("POST", { targetUrl: URL_OK, acknowledge: true })).statusCode).toBe(401);
  });

  it("refuses an API key — consent to attack traffic needs a real session", async () => {
    authMock.mockResolvedValue({ ownerId: "owner-1", via: "api_key" });
    const res = await call("POST", { targetUrl: URL_OK, acknowledge: true });
    expect(res.statusCode).toBe(403);
    expect(recordMock).not.toHaveBeenCalled();
  });

  it("400s unless acknowledge is literally true", async () => {
    for (const acknowledge of [false, "true", undefined]) {
      expect((await call("POST", { targetUrl: URL_OK, acknowledge })).statusCode).toBe(400);
    }
    expect(recordMock).not.toHaveBeenCalled();
  });

  it("404s for a URL the caller doesn't monitor, before any plan check", async () => {
    target.current = { data: null, error: null };
    const res = await call("POST", { targetUrl: URL_OK, acknowledge: true });
    expect(res.statusCode).toBe(404);
    expect(gateMock).not.toHaveBeenCalled();
  });

  it("500s when the ownership lookup itself fails", async () => {
    target.current = { data: null, error: { message: "db" } };
    expect((await call("POST", { targetUrl: URL_OK, acknowledge: true })).statusCode).toBe(500);
  });

  it("403s a non-Tier-A owner and 500s when the plan can't be checked", async () => {
    gateMock.mockResolvedValue("denied");
    expect((await call("POST", { targetUrl: URL_OK, acknowledge: true })).statusCode).toBe(403);
    gateMock.mockResolvedValue("error");
    expect((await call("POST", { targetUrl: URL_OK, acknowledge: true })).statusCode).toBe(500);
    expect(recordMock).not.toHaveBeenCalled();
  });

  it("records the authorization with the default scope and no expiry", async () => {
    const res = await call("POST", { targetUrl: URL_OK, acknowledge: true });
    expect(res.statusCode).toBe(200);
    expect(res._getJSONData()).toEqual({ ok: true, host: "shop.example.com" });
    expect(recordMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ owner: "owner-1", authorizedBy: "owner-1", expiresAt: null, scope: expect.stringContaining("Authorised offensive") }));
  });

  it("passes through a custom scope and expiry", async () => {
    await call("POST", { targetUrl: URL_OK, acknowledge: true, scope: "login only", expiresAt: "2027-01-01T00:00:00Z" });
    expect(recordMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ scope: "login only", expiresAt: "2027-01-01T00:00:00Z" }));
  });

  it.each([
    ["unavailable", 503],
    ["invalid_url", 400],
    ["db", 500],
  ])("maps a record failure of %s to %i", async (reason, status) => {
    recordMock.mockResolvedValue({ ok: false, reason });
    expect((await call("POST", { targetUrl: URL_OK, acknowledge: true })).statusCode).toBe(status);
  });

  it("DELETE revokes without needing Tier A or an acknowledgement", async () => {
    gateMock.mockResolvedValue("denied");
    const res = await call("DELETE", { targetUrl: URL_OK });
    expect(res.statusCode).toBe(200);
    expect(res._getJSONData()).toEqual({ ok: true, revoked: true });
    expect(gateMock).not.toHaveBeenCalled();
  });

  it("DELETE maps a revoke failure to its status", async () => {
    revokeMock.mockResolvedValue({ ok: false, reason: "unavailable" });
    expect((await call("DELETE", { targetUrl: URL_OK })).statusCode).toBe(503);
  });
});
