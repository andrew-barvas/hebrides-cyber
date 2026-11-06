import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authMock, gateMock, recordMock, revokeMock, linkMock, target } = vi.hoisted(() => ({
  linkMock: vi.fn(),
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
vi.mock("@/lib/offensiveAuthorization", () => ({ authHostFromUrl: (u: string) => new URL(u).hostname, recordOffensiveAuthorization: recordMock, revokeOffensiveAuthorization: revokeMock }));
vi.mock("@/lib/engagements", async (original) => ({ ...(await original<typeof import("@/lib/engagements")>()), checkAuthorizationLink: linkMock }));

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

describe("/api/account/offensive-authorization with an engagement", () => {
  const ENGAGEMENT = "e1000000-0000-4000-8000-000000000001";
  const body = { targetUrl: URL_OK, acknowledge: true, engagementId: ENGAGEMENT };

  it("links the authorisation once the engagement accepts this host", async () => {
    linkMock.mockReset().mockResolvedValue({ status: "ok", data: { ok: true } });
    expect((await call("POST", body)).statusCode).toBe(200);
    expect(linkMock.mock.calls[0].slice(1)).toEqual(["owner-1", ENGAGEMENT, "shop.example.com"]);
    expect(recordMock.mock.calls[0][1]).toMatchObject({ engagementId: ENGAGEMENT });
  });

  it.each([
    ["host_not_in_scope", 409],
    ["state_disallows", 409],
  ])("records nothing on %s", async (reason, status) => {
    linkMock.mockReset().mockResolvedValue({ status: "ok", data: { ok: false, reason } });
    const res = await call("POST", body);
    expect(res.statusCode).toBe(status);
    expect(res._getJSONData().reason).toBe(reason);
    expect(recordMock).not.toHaveBeenCalled();
  });

  it("is 404 for someone else's engagement and records nothing on a failed read", async () => {
    linkMock.mockReset().mockResolvedValue({ status: "not_found" });
    expect((await call("POST", body)).statusCode).toBe(404);
    linkMock.mockReset().mockResolvedValue({ status: "error", error: { message: "down" } });
    expect((await call("POST", body)).statusCode).toBe(500);
    expect(recordMock).not.toHaveBeenCalled();
  });

  it("doesn't consult an engagement when none is named", async () => {
    linkMock.mockReset();
    expect((await call("POST", { targetUrl: URL_OK, acknowledge: true })).statusCode).toBe(200);
    expect(linkMock).not.toHaveBeenCalled();
    expect(recordMock.mock.calls[0][1].engagementId).toBeUndefined();
  });
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
