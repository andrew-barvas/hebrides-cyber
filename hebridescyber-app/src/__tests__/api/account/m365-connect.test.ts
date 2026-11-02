import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createMocks, type RequestMethod } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock, planGateMock, auditMock, queues, deletes } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  planGateMock: vi.fn(),
  auditMock: vi.fn(),
  queues: {} as Record<string, unknown[]>,
  deletes: [] as string[],
}));

function makeBuilder(table: string) {
  const next = () => Promise.resolve(queues[table]?.shift() ?? { data: null, error: null });
  const builder: Record<string, unknown> = {
    select: () => builder,
    delete: () => {
      deletes.push(table);
      return builder;
    },
    eq: () => builder,
    maybeSingle: next,
    then: (resolve: (v: unknown) => void) => next().then(resolve),
  };
  return builder;
}

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: { from: (table: string) => makeBuilder(table) },
}));
vi.mock("@/lib/planAccess", () => ({ planGate: planGateMock }));
vi.mock("@/lib/audit", () => ({ logAuditEvent: auditMock }));

import handler from "@/pages/api/account/m365-connect";
import { verifyState } from "@/lib/m365Consent";

const OWNER_ID = "44444444-4444-4444-4444-444444444444";
const CONFIG = { clientId: "11111111-1111-1111-1111-111111111111", clientSecret: "secret" };

function call(method: RequestMethod) {
  return createMocks<NextApiRequest, NextApiResponse>({ method });
}

describe("/api/account/m365-connect", () => {
  const saved = { id: process.env.M365_CLIENT_ID, secret: process.env.M365_CLIENT_SECRET };
  beforeEach(() => {
    for (const k of Object.keys(queues)) delete queues[k];
    deletes.length = 0;
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: OWNER_ID, via: "session" });
    planGateMock.mockReset().mockResolvedValue("ok");
    auditMock.mockReset();
    process.env.M365_CLIENT_ID = CONFIG.clientId;
    process.env.M365_CLIENT_SECRET = CONFIG.clientSecret;
  });
  afterEach(() => {
    if (saved.id === undefined) delete process.env.M365_CLIENT_ID;
    else process.env.M365_CLIENT_ID = saved.id;
    if (saved.secret === undefined) delete process.env.M365_CLIENT_SECRET;
    else process.env.M365_CLIENT_SECRET = saved.secret;
  });

  it("rejects other methods, anonymous callers and API keys", async () => {
    let r = call("PUT");
    await handler(r.req, r.res);
    expect(r.res._getStatusCode()).toBe(405);

    authenticateApiRequestMock.mockResolvedValueOnce(null);
    r = call("GET");
    await handler(r.req, r.res);
    expect(r.res._getStatusCode()).toBe(401);

    authenticateApiRequestMock.mockResolvedValueOnce({ ownerId: OWNER_ID, via: "key" });
    r = call("POST");
    await handler(r.req, r.res);
    expect(r.res._getStatusCode()).toBe(403);
  });

  it("GET reports the connection", async () => {
    queues.m365_tenants = [{ data: { tenant_id: "t", consented_at: "c", last_checked_at: null }, error: null }];
    const { req, res } = call("GET");
    await handler(req, res);
    expect(res._getStatusCode()).toBe(200);
    expect(JSON.parse(res._getData())).toEqual({ configured: true, connected: true, tenantId: "t", consentedAt: "c", lastCheckedAt: null });
  });

  it("GET degrades to not connected before the migration lands", async () => {
    queues.m365_tenants = [{ data: null, error: { code: "42P01", message: "relation does not exist" } }];
    const { req, res } = call("GET");
    await handler(req, res);
    expect(res._getStatusCode()).toBe(200);
    expect(JSON.parse(res._getData()).connected).toBe(false);
  });

  it("POST returns the consent URL and sets the nonce cookie that the state is bound to", async () => {
    const { req, res } = call("POST");
    await handler(req, res);
    expect(res._getStatusCode()).toBe(200);
    const url = new URL(JSON.parse(res._getData()).url);
    expect(url.hostname).toBe("login.microsoftonline.com");
    const cookie = String(res.getHeader("Set-Cookie"));
    const nonce = cookie.match(/^hc_m365_nonce=([^;]+)/)![1];
    expect(verifyState(url.searchParams.get("state"), nonce, CONFIG)).toEqual({ ok: true, ownerId: OWNER_ID });
    expect(auditMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ action: "m365_tenant.consent_started" }));
  });

  it("POST is plan-gated and 503s when the app isn't configured", async () => {
    planGateMock.mockResolvedValueOnce("denied");
    let r = call("POST");
    await handler(r.req, r.res);
    expect(r.res._getStatusCode()).toBe(403);

    planGateMock.mockResolvedValueOnce("error");
    r = call("POST");
    await handler(r.req, r.res);
    expect(r.res._getStatusCode()).toBe(500);

    delete process.env.M365_CLIENT_SECRET;
    r = call("POST");
    await handler(r.req, r.res);
    expect(r.res._getStatusCode()).toBe(503);
  });

  it("DELETE forgets the tenant, audits it and points at the revoke step", async () => {
    const { req, res } = call("DELETE");
    await handler(req, res);
    expect(res._getStatusCode()).toBe(200);
    expect(deletes).toEqual(["m365_tenants"]);
    expect(JSON.parse(res._getData()).revokeUrl).toContain("entra.microsoft.com");
    expect(auditMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ action: "m365_tenant.disconnected" }));
  });

  it("DELETE reports database failures", async () => {
    queues.m365_tenants = [{ data: null, error: { code: "XX000", message: "boom" } }];
    let r = call("DELETE");
    await handler(r.req, r.res);
    expect(r.res._getStatusCode()).toBe(500);

    queues.m365_tenants = [{ data: null, error: { code: "42P01", message: "missing" } }];
    r = call("DELETE");
    await handler(r.req, r.res);
    expect(r.res._getStatusCode()).toBe(503);
  });
});
