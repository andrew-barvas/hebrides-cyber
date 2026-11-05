import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { getAppTokenMock, rateLimitMock, auditMock, upserts, upsertResult } = vi.hoisted(() => ({
  getAppTokenMock: vi.fn(),
  rateLimitMock: vi.fn(),
  auditMock: vi.fn(),
  upserts: [] as Array<{ row: Record<string, unknown>; opts: unknown }>,
  upsertResult: { current: { error: null } as { error: { code?: string; message: string } | null } },
}));

vi.mock("@/lib/apiAuth", () => ({
  supabaseAdmin: {
    from: () => ({
      upsert: (row: Record<string, unknown>, opts: unknown) => {
        upserts.push({ row, opts });
        return Promise.resolve(upsertResult.current);
      },
    }),
  },
}));
vi.mock("@/lib/rateLimit", () => ({ checkRateLimit: rateLimitMock, getClientIp: () => "203.0.113.9" }));
vi.mock("@/lib/audit", () => ({ logAuditEvent: auditMock }));
vi.mock("@/lib/m365Graph", async (importOriginal) => ({ ...(await importOriginal<typeof import("@/lib/m365Graph")>()), getAppToken: getAppTokenMock }));

import handler from "@/pages/api/account/m365-callback";
import { signState } from "@/lib/m365Consent";
import { M365_REQUIRED_APP_ROLES as ROLES } from "@/lib/m365Graph";

const OWNER_ID = "44444444-4444-4444-4444-444444444444";
const TENANT = "22222222-2222-2222-2222-222222222222";
const CONFIG = { clientId: "11111111-1111-1111-1111-111111111111", clientSecret: "secret" };
const NONCE = "nonce-1";

function callback(query: Record<string, string>, cookies: Record<string, string> = { hc_m365_nonce: NONCE }) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "GET", query, cookies });
  return { req, res };
}

const goodQuery = () => ({ tenant: TENANT, admin_consent: "True", state: signState(OWNER_ID, NONCE, CONFIG), scope: "https://graph.microsoft.com/.default" });
const outcome = (res: ReturnType<typeof callback>["res"]) => new URL(String(res._getRedirectUrl())).searchParams.get("m365");

describe("GET /api/account/m365-callback", () => {
  const saved = { id: process.env.M365_CLIENT_ID, secret: process.env.M365_CLIENT_SECRET };
  beforeEach(() => {
    upserts.length = 0;
    upsertResult.current = { error: null };
    rateLimitMock.mockReset().mockResolvedValue({ allowed: true, retryAfterSeconds: 0 });
    auditMock.mockReset();
    getAppTokenMock.mockReset().mockResolvedValue({ ok: true, body: { accessToken: "t", roles: [...ROLES], tenantId: TENANT } });
    process.env.M365_CLIENT_ID = CONFIG.clientId;
    process.env.M365_CLIENT_SECRET = CONFIG.clientSecret;
  });
  afterEach(() => {
    if (saved.id === undefined) delete process.env.M365_CLIENT_ID;
    else process.env.M365_CLIENT_ID = saved.id;
    if (saved.secret === undefined) delete process.env.M365_CLIENT_SECRET;
    else process.env.M365_CLIENT_SECRET = saved.secret;
  });

  it("stores only the tenant ID after a verified consent and redirects to www", async () => {
    const { req, res } = callback(goodQuery());
    await handler(req, res);
    expect(res._getStatusCode()).toBe(302);
    expect(String(res._getRedirectUrl())).toBe("https://www.hebridescyber.co.uk/dashboard/integrations?m365=connected#cloud");
    expect(upserts).toHaveLength(1);
    expect(Object.keys(upserts[0].row).sort()).toEqual(["consented_at", "last_checked_at", "owner", "tenant_id"]);
    expect(upserts[0].row).toMatchObject({ owner: OWNER_ID, tenant_id: TENANT });
    expect(getAppTokenMock).toHaveBeenCalledWith(TENANT, CONFIG);
    expect(String(res.getHeader("Set-Cookie"))).toContain("Max-Age=0");
    expect(auditMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ action: "m365_tenant.connected", actorId: OWNER_ID }));
  });

  it("requires every Graph permission the checks use", () => {
    expect([...ROLES]).toEqual(expect.arrayContaining(["Policy.Read.All", "Directory.Read.All", "Reports.Read.All", "MailboxSettings.Read"]));
  });

  it("rejects a state from another browser, a forged state, or none", async () => {
    for (const r of [callback(goodQuery(), {}), callback(goodQuery(), { hc_m365_nonce: "other" }), callback({ ...goodQuery(), state: "x.y" })]) {
      await handler(r.req, r.res);
      expect(outcome(r.res)).toBe("invalid_state");
    }
    expect(upserts).toEqual([]);
    expect(getAppTokenMock).not.toHaveBeenCalled();
  });

  it("reports a declined consent without reflecting Microsoft's text", async () => {
    const r = callback({ error: "access_denied", error_description: "<script>alert(1)</script>", state: goodQuery().state });
    await handler(r.req, r.res);
    expect(outcome(r.res)).toBe("declined");
    expect(String(r.res._getRedirectUrl())).not.toContain("script");
    expect(upserts).toEqual([]);
  });

  it("rejects a bad tenant or a missing admin_consent", async () => {
    for (const q of [{ ...goodQuery(), tenant: "contoso.com" }, { ...goodQuery(), admin_consent: "False" }]) {
      const r = callback(q);
      await handler(r.req, r.res);
      expect(outcome(r.res)).toBe("invalid_tenant");
    }
  });

  it("doesn't trust the tenant parameter: no token means no consent", async () => {
    getAppTokenMock.mockResolvedValueOnce({ ok: false, error: { status: 400, code: "unauthorized_client", message: "unauthorized_client (AADSTS700016)" } });
    const r = callback(goodQuery());
    await handler(r.req, r.res);
    expect(outcome(r.res)).toBe("consent_not_found");
    expect(upserts).toEqual([]);
  });

  it("rejects a token issued for a different tenant", async () => {
    getAppTokenMock.mockResolvedValueOnce({ ok: true, body: { accessToken: "t", roles: [...ROLES], tenantId: "33333333-3333-3333-3333-333333333333" } });
    const r = callback(goodQuery());
    await handler(r.req, r.res);
    expect(outcome(r.res)).toBe("invalid_tenant");
  });

  it("reports a partial consent instead of storing it", async () => {
    getAppTokenMock.mockResolvedValueOnce({ ok: true, body: { accessToken: "t", roles: ["Policy.Read.All"], tenantId: TENANT } });
    const r = callback(goodQuery());
    await handler(r.req, r.res);
    expect(outcome(r.res)).toBe("missing_permissions");
    expect(upserts).toEqual([]);
  });

  it("is rate-limited, needs app config, and only answers GET", async () => {
    rateLimitMock.mockResolvedValueOnce({ allowed: false, retryAfterSeconds: 60 });
    let r = callback(goodQuery());
    await handler(r.req, r.res);
    expect(outcome(r.res)).toBe("rate_limited");

    delete process.env.M365_CLIENT_ID;
    r = callback(goodQuery());
    await handler(r.req, r.res);
    expect(outcome(r.res)).toBe("not_configured");

    const post = createMocks<NextApiRequest, NextApiResponse>({ method: "POST" });
    await handler(post.req, post.res);
    expect(post.res._getStatusCode()).toBe(405);
  });

  it("reports a storage failure", async () => {
    upsertResult.current = { error: { code: "XX000", message: "boom" } };
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const r = callback(goodQuery());
    await handler(r.req, r.res);
    expect(outcome(r.res)).toBe("error");
    errSpy.mockRestore();
  });
});
