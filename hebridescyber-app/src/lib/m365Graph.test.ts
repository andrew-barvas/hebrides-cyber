import { describe, it, expect, vi } from "vitest";
import { createGraphClient, decodeTokenClaims, getAppToken, isTenantId, m365AppConfig, GRAPH_BASE } from "./m365Graph";

const CONFIG = { clientId: "11111111-1111-1111-1111-111111111111", clientSecret: "secret" };
const TENANT = "22222222-2222-2222-2222-222222222222";
const jwt = (claims: object) => `h.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.s`;

describe("m365AppConfig", () => {
  it("needs both variables", () => {
    expect(m365AppConfig({ M365_CLIENT_ID: "a" })).toBeNull();
    expect(m365AppConfig({ M365_CLIENT_ID: " a ", M365_CLIENT_SECRET: "b" })).toEqual({ clientId: "a", clientSecret: "b" });
  });
});

describe("isTenantId / decodeTokenClaims", () => {
  it("accepts GUIDs only", () => {
    expect(isTenantId(TENANT)).toBe(true);
    expect(isTenantId("contoso.onmicrosoft.com")).toBe(false);
    expect(isTenantId(undefined)).toBe(false);
  });

  it("reads roles and tid, and tolerates garbage", () => {
    expect(decodeTokenClaims(jwt({ tid: TENANT, roles: ["Policy.Read.All", 3] }))).toEqual({ roles: ["Policy.Read.All"], tid: TENANT });
    expect(decodeTokenClaims("not-a-jwt")).toEqual({ roles: [], tid: null });
  });
});

describe("getAppToken", () => {
  it("posts client credentials to the tenant's token endpoint", async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ access_token: jwt({ tid: TENANT, roles: ["Directory.Read.All"] }) }), { status: 200 }));
    const result = await getAppToken(TENANT, CONFIG, fetchImpl as unknown as typeof fetch);
    expect(result).toMatchObject({ ok: true, body: { roles: ["Directory.Read.All"], tenantId: TENANT } });
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(`https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`);
    const body = new URLSearchParams(String(init.body));
    expect(body.get("grant_type")).toBe("client_credentials");
    expect(body.get("scope")).toBe("https://graph.microsoft.com/.default");
  });

  it("surfaces the AADSTS code without the description text", async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ error: "invalid_client", error_description: "AADSTS7000215: Invalid client secret provided. Trace ID: x" }), { status: 401 }));
    const result = await getAppToken(TENANT, CONFIG, fetchImpl as unknown as typeof fetch);
    expect(result).toEqual({ ok: false, error: { status: 401, code: "invalid_client", message: "invalid_client (AADSTS7000215)" } });
  });

  it("refuses a non-GUID tenant without calling out, and reports network failures", async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error("ECONNRESET");
    });
    expect((await getAppToken("../evil", CONFIG, fetchImpl as unknown as typeof fetch)).ok).toBe(false);
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(await getAppToken(TENANT, CONFIG, fetchImpl as unknown as typeof fetch)).toMatchObject({ ok: false, error: { code: "network_error" } });
  });
});

describe("createGraphClient", () => {
  it("returns Graph's error code on failure", async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ error: { code: "Authorization_RequestDenied", message: "Insufficient privileges" } }), { status: 403 }));
    const client = createGraphClient("tok", fetchImpl as unknown as typeof fetch);
    expect(await client.get("/policies/authorizationPolicy")).toEqual({
      ok: false,
      error: { status: 403, code: "Authorization_RequestDenied", message: "Insufficient privileges" },
    });
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(`${GRAPH_BASE}/policies/authorizationPolicy`);
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer tok");
  });

  it("stops at maxItems and says so", async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ value: [1, 2, 3] }), { status: 200 }));
    const client = createGraphClient("tok", fetchImpl as unknown as typeof fetch);
    expect(await client.getAll("/users", 2)).toEqual({ ok: true, body: { items: [1, 2], truncated: true } });
    expect(await client.getAll("/users", 3)).toEqual({ ok: true, body: { items: [1, 2, 3], truncated: false } });
  });

  it("reports a thrown fetch as a network error", async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error("timeout");
    });
    expect(await createGraphClient("tok", fetchImpl as unknown as typeof fetch).get("/x")).toMatchObject({ ok: false, error: { code: "network_error" } });
  });
});
