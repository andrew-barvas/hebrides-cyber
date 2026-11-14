import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { state } = vi.hoisted(() => ({ state: { upserts: [] as Array<Record<string, unknown>>, encConfigured: true } }));

vi.mock("@/lib/apiAuth", () => ({ supabaseAdmin: { from: () => ({ upsert: (row: Record<string, unknown>) => (state.upserts.push(row), Promise.resolve({ error: null })) }) } }));
vi.mock("@/lib/audit", () => ({ logAuditEvent: vi.fn() }));
vi.mock("@/lib/rateLimit", () => ({ checkRateLimit: async () => ({ allowed: true }), getClientIp: () => "1.2.3.4" }));
vi.mock("@/lib/credentialEncryption", () => ({ isCredentialEncryptionConfigured: () => state.encConfigured, encryptSecret: (v: string) => `enc:v1:${Buffer.from(v).toString("base64")}` }));

import handler from "@/pages/api/account/workspace-callback";
import { signState, WORKSPACE_NONCE_COOKIE, WORKSPACE_SCOPES } from "@/lib/workspaceConsent";

const config = { clientId: "cid", clientSecret: "secret" };

async function callback(query: Record<string, string>, cookie = "nonce-1") {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "GET", query, cookies: { [WORKSPACE_NONCE_COOKIE]: cookie } });
  await handler(req, res);
  return new URL(res._getRedirectUrl()).searchParams.get("workspace");
}

describe("GET /api/account/workspace-callback", () => {
  beforeEach(() => {
    process.env.GOOGLE_WORKSPACE_CLIENT_ID = config.clientId;
    process.env.GOOGLE_WORKSPACE_CLIENT_SECRET = config.clientSecret;
    state.upserts = [];
    state.encConfigured = true;
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ access_token: "at", refresh_token: "1//rt", scope: WORKSPACE_SCOPES.join(" ") }))));
  });

  it("stores the refresh token sealed, never in plaintext", async () => {
    expect(await callback({ state: signState("owner-1", "nonce-1", config), code: "c" })).toBe("connected");
    expect(state.upserts).toHaveLength(1);
    expect(state.upserts[0].owner).toBe("owner-1");
    expect(state.upserts[0].refresh_token).toMatch(/^enc:v1:/);
    expect(JSON.stringify(state.upserts[0])).not.toContain("1//rt");
  });

  it("refuses a state from another browser (nonce mismatch) or a forged one", async () => {
    expect(await callback({ state: signState("owner-1", "nonce-1", config), code: "c" }, "different")).toBe("invalid_state");
    expect(await callback({ state: signState("owner-1", "nonce-1", { ...config, clientSecret: "other" }), code: "c" })).toBe("invalid_state");
    expect(state.upserts).toEqual([]);
  });

  it("refuses missing scopes and never stores a token without encryption configured", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ access_token: "at", refresh_token: "1//rt", scope: WORKSPACE_SCOPES[0] }))));
    expect(await callback({ state: signState("owner-1", "nonce-1", config), code: "c" })).toBe("missing_permissions");
    state.encConfigured = false;
    expect(await callback({ state: signState("owner-1", "nonce-1", config), code: "c" })).toBe("not_configured");
    expect(state.upserts).toEqual([]);
  });
});
