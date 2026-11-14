import { describe, it, expect } from "vitest";
import { missingScopes, signState, verifyState, workspaceAppConfig, workspaceAuthUrl, WORKSPACE_SCOPES } from "./workspaceConsent";

const config = { clientId: "cid.apps.googleusercontent.com", clientSecret: "secret" };

describe("workspaceConsent", () => {
  it("is dark until both env vars are set", () => {
    expect(workspaceAppConfig({})).toBeNull();
    expect(workspaceAppConfig({ GOOGLE_WORKSPACE_CLIENT_ID: "a" })).toBeNull();
    expect(workspaceAppConfig({ GOOGLE_WORKSPACE_CLIENT_ID: "a", GOOGLE_WORKSPACE_CLIENT_SECRET: "b" })).toEqual({ clientId: "a", clientSecret: "b" });
  });

  it("asks Google for offline, read-only access with our signed state", () => {
    const url = new URL(workspaceAuthUrl(config, "STATE", { NEXT_PUBLIC_SITE_URL: "https://www.hebridescyber.co.uk" }));
    expect(url.origin + url.pathname).toBe("https://accounts.google.com/o/oauth2/v2/auth");
    expect(url.searchParams.get("access_type")).toBe("offline");
    expect(url.searchParams.get("scope")).toBe(WORKSPACE_SCOPES.join(" "));
    expect(WORKSPACE_SCOPES.every((s) => s.endsWith(".readonly"))).toBe(true);
    expect(url.searchParams.get("redirect_uri")).toBe("https://www.hebridescyber.co.uk/api/account/workspace-callback");
    expect(url.searchParams.get("state")).toBe("STATE");
  });

  it("lists required scopes Google didn't grant", () => {
    expect(missingScopes(WORKSPACE_SCOPES.join(" "))).toEqual([]);
    expect(missingScopes(WORKSPACE_SCOPES[0])).toEqual([WORKSPACE_SCOPES[1]]);
    expect(missingScopes(undefined)).toEqual([...WORKSPACE_SCOPES]);
  });

  it("verifies state only with the matching nonce cookie and this app's secret", () => {
    const state = signState("owner-1", "nonce-1", config);
    expect(verifyState(state, "nonce-1", config)).toEqual({ ok: true, ownerId: "owner-1" });
    expect(verifyState(state, "other", config)).toMatchObject({ ok: false, reason: "nonce_mismatch" });
    expect(verifyState(state, "nonce-1", { ...config, clientSecret: "different" })).toMatchObject({ ok: false, reason: "bad_signature" });
  });
});
