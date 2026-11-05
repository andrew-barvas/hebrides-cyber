import { describe, it, expect } from "vitest";
import { adminConsentUrl, clearNonceCookie, missingRoles, newNonce, nonceCookie, redirectUri, signState, verifyState, M365_STATE_TTL_SECONDS } from "./m365Consent";

const CONFIG = { clientId: "11111111-1111-1111-1111-111111111111", clientSecret: "secret" };
const OWNER = "44444444-4444-4444-4444-444444444444";
const NOW = Date.UTC(2026, 10, 1);

describe("consent state", () => {
  it("round-trips the owner when the nonce matches", () => {
    const nonce = newNonce();
    expect(verifyState(signState(OWNER, nonce, CONFIG, NOW), nonce, CONFIG, NOW)).toEqual({ ok: true, ownerId: OWNER });
  });

  it("rejects a different browser (no or wrong nonce cookie)", () => {
    const state = signState(OWNER, "n1", CONFIG, NOW);
    expect(verifyState(state, undefined, CONFIG, NOW)).toEqual({ ok: false, reason: "nonce_mismatch" });
    expect(verifyState(state, "n2", CONFIG, NOW)).toEqual({ ok: false, reason: "nonce_mismatch" });
  });

  it("rejects a forged or re-pointed state", () => {
    const state = signState(OWNER, "n1", CONFIG, NOW);
    const [, mac] = state.split(".");
    const forgedBody = Buffer.from(JSON.stringify({ o: "attacker", n: "n1", e: NOW / 1000 + 600 })).toString("base64url");
    expect(verifyState(`${forgedBody}.${mac}`, "n1", CONFIG, NOW)).toEqual({ ok: false, reason: "bad_signature" });
    expect(verifyState(state, "n1", { ...CONFIG, clientSecret: "rotated" }, NOW)).toEqual({ ok: false, reason: "bad_signature" });
  });

  it("expires", () => {
    const state = signState(OWNER, "n1", CONFIG, NOW);
    expect(verifyState(state, "n1", CONFIG, NOW + (M365_STATE_TTL_SECONDS + 1) * 1000)).toEqual({ ok: false, reason: "expired" });
  });

  it("rejects malformed input", () => {
    for (const bad of [undefined, 42, "", "a", "a.b.c", "x".repeat(2000)]) {
      expect(verifyState(bad, "n", CONFIG, NOW).ok).toBe(false);
    }
  });
});

describe("adminConsentUrl", () => {
  it("asks for the app's configured permissions via .default and returns to www", () => {
    const url = new URL(adminConsentUrl(CONFIG, "st", {}));
    expect(url.origin + url.pathname).toBe("https://login.microsoftonline.com/organizations/v2.0/adminconsent");
    expect(url.searchParams.get("client_id")).toBe(CONFIG.clientId);
    expect(url.searchParams.get("scope")).toBe("https://graph.microsoft.com/.default");
    expect(url.searchParams.get("redirect_uri")).toBe("https://www.hebridescyber.co.uk/api/account/m365-callback");
    expect(url.searchParams.get("state")).toBe("st");
  });

  it("follows NEXT_PUBLIC_SITE_URL", () => {
    expect(redirectUri({ NEXT_PUBLIC_SITE_URL: "http://localhost:3000/" })).toBe("http://localhost:3000/api/account/m365-callback");
  });
});

describe("cookies and roles", () => {
  it("scopes the nonce cookie to the callback and clears it", () => {
    expect(nonceCookie("abc")).toBe("hc_m365_nonce=abc; Path=/api/account/m365-callback; Max-Age=600; HttpOnly; Secure; SameSite=Lax");
    expect(clearNonceCookie()).toContain("Max-Age=0");
  });

  it("lists missing roles", () => {
    expect(missingRoles(["A", "B"], ["A", "B", "C"])).toEqual(["C"]);
    expect(missingRoles(["A"], ["A"])).toEqual([]);
  });
});
