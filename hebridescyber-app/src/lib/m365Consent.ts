// Microsoft 365 admin-consent flow (P1-4). Pure helpers, used by
// src/pages/api/account/m365-connect.ts (start, status, disconnect) and
// src/pages/api/account/m365-callback.ts (Microsoft's redirect back).
//
// The callback is a top-level browser redirect from login.microsoftonline.com,
// so it carries no Authorization header. Who started the flow is proved two
// ways, both required:
//   1. `state` is HMAC-signed by us over { owner, nonce, expiry }, so it can't
//      be forged or pointed at another account, and it expires in 10 minutes.
//   2. The same nonce is in an HttpOnly cookie set by the connect call, so a
//      consent link started in one browser can't be completed in another
//      (login CSRF: an attacker tricking a victim into attaching the
//      attacker's tenant, or the reverse).
// The HMAC key is derived from our app's own client secret with a fixed
// label, so the flow needs no extra environment variable, and rotating the
// secret simply invalidates any consent in flight.
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { Env, M365AppConfig } from "./m365Graph";

export const M365_CALLBACK_PATH = "/api/account/m365-callback";
export const M365_NONCE_COOKIE = "hc_m365_nonce";
export const M365_STATE_TTL_SECONDS = 600;
/** Where the callback sends the browser afterwards. */
export const M365_RETURN_PATH = "/dashboard/integrations";
/** Removing the app from the tenant is the admin's step: our read-only permissions can't delete our own service principal. */
export const M365_REVOKE_URL = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview";

export function siteUrl(env: Env = process.env): string {
  return (env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk").replace(/\/+$/, "");
}

export function redirectUri(env: Env = process.env): string {
  return `${siteUrl(env)}${M365_CALLBACK_PATH}`;
}

function stateKey(config: M365AppConfig): Buffer {
  return createHmac("sha256", config.clientSecret).update("hebrides-m365-consent-state-v1").digest();
}

type StatePayload = { o: string; n: string; e: number };

export function newNonce(): string {
  return randomBytes(18).toString("base64url");
}

export function signState(ownerId: string, nonce: string, config: M365AppConfig, nowMs: number = Date.now()): string {
  const payload: StatePayload = { o: ownerId, n: nonce, e: Math.floor(nowMs / 1000) + M365_STATE_TTL_SECONDS };
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const mac = createHmac("sha256", stateKey(config)).update(body).digest("base64url");
  return `${body}.${mac}`;
}

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

export type StateCheck = { ok: true; ownerId: string } | { ok: false; reason: "malformed" | "bad_signature" | "expired" | "nonce_mismatch" };

/** Verifies the signature, the expiry and that the nonce matches the browser's cookie. */
export function verifyState(state: unknown, cookieNonce: unknown, config: M365AppConfig, nowMs: number = Date.now()): StateCheck {
  if (typeof state !== "string" || state.length > 1024) return { ok: false, reason: "malformed" };
  const [body, mac, extra] = state.split(".");
  if (!body || !mac || extra !== undefined) return { ok: false, reason: "malformed" };
  const expected = createHmac("sha256", stateKey(config)).update(body).digest("base64url");
  if (!safeEqual(mac, expected)) return { ok: false, reason: "bad_signature" };
  let payload: StatePayload;
  try {
    payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as StatePayload;
  } catch {
    return { ok: false, reason: "malformed" };
  }
  if (typeof payload.o !== "string" || typeof payload.n !== "string" || typeof payload.e !== "number") return { ok: false, reason: "malformed" };
  if (payload.e * 1000 < nowMs) return { ok: false, reason: "expired" };
  if (typeof cookieNonce !== "string" || !safeEqual(cookieNonce, payload.n)) return { ok: false, reason: "nonce_mismatch" };
  return { ok: true, ownerId: payload.o };
}

/**
 * Microsoft identity platform v2 admin-consent URL. `/organizations` lets an
 * admin of any work tenant consent; `.default` asks for exactly the
 * application permissions configured on our app registration
 * (M365_REQUIRED_APP_ROLES), nothing more.
 */
export function adminConsentUrl(config: M365AppConfig, state: string, env: Env = process.env): string {
  const params = new URLSearchParams({
    client_id: config.clientId,
    scope: "https://graph.microsoft.com/.default",
    redirect_uri: redirectUri(env),
    state,
  });
  return `https://login.microsoftonline.com/organizations/v2.0/adminconsent?${params.toString()}`;
}

/** Set-Cookie value for the nonce: scoped to the callback path, gone after the TTL. Lax so the top-level redirect from Microsoft carries it. */
export function nonceCookie(nonce: string): string {
  return `${M365_NONCE_COOKIE}=${nonce}; Path=${M365_CALLBACK_PATH}; Max-Age=${M365_STATE_TTL_SECONDS}; HttpOnly; Secure; SameSite=Lax`;
}

export function clearNonceCookie(): string {
  return `${M365_NONCE_COOKIE}=; Path=${M365_CALLBACK_PATH}; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}

/** Roles the consented app is missing, read from the app-only token Microsoft just issued. */
export function missingRoles(granted: readonly string[], required: readonly string[]): string[] {
  const have = new Set(granted);
  return required.filter((r) => !have.has(r));
}
