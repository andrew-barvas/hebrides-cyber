// Google Workspace connection (NEXT-BUILDS-DESIGN-2026-11.md task 10). A
// Workspace super admin authorises our Google Cloud app with READ-ONLY Admin
// SDK scopes; we keep the refresh token, sealed (CLAUDE.md rule 20), and the
// scanner reads users, admins and 2-Step Verification with it.
//
// Dark until OT-58: without GOOGLE_WORKSPACE_CLIENT_ID and
// GOOGLE_WORKSPACE_CLIENT_SECRET every route answers "not set up".
//
// The callback is protected exactly like Microsoft 365's (m365Consent.ts): an
// HMAC-signed state naming the owner, plus the same nonce in an HttpOnly
// cookie, so a consent started in one browser can't be completed in another.
// The signing helpers are shared; they key off this app's own secret.
import { siteUrl } from "./m365Consent";

export { newNonce, signState, verifyState } from "./m365Consent";

export type WorkspaceAppConfig = { clientId: string; clientSecret: string };
type Env = Record<string, string | undefined>;

export const WORKSPACE_CALLBACK_PATH = "/api/account/workspace-callback";
export const WORKSPACE_NONCE_COOKIE = "hc_workspace_nonce";
export const WORKSPACE_RETURN_PATH = "/dashboard/integrations";
const STATE_TTL_SECONDS = 600;

/** Read-only scopes only. Each one is listed on the consent screen (OT-58). */
export const WORKSPACE_SCOPES = [
  "https://www.googleapis.com/auth/admin.directory.user.readonly",
  "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
] as const;

export const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
export const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
export const GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke";

export function workspaceAppConfig(env: Env = process.env): WorkspaceAppConfig | null {
  const clientId = env.GOOGLE_WORKSPACE_CLIENT_ID?.trim();
  const clientSecret = env.GOOGLE_WORKSPACE_CLIENT_SECRET?.trim();
  return clientId && clientSecret ? { clientId, clientSecret } : null;
}

export function workspaceRedirectUri(env: Env = process.env): string {
  return `${siteUrl(env)}${WORKSPACE_CALLBACK_PATH}`;
}

/** Google's consent URL: offline access (a refresh token), consent shown every time so a refresh token is always issued. */
export function workspaceAuthUrl(config: WorkspaceAppConfig, state: string, env: Env = process.env): string {
  const params = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: workspaceRedirectUri(env),
    response_type: "code",
    scope: WORKSPACE_SCOPES.join(" "),
    access_type: "offline",
    prompt: "consent",
    include_granted_scopes: "false",
    state,
  });
  return `${GOOGLE_AUTH_URL}?${params.toString()}`;
}

export function workspaceNonceCookie(nonce: string): string {
  return `${WORKSPACE_NONCE_COOKIE}=${nonce}; Path=${WORKSPACE_CALLBACK_PATH}; Max-Age=${STATE_TTL_SECONDS}; HttpOnly; Secure; SameSite=Lax`;
}

export function clearWorkspaceNonceCookie(): string {
  return `${WORKSPACE_NONCE_COOKIE}=; Path=${WORKSPACE_CALLBACK_PATH}; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}

/** Pure: scopes Google granted that we required but didn't get. */
export function missingScopes(granted: string | undefined): string[] {
  const have = new Set((granted ?? "").split(/\s+/).filter(Boolean));
  return WORKSPACE_SCOPES.filter((s) => !have.has(s));
}

export type TokenResult = { ok: true; accessToken: string; refreshToken: string | null; scope: string | undefined } | { ok: false; error: string };

async function tokenRequest(body: URLSearchParams, fetchImpl: typeof fetch): Promise<TokenResult> {
  try {
    const res = await fetchImpl(GOOGLE_TOKEN_URL, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body, signal: AbortSignal.timeout(15_000) });
    const json = (await res.json().catch(() => ({}))) as { access_token?: string; refresh_token?: string; scope?: string; error?: string };
    if (!res.ok || !json.access_token) return { ok: false, error: json.error ?? `HTTP ${res.status}` };
    return { ok: true, accessToken: json.access_token, refreshToken: json.refresh_token ?? null, scope: json.scope };
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }
}

export function exchangeCode(config: WorkspaceAppConfig, code: string, fetchImpl: typeof fetch = fetch, env: Env = process.env): Promise<TokenResult> {
  return tokenRequest(new URLSearchParams({ code, client_id: config.clientId, client_secret: config.clientSecret, redirect_uri: workspaceRedirectUri(env), grant_type: "authorization_code" }), fetchImpl);
}

export function refreshAccessToken(config: WorkspaceAppConfig, refreshToken: string, fetchImpl: typeof fetch = fetch): Promise<TokenResult> {
  return tokenRequest(new URLSearchParams({ refresh_token: refreshToken, client_id: config.clientId, client_secret: config.clientSecret, grant_type: "refresh_token" }), fetchImpl);
}
