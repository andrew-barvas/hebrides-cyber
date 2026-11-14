// GET /api/account/workspace-callback — Google's redirect back after a
// Workspace super admin consents (migration 076). A top-level browser
// redirect, so no Authorization header: the signed state plus the nonce
// cookie prove who started it (workspaceConsent.ts). Checks every required
// scope was granted, seals the refresh token (CLAUDE.md rule 20, never a
// plaintext fallback) and stores it, then returns to the integrations page.
import type { NextApiRequest, NextApiResponse } from "next";
import { supabaseAdmin } from "@/lib/apiAuth";
import { checkRateLimit, getClientIp } from "@/lib/rateLimit";
import { logAuditEvent } from "@/lib/audit";
import { encryptSecret, isCredentialEncryptionConfigured } from "@/lib/credentialEncryption";
import { siteUrl } from "@/lib/m365Consent";
import { clearWorkspaceNonceCookie, exchangeCode, missingScopes, verifyState, workspaceAppConfig, WORKSPACE_NONCE_COOKIE, WORKSPACE_RETURN_PATH } from "@/lib/workspaceConsent";

export type WorkspaceCallbackOutcome = "connected" | "declined" | "invalid_state" | "missing_permissions" | "no_refresh_token" | "not_configured" | "rate_limited" | "error";

function finish(res: NextApiResponse, outcome: WorkspaceCallbackOutcome) {
  res.setHeader("Set-Cookie", clearWorkspaceNonceCookie());
  res.setHeader("Cache-Control", "no-store");
  res.redirect(302, `${siteUrl()}${WORKSPACE_RETURN_PATH}?workspace=${outcome}#cloud`);
}

const param = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v);

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });
  const limit = await checkRateLimit(getClientIp(req), "workspace-callback", { max: 20, windowSeconds: 60 * 60 });
  if (!limit.allowed) return finish(res, "rate_limited");

  const config = workspaceAppConfig();
  if (!config || !isCredentialEncryptionConfigured()) return finish(res, "not_configured");

  const state = verifyState(param(req.query.state), req.cookies?.[WORKSPACE_NONCE_COOKIE], config);
  if (!state.ok) return finish(res, "invalid_state");
  const ownerId = state.ownerId;

  if (param(req.query.error)) {
    await logAuditEvent(supabaseAdmin, { actorId: ownerId, action: "workspace_connection.consent_declined", resourceType: "workspace_connection", metadata: { error: param(req.query.error)?.slice(0, 100) } });
    return finish(res, "declined");
  }
  const code = param(req.query.code);
  if (!code || code.length > 2048) return finish(res, "invalid_state");

  const token = await exchangeCode(config, code);
  if (!token.ok) return finish(res, "error");
  const missing = missingScopes(token.scope);
  if (missing.length > 0) {
    await logAuditEvent(supabaseAdmin, { actorId: ownerId, action: "workspace_connection.consent_failed", resourceType: "workspace_connection", metadata: { missing } });
    return finish(res, "missing_permissions");
  }
  if (!token.refreshToken) return finish(res, "no_refresh_token");

  const { error } = await supabaseAdmin
    .from("workspace_connections")
    .upsert({ owner: ownerId, refresh_token: encryptSecret(token.refreshToken), scopes: token.scope ?? "", connected_at: new Date().toISOString(), last_checked_at: null }, { onConflict: "owner" });
  if (error) {
    console.error("[workspace-callback] upsert failed");
    return finish(res, "error");
  }
  await logAuditEvent(supabaseAdmin, { actorId: ownerId, action: "workspace_connection.connected", resourceType: "workspace_connection" });
  return finish(res, "connected");
}
