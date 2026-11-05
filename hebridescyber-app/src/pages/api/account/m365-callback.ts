// GET /api/account/m365-callback — Microsoft's redirect back after a tenant
// admin answers the consent prompt started by ./m365-connect.ts (P1-4).
//
// A top-level browser redirect, so there's no Authorization header: the
// caller is identified by the signed `state` plus the matching HttpOnly nonce
// cookie (src/lib/m365Consent.ts explains why both). It is rate-limited by IP
// because it is reachable without a session.
//
// Microsoft's `tenant` query parameter is not trusted on its own: we ask for
// an app-only token for that tenant, which only succeeds if our app really is
// consented there, and read the granted roles from it, so a partial consent
// is reported rather than stored. Only then is the tenant ID saved. The
// browser always lands back on the integrations page with a short status
// code; Microsoft's error text is never reflected into the page.
import type { NextApiRequest, NextApiResponse } from "next";
import { supabaseAdmin } from "@/lib/apiAuth";
import { checkRateLimit, getClientIp } from "@/lib/rateLimit";
import { isMissingSchemaError } from "@/lib/dbErrors";
import { logAuditEvent } from "@/lib/audit";
import { getAppToken, isTenantId, m365AppConfig, M365_REQUIRED_APP_ROLES } from "@/lib/m365Graph";
import { clearNonceCookie, missingRoles, siteUrl, verifyState, M365_NONCE_COOKIE, M365_RETURN_PATH } from "@/lib/m365Consent";

export type M365CallbackOutcome =
  | "connected"
  | "declined"
  | "invalid_state"
  | "invalid_tenant"
  | "consent_not_found"
  | "missing_permissions"
  | "not_configured"
  | "rate_limited"
  | "error";

function finish(res: NextApiResponse, outcome: M365CallbackOutcome) {
  res.setHeader("Set-Cookie", clearNonceCookie());
  res.setHeader("Cache-Control", "no-store");
  res.redirect(302, `${siteUrl()}${M365_RETURN_PATH}?m365=${outcome}#cloud`);
}

function param(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

  const limit = await checkRateLimit(getClientIp(req), "m365-callback", { max: 20, windowSeconds: 60 * 60 });
  if (!limit.allowed) return finish(res, "rate_limited");

  const config = m365AppConfig();
  if (!config) return finish(res, "not_configured");

  const state = verifyState(param(req.query.state), req.cookies?.[M365_NONCE_COOKIE], config);
  if (!state.ok) return finish(res, "invalid_state");
  const ownerId = state.ownerId;

  if (param(req.query.error)) {
    await logAuditEvent(supabaseAdmin, { actorId: ownerId, action: "m365_tenant.consent_declined", resourceType: "m365_tenant", metadata: { error: param(req.query.error)?.slice(0, 100) } });
    return finish(res, "declined");
  }

  const tenantId = param(req.query.tenant);
  if (!isTenantId(tenantId) || param(req.query.admin_consent)?.toLowerCase() !== "true") return finish(res, "invalid_tenant");

  const token = await getAppToken(tenantId, config);
  if (!token.ok) {
    await logAuditEvent(supabaseAdmin, { actorId: ownerId, action: "m365_tenant.consent_failed", resourceType: "m365_tenant", resourceId: tenantId, metadata: { reason: token.error.message } });
    return finish(res, "consent_not_found");
  }
  if (token.body.tenantId && token.body.tenantId.toLowerCase() !== tenantId.toLowerCase()) return finish(res, "invalid_tenant");
  const missing = missingRoles(token.body.roles, M365_REQUIRED_APP_ROLES);
  if (missing.length > 0) {
    await logAuditEvent(supabaseAdmin, { actorId: ownerId, action: "m365_tenant.consent_failed", resourceType: "m365_tenant", resourceId: tenantId, metadata: { missing } });
    return finish(res, "missing_permissions");
  }

  const { error } = await supabaseAdmin
    .from("m365_tenants")
    .upsert({ owner: ownerId, tenant_id: tenantId.toLowerCase(), consented_at: new Date().toISOString(), last_checked_at: null }, { onConflict: "owner" });
  if (error) {
    if (!isMissingSchemaError(error)) console.error("[m365-callback] upsert failed:", error.message);
    return finish(res, "error");
  }

  await logAuditEvent(supabaseAdmin, { actorId: ownerId, action: "m365_tenant.connected", resourceType: "m365_tenant", resourceId: tenantId.toLowerCase() });
  return finish(res, "connected");
}
