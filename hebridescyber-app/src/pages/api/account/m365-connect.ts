// GET/POST/DELETE /api/account/m365-connect — the Microsoft 365 / Entra ID
// posture connection (P1-4).
//   GET    → { configured, connected, tenantId?, consentedAt?, lastCheckedAt? }
//   POST   → { url }: Microsoft's admin-consent page. Also sets the HttpOnly
//            nonce cookie the callback checks (src/lib/m365Consent.ts).
//   DELETE → forgets the tenant and returns where the admin removes our app.
// The callback that completes a connection is ./m365-callback.ts. We store
// the tenant ID only (sql/migrations/068_m365_tenants.sql); our app's own
// credential lives in the environment. Pro plan and up for POST.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { planGate } from "@/lib/planAccess";
import { isMissingSchemaError } from "@/lib/dbErrors";
import { logAuditEvent } from "@/lib/audit";
import { m365AppConfig } from "@/lib/m365Graph";
import { adminConsentUrl, newNonce, nonceCookie, signState, M365_REVOKE_URL } from "@/lib/m365Consent";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET" && req.method !== "POST" && req.method !== "DELETE") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") {
    return res.status(403).json({ error: "Microsoft 365 can only be connected from a logged-in session." });
  }

  const config = m365AppConfig();

  if (req.method === "GET") {
    const { data, error } = await supabaseAdmin
      .from("m365_tenants")
      .select("tenant_id, consented_at, last_checked_at")
      .eq("owner", caller.ownerId)
      .maybeSingle();
    if (error && !isMissingSchemaError(error)) return res.status(500).json({ error: error.message });
    return res.status(200).json({
      configured: Boolean(config),
      connected: Boolean(data),
      tenantId: data?.tenant_id ?? null,
      consentedAt: data?.consented_at ?? null,
      lastCheckedAt: data?.last_checked_at ?? null,
    });
  }

  if (req.method === "DELETE") {
    const { error } = await supabaseAdmin.from("m365_tenants").delete().eq("owner", caller.ownerId);
    if (error) {
      if (isMissingSchemaError(error)) return res.status(503).json({ error: "Microsoft 365 connections aren't available yet — try again shortly." });
      return res.status(500).json({ error: error.message });
    }
    await logAuditEvent(supabaseAdmin, { actorId: caller.ownerId, action: "m365_tenant.disconnected", resourceType: "m365_tenant" });
    return res.status(200).json({
      ok: true,
      // Forgetting the tenant stops our scans. Removing the consent itself is
      // the customer admin's step in their own tenant.
      revokeUrl: M365_REVOKE_URL,
      revokeSteps:
        "To withdraw consent too, a Global Administrator opens Microsoft Entra admin center → Enterprise applications, selects Hebrides Cyber, then Properties → Delete.",
    });
  }

  // POST — start the admin-consent flow.
  if (!config) {
    return res.status(503).json({ error: "Microsoft 365 checks aren't set up on this deployment yet." });
  }
  const gate = await planGate(supabaseAdmin, caller.ownerId, "pro");
  if (gate === "error") return res.status(500).json({ error: "Could not check your plan — try again." });
  if (gate === "denied") return res.status(403).json({ error: "Microsoft 365 posture checks are on the Pro plan and above." });

  const nonce = newNonce();
  res.setHeader("Set-Cookie", nonceCookie(nonce));
  await logAuditEvent(supabaseAdmin, { actorId: caller.ownerId, action: "m365_tenant.consent_started", resourceType: "m365_tenant" });
  return res.status(200).json({ url: adminConsentUrl(config, signState(caller.ownerId, nonce, config)) });
}
