// /api/account/workspace-connect — Google Workspace connection (migration 076).
//   GET    → { configured, connected, connectedAt, lastCheckedAt }
//   POST   → { url }: Google's consent screen (Pro and above), with the nonce cookie set
//   DELETE → disconnects: revokes the token at Google, then deletes the row
// Session only, like Microsoft 365 (m365-connect.ts).
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { planGate } from "@/lib/planAccess";
import { isMissingSchemaError } from "@/lib/dbErrors";
import { logAuditEvent } from "@/lib/audit";
import { respondInternalError } from "@/lib/apiError";
import { decryptSecret } from "@/lib/credentialEncryption";
import { GOOGLE_REVOKE_URL, newNonce, signState, workspaceAppConfig, workspaceAuthUrl, workspaceNonceCookie } from "@/lib/workspaceConsent";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET" && req.method !== "POST" && req.method !== "DELETE") return res.status(405).json({ error: "Method not allowed" });
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") return res.status(403).json({ error: "Google Workspace can only be connected from a logged-in session." });
  const config = workspaceAppConfig();

  if (req.method === "GET") {
    const { data, error } = await supabaseAdmin.from("workspace_connections").select("connected_at, last_checked_at").eq("owner", caller.ownerId).maybeSingle();
    if (error && !isMissingSchemaError(error)) return respondInternalError(res, "account/workspace-connect", error);
    return res.status(200).json({ configured: Boolean(config), connected: Boolean(data), connectedAt: data?.connected_at ?? null, lastCheckedAt: data?.last_checked_at ?? null });
  }

  if (req.method === "DELETE") {
    const { data } = await supabaseAdmin.from("workspace_connections").select("refresh_token").eq("owner", caller.ownerId).maybeSingle();
    if (data) {
      // Best-effort revoke at Google, so the token stops working there too.
      try {
        const token = decryptSecret((data as { refresh_token: string }).refresh_token);
        await fetch(GOOGLE_REVOKE_URL, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ token }), signal: AbortSignal.timeout(10_000) });
      } catch {
        // deleting our copy below still disconnects us
      }
    }
    const { error } = await supabaseAdmin.from("workspace_connections").delete().eq("owner", caller.ownerId);
    if (error) return respondInternalError(res, "account/workspace-connect", error);
    await logAuditEvent(supabaseAdmin, { actorId: caller.ownerId, action: "workspace_connection.disconnected", resourceType: "workspace_connection" });
    return res.status(200).json({ ok: true });
  }

  if (!config) return res.status(503).json({ error: "Google Workspace checks aren't set up on this deployment yet." });
  const gate = await planGate(supabaseAdmin, caller.ownerId, "pro");
  if (gate === "error") return res.status(500).json({ error: "Could not check your plan. Try again." });
  if (gate === "denied") return res.status(403).json({ error: "Google Workspace posture checks are on the Pro plan and above." });

  const nonce = newNonce();
  res.setHeader("Set-Cookie", workspaceNonceCookie(nonce));
  await logAuditEvent(supabaseAdmin, { actorId: caller.ownerId, action: "workspace_connection.consent_started", resourceType: "workspace_connection" });
  return res.status(200).json({ url: workspaceAuthUrl(config, signState(caller.ownerId, nonce, config)) });
}
