// POST/DELETE /api/account/uptime-integration — connect or disconnect the
// customer's OWN UptimeRobot account (bring-your-own: UptimeRobot's terms bar
// reselling or white-labelling its monitoring, so there is no shared Hebrides
// account). The key is checked against UptimeRobot once at save time, then
// stored encrypted in uptime_integrations (migration 062), a table with no
// client policy at all: the browser can never read it back. Pro and above.
//
// Disconnecting removes the key and our record of the monitors. It does NOT
// delete monitors in the customer's UptimeRobot account; they own those.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { logAuditEvent } from "@/lib/audit";
import { ENCRYPTION_NOT_CONFIGURED_MESSAGE, isCredentialEncryptionConfigured, sealSecrets } from "@/lib/credentialEncryption";
import { planGate } from "@/lib/planAccess";
import { checkRateLimit } from "@/lib/rateLimit";
import { uptimeRobotProvider } from "@/lib/uptimeRobot";
import { parseBody } from "@/lib/validate";

const postSchema = z.object({
  provider: z.literal("uptimerobot").default("uptimerobot"),
  apiKey: z.string().trim().min(8, "apiKey is required").max(512),
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST" && req.method !== "DELETE") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") {
    return res.status(403).json({ error: "Uptime monitoring can only be managed from a logged-in session, not with an API key." });
  }

  if (req.method === "DELETE") {
    const [{ error: monitorsError }, { error }] = await Promise.all([
      supabaseAdmin.from("uptime_monitors").delete().eq("owner", caller.ownerId).eq("provider", "uptimerobot"),
      supabaseAdmin.from("uptime_integrations").delete().eq("owner", caller.ownerId).eq("provider", "uptimerobot"),
    ]);
    if (error || monitorsError) return res.status(500).json({ error: (error ?? monitorsError)!.message });
    await logAuditEvent(supabaseAdmin, { actorId: caller.ownerId, action: "uptime.disconnected", resourceType: "uptime_integration", metadata: { provider: "uptimerobot" } });
    return res.status(200).json({ ok: true });
  }

  const body = parseBody(postSchema, req.body, res);
  if (!body) return;

  const gate = await planGate(supabaseAdmin, caller.ownerId, "pro");
  if (gate === "error") return res.status(500).json({ error: "Could not check your plan — try again." });
  if (gate === "denied") return res.status(403).json({ error: "Uptime monitoring is a Pro-and-up feature." });

  // The key is stored encrypted; never fall back to plaintext.
  if (!isCredentialEncryptionConfigured()) return res.status(503).json({ error: ENCRYPTION_NOT_CONFIGURED_MESSAGE });

  // Each attempt is a real call to UptimeRobot with a user-supplied key.
  const limit = await checkRateLimit(caller.ownerId, "uptime-connect", { max: 10, windowSeconds: 60 * 60 });
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds));
    return res.status(429).json({ error: "Too many attempts — try again later." });
  }

  const check = await uptimeRobotProvider(body.apiKey).validate();
  if (!check.ok) {
    const status = check.kind === "auth" ? 400 : check.kind === "rate_limited" ? 429 : 502;
    return res.status(status).json({ error: check.error });
  }

  const { error } = await supabaseAdmin
    .from("uptime_integrations")
    .upsert(sealSecrets({ owner: caller.ownerId, provider: "uptimerobot", api_key: body.apiKey, last_error: null, updated_at: new Date().toISOString() }, ["api_key"]), {
      onConflict: "owner,provider",
    });
  if (error) return res.status(500).json({ error: error.message });

  await logAuditEvent(supabaseAdmin, { actorId: caller.ownerId, action: "uptime.connected", resourceType: "uptime_integration", metadata: { provider: "uptimerobot" } });
  return res.status(200).json({ ok: true, provider: "uptimerobot" });
}
