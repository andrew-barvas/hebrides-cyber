// POST/DELETE /api/account/offensive-authorization — records or revokes the
// per-target authorization that unlocks the Tier A `offensive` scan profile
// (brute-force / real-attack tools) for a host the caller controls.
//
// This is the informed-consent gate. An offensive scan will not run without a
// current row here (run-queued-scan-jobs.ts checks it beside domain-ownership),
// so recording one is a deliberate, audited act: the caller must be on Tier A,
// own the monitored target, and explicitly acknowledge that the platform will
// send real attack traffic at the host. Session only — never an API key —
// because it authorises something with real-world impact.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { planGate } from "@/lib/planAccess";
import { parseBody } from "@/lib/validate";
import { recordOffensiveAuthorization, revokeOffensiveAuthorization } from "@/lib/offensiveAuthorization";

const postBodySchema = z.object({
  targetUrl: z.string().url("targetUrl must be a valid URL"),
  // Must be literally true — an unchecked box cannot authorise an attack.
  acknowledge: z.literal(true, { message: "You must acknowledge that real attack traffic will be sent to this target." }),
  // What the owner is authorising, stored for the audit record.
  scope: z.string().min(1).max(2000).optional(),
  // Optional ISO expiry; omitted means it stays until revoked.
  expiresAt: z.string().datetime().optional(),
});

const deleteBodySchema = z.object({
  targetUrl: z.string().url("targetUrl must be a valid URL"),
});

const DEFAULT_SCOPE =
  "Authorised offensive scanning (content/credential/exploit testing) of this owned, verified target.";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST" && req.method !== "DELETE") {
    res.setHeader("Allow", "POST, DELETE");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") {
    return res.status(403).json({ error: "Offensive-scan authorization can only be managed from a logged-in session, not with an API key." });
  }

  // Parse once per method, so the target-ownership check can use the URL.
  const body = req.method === "POST" ? parseBody(postBodySchema, req.body, res) : parseBody(deleteBodySchema, req.body, res);
  if (!body) return; // parseBody already wrote the 400
  const targetUrl = body.targetUrl;

  // Must own a monitored target for this URL — same per-target ownership check
  // every other account route makes before a write.
  const { data: target, error: targetErr } = await supabaseAdmin
    .from("monitored_targets")
    .select("id, owner")
    .eq("owner", caller.ownerId)
    .eq("target_url", targetUrl)
    .maybeSingle();
  if (targetErr) return res.status(500).json({ error: "Could not look up the target — try again." });
  if (!target) return res.status(404).json({ error: "You don't have a monitored target with that URL." });

  if (req.method === "DELETE") {
    const result = await revokeOffensiveAuthorization(supabaseAdmin, { owner: caller.ownerId, actorId: caller.ownerId, targetUrl });
    if (!result.ok) {
      if (result.reason === "unavailable") return res.status(503).json({ error: "Offensive scanning isn't available yet." });
      return res.status(result.reason === "invalid_url" ? 400 : 500).json({ error: "Could not revoke the authorization." });
    }
    return res.status(200).json({ ok: true, revoked: true });
  }

  // POST: Tier A required.
  const gate = await planGate(supabaseAdmin, caller.ownerId, "tier_a");
  if (gate === "error") return res.status(500).json({ error: "Could not check your plan — try again." });
  if (gate === "denied") return res.status(403).json({ error: "Offensive scanning is a Tier A feature." });

  const post = body as z.infer<typeof postBodySchema>;
  const result = await recordOffensiveAuthorization(supabaseAdmin, {
    owner: caller.ownerId,
    authorizedBy: caller.ownerId,
    targetUrl,
    scope: post.scope ?? DEFAULT_SCOPE,
    expiresAt: post.expiresAt ?? null,
  });
  if (!result.ok) {
    if (result.reason === "unavailable") return res.status(503).json({ error: "Offensive scanning isn't available yet." });
    return res.status(result.reason === "invalid_url" ? 400 : 500).json({ error: "Could not record the authorization." });
  }
  return res.status(200).json({ ok: true, host: result.host });
}
