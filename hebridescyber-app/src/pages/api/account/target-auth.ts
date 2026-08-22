// POST/DELETE /api/account/target-auth — saves or removes the authenticated-
// scanning credential for one monitored target (see
// sql/migrations/014_target_auth_credentials.sql and
// src/lib/scanners/authenticatedCheck.ts).
//
// Unlike connect-repo.ts/ticket-integration.ts, this does NOT make a live
// call to validate the credential before saving. Those integrations have a
// generic "am I authenticated" endpoint (GitHub's /repos/{owner}/{repo},
// Jira's /myself, Linear's { viewer }); an arbitrary customer site has no
// such generic signal — a 200 response proves nothing about whether the
// cookie/credential actually reached an authenticated state versus a login
// page that also happens to return 200. Being honest about that limitation
// is better than a validation check that would give false confidence.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";

type CookieBody = { monitoredTargetId: string; authType: "cookie"; cookieValue: string };
type BasicBody = { monitoredTargetId: string; authType: "basic"; username: string; password: string };

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST" && req.method !== "DELETE") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") {
    return res.status(403).json({ error: "Authenticated-scan credentials can only be managed from a logged-in session, not with an API key." });
  }

  const { monitoredTargetId } = req.body as { monitoredTargetId?: string };
  if (!monitoredTargetId) return res.status(400).json({ error: "monitoredTargetId is required" });

  // Confirm the caller actually owns this monitored target before touching
  // any credential row for it — the same ownership check every other
  // per-target route in this app does before a write.
  const { data: target } = await supabaseAdmin
    .from("monitored_targets")
    .select("id, owner")
    .eq("id", monitoredTargetId)
    .maybeSingle();
  if (!target) return res.status(404).json({ error: "Monitored target not found" });
  if (target.owner !== caller.ownerId) return res.status(403).json({ error: "Forbidden" });

  if (req.method === "DELETE") {
    const { error } = await supabaseAdmin.from("target_auth_credentials").delete().eq("monitored_target_id", monitoredTargetId);
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ ok: true });
  }

  const body = req.body as CookieBody | BasicBody;

  if (body.authType === "cookie") {
    if (!body.cookieValue) return res.status(400).json({ error: "cookieValue is required" });
    const { error } = await supabaseAdmin.from("target_auth_credentials").upsert(
      { owner: caller.ownerId, monitored_target_id: monitoredTargetId, auth_type: "cookie", cookie_value: body.cookieValue, basic_username: null, basic_password: null },
      { onConflict: "monitored_target_id" }
    );
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ ok: true });
  }

  if (body.authType === "basic") {
    if (!body.username || !body.password) return res.status(400).json({ error: "username and password are both required" });
    const { error } = await supabaseAdmin.from("target_auth_credentials").upsert(
      { owner: caller.ownerId, monitored_target_id: monitoredTargetId, auth_type: "basic", basic_username: body.username, basic_password: body.password, cookie_value: null },
      { onConflict: "monitored_target_id" }
    );
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ ok: true });
  }

  return res.status(400).json({ error: "authType must be 'cookie' or 'basic'" });
}
