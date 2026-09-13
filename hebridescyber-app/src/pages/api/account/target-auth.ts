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
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { parseBody } from "@/lib/validate";


const deleteBodySchema = z.object({
  monitoredTargetId: z.string().min(1, "monitoredTargetId is required"),
});

const postBodySchema = z.discriminatedUnion("authType", [
  z.object({
    monitoredTargetId: z.string().min(1, "monitoredTargetId is required"),
    authType: z.literal("cookie"),
    cookieValue: z.string().min(1, "cookieValue is required"),
  }),
  z.object({
    monitoredTargetId: z.string().min(1, "monitoredTargetId is required"),
    authType: z.literal("basic"),
    username: z.string().min(1, "username is required"),
    password: z.string().min(1, "password is required"),
  }),
]);

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST" && req.method !== "DELETE") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") {
    return res.status(403).json({ error: "Authenticated-scan credentials can only be managed from a logged-in session, not with an API key." });
  }

  // DELETE only needs monitoredTargetId; POST uses the full discriminated union.
  if (req.method === "DELETE") {
    const parsed = parseBody(deleteBodySchema, req.body, res);
    if (!parsed) return;
    const { monitoredTargetId } = parsed;
    return handleTargetAuth(req, res, caller, monitoredTargetId);
  }

  const parsed = parseBody(postBodySchema, req.body, res);
  if (!parsed) return;
  const { monitoredTargetId } = parsed;
  return handleTargetAuth(req, res, caller, monitoredTargetId, parsed);
}

async function handleTargetAuth(
  req: NextApiRequest,
  res: NextApiResponse,
  caller: { ownerId: string; via: string },
  monitoredTargetId: string,
  body?: z.infer<typeof postBodySchema>,
) {

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

  // E-02 (docs/ENHANCEMENTS.md): authenticated scanning is advertised as
  // "Optional (Agency)" on /what-we-check but was enforced nowhere. Only
  // gating the write (POST) — DELETE stays available regardless of plan, so
  // an account that's since downgraded can still remove a credential it can
  // no longer add.
  if (req.method === "POST") {
    const { data: subscription, error: subError } = await supabaseAdmin
      .from("subscriptions")
      .select("plan")
      .eq("owner", caller.ownerId)
      .maybeSingle();
    if (subError) return res.status(500).json({ error: subError.message });
    if (subscription?.plan !== "agency") {
      return res.status(403).json({ error: "Authenticated scanning is an Agency-plan feature." });
    }
  }

  if (req.method === "DELETE") {
    const { error } = await supabaseAdmin.from("target_auth_credentials").delete().eq("monitored_target_id", monitoredTargetId);
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ ok: true });
  }

  if (!body) return res.status(400).json({ error: "authType is required" });

  if (body.authType === "cookie") {
    const { error } = await supabaseAdmin.from("target_auth_credentials").upsert(
      { owner: caller.ownerId, monitored_target_id: monitoredTargetId, auth_type: "cookie", cookie_value: body.cookieValue, basic_username: null, basic_password: null },
      { onConflict: "monitored_target_id" }
    );
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ ok: true });
  }

  if (body.authType === "basic") {
    const { error } = await supabaseAdmin.from("target_auth_credentials").upsert(
      { owner: caller.ownerId, monitored_target_id: monitoredTargetId, auth_type: "basic", basic_username: body.username, basic_password: body.password, cookie_value: null },
      { onConflict: "monitored_target_id" }
    );
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ ok: true });
  }

  return res.status(400).json({ error: "authType must be 'cookie' or 'basic'" });
}
