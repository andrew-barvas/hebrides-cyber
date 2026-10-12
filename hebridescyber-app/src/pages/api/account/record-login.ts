// POST /api/account/record-login — drives a real login FORM (see
// src/lib/scanners/loginRecorder.ts) and saves the resulting session cookie
// the same way /api/account/target-auth's "cookie" path does, as an
// alternative to the owner manually copying a cookie out of devtools.
//
// Same Agency gate and ownership check as target-auth.ts, plus: session
// auth only (a credential this sensitive shouldn't be scriptable by an API
// key), rate-limited (this launches a real browser against a third-party
// site per call — same reasoning as generate-report.ts), and an explicit
// `acknowledged: true` the caller must send, matching the Tier A offensive
// profile's per-action consent — a FINAL public-facing consent-wording
// review is still owed here (see docs/AUTHENTICATED-CRAWL.md); this route
// only enforces that -some- explicit acknowledgement was sent.
//
// The password never reaches a response, a log line, or the audit row below
// — only whether the attempt succeeded.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { planGate } from "@/lib/planAccess";
import { checkRateLimit } from "@/lib/rateLimit";
import { parseBody } from "@/lib/validate";
import { logAuditEvent } from "@/lib/audit";
import { recordLogin, playwrightLoginRun } from "@/lib/scanners/loginRecorder";

const bodySchema = z.object({
  monitoredTargetId: z.string().min(1, "monitoredTargetId is required"),
  loginUrl: z.string().min(1, "loginUrl is required"),
  username: z.string().min(1, "username is required"),
  password: z.string().min(1, "password is required"),
  usernameSelector: z.string().optional(),
  passwordSelector: z.string().optional(),
  acknowledged: z.literal(true, { message: "You must acknowledge the consent statement before recording a login." }),
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") {
    return res.status(403).json({ error: "Login recording can only be run from a logged-in session, not with an API key." });
  }

  const parsed = parseBody(bodySchema, req.body, res);
  if (!parsed) return;
  const { monitoredTargetId, loginUrl, username, password, usernameSelector, passwordSelector } = parsed;

  const { data: target } = await supabaseAdmin.from("monitored_targets").select("id, owner, target_url").eq("id", monitoredTargetId).maybeSingle();
  if (!target) return res.status(404).json({ error: "Monitored target not found" });
  if (target.owner !== caller.ownerId) return res.status(403).json({ error: "Forbidden" });

  const gate = await planGate(supabaseAdmin, caller.ownerId, "agency");
  if (gate === "error") return res.status(500).json({ error: "Could not check your plan — try again." });
  if (gate === "denied") return res.status(403).json({ error: "Authenticated scanning is an Agency-plan feature." });

  const limit = await checkRateLimit(caller.ownerId, "record-login");
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds));
    return res.status(429).json({ error: "Rate limit exceeded — try again later", retryAfterSeconds: limit.retryAfterSeconds });
  }

  // Only the target's own host, never wherever the owner typed — the whole
  // point of the ownership check above is pointless if the login page can
  // be anywhere.
  let loginHost: string;
  try {
    loginHost = new URL(loginUrl).hostname;
  } catch {
    return res.status(400).json({ error: "loginUrl is not a valid URL." });
  }
  const targetHost = (() => {
    try {
      return new URL(target.target_url as string).hostname;
    } catch {
      return null;
    }
  })();
  if (!targetHost || (loginHost !== targetHost && !loginHost.endsWith(`.${targetHost}`))) {
    return res.status(400).json({ error: "loginUrl must be on the same host as this monitored target." });
  }

  const result = await recordLogin({ loginUrl, username, password, usernameSelector, passwordSelector }, playwrightLoginRun);

  await logAuditEvent(supabaseAdmin, {
    actorId: caller.ownerId,
    action: result.status === "recorded" ? "login_recorder.succeeded" : "login_recorder.failed",
    resourceType: "monitored_target",
    resourceId: monitoredTargetId,
    metadata: { loginUrl, note: result.status === "error" ? result.note : undefined },
  });

  if (result.status === "error") return res.status(422).json({ error: result.note });

  const { error } = await supabaseAdmin.from("target_auth_credentials").upsert(
    { owner: caller.ownerId, monitored_target_id: monitoredTargetId, auth_type: "cookie", cookie_value: result.cookieValue, basic_username: null, basic_password: null },
    { onConflict: "monitored_target_id" }
  );
  if (error) return res.status(500).json({ error: error.message });

  return res.status(200).json({ ok: true });
}
