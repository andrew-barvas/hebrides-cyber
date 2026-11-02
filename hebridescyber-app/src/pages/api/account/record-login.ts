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
// Optional `totpSecret` (base32, RFC 6238) answers an authenticator-app MFA
// step; it needs the target's domain to be verified, is stored encrypted
// beside the cookie, and is reused when a later recording omits it.
//
// The password, TOTP secret and codes never reach a response, a log line, or
// the audit row below — only whether the attempt succeeded.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { planGate } from "@/lib/planAccess";
import { checkRateLimit } from "@/lib/rateLimit";
import { parseBody } from "@/lib/validate";
import { logAuditEvent } from "@/lib/audit";
import { recordLogin, playwrightLoginRun } from "@/lib/scanners/loginRecorder";
import { ENCRYPTION_NOT_CONFIGURED_MESSAGE, isCredentialEncryptionConfigured, revealSecrets, sealSecrets } from "@/lib/credentialEncryption";
import { isDomainVerified } from "@/lib/ownership";
import { isValidTotpSecret, normaliseTotpSecret } from "@/lib/totp";

const bodySchema = z.object({
  monitoredTargetId: z.string().min(1, "monitoredTargetId is required"),
  loginUrl: z.string().min(1, "loginUrl is required"),
  username: z.string().min(1, "username is required"),
  password: z.string().min(1, "password is required"),
  usernameSelector: z.string().optional(),
  passwordSelector: z.string().optional(),
  totpSecret: z.string().max(256).optional(),
  mfaSelector: z.string().optional(),
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
  const { monitoredTargetId, loginUrl, username, password, usernameSelector, passwordSelector, mfaSelector } = parsed;
  const suppliedTotp = parsed.totpSecret?.trim() ? normaliseTotpSecret(parsed.totpSecret) : undefined;
  if (suppliedTotp !== undefined && !isValidTotpSecret(suppliedTotp)) {
    return res.status(400).json({ error: "totpSecret must be the base32 key shown when the authenticator was set up." });
  }

  const { data: target } = await supabaseAdmin.from("monitored_targets").select("id, owner, target_url").eq("id", monitoredTargetId).maybeSingle();
  if (!target) return res.status(404).json({ error: "Monitored target not found" });
  if (target.owner !== caller.ownerId) return res.status(403).json({ error: "Forbidden" });

  const gate = await planGate(supabaseAdmin, caller.ownerId, "agency");
  if (gate === "error") return res.status(500).json({ error: "Could not check your plan — try again." });
  if (gate === "denied") return res.status(403).json({ error: "Authenticated scanning is an Agency-plan feature." });

  // The recorded session cookie is stored encrypted; refuse before driving a
  // browser through the customer's login rather than save it in plaintext.
  if (!isCredentialEncryptionConfigured()) return res.status(503).json({ error: ENCRYPTION_NOT_CONFIGURED_MESSAGE });

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

  // The MFA step is only ever answered on a domain the owner has proven they
  // control — the same bar as every other active scan path.
  if (suppliedTotp !== undefined && !(await isDomainVerified(supabaseAdmin, caller.ownerId, target.target_url as string))) {
    return res.status(403).json({ error: "Verify ownership of this domain before adding a TOTP secret." });
  }

  // A secret stored by an earlier recording is reused; one that can't be
  // decrypted is an error, never a silent login attempt without MFA.
  let totpSecret = suppliedTotp;
  if (totpSecret === undefined) {
    const { data: stored } = await supabaseAdmin.from("target_auth_credentials").select("totp_secret").eq("monitored_target_id", monitoredTargetId).maybeSingle();
    if (stored?.totp_secret) {
      const revealed = revealSecrets({ totp_secret: stored.totp_secret as string }, ["totp_secret"]);
      if (!revealed) return res.status(500).json({ error: "The stored TOTP secret can't be decrypted — enter it again." });
      if (await isDomainVerified(supabaseAdmin, caller.ownerId, target.target_url as string)) totpSecret = revealed.totp_secret;
    }
  }

  const result = await recordLogin({ loginUrl, username, password, usernameSelector, passwordSelector, totpSecret, mfaSelector }, playwrightLoginRun);

  await logAuditEvent(supabaseAdmin, {
    actorId: caller.ownerId,
    action: result.status === "recorded" ? "login_recorder.succeeded" : "login_recorder.failed",
    resourceType: "monitored_target",
    resourceId: monitoredTargetId,
    metadata: { loginUrl, note: result.status === "error" ? result.note : undefined },
  });

  if (result.status === "error") return res.status(422).json({ error: result.note });

  const { error } = await supabaseAdmin.from("target_auth_credentials").upsert(
    sealSecrets(
      { owner: caller.ownerId, monitored_target_id: monitoredTargetId, auth_type: "cookie", cookie_value: result.cookieValue, basic_username: null, basic_password: null, totp_secret: totpSecret ?? null },
      ["cookie_value", "totp_secret"]
    ),
    { onConflict: "monitored_target_id" }
  );
  if (error) return res.status(500).json({ error: error.message });

  return res.status(200).json({ ok: true });
}
