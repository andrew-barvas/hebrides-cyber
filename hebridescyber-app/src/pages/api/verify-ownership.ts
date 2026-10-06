// Two actions, driven by `action` in the request body:
//   - "start": generate (or return the existing) verification token for a
//     domain, and return DNS TXT + file instructions.
//   - "check": actually perform the DNS TXT / file lookup (see
//     src/lib/ownership.ts) and, on success, mark the verification as
//     verified in Supabase.
//
// run-scan (src/pages/api/run-scan.ts) checks the `verifications` table this
// writes to, via src/lib/ownership.ts's isDomainVerified().
//
// Rebuilt as a Next.js API route alongside run-scan — see that file's header
// for why (the standalone src/functions/ Azure Functions app was never
// actually deployable).
import type { NextApiRequest, NextApiResponse } from "next";
import { randomBytes } from "node:crypto";
import { z } from "zod";
import { hostnameFromUrl, verificationHints, verifyDomain, VERIFICATION_PREFIX, WELL_KNOWN_PATH } from "@/lib/ownership";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { logAuditEvent } from "@/lib/audit";
import { checkRateLimit } from "@/lib/rateLimit";
import { parseBody } from "@/lib/validate";

const START_RATE_LIMIT = { max: 20, windowSeconds: 60 * 60 };
const CHECK_RATE_LIMIT = { max: 30, windowSeconds: 60 * 60 };

const bodySchema = z.object({
  action: z.enum(["start", "check"]).optional(),
  targetUrl: z.string().min(1, "targetUrl is required"),
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") {
    return res.status(403).json({ error: "Domain verification can only be managed from a logged-in session, not with an API key." });
  }

  const parsed = parseBody(bodySchema, req.body, res);
  if (!parsed) return;
  const { action, targetUrl } = parsed;

  // E-12 (docs/ENHANCEMENTS.md): outbound DNS+HTTP per check, uncapped before
  // this. "start" and "check" have separate buckets: someone waiting for DNS
  // to propagate presses "Check now" repeatedly, and that used to lock them
  // out of fetching their instructions too.
  const limit = action === "check"
    ? await checkRateLimit(caller.ownerId, "verify-ownership-check", CHECK_RATE_LIMIT)
    : await checkRateLimit(caller.ownerId, "verify-ownership", START_RATE_LIMIT);
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds));
    const minutes = Math.max(1, Math.ceil(limit.retryAfterSeconds / 60));
    return res.status(429).json({ error: `Too many attempts. Try again in ${minutes} minute${minutes === 1 ? "" : "s"}.`, retryAfterSeconds: limit.retryAfterSeconds });
  }

  let domain: string;
  try {
    domain = hostnameFromUrl(targetUrl);
  } catch {
    return res.status(400).json({ error: "targetUrl must be a valid URL" });
  }

  if (action === "check") {
    const { data: existing, error: fetchError } = await supabaseAdmin
      .from("verifications")
      .select("id, token, verified_at")
      .eq("owner", caller.ownerId)
      .eq("domain", domain)
      .maybeSingle();

    if (fetchError || !existing) {
      return res.status(404).json({ error: "No pending verification for this domain — call action=start first" });
    }

    if (existing.verified_at) {
      return res.status(200).json({ verified: true, alreadyVerified: true });
    }

    const result = await verifyDomain(domain, existing.token);
    if (result.verified) {
      await supabaseAdmin
        .from("verifications")
        .update({ verified_at: new Date().toISOString(), method: result.method })
        .eq("id", existing.id);
    }

    // Logged both ways — repeated failures against the same domain are worth
    // being able to see (someone probing a domain they don't actually
    // control), not just successes.
    await logAuditEvent(supabaseAdmin, {
      actorId: caller.ownerId,
      action: result.verified ? "domain_verification.succeeded" : "domain_verification.failed",
      resourceType: "domain",
      resourceId: domain,
      metadata: { method: result.method },
    });

    return res.status(200).json({
      verified: result.verified,
      method: result.method,
      ...(result.verified ? {} : { hints: verificationHints(domain, existing.token, result) }),
    });
  }

  // Default / "start": create-or-return the verification token for this domain.
  const { data: existing } = await supabaseAdmin
    .from("verifications")
    .select("token, verified_at")
    .eq("owner", caller.ownerId)
    .eq("domain", domain)
    .maybeSingle();

  const token = existing?.token ?? randomBytes(16).toString("hex");

  if (!existing) {
    const { error: insertError } = await supabaseAdmin.from("verifications").insert({
      owner: caller.ownerId,
      domain,
      token,
    });
    if (insertError) return res.status(500).json({ error: insertError.message });
  }

  return res.status(200).json({
    domain,
    token,
    verified: Boolean(existing?.verified_at),
    dnsRecord: { type: "TXT", name: domain, value: `${VERIFICATION_PREFIX}=${token}` },
    file: { url: `https://${domain}${WELL_KNOWN_PATH}`, contents: token },
    instructions: "Add EITHER the DNS TXT record OR upload the file, then call this endpoint again with action=check.",
  });
}
