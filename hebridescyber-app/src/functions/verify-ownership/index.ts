// Azure Function (HTTP trigger): verify-ownership
//
// Two actions, driven by `action` in the request body:
//   - "start": generate (or return the existing) verification token for a
//     domain, and return DNS TXT + file instructions.
//   - "check": actually perform the DNS TXT / file lookup (see
//     src/lib/ownership.ts) and, on success, mark the verification as
//     verified in Supabase.
//
// This is the real implementation of the proof-of-ownership flow that was
// previously just a TODO in run-scan/index.ts and docs/security.md.
// run-scan checks the `verifications` table this function writes to.

import { createClient } from "@supabase/supabase-js";
import { randomBytes } from "node:crypto";
import { hostnameFromUrl, verifyDomain, VERIFICATION_PREFIX, WELL_KNOWN_PATH } from "../../lib/ownership";

type HttpRequest = {
  headers: Record<string, string | undefined>;
  body: { action?: "start" | "check"; targetUrl?: string };
};
type HttpResponseInit = { status: number; jsonBody: unknown };

const supabaseUrl = process.env.SUPABASE_URL ?? "";
const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY ?? "";
const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey);

async function resolveOwner(req: HttpRequest): Promise<string | null> {
  const authHeader = req.headers["authorization"];
  if (!authHeader?.startsWith("Bearer ")) return null;
  const { data, error } = await supabaseAdmin.auth.getUser(authHeader.slice("Bearer ".length));
  if (error || !data.user) return null;
  return data.user.id;
}

export default async function verifyOwnershipHandler(req: HttpRequest): Promise<HttpResponseInit> {
  const owner = await resolveOwner(req);
  if (!owner) {
    return { status: 401, jsonBody: { error: "Missing or invalid Authorization Bearer token" } };
  }

  const { action, targetUrl } = req.body;
  if (!targetUrl) {
    return { status: 400, jsonBody: { error: "targetUrl is required" } };
  }

  let domain: string;
  try {
    domain = hostnameFromUrl(targetUrl);
  } catch {
    return { status: 400, jsonBody: { error: "targetUrl must be a valid URL" } };
  }

  if (action === "check") {
    const { data: existing, error: fetchError } = await supabaseAdmin
      .from("verifications")
      .select("id, token, verified_at")
      .eq("owner", owner)
      .eq("domain", domain)
      .maybeSingle();

    if (fetchError || !existing) {
      return { status: 404, jsonBody: { error: "No pending verification for this domain — call action=start first" } };
    }

    if (existing.verified_at) {
      return { status: 200, jsonBody: { verified: true, alreadyVerified: true } };
    }

    const result = await verifyDomain(domain, existing.token);
    if (result.verified) {
      await supabaseAdmin
        .from("verifications")
        .update({ verified_at: new Date().toISOString(), method: result.method })
        .eq("id", existing.id);
    }

    return { status: 200, jsonBody: { verified: result.verified, method: result.method } };
  }

  // Default / "start": create-or-return the verification token for this domain.
  const { data: existing } = await supabaseAdmin
    .from("verifications")
    .select("token, verified_at")
    .eq("owner", owner)
    .eq("domain", domain)
    .maybeSingle();

  const token = existing?.token ?? randomBytes(16).toString("hex");

  if (!existing) {
    const { error: insertError } = await supabaseAdmin.from("verifications").insert({
      owner,
      domain,
      token,
    });
    if (insertError) {
      return { status: 500, jsonBody: { error: insertError.message } };
    }
  }

  return {
    status: 200,
    jsonBody: {
      domain,
      token,
      verified: Boolean(existing?.verified_at),
      dnsRecord: { type: "TXT", name: domain, value: `${VERIFICATION_PREFIX}=${token}` },
      file: { url: `https://${domain}${WELL_KNOWN_PATH}`, contents: token },
      instructions:
        "Add EITHER the DNS TXT record OR upload the file, then call this endpoint again with action=check.",
    },
  };
}
