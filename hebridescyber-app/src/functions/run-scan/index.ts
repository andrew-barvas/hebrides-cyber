// Azure Function (HTTP trigger): run-scan
//
// Two-step flow:
//   1. POST with { targetUrl } and NO scanId → creates a `scans` row and
//      returns { scanId, proofToken, status: "awaiting_verification" }.
//   2. POST with { scanId } → actually runs the scan, IF ownership of the
//      target's domain has been proven. Ownership is resolved in this
//      order:
//        a. A verified row in `verifications` for (owner, domain) — the
//           real DNS TXT / file-upload check, see src/lib/ownership.ts
//           and src/functions/verify-ownership. This is the path that
//           should be required in production.
//        b. DEV-ONLY fallback: an `X-Scan-Token` header (or
//           `?verification=` query param) matching the proofToken from
//           step 1. Gated by ALLOW_DEV_TOKEN_VERIFICATION (defaults to
//           "true" so the dashboard's quick self-service flow keeps
//           working out of the box) — set it to "false" once every
//           customer is expected to complete real DNS/file verification.
//
// Deploy as its own Azure Functions app (Node.js), separate from the
// Next.js static site. See azure/terraform/main.tf and
// azure/cli-scripts/provision.sh for provisioning.

import { createClient } from "@supabase/supabase-js";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { runAllChecks, summariseResults, scoreFromFindings, generateAiSummary } from "../../lib/scanners";
import { hostnameFromUrl, validateNoSsrf } from "../../lib/ownership";
import { checkRateLimit } from "../../lib/rateLimit";
import { buildScanReport, findPreviousFindings } from "../../lib/scanReport";
import { dispatchScanCompletedWebhooks } from "../../lib/webhooks";

// TODO: replace with the Azure Functions v4 programming model types
// (`@azure/functions`) once this is wired into a real Functions project.
type HttpRequest = {
  headers: Record<string, string | undefined>;
  query: Record<string, string | undefined>;
  body: { targetUrl?: string; scanId?: string; owner?: string };
};
type HttpResponseInit = { status: number; jsonBody: unknown };

const supabaseUrl = process.env.SUPABASE_URL ?? "";
const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY ?? "";
// Shared secret used by scheduled-scans.yml to call this function on behalf
// of subscribed customers, without a per-user session token.
const serviceToken = process.env.GITHUB_ACTIONS_TOKEN ?? "";
const allowDevTokenVerification = (process.env.ALLOW_DEV_TOKEN_VERIFICATION ?? "true") === "true";

// Service-role client — bypasses RLS. Only ever use this in trusted
// server-side code like this function, never in the browser.
const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey);

// ---- Proof of ownership -------------------------------------------------
async function isOwnershipVerified(
  ownerId: string,
  targetUrl: string,
  scan: { proof_token: string },
  req: HttpRequest
): Promise<boolean> {
  let domain: string;
  try {
    domain = hostnameFromUrl(targetUrl);
  } catch {
    return false;
  }

  const { data: verification } = await supabaseAdmin
    .from("verifications")
    .select("verified_at")
    .eq("owner", ownerId)
    .eq("domain", domain)
    .maybeSingle();

  if (verification?.verified_at) return true;

  if (!allowDevTokenVerification) return false;

  // DEV-ONLY fallback — proves the caller received the token from step 1,
  // NOT that they control the domain. See module comment above.
  const supplied = req.headers["x-scan-token"] ?? req.query.verification;
  if (!supplied) return false;
  const a = Buffer.from(supplied);
  const b = Buffer.from(scan.proof_token);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/** Resolves who is making this request: a logged-in dashboard user, or the
 * trusted scheduled-scans workflow acting on behalf of a customer. */
async function resolveCaller(
  req: HttpRequest
): Promise<{ ownerId: string; isService: boolean } | null> {
  const authHeader = req.headers["authorization"];
  if (authHeader?.startsWith("Bearer ")) {
    const token = authHeader.slice("Bearer ".length);
    const { data, error } = await supabaseAdmin.auth.getUser(token);
    if (error || !data.user) return null;
    return { ownerId: data.user.id, isService: false };
  }

  const provided = req.headers["x-service-token"];
  if (provided && serviceToken && provided === serviceToken) {
    // Scheduled/service calls must say which customer this scan is for.
    if (!req.body.owner) return null;
    return { ownerId: req.body.owner, isService: true };
  }

  return null;
}

export default async function runScan(req: HttpRequest): Promise<HttpResponseInit> {
  const caller = await resolveCaller(req);
  if (!caller) {
    return { status: 401, jsonBody: { error: "Missing or invalid Authorization / X-Service-Token" } };
  }

  const rateLimit = await checkRateLimit(caller.ownerId);
  if (!rateLimit.allowed) {
    return {
      status: 429,
      jsonBody: { error: "Rate limit exceeded — try again later", retryAfterSeconds: rateLimit.retryAfterSeconds },
    };
  }

  const { targetUrl, scanId } = req.body;

  // --- Step 1: create a new scan, return a proof token ------------------
  if (!scanId) {
    if (!targetUrl) {
      return { status: 400, jsonBody: { error: "targetUrl is required to create a scan" } };
    }

    // Fail fast on SSRF before writing a DB row.
    try {
      await validateNoSsrf(targetUrl);
    } catch (err) {
      return { status: 400, jsonBody: { error: `Invalid target: ${(err as Error).message}` } };
    }

    const proofToken = randomBytes(16).toString("hex");
    const { data: newScan, error: insertError } = await supabaseAdmin
      .from("scans")
      .insert({
        owner: caller.ownerId,
        target_url: targetUrl,
        status: "pending",
        proof_token: proofToken,
        owner_verified: false,
      })
      .select("id")
      .single();

    if (insertError || !newScan) {
      return { status: 500, jsonBody: { error: insertError?.message ?? "Failed to create scan" } };
    }

    return {
      status: 200,
      jsonBody: {
        scanId: newScan.id,
        status: "awaiting_verification",
        proofToken,
        verifyInstructions:
          "Preferred: POST to verify-ownership with action=start for this targetUrl, add the DNS TXT " +
          "record or file it gives you, then action=check. Quick/dev path: resubmit this request with " +
          "scanId and an X-Scan-Token header set to proofToken (only works while ALLOW_DEV_TOKEN_VERIFICATION=true).",
      },
    };
  }

  // --- Step 2: verify ownership, then actually run the scan -------------
  const { data: scan, error: fetchError } = await supabaseAdmin
    .from("scans")
    .select("id, owner, target_url, proof_token, status")
    .eq("id", scanId)
    .maybeSingle();

  if (fetchError || !scan) {
    return { status: 404, jsonBody: { error: fetchError?.message ?? "Scan not found" } };
  }

  if (!caller.isService && scan.owner !== caller.ownerId) {
    return { status: 403, jsonBody: { error: "You do not own this scan" } };
  }

  if (!(await isOwnershipVerified(scan.owner, scan.target_url, scan, req))) {
    return {
      status: 401,
      jsonBody: {
        error:
          "Ownership not verified. Complete DNS/file verification via verify-ownership, or (dev only) " +
          "supply the correct X-Scan-Token.",
      },
    };
  }

  // SSRF guard: resolve the target hostname and block private/reserved ranges
  // so the scanner can't be used as a proxy to reach internal infrastructure.
  try {
    await validateNoSsrf(scan.target_url);
  } catch (err) {
    await supabaseAdmin.from("scans").update({ status: "failed" }).eq("id", scanId);
    return { status: 400, jsonBody: { error: `SSRF check failed: ${(err as Error).message}` } };
  }

  await supabaseAdmin.from("scans").update({ status: "running", owner_verified: true }).eq("id", scanId);

  // TODO: move to an async queue + isolated worker container — see docs/architecture.md.
  const results = await runAllChecks(scan.target_url);
  const { findings } = summariseResults(results);
  const summary = await generateAiSummary(results, findings);
  const score = scoreFromFindings(findings);

  const { error: resultsError } = await supabaseAdmin.from("scan_results").insert({
    scan_id: scanId,
    results: { ...results, findings },
    summary,
    score,
  });

  if (resultsError) {
    await supabaseAdmin.from("scans").update({ status: "failed" }).eq("id", scanId);
    return { status: 500, jsonBody: { error: resultsError.message } };
  }

  const completedAt = new Date().toISOString();
  await supabaseAdmin.from("scans").update({ status: "completed" }).eq("id", scanId);

  // This is the real production scan-trigger path (the dashboard's "Run
  // scan" button), so it's the one that matters most for webhook delivery —
  // unlike src/pages/api/v1/scans.ts, a slow/dead customer endpoint here
  // can't fail an API response since nothing is waiting on this HTTP call in
  // the same way a CI job would be.
  const previous = await findPreviousFindings(supabaseAdmin, scan.owner, scanId, scan.target_url, completedAt);
  const report = buildScanReport(
    { id: scanId, owner: scan.owner, target_url: scan.target_url, status: "completed", created_at: completedAt },
    { results: { findings }, summary, score, created_at: completedAt },
    previous
  );
  await dispatchScanCompletedWebhooks(supabaseAdmin, scan.owner, report);

  return { status: 200, jsonBody: { ok: true, scanId, status: "completed", score, summary } };
}
