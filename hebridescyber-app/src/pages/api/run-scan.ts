// Two-step scan flow — POST with { targetUrl } (no scanId) to create a scan
// and get a proofToken back, then POST again with { scanId } and an
// X-Scan-Token header set to that token to actually run it.
//
// Rebuilt as a Next.js API route (deploys via the same Azure Static Web
// Apps pipeline as the rest of the app — see .github/workflows/deploy.yml)
// rather than as a separate standalone Azure Functions app. That second app
// (src/functions/run-scan) was never actually deployable — no host.json, no
// Functions-specific package.json, no real @azure/functions registration —
// and this file itself used to be a stale, independently-drifted duplicate
// of it (missing the free-tier cap, admin bypass, shared executeScan(), and
// every other fix built around those). One implementation now, reused by
// every path that runs a scan: this route, the scheduled queue's workers
// (src/scripts/run-queued-scan-jobs.ts), and the public API
// (src/pages/api/v1/scans.ts).
//
// Session-only: nothing calls this with a service/scheduled credential
// anymore — the scheduled queue calls executeScan() directly instead of
// going through this HTTP round-trip (see src/scripts/enqueue-scheduled-scans.ts).
import type { NextApiRequest, NextApiResponse } from "next";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { validateNoSsrf, isDomainVerified } from "@/lib/ownership";
import { checkRateLimit } from "@/lib/rateLimit";
import { isFreeTierExhausted, FREE_TIER_EXHAUSTED_MESSAGE } from "@/lib/freeTier";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";

// Defaults to requiring real DNS/file domain verification. Set
// ALLOW_DEV_TOKEN_VERIFICATION=true only for local dev — see
// src/lib/ownership.ts and docs/security.md.
const allowDevTokenVerification = process.env.ALLOW_DEV_TOKEN_VERIFICATION === "true";

// This repo's own identity, for dispatching .github/workflows/on-demand-scan.yml
// — not customer-supplied, so it's a constant rather than an input like
// generate-fix-pr.ts's githubRepo.
const OWN_GITHUB_REPO = "andrew-barvas/hebrides-cyber";

/**
 * Best-effort trigger for the on-demand-scan.yml workflow, so a queued job
 * gets picked up in roughly a minute instead of waiting for
 * scheduled-scans.yml's next daily cron. Never throws — GITHUB_PAT being
 * unset, or GitHub's API being briefly unavailable, must never turn a
 * successful "queued" response into a 500, since the job is safely queued
 * either way and the daily cron is a real fallback, just a slower one.
 */
async function triggerOnDemandWorkflow(): Promise<void> {
  const pat = process.env.GITHUB_PAT;
  if (!pat) {
    console.warn("[run-scan] GITHUB_PAT not set — queued scan will wait for the next scheduled-scans.yml cron.");
    return;
  }
  try {
    const res = await fetch(
      `https://api.github.com/repos/${OWN_GITHUB_REPO}/actions/workflows/on-demand-scan.yml/dispatches`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${pat}`,
          Accept: "application/vnd.github+json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ ref: "master" }),
        signal: AbortSignal.timeout(6_000),
      }
    );
    if (!res.ok) {
      console.warn(`[run-scan] on-demand-scan.yml dispatch failed (${res.status}) — falling back to the daily cron.`);
    }
  } catch (err) {
    console.warn("[run-scan] on-demand-scan.yml dispatch threw — falling back to the daily cron:", (err as Error).message);
  }
}

// Scan results can be large.
export const config = { api: { bodyParser: { sizeLimit: "1mb" } } };

async function isOwnershipVerified(
  ownerId: string,
  targetUrl: string,
  proofToken: string,
  req: NextApiRequest
): Promise<boolean> {
  if (await isDomainVerified(supabaseAdmin, ownerId, targetUrl)) return true;
  if (!allowDevTokenVerification) return false;

  // DEV-ONLY fallback — proves the caller received the token from step 1,
  // NOT that they control the domain.
  const supplied = (req.headers["x-scan-token"] as string | undefined) ?? (req.query.verification as string | undefined);
  if (!supplied) return false;
  const a = Buffer.from(supplied);
  const b = Buffer.from(proofToken);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  try {
    return await handleScan(req, res);
  } catch (err) {
    return res.status(500).json({ error: (err as Error).message });
  }
}

async function handleScan(req: NextApiRequest, res: NextApiResponse) {
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") {
    return res.status(403).json({ error: "Scans can only be run from a logged-in session, not with an API key — use POST /api/v1/scans instead." });
  }

  const limit = await checkRateLimit(caller.ownerId);
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds ?? 60));
    return res.status(429).json({ error: "Rate limit exceeded — try again later", retryAfterSeconds: limit.retryAfterSeconds });
  }

  const { targetUrl, scanId } = req.body as { targetUrl?: string; scanId?: string };

  // --- Step 1: create a new scan, return a proof token -----------------
  if (!scanId) {
    if (!targetUrl) return res.status(400).json({ error: "targetUrl is required to create a scan" });

    if (await isFreeTierExhausted(supabaseAdmin, caller.ownerId)) {
      return res.status(402).json({ error: FREE_TIER_EXHAUSTED_MESSAGE, code: "free_tier_exhausted" });
    }

    try {
      await validateNoSsrf(targetUrl);
    } catch (err) {
      return res.status(400).json({ error: `Invalid target: ${(err as Error).message}` });
    }

    const proofToken = randomBytes(16).toString("hex");
    const { data: scan, error } = await supabaseAdmin
      .from("scans")
      .insert({ owner: caller.ownerId, target_url: targetUrl, status: "pending", proof_token: proofToken, owner_verified: false })
      .select("id")
      .single();

    if (error || !scan) return res.status(500).json({ error: error?.message ?? "Failed to create scan" });

    return res.status(200).json({
      scanId: scan.id,
      status: "awaiting_verification",
      proofToken,
      verifyInstructions:
        "Preferred: POST to /api/verify-ownership with action=start for this targetUrl, add the DNS TXT " +
        "record or file it gives you, then action=check. " +
        (allowDevTokenVerification
          ? "Dev path: resubmit this request with scanId and an X-Scan-Token header set to proofToken."
          : "There is no dev-token shortcut on this deployment — domain verification is required."),
    });
  }

  // --- Step 2: verify ownership, then actually run the scan -------------
  const { data: scan, error: fetchError } = await supabaseAdmin
    .from("scans")
    .select("id, owner, target_url, proof_token, status")
    .eq("id", scanId)
    .maybeSingle();

  if (fetchError || !scan) return res.status(404).json({ error: fetchError?.message ?? "Scan not found" });
  if (scan.owner !== caller.ownerId) return res.status(403).json({ error: "You do not own this scan" });

  // Idempotent replay: the dashboard polls this same endpoint while a scan is
  // queued/running, so a scan that already finished (or already failed)
  // shouldn't be re-verified or re-queued just because step 2 was called
  // again — and a scan that's mid-flight must return its current status
  // without inserting a second scan_jobs row for it.
  if (scan.status === "completed") {
    const { data: existingResult } = await supabaseAdmin
      .from("scan_results")
      .select("score, summary")
      .eq("scan_id", scanId)
      .maybeSingle();
    return res.status(200).json({
      ok: true,
      scanId,
      status: "completed",
      score: existingResult?.score ?? null,
      summary: existingResult?.summary ?? null,
    });
  }

  if (scan.status === "failed") {
    return res.status(200).json({ ok: false, scanId, status: "failed", error: "Scan failed — try running it again." });
  }

  if (scan.status === "running") {
    return res.status(202).json({ ok: true, scanId, status: "running" });
  }

  // scan.status === "pending" — first time step 2 has been reached for this
  // scan, so this is the only branch that verifies ownership and enqueues.
  if (!(await isOwnershipVerified(scan.owner, scan.target_url, scan.proof_token, req))) {
    return res.status(401).json({
      error: "This domain hasn't been verified yet — use the \"Verify domain ownership\" section below, then run your scan again.",
      code: "domain_not_verified",
    });
  }

  try {
    await validateNoSsrf(scan.target_url);
  } catch (err) {
    await supabaseAdmin.from("scans").update({ status: "failed" }).eq("id", scanId);
    return res.status(400).json({ error: `SSRF check failed: ${(err as Error).message}` });
  }

  await supabaseAdmin.from("scans").update({ status: "running", owner_verified: true }).eq("id", scanId);

  // Enqueue rather than call executeScan() directly — see
  // .github/workflows/on-demand-scan.yml's header comment for why running
  // the check suite synchronously inside this HTTP request isn't safe on
  // Azure Static Web Apps' Free SKU. scan_id is pre-set so
  // run-queued-scan-jobs.ts reuses this row and stays passive-only, rather
  // than creating a second scans row the way scheduled jobs do.
  const { error: jobError } = await supabaseAdmin.from("scan_jobs").insert({
    owner: scan.owner,
    target_url: scan.target_url,
    scan_id: scanId,
    status: "pending",
  });
  if (jobError) {
    await supabaseAdmin.from("scans").update({ status: "failed" }).eq("id", scanId);
    return res.status(500).json({ error: `Failed to queue scan: ${jobError.message}` });
  }

  // Awaited so the dispatch call isn't cut off by the function returning —
  // but it never throws or blocks the response beyond its own 6s timeout,
  // see triggerOnDemandWorkflow's doc comment.
  await triggerOnDemandWorkflow();

  return res.status(202).json({
    ok: true,
    scanId,
    status: "queued",
    message: "Scan queued — this usually takes under a minute.",
  });
}
