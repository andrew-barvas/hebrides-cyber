// POST /api/scans/{id}/replay — "rerun with the same settings"
// (docs/24-FEATURE-EXPANSION-SPEC.md #16). Same shape as retest-finding.ts
// (a bounded, ownership-checked, cost-bearing click action — session or API
// key, not the session-only restriction run-scan.ts's fresh-scan path has),
// but for the whole scan rather than one checkId.
//
// "Same settings" means the scan_profile the target this scan belongs to
// is CURRENTLY configured for (src/lib/scanProfiles.ts), not necessarily
// whatever profile the original scan actually ran with — there's no column
// recording that per past scan, and re-reading the target's live setting is
// the more useful behaviour anyway (a customer who's since switched a
// target's profile expects a "replay" to reflect that, not resurrect a
// stale one).
//
// scan_jobs.scan_profile is set explicitly here rather than left null,
// because this route pre-sets scan_id on the job (so the caller gets an
// immediate scanId to poll, matching retest-finding.ts's UX) — and
// src/scripts/run-queued-scan-jobs.ts's resolveScanConfig() short-circuits
// straight to "safe" for any job with scan_id preset UNLESS scan_profile is
// also explicitly set, never even looking up monitored_targets in that
// case. Explicitly resolving it here, rather than relying on that
// short-circuit, is what lets a replay of a registered target's scan
// actually run its configured extended-tool suite instead of always
// silently downgrading to passive-only.
//
// Known, disclosed gap: only monitored_targets.scan_profile is read — a
// target's scan_bundle_id (tool_overrides) is NOT resolved, since
// scan_bundles has no CRUD API yet (Q1 of docs/24-FEATURE-EXPANSION-SPEC.md
// shipped the table only) and scan_jobs has no column to carry per-job tool
// overrides through anyway. Once bundles get a real CRUD path this should
// be revisited alongside whatever solves that same problem for scheduled
// jobs with scan_bundle_id set.
//
// Only "safe" profile replays call triggerOnDemandWorkflow() for fast
// pickup. .github/workflows/on-demand-scan.yml installs none of the
// extended-tool binaries (nuclei/sqlmap/ZAP/etc.) — only
// scheduled-scans.yml's workers do — so dispatching the fast on-demand
// runner for a "full"/"api"/"cms"/"osint" replay would have every one of
// those tools silently degrade to not_configured (their own correct
// behaviour for a missing binary), quietly under-delivering on exactly the
// thing "replay with the same settings" promises. A non-"safe" replay
// instead just sits in scan_jobs until the next scheduled-scans.yml cron
// run claims it — the same "fallback if the fast dispatch path can't help"
// reasoning onDemandScanTrigger.ts already documents for its own failure
// case, just applied deliberately here instead of as an error recovery.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { checkRateLimit } from "@/lib/rateLimit";
import { validateNoSsrf, isDomainVerified } from "@/lib/ownership";
import { triggerOnDemandWorkflow } from "@/lib/onDemandScanTrigger";
import { callerCanActFor } from "@/lib/teamAccess";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  const limit = await checkRateLimit(caller.ownerId, "scan-replay");
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds));
    return res.status(429).json({ error: "Rate limit exceeded — try again later", retryAfterSeconds: limit.retryAfterSeconds });
  }

  const scanId = req.query.id as string;
  const { data: scan } = await supabaseAdmin.from("scans").select("id, owner, target_url").eq("id", scanId).maybeSingle();
  if (!scan) return res.status(404).json({ error: "Scan not found" });
  const isOwner = scan.owner === caller.ownerId;
  if (!isOwner && !(await callerCanActFor(supabaseAdmin, caller.ownerId, scan.owner))) {
    return res.status(403).json({ error: "Forbidden" });
  }
  // Q4 #18: a team 'admin'/'developer' can trigger this on the owner's
  // behalf, but every write below is still attributed to the owner
  // (scan.owner), never the acting caller — same account the scan already
  // belongs to keeps the plan cap, rate-limit bucket, and dashboard listing.
  const actingOwnerId = scan.owner;

  try {
    await validateNoSsrf(scan.target_url);
  } catch (err) {
    return res.status(400).json({ error: `SSRF check failed: ${(err as Error).message}` });
  }

  if (!(await isDomainVerified(supabaseAdmin, actingOwnerId, scan.target_url))) {
    return res.status(403).json({ error: "Domain ownership verification is no longer on file for this target." });
  }

  const { data: target } = await supabaseAdmin
    .from("monitored_targets")
    .select("scan_profile")
    .eq("owner", actingOwnerId)
    .eq("target_url", scan.target_url)
    .maybeSingle();
  const scanProfile = target?.scan_profile ?? "safe";

  const { data: newScan, error: insertError } = await supabaseAdmin
    .from("scans")
    .insert({ owner: actingOwnerId, target_url: scan.target_url, status: "running", owner_verified: true })
    .select("id")
    .single();
  if (insertError || !newScan) return res.status(500).json({ error: insertError?.message ?? "Failed to create replay scan" });

  const { error: jobError } = await supabaseAdmin.from("scan_jobs").insert({
    owner: actingOwnerId,
    target_url: scan.target_url,
    scan_id: newScan.id,
    scan_profile: scanProfile,
    status: "pending",
  });
  if (jobError) {
    await supabaseAdmin.from("scans").update({ status: "failed" }).eq("id", newScan.id);
    return res.status(500).json({ error: `Failed to queue replay: ${jobError.message}` });
  }

  // See this module's header for why only a "safe" replay gets the fast
  // on-demand dispatch — anything else waits for the next scheduled-scans.yml
  // cron, which is the only environment with the extended-tool binaries.
  if (scanProfile === "safe") {
    await triggerOnDemandWorkflow();
  }

  return res.status(202).json({
    ok: true,
    scanId: newScan.id,
    status: "queued",
    scanProfile,
    note: scanProfile === "safe" ? undefined : "This profile requires the scheduled scan runner — it'll be picked up within a day, not immediately.",
  });
}
