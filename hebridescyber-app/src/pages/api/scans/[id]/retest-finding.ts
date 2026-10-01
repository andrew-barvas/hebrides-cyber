// POST /api/scans/{id}/retest-finding — the "recheck this one finding now"
// half of E-30 (docs/ENHANCEMENTS.md), harvested from Closed Door Security's
// PTaaS retest loop. Session or API key (same shape as ai-fix.ts/
// create-ticket.ts: a bounded, ownership-checked, cost-bearing click action,
// not "create a scan" — run-scan.ts's session-only restriction doesn't apply
// here).
//
// This is a real on-demand rescan (the same fast, base-suite-only path any
// "Scan now" click already triggers), not a scoped single-check re-run —
// there's no way to run just one check in isolation (runAllChecks() and the
// extended-tool batch in scanExecution.ts both always run as one atomic
// unit). The frontend surfaces it as "did THIS finding get fixed?" without
// implying anything narrower actually ran.
//
// Extended-tool findings (nuclei/zap/sqlmap/xsser/commix/nmap/subdomains/
// deep-tls/secretScan/dependency-manifest/docker-base-image/trivy-image/
// trivy-config/auth-check) are rejected outright — this route always
// pre-sets scan_id on the scan_jobs row it creates, and
// src/scripts/run-queued-scan-jobs.ts's resolveScanConfig() resolves any
// job with scan_id preset to the "safe" scan profile (src/lib/scanProfiles.ts),
// which runs none of those tools — so "retesting" one of their findings
// this way would silently report "fixed" without the tool that found it
// ever running again. See src/lib/extendedToolCheckIds.ts.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { checkRateLimit } from "@/lib/rateLimit";
import { triggerOnDemandWorkflow } from "@/lib/onDemandScanTrigger";
import { isExtendedToolFinding } from "@/lib/extendedToolCheckIds";
import { callerCanActFor } from "@/lib/teamAccess";
import type { Finding, ScanResults } from "@/lib/scanners";
import { parseBody } from "@/lib/validate";

const bodySchema = z.object({
  checkId: z.string().min(1, "checkId is required"),
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  const limit = await checkRateLimit(caller.ownerId, "retest-finding");
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds));
    return res.status(429).json({ error: "Rate limit exceeded — try again later", retryAfterSeconds: limit.retryAfterSeconds });
  }

  const scanId = req.query.id as string;
  const parsed = parseBody(bodySchema, req.body, res);
  if (!parsed) return;
  const { checkId } = parsed;

  const { data: scan } = await supabaseAdmin.from("scans").select("id, owner, target_url").eq("id", scanId).maybeSingle();
  if (!scan) return res.status(404).json({ error: "Scan not found" });
  const isOwner = scan.owner === caller.ownerId;
  if (!isOwner && !(await callerCanActFor(supabaseAdmin, caller.ownerId, scan.owner))) {
    return res.status(403).json({ error: "Forbidden" });
  }
  // Q4 #18: a team 'admin'/'developer' can retest on the owner's behalf; the
  // new scan/job rows still belong to the owner (scan.owner), not the caller.
  const actingOwnerId = scan.owner;

  const { data: result } = await supabaseAdmin
    .from("scan_results")
    .select("results")
    .eq("scan_id", scanId)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();
  if (!result) return res.status(404).json({ error: "No results for this scan yet" });

  const stored = result.results as ScanResults & { findings?: Finding[] };
  const finding = (stored.findings ?? []).find((f) => f.checkId === checkId);
  if (!finding) return res.status(404).json({ error: `No finding with checkId "${checkId}" on this scan` });

  if (isExtendedToolFinding(checkId)) {
    return res.status(400).json({
      error: "This finding was found by an extended scanning tool and can't be individually rechecked yet — run a new full scan to re-verify it.",
      code: "not_retestable",
    });
  }

  // owner_verified: true is display-only here, not a security shortcut —
  // src/scripts/run-queued-scan-jobs.ts's runOne() unconditionally
  // re-checks isDomainVerified() against the verifications table for every
  // job regardless of this flag, before ever calling executeScan(). The
  // real gate is enforced downstream either way; this just avoids making a
  // retest of an already-verified domain sit through the proof-token dance
  // run-scan.ts's fresh-scan flow needs.
  const { data: newScan, error: insertError } = await supabaseAdmin
    .from("scans")
    .insert({ owner: actingOwnerId, target_url: scan.target_url, status: "running", owner_verified: true })
    .select("id")
    .single();
  if (insertError || !newScan) return res.status(500).json({ error: insertError?.message ?? "Failed to create retest scan" });

  const { error: jobError } = await supabaseAdmin.from("scan_jobs").insert({
    owner: actingOwnerId,
    target_url: scan.target_url,
    scan_id: newScan.id,
    status: "pending",
  });
  if (jobError) {
    await supabaseAdmin.from("scans").update({ status: "failed" }).eq("id", newScan.id);
    return res.status(500).json({ error: `Failed to queue retest: ${jobError.message}` });
  }

  await triggerOnDemandWorkflow();

  return res.status(202).json({ ok: true, scanId: newScan.id, status: "queued", checkId });
}
