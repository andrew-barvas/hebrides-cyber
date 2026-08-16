// Shared "finish a scan" logic: run the checks, write results, mark the scan
// completed, fire webhooks and the Slack change-alert. Extracted out of
// src/functions/run-scan/index.ts (the dashboard's synchronous scan path) so
// the queued-worker path (src/scripts/run-queued-scan-jobs.ts) executes the
// exact same sequence rather than a second copy that can drift — the same
// reasoning as src/lib/scanReport.ts's "one contract" comment.
//
// Callers are responsible for everything BEFORE this: creating the `scans`
// row, verifying ownership, and the SSRF check (validateNoSsrf). This
// function assumes all of that already happened.
import type { SupabaseClient } from "@supabase/supabase-js";
import { runAllChecks, summariseResults, scoreFromFindings, generateAiSummary, type Finding } from "./scanners";
import { buildScanReport, findPreviousFindings, type ScanReport } from "./scanReport";
import { dispatchScanCompletedWebhooks } from "./webhooks";
import { sendSlackAlert } from "./slack";

export type ScanExecutionResult =
  | { ok: true; score: number; summary: string; report: ScanReport }
  | { ok: false; error: string };

export async function executeScan(
  supabaseAdmin: SupabaseClient,
  scanId: string,
  ownerId: string,
  targetUrl: string
): Promise<ScanExecutionResult> {
  // Phase 1: the part that determines success/failure. Anything thrown here
  // means the scan itself didn't complete, so marking the row 'failed' is
  // correct.
  let score: number;
  let summary: string;
  let findings: Finding[];
  try {
    const results = await runAllChecks(targetUrl);
    ({ findings } = summariseResults(results));
    summary = await generateAiSummary(results, findings);
    score = scoreFromFindings(findings);

    const { error: resultsError } = await supabaseAdmin.from("scan_results").insert({
      scan_id: scanId,
      results: { ...results, findings },
      summary,
      score,
    });
    if (resultsError) throw new Error(resultsError.message);

    await supabaseAdmin.from("scans").update({ status: "completed" }).eq("id", scanId);
  } catch (err) {
    await supabaseAdmin
      .from("scans")
      .update({ status: "failed" })
      .eq("id", scanId)
      .then(
        () => {},
        () => {}
      );
    return { ok: false, error: (err as Error).message };
  }

  // Phase 1.5: build the report. The scan already succeeded and is already
  // recorded as 'completed' above, so a failure here (e.g. a transient
  // Supabase error while looking up the previous scan to diff against) must
  // not flip that back to 'failed' — it just means the report comes back
  // without new/fixed-finding comparison, same as a genuine first-ever scan.
  const completedAt = new Date().toISOString();
  const scanRow = { id: scanId, owner: ownerId, target_url: targetUrl, status: "completed", created_at: completedAt };
  const resultRow = { results: { findings }, summary, score, created_at: completedAt };
  let report: ScanReport;
  try {
    const previous = await findPreviousFindings(supabaseAdmin, ownerId, scanId, targetUrl, completedAt);
    report = buildScanReport(scanRow, resultRow, previous);
  } catch (err) {
    console.error(`[scanExecution] could not look up previous scan for diffing (scan ${scanId}):`, (err as Error).message);
    report = buildScanReport(scanRow, resultRow, null);
  }

  // Phase 2: notifications. dispatchScanCompletedWebhooks and the Slack
  // alert both already swallow their own errors internally, but wrapping
  // the whole phase keeps it that way even if that ever changes.
  try {
    await dispatchScanCompletedWebhooks(supabaseAdmin, ownerId, report);
    await sendChangeAlertIfDue(supabaseAdmin, ownerId, report, findings);
  } catch (err) {
    console.error(`[scanExecution] post-completion notifications failed for scan ${scanId}:`, (err as Error).message);
  }

  return { ok: true, score, summary, report };
}

/**
 * Slack "change alert" — fires only when this scan found something new
 * compared to the last one, so nightly monitoring doesn't spam a channel
 * with an identical "all clear" message every night. Gated to Pro/Agency
 * plans, matching what the services page advertises ("Slack alerts on score
 * change (Pro/Agency plan)").
 */
async function sendChangeAlertIfDue(
  supabaseAdmin: SupabaseClient,
  ownerId: string,
  report: ScanReport,
  findings: { severity: string }[]
): Promise<void> {
  if (!report.new_finding_count) return; // null (no previous scan) or 0 — nothing changed

  const { data: sub } = await supabaseAdmin
    .from("subscriptions")
    .select("plan, status, slack_webhook_url")
    .eq("owner", ownerId)
    .maybeSingle();

  if (!sub?.slack_webhook_url) return;
  if (sub.status !== "active") return;
  if (sub.plan !== "pro" && sub.plan !== "agency") return;

  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const highCount = findings.filter((f) => f.severity === "high").length;

  await sendSlackAlert(sub.slack_webhook_url, {
    scanId: report.scan_id,
    targetUrl: report.target_url,
    score: report.score ?? 0,
    findingsCount: findings.length,
    criticalCount,
    highCount,
    newFindingsCount: report.new_finding_count,
    fixedFindingsCount: report.fixed_finding_count ?? 0,
    dashboardUrl: process.env.NEXT_PUBLIC_SITE_URL ?? "https://hebridescyber.com",
  }).catch((err) => console.error("[scanExecution] slack change alert failed:", (err as Error).message));
}
