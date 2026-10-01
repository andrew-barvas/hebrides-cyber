// Scheduled report delivery — generates and emails periodic scan summaries.
//
// Called by a scheduled script (src/scripts/send-scheduled-reports.ts)
// to find due reports, generate content, and deliver via email.
// Follows the same best-effort pattern as the newsletter/digest scripts.

import type { SupabaseClient } from "@supabase/supabase-js";

export type ReportFrequency = "daily" | "weekly" | "monthly";
export type ReportFormat = "pdf" | "csv" | "json";

export type ScheduledReport = {
  id: string;
  owner: string;
  target_url: string | null;
  frequency: ReportFrequency;
  format: ReportFormat;
  recipients: string[];
  enabled: boolean;
  last_sent: string | null;
  next_due: string | null;
};

function computeNextDue(frequency: ReportFrequency, from: Date): Date {
  const next = new Date(from);
  switch (frequency) {
    case "daily":
      next.setUTCDate(next.getUTCDate() + 1);
      break;
    case "weekly":
      next.setUTCDate(next.getUTCDate() + 7);
      break;
    case "monthly":
      next.setUTCMonth(next.getUTCMonth() + 1);
      break;
  }
  return next;
}

/**
 * Pure function: is a report due now?
 */
export function isReportDue(nextDue: string | null, now: Date): boolean {
  if (!nextDue) return true;
  return now >= new Date(nextDue);
}

export type FindingSummary = {
  targetUrl: string;
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  score: number | null;
  lastScanDate: string | null;
};

/**
 * Gather findings summary for a report — either for one target or all targets.
 */
export async function gatherReportData(
  supabaseAdmin: SupabaseClient,
  ownerId: string,
  targetUrl: string | null,
): Promise<FindingSummary[]> {
  const summaries: FindingSummary[] = [];

  let targetsQuery = supabaseAdmin
    .from("monitored_targets")
    .select("target_url")
    .eq("owner", ownerId);

  if (targetUrl) {
    targetsQuery = targetsQuery.eq("target_url", targetUrl);
  }

  const { data: targets } = await targetsQuery;
  if (!targets || targets.length === 0) return summaries;

  for (const target of targets) {
    const { data: latestScan } = await supabaseAdmin
      .from("scans")
      .select("id, score, created_at")
      .eq("owner", ownerId)
      .eq("target_url", target.target_url)
      .eq("status", "completed")
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();

    if (!latestScan) {
      summaries.push({
        targetUrl: target.target_url,
        totalFindings: 0,
        critical: 0, high: 0, medium: 0, low: 0, info: 0,
        score: null,
        lastScanDate: null,
      });
      continue;
    }

    const { data: results } = await supabaseAdmin
      .from("scan_results")
      .select("results")
      .eq("scan_id", latestScan.id)
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();

    const findings = (results?.results as { findings?: Array<{ severity: string }> })?.findings ?? [];
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) {
      const sev = f.severity as keyof typeof counts;
      if (sev in counts) counts[sev]++;
    }

    summaries.push({
      targetUrl: target.target_url,
      totalFindings: findings.length,
      ...counts,
      score: latestScan.score ?? null,
      lastScanDate: latestScan.created_at,
    });
  }

  return summaries;
}

/**
 * Format a report as CSV text.
 */
export function formatReportCsv(summaries: FindingSummary[]): string {
  const header = "target_url,score,total_findings,critical,high,medium,low,info,last_scan_date";
  const rows = summaries.map((s) =>
    `${s.targetUrl},${s.score ?? ""},${s.totalFindings},${s.critical},${s.high},${s.medium},${s.low},${s.info},${s.lastScanDate ?? ""}`
  );
  return [header, ...rows].join("\r\n");
}

/**
 * Format a report as JSON.
 */
export function formatReportJson(summaries: FindingSummary[]): string {
  return JSON.stringify({ generated_at: new Date().toISOString(), targets: summaries }, null, 2);
}

/**
 * Mark a report as sent and compute the next due date.
 */
export async function markReportSent(
  supabaseAdmin: SupabaseClient,
  reportId: string,
  frequency: ReportFrequency,
): Promise<void> {
  const now = new Date();
  await supabaseAdmin
    .from("scheduled_reports")
    .update({
      last_sent: now.toISOString(),
      next_due: computeNextDue(frequency, now).toISOString(),
      updated_at: now.toISOString(),
    })
    .eq("id", reportId);
}
