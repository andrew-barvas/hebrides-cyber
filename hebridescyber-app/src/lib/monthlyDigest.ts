// Sends every active subscriber a monthly Security Score digest email — one
// email per subscriber (not per scan), summarising the most recent
// completed scan for each of their monitored targets.
//
// Extracted from the former src/pages/api/send-monthly-digest.ts (see
// docs/ENHANCEMENTS.md E-11): a serial loop over every active subscriber,
// each iteration issuing 3+ Supabase queries plus an outbound email, all
// inside a single HTTP request, is the exact execution-ceiling failure mode
// ("Backend call failure") already hit and fixed twice for daily-blog.yml
// and weekly-newsletter.yml — see src/scripts/generate-daily-blog.ts's
// header. This is that same fix applied a third time: the logic lives here
// as a plain function, run directly against Supabase by
// src/scripts/send-monthly-digest.ts with no HTTP hop, instead of behind an
// API route.
import type { SupabaseClient } from "@supabase/supabase-js";
import { diffFindings } from "./findingsDiff";
import type { Finding } from "./scanners";
import { escapeHtml, sendEmail } from "./email";

type ScanResultRow = { results: { findings?: Finding[] }; score: number | null; created_at: string };
type ScanRow = { id: string; target_url: string; created_at: string; scan_results: ScanResultRow[] };

type TargetSummary = {
  targetUrl: string;
  score: number | null;
  scoreDelta: number | null;
  newCount: number | null;
  fixedCount: number | null;
  scanId: string;
};

export type MonthlyDigestResult = { ok: true; sent: number; skipped: number; errors: string[] };

// How far back a "last month" comparison scan must be from the latest one to
// count as a real month-over-month delta, not just two scans a few days
// apart. Approximates "roughly a month back" without requiring an exact
// prior scan to exist on a fixed schedule.
const MIN_COMPARISON_GAP_MS = 20 * 24 * 60 * 60 * 1000;
// How far back to even fetch scans from — enough slack past the comparison
// gap to reliably find a candidate, without scanning full history.
const LOOKBACK_MS = 45 * 24 * 60 * 60 * 1000;

export async function sendMonthlyDigest(supabaseAdmin: SupabaseClient): Promise<MonthlyDigestResult> {
  const { data: activeSubs, error: subsError } = await supabaseAdmin
    .from("subscriptions")
    .select("owner")
    .eq("status", "active");
  if (subsError) throw new Error(subsError.message);

  let sent = 0;
  let skipped = 0;
  const errors: string[] = [];

  for (const sub of activeSubs ?? []) {
    try {
      const outcome = await sendDigestForOwner(supabaseAdmin, sub.owner as string);
      if (outcome === "sent") sent++;
      else skipped++;
    } catch (err) {
      errors.push(`${sub.owner}: ${(err as Error).message}`);
    }
  }

  return { ok: true, sent, skipped, errors };
}

async function sendDigestForOwner(supabaseAdmin: SupabaseClient, ownerId: string): Promise<"sent" | "skipped"> {
  const { data: targets } = await supabaseAdmin.from("monitored_targets").select("target_url").eq("owner", ownerId);
  if (!targets || targets.length === 0) return "skipped";

  const { data: userRow } = await supabaseAdmin.from("users").select("email").eq("id", ownerId).maybeSingle();
  const toEmail = userRow?.email;
  if (!toEmail) {
    console.error(`[monthlyDigest] no email on file for owner ${ownerId}`);
    return "skipped";
  }

  const since = new Date(Date.now() - LOOKBACK_MS).toISOString();
  const { data: scans } = await supabaseAdmin
    .from("scans")
    .select("id, target_url, created_at, scan_results(results, score, created_at)")
    .eq("owner", ownerId)
    .eq("status", "completed")
    .gte("created_at", since)
    .order("created_at", { ascending: false });

  const targetUrls = new Set((targets ?? []).map((t) => t.target_url as string));
  const rows = ((scans ?? []) as ScanRow[]).filter((s) => targetUrls.has(s.target_url) && s.scan_results?.[0]);

  // Group by target — one entry (most recent completed scan) per monitored
  // target this owner has, not one per scan. `rows` is already sorted
  // newest-first (inherited from the query's order), so the first row seen
  // per target is its most recent.
  const byTarget = new Map<string, ScanRow[]>();
  for (const row of rows) {
    const list = byTarget.get(row.target_url) ?? [];
    list.push(row);
    byTarget.set(row.target_url, list);
  }

  const summaries: TargetSummary[] = [];
  for (const [targetUrl, scanList] of byTarget) {
    const latest = scanList[0];
    const latestResult = latest.scan_results[0];
    const latestFindings = latestResult.results?.findings ?? [];
    const latestTime = new Date(latest.created_at).getTime();

    const comparison = scanList
      .slice(1)
      .find((s) => latestTime - new Date(s.created_at).getTime() >= MIN_COMPARISON_GAP_MS);

    let scoreDelta: number | null = null;
    let newCount: number | null = null;
    let fixedCount: number | null = null;
    if (comparison) {
      const comparisonResult = comparison.scan_results[0];
      if (typeof latestResult.score === "number" && typeof comparisonResult.score === "number") {
        scoreDelta = latestResult.score - comparisonResult.score;
      }
      const diff = diffFindings(latestFindings, comparisonResult.results?.findings ?? []);
      newCount = diff.added.length;
      fixedCount = diff.fixed.length;
    }

    summaries.push({ targetUrl, score: latestResult.score, scoreDelta, newCount, fixedCount, scanId: latest.id });
  }

  if (summaries.length === 0) return "skipped"; // nothing completed in the lookback window to report on

  summaries.sort((a, b) => a.targetUrl.localeCompare(b.targetUrl));

  const siteUrl = process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk";
  const monthLabel = new Date().toLocaleString("en-GB", { month: "long", year: "numeric" });
  const html = buildDigestHtml(summaries, siteUrl);

  const result = await sendEmail({
    to: toEmail,
    subject: `Your Hebrides Cyber Security Score digest — ${monthLabel}`,
    html,
  });
  if (!result.ok) throw new Error(result.error ?? "send failed");
  return "sent";
}

function buildDigestHtml(summaries: TargetSummary[], siteUrl: string): string {
  const rows = summaries
    .map((s) => {
      const host = hostnameOf(s.targetUrl);
      const deltaText =
        s.scoreDelta === null ? "" : s.scoreDelta === 0 ? " (no change)" : s.scoreDelta > 0 ? ` (+${s.scoreDelta})` : ` (${s.scoreDelta})`;
      const changeText = s.newCount === null ? "no prior scan to compare" : `${s.newCount} new · ${s.fixedCount} fixed`;
      return (
        `<tr>` +
        `<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-size:14px;">${escapeHtml(host)}</td>` +
        `<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-size:14px;">${s.score ?? "—"}/100${escapeHtml(deltaText)}</td>` +
        `<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-size:14px;">${escapeHtml(changeText)}</td>` +
        `<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-size:14px;"><a href="${siteUrl}/dashboard/scans/${s.scanId}">View</a></td>` +
        `</tr>`
      );
    })
    .join("");

  return `
    <div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:600px;margin:0 auto;color:#111827;">
      <h2 style="margin:0 0 8px;font-size:20px;">Your monthly Security Score digest</h2>
      <p style="margin:0 0 16px;color:#4b5563;font-size:14px;line-height:1.5;">
        Here's how your monitored sites are doing.
      </p>
      <table style="width:100%;border-collapse:collapse;margin-bottom:20px;">
        <thead>
          <tr>
            <th style="text-align:left;padding:8px 12px;border-bottom:2px solid #111827;font-size:12px;">Target</th>
            <th style="text-align:left;padding:8px 12px;border-bottom:2px solid #111827;font-size:12px;">Score</th>
            <th style="text-align:left;padding:8px 12px;border-bottom:2px solid #111827;font-size:12px;">Since last month</th>
            <th style="text-align:left;padding:8px 12px;border-bottom:2px solid #111827;font-size:12px;"></th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
      <p style="margin:0 0 24px;">
        <a href="${siteUrl}/dashboard" style="display:inline-block;background:#111827;color:#ffffff;padding:10px 20px;border-radius:6px;text-decoration:none;font-size:14px;">
          Open dashboard
        </a>
      </p>
      <p style="margin:0;color:#9ca3af;font-size:12px;">
        You're receiving this because monthly Security Score emails are
        included with your Hebrides Cyber plan.
      </p>
    </div>
  `;
}

function hostnameOf(targetUrl: string): string {
  try {
    return new URL(targetUrl).hostname;
  } catch {
    return targetUrl;
  }
}
