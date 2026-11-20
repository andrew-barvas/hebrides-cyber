// The weekly "one thing to fix" email (IMPROVEMENT-REVIEW-2026-11.md idea,
// next-10 task 4). Each active subscriber who hasn't turned it off gets one
// email a week naming the single most urgent open finding across their sites
// (estatePriority.ts's "fix this first" rank, which already leaves out
// triaged and info findings), why it matters, how to fix it (the finding's
// own remediation, which carries the platform-specific steps from
// platformGuides.ts), a rough effort, and a link to the report where "Check
// it's fixed" reruns just that check. It also says whether last week's
// suggestion has been fixed. No finding worth fixing means no email.
//
// When the site isn't yet rated Strong, it also says how many fixes, starting
// with this one, would lift it to the next rating (scorePlanner.ts), counting
// only open, untriaged findings from that site's latest scan.
import type { SupabaseClient } from "@supabase/supabase-js";
import { escapeHtml, sendEmail } from "./email";
import { buildHostSignals, loadTargetContexts, rankFindings, type PrioritisedFinding } from "./estatePriority";
import { loadFindingsView, type HostDetail } from "./findingsView";
import { estimateFixMinutes, getFixDifficulty } from "./scanners/fixDifficulty";
import { nextRatingTarget, planCandidates, planToTarget, ratingLabel } from "./scorePlanner";

/** A re-run within this window of the last send skips the owner, so the cron or a manual dispatch never sends twice in a week. */
export const RESEND_GUARD_MS = 6 * 24 * 60 * 60 * 1000;
const REMEDIATION_MAX = 1500;

export type LastSuggestion = { host: string; checkId: string; title: string; fixed: boolean } | null;

/** How many fixes, starting with this week's, lift the site to its next rating. */
export type RatingStep = { fixes: number; fromLabel: string; toLabel: string };

export type WeeklyFixInput = {
  finding: PrioritisedFinding;
  remediation: string | null;
  openCount: number;
  last: LastSuggestion;
  siteUrl: string;
  ratingStep?: RatingStep | null;
};

/** Pure: the most urgent finding worth a weekly nudge, or null. */
export function pickWeeklyFix(ranked: readonly PrioritisedFinding[]): PrioritisedFinding | null {
  return ranked.find((f) => f.triage === null && f.severity !== "info") ?? null;
}

/** Pure: the finding's stored remediation from the latest scan of its site. */
export function remediationFor(detailByHost: ReadonlyMap<string, HostDetail>, host: string, checkId: string): string | null {
  const f = detailByHost.get(host)?.findings.find((x) => x.checkId === checkId) as { remediation?: unknown } | undefined;
  return typeof f?.remediation === "string" && f.remediation.trim() ? f.remediation.trim() : null;
}

/**
 * Pure. The rating step for this week's finding's site, or null when the site
 * has no stored score, is already Strong, or can't reach the next rating from
 * its open, untriaged findings. `openCheckIds` is the site's open, untriaged
 * checkIds (from the ranked rows), so fixed and triaged findings never appear.
 */
export function ratingStepFor(detail: HostDetail | undefined, openCheckIds: ReadonlySet<string>, checkId: string): RatingStep | null {
  if (!detail || typeof detail.score !== "number") return null;
  const target = nextRatingTarget(detail.score);
  if (!target) return null;
  const candidates = planCandidates(detail.findings.filter((f) => f.checkId && openCheckIds.has(f.checkId)));
  if (!candidates.some((c) => c.checkId === checkId)) return null;
  const plan = planToTarget(detail.score, candidates, target.minScore, { include: [checkId] });
  if (!plan.reachable || plan.fixes.length === 0) return null;
  return { fixes: plan.fixes.length, fromLabel: ratingLabel(detail.score), toLabel: target.label };
}

/** Minimal Markdown (bold, line breaks) to safe HTML; everything else is escaped. */
function markdownish(text: string): string {
  const cut = text.length > REMEDIATION_MAX ? `${text.slice(0, REMEDIATION_MAX).replace(/\s+\S*$/, "")}…` : text;
  return escapeHtml(cut)
    .replace(/\*\*(.+?)\*\*/g, "<b>$1</b>")
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\r?\n/g, "<br>");
}

function effortLabel(checkId: string): string | null {
  const difficulty = getFixDifficulty(checkId);
  if (!difficulty) return null;
  const minutes = estimateFixMinutes(difficulty);
  return minutes < 60 ? `about ${minutes} minutes` : `about ${Math.round(minutes / 60)} hour${minutes >= 120 ? "s" : ""}`;
}

/** Pure. */
export function buildWeeklyFixEmail(input: WeeklyFixInput): { subject: string; html: string } {
  const { finding, remediation, openCount, last, siteUrl, ratingStep } = input;
  const e = escapeHtml;
  const effort = effortLabel(finding.checkId);
  const reportUrl = finding.scanId ? `${siteUrl}/dashboard/scans/${finding.scanId}` : `${siteUrl}/dashboard/findings?sort=priority`;
  const p = (html: string) => `<p style="margin:0 0 12px;font-size:14px;line-height:1.5;">${html}</p>`;

  const progress = last
    ? last.fixed
      ? p(`<b>Last week's is fixed:</b> ${e(last.title)}. Nice work.`)
      : last.checkId === finding.checkId && last.host === finding.host
        ? p("This is still last week's suggestion. It's the most important one to get done.")
        : ""
    : "";
  const step = ratingStep
    ? p(
        ratingStep.fixes === 1
          ? `<b>Fixing this one</b> should take ${e(finding.host)} from ${e(ratingStep.fromLabel)} to ${e(ratingStep.toLabel)}.`
          : `<b>Fixing this and ${ratingStep.fixes - 1} more</b> should take ${e(finding.host)} from ${e(ratingStep.fromLabel)} to ${e(ratingStep.toLabel)}. The report's planner shows which.`
      )
    : "";
  const remaining = openCount > 1 ? p(`<span style="color:#4b5563">${openCount - 1} other open issue${openCount - 1 === 1 ? "" : "s"} can wait until this one's done.</span>`) : "";

  const html = `
    <div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:600px;margin:0 auto;color:#111827;">
      <h2 style="margin:0 0 4px;font-size:20px;">One thing to fix this week</h2>
      <p style="margin:0 0 16px;color:#4b5563;font-size:14px;">${e(finding.host)}${effort ? ` · ${e(effort)}` : ""}</p>
      ${progress}
      <h3 style="margin:0 0 8px;font-size:16px;">${e(finding.title)}</h3>
      ${p(`<b>Why this one:</b> ${e(finding.priority.reason)}`)}
      ${finding.detail ? p(e(finding.detail)) : ""}
      ${remediation ? `<div style="margin:0 0 16px;padding:12px;border:1px solid #e5e7eb;border-radius:8px;font-size:14px;line-height:1.5;"><b>How to fix it</b><br>${markdownish(remediation)}</div>` : ""}
      ${step}
      <p style="margin:0 0 16px;"><a href="${reportUrl}" style="display:inline-block;background:#0b3d5b;color:#ffffff;text-decoration:none;padding:10px 16px;border-radius:6px;font-size:14px;">Open the report and check it's fixed</a></p>
      ${remaining}
      <p style="margin:24px 0 0;color:#6b7280;font-size:12px;line-height:1.5;">You get this weekly as part of your Hebrides Cyber plan. Turn it off under Integrations → Notification preferences: ${siteUrl}/dashboard/integrations</p>
    </div>`;
  return { subject: `One thing to fix this week: ${finding.title}`.slice(0, 150), html };
}

type SubRow = { owner: string; notify_weekly_fix: boolean | null; weekly_fix_sent_at: string | null; weekly_fix_host: string | null; weekly_fix_check_id: string | null; weekly_fix_title: string | null };

export type WeeklyFixResult = { sent: number; skipped: number; errors: string[] };

export async function sendWeeklyFixEmails(supabaseAdmin: SupabaseClient, opts: { now?: Date; siteUrl?: string } = {}): Promise<WeeklyFixResult> {
  const now = opts.now ?? new Date();
  const siteUrl = opts.siteUrl ?? process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk";
  const { data: subs, error } = await supabaseAdmin
    .from("subscriptions")
    .select("owner, notify_weekly_fix, weekly_fix_sent_at, weekly_fix_host, weekly_fix_check_id, weekly_fix_title")
    .eq("status", "active");
  if (error) throw new Error(error.message);

  const result: WeeklyFixResult = { sent: 0, skipped: 0, errors: [] };
  for (const sub of (subs ?? []) as SubRow[]) {
    try {
      const outcome = await sendForOwner(supabaseAdmin, sub, now, siteUrl);
      if (outcome === "sent") result.sent++;
      else result.skipped++;
    } catch (err) {
      result.errors.push(`${sub.owner}: ${(err as Error).message}`);
    }
  }
  return result;
}

async function sendForOwner(supabaseAdmin: SupabaseClient, sub: SubRow, now: Date, siteUrl: string): Promise<"sent" | "skipped"> {
  if (sub.notify_weekly_fix === false) return "skipped";
  if (sub.weekly_fix_sent_at && now.getTime() - Date.parse(sub.weekly_fix_sent_at) < RESEND_GUARD_MS) return "skipped";

  const [view, targets] = await Promise.all([loadFindingsView(supabaseAdmin, sub.owner, now), loadTargetContexts(supabaseAdmin, sub.owner)]);
  if (!view.ok) throw new Error(view.error);
  const ranked = rankFindings(view.data.rows, targets.contexts, buildHostSignals(view.data.detailByHost));
  const finding = pickWeeklyFix(ranked);
  if (!finding) return "skipped";

  let last: LastSuggestion = null;
  if (sub.weekly_fix_host && sub.weekly_fix_check_id) {
    const stillOpen = view.data.rows.some((r) => r.host === sub.weekly_fix_host && r.checkId === sub.weekly_fix_check_id);
    last = { host: sub.weekly_fix_host, checkId: sub.weekly_fix_check_id, title: sub.weekly_fix_title ?? sub.weekly_fix_check_id, fixed: !stillOpen };
  }

  const { data: user } = await supabaseAdmin.from("users").select("email").eq("id", sub.owner).maybeSingle();
  const to = (user as { email?: string } | null)?.email;
  if (!to) return "skipped";

  const openOnHost = new Set(ranked.filter((r) => r.host === finding.host && r.triage === null).map((r) => r.checkId));
  const email = buildWeeklyFixEmail({
    finding,
    remediation: remediationFor(view.data.detailByHost, finding.host, finding.checkId),
    openCount: ranked.length,
    last,
    siteUrl,
    ratingStep: ratingStepFor(view.data.detailByHost.get(finding.host), openOnHost, finding.checkId),
  });
  const sent = await sendEmail({ to, subject: email.subject, html: email.html });
  if (!sent.ok) throw new Error(sent.error ?? "send failed");

  await supabaseAdmin
    .from("subscriptions")
    .update({ weekly_fix_sent_at: now.toISOString(), weekly_fix_host: finding.host, weekly_fix_check_id: finding.checkId, weekly_fix_title: finding.title })
    .eq("owner", sub.owner);
  return "sent";
}
