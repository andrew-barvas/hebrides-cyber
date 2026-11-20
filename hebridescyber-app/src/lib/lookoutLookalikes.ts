// Lookalike domains in a Lookout report (next-10 task 3). The weekly
// lookalike sweep (lookalikeDomainMonitor.ts, migration 053) records each
// registered lookalike of a customer's domain once; a report lists those
// spotted during its period, plus how many are known in all. Spotted = when
// our sweep first found it (notified_at), not the certificate's own date,
// which can be much older.
import type { SupabaseClient } from "@supabase/supabase-js";
import { isMissingSchemaError } from "./dbErrors";
import { lookalikeTechniqueLabel } from "./lookalikeDomainMonitor";

export const REPORT_LOOKALIKES_MAX = 20;

export type ReportLookalike = { domain: string; targetDomain: string; how: string; spottedAt: string; certificateSeenAt: string };
export type ReportLookalikes = { available: boolean; newInPeriod: ReportLookalike[]; totalKnown: number };

type Row = { candidate_domain: string; target_domain: string; technique: string; first_seen_at: string; notified_at: string | null };

/** Pure: rows → the report's section for [periodStart, periodEnd] (dates, inclusive). */
export function lookalikesForPeriod(rows: readonly Row[], periodStart: string, periodEnd: string): Omit<ReportLookalikes, "available"> {
  const from = Date.parse(`${periodStart}T00:00:00Z`);
  const to = Date.parse(`${periodEnd}T23:59:59Z`);
  const newInPeriod = rows
    .map((r) => ({ r, spotted: r.notified_at ?? r.first_seen_at }))
    .filter(({ spotted }) => {
      const t = Date.parse(spotted);
      return Number.isFinite(t) && t >= from && t <= to;
    })
    .sort((a, b) => b.spotted.localeCompare(a.spotted))
    .slice(0, REPORT_LOOKALIKES_MAX)
    .map(({ r, spotted }) => ({ domain: r.candidate_domain, targetDomain: r.target_domain, how: lookalikeTechniqueLabel(r.technique), spottedAt: spotted, certificateSeenAt: r.first_seen_at }));
  return { newInPeriod, totalKnown: rows.length };
}

export async function loadReportLookalikes(supabaseAdmin: SupabaseClient, customer: string, periodStart: string, periodEnd: string): Promise<ReportLookalikes> {
  try {
    const { data, error } = await supabaseAdmin
      .from("lookalike_domains")
      .select("candidate_domain, target_domain, technique, first_seen_at, notified_at")
      .eq("owner", customer);
    if (error) {
      if (!isMissingSchemaError(error)) console.error("[lookout-lookalikes] read failed:", error.message);
      return { available: false, newInPeriod: [], totalKnown: 0 };
    }
    return { available: true, ...lookalikesForPeriod((data ?? []) as Row[], periodStart, periodEnd) };
  } catch {
    return { available: false, newInPeriod: [], totalKnown: 0 };
  }
}

/** One sentence for the draft summary; "" when nothing new. */
export function lookalikeSummarySentence(section: Pick<ReportLookalikes, "newInPeriod">): string {
  const n = section.newInPeriod.length;
  if (n === 0) return "";
  const names = section.newInPeriod.slice(0, 3).map((l) => l.domain).join(", ");
  return `We spotted ${n} new lookalike domain${n === 1 ? "" : "s"} of yours (${names}${n > 3 ? " and others" : ""}), a common setup for phishing your customers or staff.`;
}
