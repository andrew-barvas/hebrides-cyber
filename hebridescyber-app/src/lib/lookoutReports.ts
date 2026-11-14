// Lookout analyst reports (migration 075, NEXT-BUILDS-DESIGN-2026-11.md task
// 5). An admin creates a draft for a customer and period; it is pre-filled
// from the customer's "fix this first" ranking (estatePriority.ts) and what
// changed in the period (estateDrift.ts). The admin edits it, publishes it,
// and the customer confirms they've read it.
//
// ⚑ Owner decisions recorded as defaults here: admins write reports
// (users.is_admin), "acknowledge" means "I've read this report" and nothing
// more (wording to be checked under OT-35), and cadence (OT-42) is left to
// the analyst for now.
import type { SupabaseClient } from "@supabase/supabase-js";
import type { PrioritisedFinding } from "./estatePriority";
import { buildHostSignals, loadTargetContexts, rankFindings } from "./estatePriority";
import { loadFindingsView } from "./findingsView";
import { loadEstateDrift, type EstateDrift } from "./estateDrift";

export const DRAFT_ITEMS = 10;
export const REPORT_STATUSES = ["draft", "published", "acknowledged"] as const;
export type ReportStatus = (typeof REPORT_STATUSES)[number];
export const FIX_OWNERS = ["customer", "it_supplier", "hosting_provider", "unknown"] as const;

export type DraftItem = { host: string; check_id: string; severity: string; title: string; priority: number; analyst_note: string; business_impact: string; included: boolean };

/** Pure: the draft's items from the ranked findings, top DRAFT_ITEMS included, each with the ranking's reason as a starting note. */
export function draftItemsFromRanking(ranked: PrioritisedFinding[], limit = DRAFT_ITEMS): DraftItem[] {
  return ranked.slice(0, limit).map((f, i) => ({
    host: f.host,
    check_id: f.checkId,
    severity: f.severity,
    title: f.title,
    priority: i + 1,
    analyst_note: "",
    business_impact: "",
    included: true,
  }));
}

/** Pure: a starting summary from the period's drift, for the analyst to rewrite. */
export function draftSummary(drift: EstateDrift | null): string {
  if (!drift) return "";
  const parts = [
    `In this period ${drift.opened.total} new issue${drift.opened.total === 1 ? "" : "s"} appeared and ${drift.fixed.total} ${drift.fixed.total === 1 ? "was" : "were"} fixed; ${drift.openNow.total} remain open.`,
  ];
  if (drift.newHosts.length > 0) parts.push(`We found ${drift.newHosts.length} new hostname${drift.newHosts.length === 1 ? "" : "s"}: ${drift.newHosts.slice(0, 5).join(", ")}${drift.newHosts.length > 5 ? " and others" : ""}.`);
  return parts.join(" ");
}

/** Pure: which status changes are allowed, and by whom. */
export function canTransition(from: ReportStatus, to: ReportStatus, actor: "admin" | "customer"): boolean {
  if (actor === "admin") return (from === "draft" && to === "published") || (from === "published" && to === "draft");
  return from === "published" && to === "acknowledged";
}

/** Loads what a new draft needs for this customer: the ranking and the period's drift. */
export async function loadDraftInputs(supabaseAdmin: SupabaseClient, customer: string, periodDays: 7 | 30 | 90): Promise<{ items: DraftItem[]; summary: string }> {
  const [view, targets, drift] = await Promise.all([loadFindingsView(supabaseAdmin, customer), loadTargetContexts(supabaseAdmin, customer), loadEstateDrift(supabaseAdmin, customer, periodDays)]);
  const ranked = view.ok ? rankFindings(view.data.rows, targets.contexts, buildHostSignals(view.data.detailByHost)) : [];
  return { items: draftItemsFromRanking(ranked), summary: draftSummary(drift.ok && drift.available ? drift.drift : null) };
}
