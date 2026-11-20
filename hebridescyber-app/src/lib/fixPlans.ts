// Shared fix plans (migration 083, COMPETITOR-ANALYSIS-ENTERPRISE-2026-11.md
// idea 8): an Agency user shares chosen findings from one site with whoever
// does the work, by link. SecurityScorecard's Action Plans are the pattern;
// ours is for an agency and its client.
//
// Status of an item, most certain first:
//   fixed        the owner's scans resolved it (finding_lifecycle.resolved_at,
//                which never treats a failed lookup as fixed)
//   marked_done  the person with the link says it's done; not yet confirmed
//   open
//
// The link is a bearer token (only its SHA-256 is stored). It can read the
// plan and mark items done, nothing else: it never starts a scan and never
// reads the scan itself, only the text snapshotted into the plan.
import { createHash, randomBytes } from "node:crypto";
import type { SupabaseClient } from "@supabase/supabase-js";

export const PLAN_TTL_DAYS_DEFAULT = 90;
export const PLAN_TTL_DAYS_MAX = 365;
export const PLAN_MAX_ITEMS = 50;
export const REMEDIATION_MAX = 6000;

export type ItemStatus = "fixed" | "marked_done" | "open";

export type PlanItemRow = {
  check_id: string;
  position: number;
  severity: string;
  title: string;
  remediation: string;
  client_done_at: string | null;
  client_note: string;
};

export type PlanRow = {
  id: string;
  owner: string;
  target_host: string;
  title: string;
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
};

export type PublicPlanItem = {
  checkId: string;
  position: number;
  severity: string;
  title: string;
  remediation: string;
  status: ItemStatus;
  fixedAt: string | null;
  markedDoneAt: string | null;
  note: string;
};

export type PublicPlan = {
  title: string;
  host: string;
  createdAt: string;
  expiresAt: string;
  progress: { fixed: number; markedDone: number; open: number; total: number };
  items: PublicPlanItem[];
};

export function newPlanToken(): { token: string; hash: string } {
  const token = randomBytes(32).toString("base64url");
  return { token, hash: hashPlanToken(token) };
}

export function hashPlanToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/** 43 base64url characters, what newPlanToken() makes. Anything else is rejected before a lookup. */
export function isPlanToken(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value);
}

export function planUrl(token: string, siteUrl = process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk"): string {
  return `${siteUrl.replace(/\/$/, "")}/plan/${token}`;
}

/** Pure: why a plan can't be shown, or null when it can. One message for every case, so a link's history isn't revealed. */
export function planUnavailable(plan: Pick<PlanRow, "expires_at" | "revoked_at"> | null, now: Date): string | null {
  if (!plan || plan.revoked_at || Date.parse(plan.expires_at) <= now.getTime()) return "This fix plan link isn't valid any more. Ask whoever sent it for a new one.";
  return null;
}

/** Pure. Each item's status from the owner's lifecycle rows (check_id → resolved_at). */
export function buildPublicPlan(plan: PlanRow, items: readonly PlanItemRow[], resolvedAt: ReadonlyMap<string, string | null>): PublicPlan {
  const out: PublicPlanItem[] = [...items]
    .sort((a, b) => a.position - b.position)
    .map((it) => {
      const fixedAt = resolvedAt.get(it.check_id) ?? null;
      const status: ItemStatus = fixedAt ? "fixed" : it.client_done_at ? "marked_done" : "open";
      return { checkId: it.check_id, position: it.position, severity: it.severity, title: it.title, remediation: it.remediation, status, fixedAt, markedDoneAt: it.client_done_at, note: it.client_note };
    });
  const count = (s: ItemStatus) => out.filter((i) => i.status === s).length;
  return {
    title: plan.title || `Fix plan for ${plan.target_host}`,
    host: plan.target_host,
    createdAt: plan.created_at,
    expiresAt: plan.expires_at,
    progress: { fixed: count("fixed"), markedDone: count("marked_done"), open: count("open"), total: out.length },
    items: out,
  };
}

/** Lifecycle resolution for the plan's checks on its host: check_id → resolved_at (null while open). Empty on any failure: status then falls back to what the link holder said. */
export async function loadResolutions(db: SupabaseClient, owner: string, host: string, checkIds: readonly string[]): Promise<Map<string, string | null>> {
  const out = new Map<string, string | null>();
  if (checkIds.length === 0) return out;
  try {
    const { data, error } = await db.from("finding_lifecycle").select("check_id, resolved_at").eq("owner", owner).eq("target_host", host).in("check_id", [...checkIds]);
    if (error) return out;
    for (const r of (data ?? []) as Array<{ check_id: string; resolved_at: string | null }>) out.set(r.check_id, r.resolved_at);
  } catch {
    /* enrichment only */
  }
  return out;
}

/** Loads a plan and its items by link token, or null when it doesn't exist. Throws on a read error. */
export async function loadPlanByToken(db: SupabaseClient, token: string): Promise<{ plan: PlanRow; items: PlanItemRow[] } | null> {
  const { data: plan, error } = await db
    .from("fix_plans")
    .select("id, owner, target_host, title, created_at, expires_at, revoked_at")
    .eq("token_hash", hashPlanToken(token))
    .maybeSingle();
  if (error) throw new Error(error.message);
  if (!plan) return null;
  const { data: items, error: itemsError } = await db
    .from("fix_plan_items")
    .select("check_id, position, severity, title, remediation, client_done_at, client_note")
    .eq("plan_id", (plan as PlanRow).id)
    .order("position", { ascending: true });
  if (itemsError) throw new Error(itemsError.message);
  return { plan: plan as PlanRow, items: (items ?? []) as PlanItemRow[] };
}
