// Plan checks for features sold on Pro and Agency. The one place that
// decides whether a subscription grants a tier, so every gate agrees:
// - only an ACTIVE subscription counts. The Stripe webhook marks a lapsed or
//   cancelled subscription `past_due`/`cancelled` and leaves `plan` as it
//   was, so a gate reading `plan` alone kept paid features switched on for
//   accounts that had stopped paying;
// - admins are exempt, as everywhere else;
// - the tiers nest upward: Agency includes everything Pro has, and Tier A
//   (the top tier, which unlocks the opt-in offensive scanning suite) includes
//   everything Agency and Pro have.
import type { SupabaseClient } from "@supabase/supabase-js";

/** "basic" is any paid plan. */
export type PlanTier = "basic" | "pro" | "agency" | "tier_a";

type SubscriptionRow = { plan?: string | null; status?: string | null } | null | undefined;

// Each tier's set of satisfying `plan` values, highest-inclusive-downward. A
// plan satisfies a required tier when it appears in that tier's set.
const PLANS_FOR_TIER: Record<PlanTier, readonly string[]> = {
  basic: ["basic", "pro", "agency", "tier_a"],
  pro: ["pro", "agency", "tier_a"],
  agency: ["agency", "tier_a"],
  tier_a: ["tier_a"],
};

/** The `plan` values that satisfy `tier`, for queries that filter on `plan`. */
export function plansFor(tier: PlanTier): readonly string[] {
  return PLANS_FOR_TIER[tier];
}

/**
 * Pure: does this plan satisfy the tier? Ignores status, so callers that have
 * already checked the subscription is active (or are admins) use this rather
 * than comparing plan strings, which leave Tier A out.
 */
export function planIncludes(plan: string | null | undefined, tier: PlanTier): boolean {
  return Boolean(plan) && PLANS_FOR_TIER[tier].includes(plan as string);
}

/** Pure: does this subscription row grant the tier? */
export function subscriptionGrants(sub: SubscriptionRow, tier: PlanTier): boolean {
  if (!sub || sub.status !== "active") return false;
  return planIncludes(sub.plan, tier);
}

/**
 * "error" when the plan could not be read, so a route can answer 500 rather
 * than tell a paying customer to upgrade. Either way the feature stays shut.
 */
export async function planGate(supabaseAdmin: SupabaseClient, ownerId: string, tier: PlanTier): Promise<"ok" | "denied" | "error"> {
  const [subRes, userRes] = await Promise.all([
    supabaseAdmin.from("subscriptions").select("plan, status").eq("owner", ownerId).maybeSingle(),
    supabaseAdmin.from("users").select("is_admin").eq("id", ownerId).maybeSingle(),
  ]);
  if ((userRes.data as { is_admin?: boolean } | null)?.is_admin) return "ok";
  if (subRes.error || userRes.error) return "error";
  return subscriptionGrants(subRes.data as SubscriptionRow, tier) ? "ok" : "denied";
}

export async function hasPlanAccess(supabaseAdmin: SupabaseClient, ownerId: string, tier: PlanTier): Promise<boolean> {
  return (await planGate(supabaseAdmin, ownerId, tier)) === "ok";
}

export function hasProAccess(supabaseAdmin: SupabaseClient, ownerId: string): Promise<boolean> {
  return hasPlanAccess(supabaseAdmin, ownerId, "pro");
}

export function hasAgencyAccess(supabaseAdmin: SupabaseClient, ownerId: string): Promise<boolean> {
  return hasPlanAccess(supabaseAdmin, ownerId, "agency");
}

/**
 * Tier A is the top tier that unlocks the opt-in offensive scanning suite
 * (the `offensive` scan profile). It is necessary but NOT sufficient on its
 * own: an offensive scan also requires a current per-scan authorization record
 * (offensive_scan_authorizations) and a verified domain — see
 * run-queued-scan-jobs.ts. This only answers "is the owner on Tier A".
 */
export function hasTierAAccess(supabaseAdmin: SupabaseClient, ownerId: string): Promise<boolean> {
  return hasPlanAccess(supabaseAdmin, ownerId, "tier_a");
}
