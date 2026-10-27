// Plan checks for paid features. The one place that decides whether a
// subscription grants a tier, so every gate agrees:
// - only an ACTIVE subscription counts. The Stripe webhook marks a lapsed or
//   cancelled subscription `past_due`/`cancelled` and leaves `plan` as it
//   was, so a gate reading `plan` alone kept paid features switched on for
//   accounts that had stopped paying;
// - admins are exempt, as everywhere else;
// - the tiers nest upward: Pro includes everything Basic has, Agency
//   everything Pro has, and Tier A (the top tier, which unlocks the opt-in
//   offensive scanning suite) everything Agency, Pro and Basic have.
//
// Client-safe: the only import is a type, so dashboard pages use
// `planIncludes` on `useAppSession().plan` (already "none" unless the
// subscription is active) instead of comparing plan strings, which is how
// Tier A accounts once saw paid features locked that the API allowed.
import type { SupabaseClient } from "@supabase/supabase-js";

/** A `subscriptions.plan` value, or "none" when there is no active plan. */
export type Plan = "none" | "basic" | "pro" | "agency" | "tier_a";

/** A required tier. "basic" means any paid plan. */
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

/**
 * Pure: does this plan include the tier's features? Says nothing about
 * whether the subscription is active — pass a plan that is already "none"
 * when it isn't, as `useAppSession().plan` is.
 */
export function planIncludes(plan: string | null | undefined, tier: PlanTier): boolean {
  return !!plan && PLANS_FOR_TIER[tier].includes(plan);
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
