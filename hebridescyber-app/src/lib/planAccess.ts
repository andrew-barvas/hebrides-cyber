// Plan checks for features sold on Pro and Agency. The one place that
// decides whether a subscription grants a tier, so every gate agrees:
// - only an ACTIVE subscription counts. The Stripe webhook marks a lapsed or
//   cancelled subscription `past_due`/`cancelled` and leaves `plan` as it
//   was, so a gate reading `plan` alone kept paid features switched on for
//   accounts that had stopped paying;
// - admins are exempt, as everywhere else;
// - Agency includes everything Pro has.
import type { SupabaseClient } from "@supabase/supabase-js";

export type PlanTier = "pro" | "agency";

type SubscriptionRow = { plan?: string | null; status?: string | null } | null | undefined;

/** Pure: does this subscription row grant the tier? */
export function subscriptionGrants(sub: SubscriptionRow, tier: PlanTier): boolean {
  if (!sub || sub.status !== "active") return false;
  return tier === "pro" ? sub.plan === "pro" || sub.plan === "agency" : sub.plan === "agency";
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
