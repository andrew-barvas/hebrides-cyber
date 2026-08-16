// Free-tier scan cap: an account with no active subscription gets exactly
// one scan, ever. This is a cost-control measure (each scan burns real
// compute, third-party API calls, and — if Azure OpenAI is configured —
// tokens), distinct from rateLimit.ts's per-hour abuse throttle; the two are
// independent and both apply.
import type { SupabaseClient } from "@supabase/supabase-js";

export const FREE_SCANS_ALLOWED = 1;

/**
 * True when `ownerId` has no active subscription AND has already used their
 * free scan(s). Counts every scan NOT still 'pending' — a scan stuck at
 * 'pending' (awaiting domain verification) never actually executed the check
 * suite, so it hasn't cost anything and shouldn't count against the limit.
 * 'running' and 'failed' both mean the check suite actually started (real
 * cost incurred) even if it didn't end in 'completed', so both count.
 */
export async function isFreeTierExhausted(supabaseAdmin: SupabaseClient, ownerId: string): Promise<boolean> {
  const { data: user } = await supabaseAdmin.from("users").select("is_admin").eq("id", ownerId).maybeSingle();
  if (user?.is_admin) return false;

  const { data: sub } = await supabaseAdmin
    .from("subscriptions")
    .select("status")
    .eq("owner", ownerId)
    .maybeSingle();

  if (sub?.status === "active") return false;

  const { count } = await supabaseAdmin
    .from("scans")
    .select("id", { count: "exact", head: true })
    .eq("owner", ownerId)
    .neq("status", "pending");

  return (count ?? 0) >= FREE_SCANS_ALLOWED;
}

export const FREE_TIER_EXHAUSTED_MESSAGE =
  "You've used your free scan. Subscribe to a plan to run more — see /pricing.";
