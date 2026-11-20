// Who may use the device patch-audit agent.
//
// PACKAGING IS UNDECIDED (owner decision, OT item): the agent may ship inside
// Lookout or as a separate Cyber Essentials add-on. Every gate goes through
// this one function so that decision changes one line here, not the routes.
// Until then it follows the Cyber Essentials evidence pack, which is Pro and
// up (planAccess.ts tiers nest, so Agency and Tier A are included).
import type { SupabaseClient } from "@supabase/supabase-js";
import { planGate, type PlanTier } from "@/lib/planAccess";

export const DEVICE_AGENT_TIER: PlanTier = "pro";

/** At most this many active devices per account. */
export const MAX_ACTIVE_DEVICES = 250;

export function deviceAgentGate(supabaseAdmin: SupabaseClient, ownerId: string): Promise<"ok" | "denied" | "error"> {
  return planGate(supabaseAdmin, ownerId, DEVICE_AGENT_TIER);
}
