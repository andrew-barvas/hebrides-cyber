// Plan checks for API features sold on Pro and Agency. Admins are exempt, as
// everywhere else (see slaAlerts.ts's hasSlaAccess for the Agency-only twin).
import type { SupabaseClient } from "@supabase/supabase-js";

export async function hasProAccess(supabaseAdmin: SupabaseClient, ownerId: string): Promise<boolean> {
  const [{ data: sub }, { data: user }] = await Promise.all([
    supabaseAdmin.from("subscriptions").select("plan, status").eq("owner", ownerId).maybeSingle(),
    supabaseAdmin.from("users").select("is_admin").eq("id", ownerId).maybeSingle(),
  ]);
  return Boolean(user?.is_admin) || ((sub?.plan === "pro" || sub?.plan === "agency") && sub?.status === "active");
}
