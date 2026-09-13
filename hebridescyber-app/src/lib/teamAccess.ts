// Q4 #18 "Team Accounts" (docs/24-FEATURE-EXPANSION-SPEC.md). Lets a team
// member with the 'admin' or 'developer' role take a cost-bearing action
// (replay a scan, retest a finding, create a ticket) on the team owner's
// account without impersonating them. A route calling this still attributes
// the resulting write to the OWNER (new scan/job rows get owner: scan.owner,
// tickets use the owner's own ticket_integrations row, etc.) —
// callerCanActFor only answers "is this caller allowed to act here", never
// "whose account does the write belong to".
//
// 'auditor' and the original 'member' role are deliberately excluded — both
// stay read-only, per 007_teams.sql's original "this does NOT touch how
// scans are created" design. Only two roles ever get a `true` here.
import type { SupabaseClient } from "@supabase/supabase-js";

const ACTING_ROLES = new Set(["admin", "developer"]);

export async function callerCanActFor(
  supabaseAdmin: SupabaseClient,
  callerId: string,
  targetOwnerId: string
): Promise<boolean> {
  if (callerId === targetOwnerId) return true;

  const { data: team } = await supabaseAdmin.from("teams").select("id").eq("owner_id", targetOwnerId).maybeSingle();
  if (!team) return false;

  const { data: membership } = await supabaseAdmin
    .from("team_members")
    .select("role")
    .eq("team_id", team.id)
    .eq("user_id", callerId)
    .maybeSingle();

  return Boolean(membership && ACTING_ROLES.has(membership.role as string));
}
