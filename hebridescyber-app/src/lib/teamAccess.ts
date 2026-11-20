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

export type ViewableAccount = { ownerId: string; email: string | null; role: string };

/**
 * The other accounts whose findings this caller may READ: every team they
 * belong to, in any role (007_teams.sql shares scans read-only with all of
 * them). Writing — triage, assignment — stays with the owner and the acting
 * roles above.
 */
export async function listViewableAccounts(supabaseAdmin: SupabaseClient, callerId: string): Promise<ViewableAccount[]> {
  const { data: memberships, error } = await supabaseAdmin.from("team_members").select("team_id, role").eq("user_id", callerId);
  if (error || !memberships?.length) return [];
  const roleByTeam = new Map((memberships as Array<{ team_id: string; role: string }>).map((m) => [m.team_id, m.role]));
  const { data: teams } = await supabaseAdmin.from("teams").select("id, owner_id").in("id", [...roleByTeam.keys()]);
  const owned = ((teams ?? []) as Array<{ id: string; owner_id: string }>).filter((t) => t.owner_id !== callerId);
  if (owned.length === 0) return [];
  const { data: users } = await supabaseAdmin.from("users").select("id, email").in("id", owned.map((t) => t.owner_id));
  const emailOf = new Map(((users ?? []) as Array<{ id: string; email: string | null }>).map((u) => [u.id, u.email ?? null]));
  return owned
    .map((t) => ({ ownerId: t.owner_id, email: emailOf.get(t.owner_id) ?? null, role: roleByTeam.get(t.id) ?? "member" }))
    .sort((a, b) => (a.email ?? "").localeCompare(b.email ?? ""));
}

/** May this caller read `ownerId`'s findings? Their own, or any team they're on. */
export async function callerCanView(supabaseAdmin: SupabaseClient, callerId: string, ownerId: string): Promise<boolean> {
  if (callerId === ownerId) return true;
  const accounts = await listViewableAccounts(supabaseAdmin, callerId);
  return accounts.some((a) => a.ownerId === ownerId);
}
