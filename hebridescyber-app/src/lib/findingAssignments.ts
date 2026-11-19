// Assigning findings to a person (migration 078). The assignee is always the
// account owner or a current member of the owner's team; an assignment whose
// assignee has left the team is ignored when read, so nobody outside the
// account is ever shown as responsible for its findings.
import type { SupabaseClient } from "@supabase/supabase-js";
import { isMissingSchemaError } from "./dbErrors";

export const ASSIGN_BULK_MAX = 200;

export type Assignee = { id: string; email: string | null; role: "owner" | string };
export type AssignmentRow = { target_host: string; check_id: string; assignee: string; assigned_at: string };

export const assignmentKey = (host: string, checkId: string) => `${host.toLowerCase()} ${checkId}`;

/** The owner first, then team members by email. */
export async function loadAssignees(supabaseAdmin: SupabaseClient, ownerId: string): Promise<{ ok: true; assignees: Assignee[] } | { ok: false }> {
  try {
    return await readAssignees(supabaseAdmin, ownerId);
  } catch {
    return { ok: false };
  }
}

async function readAssignees(supabaseAdmin: SupabaseClient, ownerId: string): Promise<{ ok: true; assignees: Assignee[] } | { ok: false }> {
  const { data: team, error: teamError } = await supabaseAdmin.from("teams").select("id").eq("owner_id", ownerId).maybeSingle();
  if (teamError && !isMissingSchemaError(teamError)) return { ok: false };
  let members: Array<{ user_id: string; role: string }> = [];
  if (team) {
    const { data, error } = await supabaseAdmin.from("team_members").select("user_id, role").eq("team_id", (team as { id: string }).id);
    if (error) return { ok: false };
    members = (data ?? []) as typeof members;
  }
  const ids = [ownerId, ...members.map((m) => m.user_id).filter((id) => id !== ownerId)];
  const { data: users, error: usersError } = await supabaseAdmin.from("users").select("id, email").in("id", ids);
  if (usersError) return { ok: false };
  const emailOf = new Map(((users ?? []) as Array<{ id: string; email: string | null }>).map((u) => [u.id, u.email ?? null]));
  const rest = members
    .filter((m) => m.user_id !== ownerId)
    .map((m) => ({ id: m.user_id, email: emailOf.get(m.user_id) ?? null, role: m.role }))
    .sort((a, b) => (a.email ?? "").localeCompare(b.email ?? ""));
  return { ok: true, assignees: [{ id: ownerId, email: emailOf.get(ownerId) ?? null, role: "owner" }, ...rest] };
}

export type AssignmentLoad = { available: boolean; rows: AssignmentRow[]; error: boolean };

export async function loadAssignments(supabaseAdmin: SupabaseClient, ownerId: string): Promise<AssignmentLoad> {
  let data: unknown;
  let error: { code?: string; message?: string } | null;
  try {
    ({ data, error } = await supabaseAdmin.from("finding_assignments").select("target_host, check_id, assignee, assigned_at").eq("owner", ownerId));
  } catch {
    return { available: true, rows: [], error: true };
  }
  if (error) return isMissingSchemaError(error) ? { available: false, rows: [], error: false } : { available: true, rows: [], error: true };
  return { available: true, rows: (data ?? []) as AssignmentRow[], error: false };
}

/** Pure: (host, checkId) → current assignee, dropping anyone no longer on the account. */
export function buildAssignmentIndex(rows: readonly AssignmentRow[], assignees: readonly Assignee[]): Map<string, Assignee> {
  const byId = new Map(assignees.map((a) => [a.id, a]));
  const index = new Map<string, Assignee>();
  for (const r of rows) {
    const who = byId.get(r.assignee);
    if (who) index.set(assignmentKey(r.target_host, r.check_id), who);
  }
  return index;
}
