// Google Workspace posture (NEXT-BUILDS-DESIGN-2026-11.md task 10): the
// Workspace counterpart of m365Posture.ts, against CISA's ScubaGoggles
// baseline. Reads, with the customer's consented read-only token
// (workspaceConsent.ts), the Admin SDK Directory API user list, which carries
// each user's admin flag and 2-Step Verification enrolment and enforcement.
//
// Evidence discipline: any failed read makes the result "error" with a note,
// so findingLifecycle.ts closes nothing. More users than MAX_USERS is an error
// rather than a partial "clean". Suspended and archived users are left out:
// they can't sign in.
//
// Version 1 deliberately leaves out email forwarding (needs per-user Gmail
// access through domain-wide delegation, an owner decision in the design).
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Finding } from "./index";
import { decryptSecret } from "../credentialEncryption";
import { refreshAccessToken, workspaceAppConfig } from "../workspaceConsent";
import { WORKSPACE_2SV_NOT_ENFORCED, WORKSPACE_ADMINS_WITHOUT_2SV, WORKSPACE_SINGLE_SUPER_ADMIN, WORKSPACE_TOO_MANY_SUPER_ADMINS } from "./remediationText";

export const MAX_SUPER_ADMINS = 4;
export const MIN_SUPER_ADMINS = 2;
export const MAX_USERS = 5000;
const DIRECTORY_USERS = "https://admin.googleapis.com/admin/directory/v1/users";

export type WorkspaceUser = { primaryEmail?: string; isAdmin?: boolean; isEnrolledIn2Sv?: boolean; isEnforcedIn2Sv?: boolean; suspended?: boolean; archived?: boolean };

export type WorkspaceResult =
  | { status: "not_configured"; note: string }
  | { status: "checked"; findings: Finding[]; users: number }
  | { status: "error"; note: string; findings: Finding[] };

/** Pure: findings from the active user list. */
export function workspaceFindings(allUsers: WorkspaceUser[]): Finding[] {
  const users = allUsers.filter((u) => !u.suspended && !u.archived);
  const findings: Finding[] = [];
  const admins = users.filter((u) => u.isAdmin === true);

  const adminsWithout2sv = admins.filter((u) => u.isEnrolledIn2Sv !== true);
  if (adminsWithout2sv.length > 0) {
    findings.push({
      checkId: "workspace.adminsWithout2sv",
      severity: "critical",
      title: `Google Workspace: ${adminsWithout2sv.length} super admin${adminsWithout2sv.length === 1 ? " hasn't" : "s haven't"} set up 2-Step Verification`,
      detail: `${adminsWithout2sv.map((u) => u.primaryEmail ?? "(unknown)").slice(0, 10).join(", ")} can sign in with a password alone. A super admin account controls every user, email and file in the organisation.`,
      remediation: WORKSPACE_ADMINS_WITHOUT_2SV,
    });
  }

  const notEnforced = users.filter((u) => u.isEnforcedIn2Sv !== true);
  if (notEnforced.length > 0) {
    findings.push({
      checkId: "workspace.2svNotEnforced",
      severity: "high",
      title: `Google Workspace: 2-Step Verification isn't enforced for ${notEnforced.length} of ${users.length} active users`,
      detail: `2-Step Verification is optional for ${notEnforced.length === users.length ? "everyone" : `${notEnforced.length} users`}, so a phished or reused password is enough to take over those accounts.`,
      remediation: WORKSPACE_2SV_NOT_ENFORCED,
    });
  }

  if (admins.length > MAX_SUPER_ADMINS) {
    findings.push({
      checkId: "workspace.tooManySuperAdmins",
      severity: "medium",
      title: `Google Workspace: ${admins.length} super admins`,
      detail: `${admins.length} active accounts hold the super admin role. CIS recommends no more than ${MAX_SUPER_ADMINS}; each is an account whose compromise hands over everything.`,
      remediation: WORKSPACE_TOO_MANY_SUPER_ADMINS,
    });
  } else if (admins.length < MIN_SUPER_ADMINS) {
    findings.push({
      checkId: "workspace.singleSuperAdmin",
      severity: "low",
      title: `Google Workspace: only ${admins.length} super admin`,
      detail: `With ${admins.length === 0 ? "no" : "one"} super admin there's no way back in if that account is lost or locked. CIS recommends at least ${MIN_SUPER_ADMINS}.`,
      remediation: WORKSPACE_SINGLE_SUPER_ADMIN,
    });
  }
  return findings;
}

/** Every active and suspended user, following pageToken, up to MAX_USERS. */
export async function listWorkspaceUsers(accessToken: string, fetchImpl: typeof fetch = fetch): Promise<{ ok: true; users: WorkspaceUser[] } | { ok: false; error: string }> {
  const users: WorkspaceUser[] = [];
  let pageToken: string | undefined;
  do {
    const params = new URLSearchParams({ customer: "my_customer", maxResults: "500", projection: "basic", ...(pageToken ? { pageToken } : {}) });
    let res: Response;
    try {
      res = await fetchImpl(`${DIRECTORY_USERS}?${params.toString()}`, { headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" }, signal: AbortSignal.timeout(15_000) });
    } catch (err) {
      return { ok: false, error: `users: ${(err as Error).message}` };
    }
    if (!res.ok) return { ok: false, error: `users: HTTP ${res.status}` };
    const body = (await res.json().catch(() => null)) as { users?: WorkspaceUser[]; nextPageToken?: string } | null;
    if (!body) return { ok: false, error: "users: unreadable response" };
    users.push(...(body.users ?? []));
    if (users.length > MAX_USERS) return { ok: false, error: `more than ${MAX_USERS} users; not checked` };
    pageToken = body.nextPageToken;
  } while (pageToken);
  return { ok: true, users };
}

export async function runWorkspacePostureChecks(supabaseAdmin: SupabaseClient, ownerId: string, fetchImpl: typeof fetch = fetch): Promise<WorkspaceResult> {
  const config = workspaceAppConfig();
  if (!config) return { status: "not_configured", note: "Google Workspace checks aren't set up on this deployment (OT-58)." };
  const { data, error } = await supabaseAdmin.from("workspace_connections").select("refresh_token").eq("owner", ownerId).maybeSingle();
  if (error) return { status: "error", note: "Couldn't read the Workspace connection.", findings: [] };
  if (!data) return { status: "not_configured", note: "No Google Workspace connected." };

  let refreshToken: string;
  try {
    refreshToken = decryptSecret((data as { refresh_token: string }).refresh_token);
  } catch {
    return { status: "error", note: "Couldn't unseal the Workspace token.", findings: [] };
  }
  const token = await refreshAccessToken(config, refreshToken, fetchImpl);
  if (!token.ok) return { status: "error", note: `Google refused the stored token (${token.error}); reconnect Google Workspace.`, findings: [] };
  const listed = await listWorkspaceUsers(token.accessToken, fetchImpl);
  if (!listed.ok) return { status: "error", note: listed.error, findings: [] };
  await supabaseAdmin.from("workspace_connections").update({ last_checked_at: new Date().toISOString() }).eq("owner", ownerId);
  return { status: "checked", findings: workspaceFindings(listed.users), users: listed.users.length };
}
