// RBAC — role-based access control for organization-scoped operations.
//
// Checks whether a user's role in an org grants them permission to
// perform an action on a resource. Falls back to deny-by-default.
// Used at API boundaries, not in the UI (UI can hide things optimistically
// but the server is the authority).

import type { SupabaseClient } from "@supabase/supabase-js";

export type OrgRole = "owner" | "admin" | "analyst" | "viewer" | "member";
export type RbacAction = "create" | "read" | "update" | "delete" | "execute";

export type OrgMembership = {
  orgId: string;
  userId: string;
  role: OrgRole;
};

/**
 * Get a user's membership in an organization. Returns null if not a member.
 */
export async function getOrgMembership(
  supabaseAdmin: SupabaseClient,
  userId: string,
  orgId: string,
): Promise<OrgMembership | null> {
  const { data } = await supabaseAdmin
    .from("org_members")
    .select("org_id, user_id, role")
    .eq("org_id", orgId)
    .eq("user_id", userId)
    .maybeSingle();

  if (!data) return null;
  return { orgId: data.org_id, userId: data.user_id, role: data.role as OrgRole };
}

/**
 * Pure function: check if a role has permission for an action on a resource.
 * Uses the static permission matrix. Owner always has full access.
 */
export function hasPermission(role: OrgRole, resource: string, action: RbacAction): boolean {
  if (role === "owner") return true;

  const matrix: Record<string, Record<string, RbacAction[]>> = {
    admin: {
      scans: ["create", "read", "execute", "delete"],
      members: ["create", "read", "update", "delete"],
      settings: ["read", "update"],
      reports: ["create", "read"],
      integrations: ["create", "read", "update", "delete"],
      findings: ["read", "update"],
    },
    analyst: {
      scans: ["create", "read", "execute"],
      reports: ["create", "read"],
      findings: ["read", "update"],
      integrations: ["read"],
    },
    viewer: {
      scans: ["read"],
      reports: ["read"],
      findings: ["read"],
      integrations: ["read"],
    },
    member: {
      scans: ["read"],
      reports: ["read"],
      findings: ["read"],
    },
  };

  const rolePerms = matrix[role];
  if (!rolePerms) return false;

  const resourcePerms = rolePerms[resource];
  if (!resourcePerms) return false;

  return resourcePerms.includes(action);
}

/**
 * Check permission and return a structured result for API routes.
 */
export async function checkOrgPermission(
  supabaseAdmin: SupabaseClient,
  userId: string,
  orgId: string,
  resource: string,
  action: RbacAction,
): Promise<{ allowed: boolean; membership: OrgMembership | null; reason?: string }> {
  const membership = await getOrgMembership(supabaseAdmin, userId, orgId);
  if (!membership) {
    return { allowed: false, membership: null, reason: "Not a member of this organization" };
  }

  if (!hasPermission(membership.role, resource, action)) {
    return { allowed: false, membership, reason: `Role '${membership.role}' cannot ${action} ${resource}` };
  }

  return { allowed: true, membership };
}
