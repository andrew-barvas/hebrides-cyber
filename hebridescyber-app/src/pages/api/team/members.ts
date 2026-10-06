// Team member management — POST (invite), PATCH (change role), DELETE
// (remove, or leave). Session-only — see src/pages/api/team.ts for why.
//
// Permission model (kept deliberately simple):
//   - owner: full control over their team (invite, change role, remove anyone)
//   - admin: can invite and remove non-admin role users, cannot touch other admins
//   - developer: can act on the owner's behalf for scans (see src/lib/teamAccess.ts),
//     but this file grants no extra invite/remove power over a plain member
//   - auditor: read-only, same standing as member for team management itself
//   - member: read-only, can only remove themselves (leave)
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { planGate } from "@/lib/planAccess";
import { logAuditEvent } from "@/lib/audit";
import { parseBody } from "@/lib/validate";

type TeamRole = "admin" | "developer" | "auditor" | "member";
type TeamRow = { id: string; owner_id: string };
type MemberRow = { team_id: string; user_id: string; role: TeamRole };

const TEAM_ROLES = ["admin", "developer", "auditor", "member"] as const;

const inviteSchema = z.object({
  team_id: z.string().min(1),
  email: z.string().email(),
  role: z.enum(TEAM_ROLES).optional(),
});
const setRoleSchema = z.object({
  team_id: z.string().min(1),
  user_id: z.string().min(1),
  role: z.enum(TEAM_ROLES),
});
const removeSchema = z.object({ team_id: z.string().min(1), user_id: z.string().min(1) });

async function getTeam(teamId: string): Promise<TeamRow | null> {
  const { data } = await supabaseAdmin.from("teams").select("id, owner_id").eq("id", teamId).maybeSingle();
  return data;
}

async function getMembership(teamId: string, userId: string): Promise<MemberRow | null> {
  const { data } = await supabaseAdmin
    .from("team_members")
    .select("team_id, user_id, role")
    .eq("team_id", teamId)
    .eq("user_id", userId)
    .maybeSingle();
  return data;
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") {
    return res.status(403).json({ error: "Team members can only be managed from a logged-in session, not with an API key." });
  }

  if (req.method === "POST") return invite(req, res, caller.ownerId);
  if (req.method === "PATCH") return setRole(req, res, caller.ownerId);
  if (req.method === "DELETE") return remove(req, res, caller.ownerId);
  return res.status(405).json({ error: "Method not allowed" });
}

async function invite(req: NextApiRequest, res: NextApiResponse, callerId: string) {
  const body = parseBody(inviteSchema, req.body, res);
  if (!body) return;
  const { team_id: teamId, email, role } = body;
  const memberRole = role ?? "member";

  const team = await getTeam(teamId);
  if (!team) return res.status(404).json({ error: "Team not found" });

  const isOwner = team.owner_id === callerId;
  const membership = isOwner ? null : await getMembership(teamId, callerId);
  if (!isOwner && membership?.role !== "admin") {
    return res.status(403).json({ error: "Only the team owner or an admin can invite members" });
  }

  // E-02 (docs/ENHANCEMENTS.md): team collaboration is advertised as an
  // Agency feature (team.ts already gates creation the same way). Checked
  // against the team OWNER's current plan, not the caller's — the caller
  // inviting may be an admin-role member, not the owner, and it's the
  // owner's subscription that determines whether the team can keep growing.
  // Only gates new growth (inviting); role changes/removal on an existing
  // team stay available even if the owner has since downgraded.
  const gate = await planGate(supabaseAdmin, team.owner_id, "agency");
  if (gate === "error") return res.status(500).json({ error: "Could not check your plan — try again." });
  if (gate === "denied") {
    return res.status(403).json({ error: "Team collaboration is an Agency-plan feature." });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const { data: invitee } = await supabaseAdmin
    .from("users")
    .select("id, email")
    .ilike("email", normalizedEmail)
    .maybeSingle();

  if (!invitee) {
    return res.status(404).json({
      error: `No Hebrides Cyber account found for ${normalizedEmail}. They need to sign up first, then you can add them.`,
    });
  }
  if (invitee.id === team.owner_id) {
    return res.status(400).json({ error: "That's you — the team owner is already on the team." });
  }

  const existing = await getMembership(teamId, invitee.id);
  if (existing) return res.status(400).json({ error: `${normalizedEmail} is already on this team.` });

  const { data: existingCount } = await supabaseAdmin.from("team_members").select("user_id").eq("team_id", teamId);
  if ((existingCount?.length ?? 0) >= 25) {
    return res.status(400).json({ error: "Team member limit reached (25)." });
  }

  const { error } = await supabaseAdmin
    .from("team_members")
    .insert({ team_id: teamId, user_id: invitee.id, role: memberRole });

  if (error) return res.status(500).json({ error: error.message });

  await logAuditEvent(supabaseAdmin, {
    actorId: callerId,
    action: "team_member.invited",
    resourceType: "team",
    resourceId: teamId,
    metadata: { invited_user_id: invitee.id, invited_email: invitee.email, role: memberRole },
  });

  return res.status(201).json({ user_id: invitee.id, email: invitee.email, role: memberRole });
}

async function setRole(req: NextApiRequest, res: NextApiResponse, callerId: string) {
  const body = parseBody(setRoleSchema, req.body, res);
  if (!body) return;
  const { team_id: teamId, user_id: userId, role } = body;

  const team = await getTeam(teamId);
  if (!team) return res.status(404).json({ error: "Team not found" });
  if (team.owner_id !== callerId) {
    return res.status(403).json({ error: "Only the team owner can change a member's role" });
  }

  const { error } = await supabaseAdmin
    .from("team_members")
    .update({ role })
    .eq("team_id", teamId)
    .eq("user_id", userId);

  if (error) return res.status(500).json({ error: error.message });

  await logAuditEvent(supabaseAdmin, {
    actorId: callerId,
    action: "team_member.role_changed",
    resourceType: "team",
    resourceId: teamId,
    metadata: { target_user_id: userId, new_role: role },
  });

  return res.status(200).json({ ok: true });
}

async function remove(req: NextApiRequest, res: NextApiResponse, callerId: string) {
  const body = parseBody(removeSchema, req.body, res);
  if (!body) return;
  const { team_id: teamId, user_id: userId } = body;

  const team = await getTeam(teamId);
  if (!team) return res.status(404).json({ error: "Team not found" });

  const isOwner = team.owner_id === callerId;
  const isSelf = userId === callerId;
  const callerMembership = isOwner ? null : await getMembership(teamId, callerId);
  const targetMembership = await getMembership(teamId, userId);

  if (!targetMembership) return res.status(404).json({ error: "That user is not on this team" });

  const allowed =
    isOwner || // owner can remove anyone
    isSelf || // anyone can remove themselves (leave)
    (callerMembership?.role === "admin" && targetMembership.role !== "admin"); // admin can remove any non-admin role, not other admins

  if (!allowed) {
    return res.status(403).json({ error: "You don't have permission to remove this member" });
  }

  const { error } = await supabaseAdmin.from("team_members").delete().eq("team_id", teamId).eq("user_id", userId);
  if (error) return res.status(500).json({ error: error.message });

  await logAuditEvent(supabaseAdmin, {
    actorId: callerId,
    action: isSelf ? "team_member.left" : "team_member.removed",
    resourceType: "team",
    resourceId: teamId,
    metadata: isSelf ? null : { removed_user_id: userId },
  });

  return res.status(200).json({ ok: true });
}
