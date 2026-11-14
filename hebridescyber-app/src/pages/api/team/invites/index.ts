// /api/team/invites — pending invitations for a team (migration 074).
//   GET    ?team_id=…   → { invites: [{ id, email, role, expires_at }] }
//   DELETE { team_id, id } → { cancelled: true }
// Owner or admin only, session only, like inviting itself (members.ts).
// Creating an invite happens in POST /api/team/members, when the invited
// address has no account yet.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { parseBody } from "@/lib/validate";
import { respondInternalError } from "@/lib/apiError";
import { logAuditEvent } from "@/lib/audit";

const cancelSchema = z.object({ team_id: z.string().min(1), id: z.string().min(1) });

async function canManage(teamId: string, callerId: string): Promise<"ok" | "not_found" | "forbidden"> {
  const { data: team } = await supabaseAdmin.from("teams").select("id, owner_id").eq("id", teamId).maybeSingle();
  if (!team) return "not_found";
  if ((team as { owner_id: string }).owner_id === callerId) return "ok";
  const { data: m } = await supabaseAdmin.from("team_members").select("role").eq("team_id", teamId).eq("user_id", callerId).maybeSingle();
  return (m as { role?: string } | null)?.role === "admin" ? "ok" : "forbidden";
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") return res.status(403).json({ error: "Team invitations can only be managed from a logged-in session." });

  if (req.method === "GET") {
    const teamId = String(req.query.team_id ?? "");
    if (!teamId) return res.status(400).json({ error: "team_id is required" });
    const access = await canManage(teamId, caller.ownerId);
    if (access === "not_found") return res.status(404).json({ error: "Team not found" });
    if (access === "forbidden") return res.status(403).json({ error: "Only the team owner or an admin can see invitations" });
    const { data, error } = await supabaseAdmin
      .from("team_invites")
      .select("id, email, role, expires_at")
      .eq("team_id", teamId)
      .is("accepted_at", null)
      .gt("expires_at", new Date().toISOString())
      .order("created_at", { ascending: false });
    if (error) return respondInternalError(res, "team/invites", error);
    return res.status(200).json({ invites: data ?? [] });
  }

  if (req.method === "DELETE") {
    const body = parseBody(cancelSchema, req.body, res);
    if (!body) return;
    const access = await canManage(body.team_id, caller.ownerId);
    if (access === "not_found") return res.status(404).json({ error: "Team not found" });
    if (access === "forbidden") return res.status(403).json({ error: "Only the team owner or an admin can cancel invitations" });
    const { error } = await supabaseAdmin.from("team_invites").delete().eq("team_id", body.team_id).eq("id", body.id).is("accepted_at", null);
    if (error) return respondInternalError(res, "team/invites", error);
    await logAuditEvent(supabaseAdmin, { actorId: caller.ownerId, action: "team.invite_cancelled", resourceType: "team", resourceId: body.team_id, metadata: { invite_id: body.id } });
    return res.status(200).json({ cancelled: true });
  }

  res.setHeader("Allow", "GET, DELETE");
  return res.status(405).json({ error: "Method not allowed" });
}
