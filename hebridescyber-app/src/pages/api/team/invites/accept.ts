// POST /api/team/invites/accept { token } — the signed-in invitee accepts a
// pending invitation (migration 074). Only works for the address it was sent
// to, before it expires, once. The team owner's plan is checked again, as
// inviting does (members.ts): a team only grows while the owner is on Agency.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { parseBody } from "@/lib/validate";
import { respondInternalError } from "@/lib/apiError";
import { logAuditEvent } from "@/lib/audit";
import { planGate } from "@/lib/planAccess";
import { acceptProblem, hashInviteToken, isInviteToken, type InviteRow } from "@/lib/teamInvites";

const bodySchema = z.object({ token: z.string() });

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Sign in to accept this invitation." });
  if (caller.via !== "session") return res.status(403).json({ error: "Invitations are accepted from a logged-in session." });
  const body = parseBody(bodySchema, req.body, res);
  if (!body) return;

  let invite: InviteRow | null = null;
  if (isInviteToken(body.token)) {
    const { data, error } = await supabaseAdmin
      .from("team_invites")
      .select("id, team_id, email, role, expires_at, accepted_at")
      .eq("token_hash", hashInviteToken(body.token))
      .maybeSingle();
    if (error) return respondInternalError(res, "team/invites/accept", error);
    invite = (data as InviteRow | null) ?? null;
  }
  const { data: me } = await supabaseAdmin.from("users").select("email").eq("id", caller.ownerId).maybeSingle();
  const problem = acceptProblem(invite, (me as { email?: string } | null)?.email, new Date());
  if (problem || !invite) return res.status(invite ? 403 : 404).json({ error: problem });

  const { data: team } = await supabaseAdmin.from("teams").select("id, name, owner_id").eq("id", invite.team_id).maybeSingle();
  if (!team) return res.status(404).json({ error: "That team no longer exists." });
  const gate = await planGate(supabaseAdmin, (team as { owner_id: string }).owner_id, "agency");
  if (gate === "error") return res.status(500).json({ error: "Could not check the team's plan. Try again." });
  if (gate === "denied") return res.status(403).json({ error: "This team can't take new members at the moment. Ask the person who invited you." });

  const { error: joinError } = await supabaseAdmin
    .from("team_members")
    .upsert({ team_id: invite.team_id, user_id: caller.ownerId, role: invite.role }, { onConflict: "team_id,user_id", ignoreDuplicates: true });
  if (joinError) return respondInternalError(res, "team/invites/accept", joinError);
  await supabaseAdmin.from("team_invites").update({ accepted_at: new Date().toISOString() }).eq("id", invite.id);
  await logAuditEvent(supabaseAdmin, { actorId: caller.ownerId, action: "team.invite_accepted", resourceType: "team", resourceId: invite.team_id, metadata: { role: invite.role } });
  return res.status(200).json({ joined: true, teamName: (team as { name: string }).name, role: invite.role });
}
