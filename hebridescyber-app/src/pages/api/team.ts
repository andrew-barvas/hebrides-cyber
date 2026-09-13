// Team management — GET (your team, however you relate to it), POST (create
// a team). Session-only, mirroring keys.ts/webhooks.ts: creating a team that
// shares your dashboard with someone else is an account-level write, not
// something an API key should be able to do.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { parseBody } from "@/lib/validate";

const MAX_TEAM_NAME_LENGTH = 60;

const createTeamSchema = z.object({
  name: z.string().min(1, "name is required").max(MAX_TEAM_NAME_LENGTH, `name must be ${MAX_TEAM_NAME_LENGTH} characters or fewer`),
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") {
    return res.status(403).json({ error: "Teams can only be managed from a logged-in session, not with an API key." });
  }

  if (req.method === "GET") return getTeamInfo(res, caller.ownerId);
  if (req.method === "POST") return createTeam(req, res, caller.ownerId);
  return res.status(405).json({ error: "Method not allowed" });
}

async function getTeamInfo(res: NextApiResponse, userId: string) {
  const { data: owned } = await supabaseAdmin
    .from("teams")
    .select("id, name, created_at")
    .eq("owner_id", userId)
    .maybeSingle();

  let members: Array<{ user_id: string; email: string; role: string; joined_at: string }> = [];
  if (owned) {
    const { data: memberRows } = await supabaseAdmin
      .from("team_members")
      .select("user_id, role, joined_at")
      .eq("team_id", owned.id)
      .order("joined_at", { ascending: true });

    const userIds = (memberRows ?? []).map((m) => m.user_id);
    const { data: profiles } = userIds.length
      ? await supabaseAdmin.from("users").select("id, email").in("id", userIds)
      : { data: [] as Array<{ id: string; email: string }> };
    const emailById = new Map((profiles ?? []).map((p) => [p.id, p.email]));

    members = (memberRows ?? []).map((m) => ({
      user_id: m.user_id,
      email: emailById.get(m.user_id) ?? "(unknown)",
      role: m.role,
      joined_at: m.joined_at,
    }));
  }

  // Teams this user belongs to as a member of someone else's team.
  const { data: membershipRows } = await supabaseAdmin
    .from("team_members")
    .select("team_id, role, joined_at, teams(name, owner_id)")
    .eq("user_id", userId);

  const ownerIds = (membershipRows ?? [])
    .map((m) => (m.teams as unknown as { owner_id: string } | null)?.owner_id)
    .filter((id): id is string => Boolean(id));
  const { data: ownerProfiles } = ownerIds.length
    ? await supabaseAdmin.from("users").select("id, email").in("id", ownerIds)
    : { data: [] as Array<{ id: string; email: string }> };
  const ownerEmailById = new Map((ownerProfiles ?? []).map((p) => [p.id, p.email]));

  const memberships = (membershipRows ?? []).map((m) => {
    const team = m.teams as unknown as { name: string; owner_id: string } | null;
    return {
      team_id: m.team_id,
      team_name: team?.name ?? "(unknown team)",
      owner_email: team ? ownerEmailById.get(team.owner_id) ?? "(unknown)" : "(unknown)",
      role: m.role,
      joined_at: m.joined_at,
    };
  });

  return res.status(200).json({
    owned_team: owned ? { id: owned.id, name: owned.name, created_at: owned.created_at, members } : null,
    memberships,
  });
}

async function createTeam(req: NextApiRequest, res: NextApiResponse, userId: string) {
  // E-02 (docs/ENHANCEMENTS.md): team collaboration is advertised as Agency
  // only (docs/USER-GUIDE.md §3.7) but was enforced nowhere. Only gates
  // creation, not team.ts's GET — a downgraded owner/member should still be
  // able to see who they're teamed with.
  const { data: subscription, error: subError } = await supabaseAdmin
    .from("subscriptions")
    .select("plan")
    .eq("owner", userId)
    .maybeSingle();
  if (subError) return res.status(500).json({ error: subError.message });
  if (subscription?.plan !== "agency") {
    return res.status(403).json({ error: "Team collaboration is an Agency-plan feature." });
  }

  const parsed = parseBody(createTeamSchema, req.body, res);
  if (!parsed) return;
  const teamName = parsed.name.trim();
  if (!teamName) return res.status(400).json({ error: "name is required" });

  const { data: existing } = await supabaseAdmin.from("teams").select("id").eq("owner_id", userId).maybeSingle();
  if (existing) return res.status(400).json({ error: "You already have a team. Each account can own one team." });

  const { data, error } = await supabaseAdmin
    .from("teams")
    .insert({ name: teamName, owner_id: userId })
    .select("id, name, created_at")
    .single();

  if (error) return res.status(500).json({ error: error.message });
  return res.status(201).json({ ...data, members: [] });
}
