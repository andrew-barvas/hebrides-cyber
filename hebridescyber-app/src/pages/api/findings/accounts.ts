// GET /api/findings/accounts — whose findings the caller can read: their own
// account, then the owner of every team they're on (read-only, 007_teams.sql).
// Session only. Feeds the Findings Explorer's account switcher; the list
// itself is GET /api/findings?account=<ownerId>.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { listViewableAccounts } from "@/lib/teamAccess";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Unauthorized" });
  if (caller.via !== "session") return res.status(200).json({ accounts: [{ ownerId: caller.ownerId, email: null, role: "owner", own: true }] });

  const teams = await listViewableAccounts(supabaseAdmin, caller.ownerId);
  return res.status(200).json({
    accounts: [{ ownerId: caller.ownerId, email: null, role: "owner", own: true }, ...teams.map((t) => ({ ...t, own: false }))],
  });
}
