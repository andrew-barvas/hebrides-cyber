// GET /api/estate/changes?days=7|30|90 — what changed across every site the
// caller monitors over the window: findings opened and fixed, what is open
// now, and new hostnames (src/lib/estateDrift.ts). Same access as
// GET /api/findings: the signed-in owner's own data, no plan gate. Before
// migration 043 it answers { available: false }.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { loadEstateDrift, parseDriftWindow } from "@/lib/estateDrift";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Unauthorized" });

  const days = parseDriftWindow(req.query.days);
  const loaded = await loadEstateDrift(supabaseAdmin, caller.ownerId, days);
  if (!loaded.ok) return res.status(500).json({ error: loaded.error });
  if (!loaded.available) return res.status(200).json({ available: false, days });
  return res.status(200).json({ available: true, days, ...loaded.drift });
}
