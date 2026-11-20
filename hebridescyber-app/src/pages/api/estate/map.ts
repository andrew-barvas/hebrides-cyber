// GET /api/estate/map — every known host for the caller's account, grouped by
// domain: whether it answers on the web, its certificate's expiry, exposed
// services and open findings (src/lib/estateMap.ts). Same access as
// GET /api/estate/changes: the signed-in owner's own data, no plan gate.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { respondInternalError } from "@/lib/apiError";
import { loadEstateMap } from "@/lib/estateMap";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Unauthorized" });

  const loaded = await loadEstateMap(supabaseAdmin, caller.ownerId);
  if (!loaded.ok) return respondInternalError(res, "estate/map", new Error(loaded.error), { publicMessage: "Could not load your estate map" });
  res.setHeader("Cache-Control", "no-store");
  return res.status(200).json(loaded.map);
}
