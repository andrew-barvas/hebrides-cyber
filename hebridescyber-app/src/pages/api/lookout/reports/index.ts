// GET /api/lookout/reports — the signed-in customer's published Lookout
// reports (migration 075), newest first. Drafts are never returned. A
// customer whose plan has lapsed can still read the reports they were given.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { respondInternalError } from "@/lib/apiError";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  const { data, error } = await supabaseAdmin
    .from("lookout_reports")
    .select("id, period_start, period_end, status, published_at, acknowledged_at")
    .eq("customer", caller.ownerId)
    .in("status", ["published", "acknowledged"])
    .order("published_at", { ascending: false });
  if (error) return respondInternalError(res, "lookout/reports", error);
  return res.status(200).json({ reports: data ?? [] });
}
