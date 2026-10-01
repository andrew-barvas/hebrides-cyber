// GET /api/v1/scans/{id} — full scan result, with each finding tagged
// new/unchanged relative to the previous scan of the same target.
//
// That per-finding status is the point of this endpoint for CI: it lets a
// pipeline fail only on newly introduced issues instead of the whole existing
// backlog. Gating on total findings would red-line every pipeline on its first
// run, and the check would be disabled the same day.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { buildScanReport, findPreviousFindings, pendingScanReport } from "@/lib/scanReport";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  const scanId = req.query.id as string;

  const { data: scan } = await supabaseAdmin
    .from("scans")
    .select("id, owner, target_url, status, created_at")
    .eq("id", scanId)
    .maybeSingle();

  if (!scan) return res.status(404).json({ error: "Scan not found" });
  if (scan.owner !== caller.ownerId) return res.status(403).json({ error: "Forbidden" });

  const { data: result } = await supabaseAdmin
    .from("scan_results")
    .select("results, summary, score, created_at")
    .eq("scan_id", scanId)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  if (!result) return res.status(200).json(pendingScanReport(scan));

  const previous = await findPreviousFindings(supabaseAdmin, scan.owner, scan.id, scan.target_url, scan.created_at);
  return res.status(200).json(buildScanReport(scan, result, previous));
}
