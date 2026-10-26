// GET /api/v1/scans/{id} — full scan result, with each finding tagged
// new/unchanged relative to the previous scan of the same target.
//
// That per-finding status is the point of this endpoint for CI: it lets a
// pipeline fail only on newly introduced issues instead of the whole existing
// backlog. Gating on total findings would red-line every pipeline on its first
// run, and the check would be disabled the same day.
//
// Each finding also carries `triage` — the owner's current accept-risk /
// false-positive / snooze decision, or null — so CI can ignore what the
// owner has already triaged (action/index.js does).
import type { NextApiRequest, NextApiResponse } from "next";
import { supabaseAdmin } from "@/lib/apiAuth";
import { guardV1, setV1Headers } from "@/lib/v1Guard";
import { loadTriageIndexForTarget } from "@/lib/findingTriage";
import { buildScanReport, findPreviousFindings, pendingScanReport } from "@/lib/scanReport";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") {
    setV1Headers(res);
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Method not allowed", code: "method_not_allowed" });
  }

  const caller = await guardV1(req, res, "scans:read");
  if (!caller) return;

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

  const [previous, triage] = await Promise.all([
    findPreviousFindings(supabaseAdmin, scan.owner, scan.id, scan.target_url, scan.created_at),
    loadTriageIndexForTarget(supabaseAdmin, scan.owner, scan.target_url),
  ]);
  return res.status(200).json(buildScanReport(scan, result, previous, triage.index));
}
