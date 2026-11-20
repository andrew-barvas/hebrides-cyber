// GET /api/scans/<id>/benchmark — how this scan's score compares with other
// sites' latest full-scan scores (src/lib/scoreBenchmark.ts). The owner or a
// team member who can act for them. { benchmark: null } while the feature is
// off (SCORE_BENCHMARK_ENABLED) or the group is too small, so the page simply
// shows nothing.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { respondInternalError } from "@/lib/apiError";
import { callerCanActFor } from "@/lib/teamAccess";
import { isBenchmarkEnabled, scanBenchmark } from "@/lib/scoreBenchmark";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Method not allowed" });
  }
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (!isBenchmarkEnabled()) return res.status(200).json({ benchmark: null });

  const scanId = String(req.query.id ?? "");
  const { data: scan, error } = await supabaseAdmin.from("scans").select("id, owner").eq("id", scanId).maybeSingle();
  if (error) return respondInternalError(res, "scans/id/benchmark", error);
  if (!scan) return res.status(404).json({ error: "Scan not found" });
  if (scan.owner !== caller.ownerId && !(await callerCanActFor(supabaseAdmin, caller.ownerId, scan.owner))) return res.status(403).json({ error: "Forbidden" });

  const { data: result } = await supabaseAdmin.from("scan_results").select("score").eq("scan_id", scanId).order("created_at", { ascending: false }).limit(1).maybeSingle();
  const score = (result as { score?: unknown } | null)?.score;
  if (typeof score !== "number") return res.status(200).json({ benchmark: null });

  res.setHeader("Cache-Control", "private, max-age=3600");
  return res.status(200).json({ benchmark: await scanBenchmark(supabaseAdmin, score, scan.owner) });
}
