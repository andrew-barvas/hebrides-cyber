// GET /api/v1/targets/{host}/trend — score history for every completed scan
// of a target, oldest first. The in-app dashboard has had this since the
// score trend chart shipped (src/lib/clientScanHistory.ts's
// findScoreHistoryClient, rendered by src/components/ScoreTrend.tsx) but it
// was never exposed over the public API — anyone building on the API had no
// programmatic way to get at score-over-time. This route reuses the exact
// same hostname-matching approach server-side (scoped to the caller's own
// scans via the service-role client + an explicit owner filter, since there
// is no RLS session here), rather than a second, drifting copy of the logic.
//
// Matches by hostname, not exact target_url, for the same reason
// clientScanHistory.ts does: two scans of "the same" site aren't guaranteed
// byte-identical strings (protocol, trailing slash, case).
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";

type ScanCandidate = {
  target_url: string;
  scan_results: { score: number | null; created_at: string }[];
};

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  const hostParam = req.query.host;
  const host = (typeof hostParam === "string" ? hostParam : "").toLowerCase().trim();
  if (!host) return res.status(400).json({ error: "host is required" });

  // Same shape as GET /api/v1/scans' own limit handling.
  const limit = Math.min(Number(req.query.limit) || 20, 100);

  // No indexed hostname column to query against directly (same tradeoff
  // clientScanHistory.ts accepts) — fetch this owner's most recent completed
  // scans across all targets and filter client-side. Fine at today's scale;
  // worth a real indexed column if a user routinely runs 100+ scans of other
  // targets between two scans of the same host.
  const { data: candidates, error } = await supabaseAdmin
    .from("scans")
    .select("target_url, created_at, scan_results(score, created_at)")
    .eq("owner", caller.ownerId)
    .eq("status", "completed")
    .order("created_at", { ascending: false })
    .limit(200);

  if (error) return res.status(500).json({ error: error.message });

  const points: { date: string; score: number }[] = [];
  for (const c of (candidates ?? []) as unknown as ScanCandidate[]) {
    let candidateHost: string;
    try {
      candidateHost = new URL(c.target_url).hostname.toLowerCase();
    } catch {
      continue;
    }
    if (candidateHost !== host) continue;
    const result = c.scan_results?.[0];
    if (result?.score == null) continue;
    points.push({ date: result.created_at, score: result.score });
    if (points.length >= limit) break;
  }

  points.sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime());

  return res.status(200).json({ host, points, count: points.length });
}
