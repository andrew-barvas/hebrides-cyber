// GET /api/v1/scans/{id}/plan?target=good|strong|needs-attention&fixed=<checkId,…>
// — the score planner (scorePlanner.ts) over the public API, so an agency's
// own dashboard or a CI job can ask "what's the fewest fixes to reach Good?"
// or "what would the score be if these were fixed?". Same owner-only access
// and API-key support as the other /v1/scans/{id}/* routes.
//
// Triage is as of now, like /export: findings the owner has triaged (accepted,
// false positive, snoozed) are never proposed as fixes. It's an estimate from
// the scan's stored score; the next scan sets the real one.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import type { Finding } from "@/lib/scanners";
import { applyTriage, loadTriageIndexForTarget } from "@/lib/findingTriage";
import { RATING_TARGETS, nextRatingTarget, planCandidates, planToTarget, projectWithFixes, ratingLabel } from "@/lib/scorePlanner";

const TARGET_BY_KEY: Record<string, (typeof RATING_TARGETS)[number]> = Object.fromEntries(
  RATING_TARGETS.map((t) => [t.label.toLowerCase().replace(/\s+/g, "-"), t])
);
const MAX_FIXED_IDS = 200;

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  const targetKey = typeof req.query.target === "string" ? req.query.target.toLowerCase() : undefined;
  if (targetKey !== undefined && !TARGET_BY_KEY[targetKey]) {
    return res.status(400).json({ error: `target must be one of: ${Object.keys(TARGET_BY_KEY).join(", ")}` });
  }
  const fixedRaw = typeof req.query.fixed === "string" ? req.query.fixed : "";
  const fixedIds = fixedRaw ? fixedRaw.split(",").map((s) => s.trim()).filter(Boolean) : [];
  if (fixedIds.length > MAX_FIXED_IDS) return res.status(400).json({ error: `fixed takes at most ${MAX_FIXED_IDS} checkIds` });

  const scanId = req.query.id as string;
  const { data: scan } = await supabaseAdmin.from("scans").select("id, owner, target_url").eq("id", scanId).maybeSingle();
  if (!scan) return res.status(404).json({ error: "Scan not found" });
  if (scan.owner !== caller.ownerId) return res.status(403).json({ error: "Forbidden" });

  const { data: result } = await supabaseAdmin.from("scan_results").select("score, results").eq("scan_id", scanId).order("created_at", { ascending: false }).limit(1).maybeSingle();
  if (!result) return res.status(404).json({ error: "No results for this scan yet" });
  if (typeof result.score !== "number") return res.status(409).json({ error: "This scan has no score to plan from" });

  const stored = ((result.results as { findings?: Finding[] })?.findings ?? []) as Finding[];
  const triage = await loadTriageIndexForTarget(supabaseAdmin, scan.owner, scan.target_url);
  const open = applyTriage(stored, triage.host ?? "", triage.index).filter((f) => !f.triage);
  const candidates = planCandidates(open);

  const score = result.score;
  const target = targetKey ? TARGET_BY_KEY[targetKey] : nextRatingTarget(score);
  const plan = target ? planToTarget(score, candidates, target.minScore) : null;
  const projectedWithFixed = projectWithFixes(score, candidates, fixedIds);

  return res.status(200).json({
    scanId,
    score,
    rating: ratingLabel(score),
    estimate: true,
    target: target ? { rating: target.label, minScore: target.minScore } : null,
    plan: plan
      ? {
          reachable: plan.reachable,
          projected: plan.projected,
          projectedRating: ratingLabel(plan.projected),
          fixes: plan.fixes.map((f) => ({ checkId: f.checkId, title: f.title, severity: f.severity, points: Math.round(f.points * 10) / 10 })),
        }
      : null,
    ...(fixedIds.length ? { ifFixed: { checkIds: fixedIds.filter((id) => candidates.some((c) => c.checkId === id)), projected: projectedWithFixed, projectedRating: ratingLabel(projectedWithFixed) } } : {}),
    candidates: candidates.length,
  });
}
