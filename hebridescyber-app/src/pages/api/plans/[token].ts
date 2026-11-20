// GET /api/plans/<token> — a shared fix plan, for whoever has the link (no
// account). The token is the credential, like a report share; only its hash
// is stored. Returns the plan's own snapshot plus each item's status; never
// the scan. Rate-limited per IP, which also caps token probing. Every
// invalid, expired or revoked link gets the same answer.
import type { NextApiRequest, NextApiResponse } from "next";
import { supabaseAdmin } from "@/lib/supabaseAdmin";
import { respondInternalError } from "@/lib/apiError";
import { checkRateLimit, getClientIp } from "@/lib/rateLimit";
import { buildPublicPlan, isPlanToken, loadPlanByToken, loadResolutions, planUnavailable } from "@/lib/fixPlans";

const PLAN_VIEW_RATE_LIMIT = { max: 120, windowSeconds: 60 * 60 };

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Method not allowed" });
  }
  const limit = await checkRateLimit(getClientIp(req), "fix-plan-view", PLAN_VIEW_RATE_LIMIT);
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds));
    return res.status(429).json({ error: "Too many requests — try again later." });
  }

  const token = req.query.token;
  const invalid = planUnavailable(null, new Date()) as string;
  if (!isPlanToken(token)) return res.status(404).json({ error: invalid });

  let loaded;
  try {
    loaded = await loadPlanByToken(supabaseAdmin, token);
  } catch (err) {
    return respondInternalError(res, "plans/token", err as Error);
  }
  const problem = planUnavailable(loaded?.plan ?? null, new Date());
  if (!loaded || problem) return res.status(404).json({ error: problem ?? invalid });

  const resolved = await loadResolutions(supabaseAdmin, loaded.plan.owner, loaded.plan.target_host, loaded.items.map((i) => i.check_id));
  res.setHeader("Cache-Control", "private, no-store");
  res.setHeader("X-Robots-Tag", "noindex");
  return res.status(200).json(buildPublicPlan(loaded.plan, loaded.items, resolved));
}
