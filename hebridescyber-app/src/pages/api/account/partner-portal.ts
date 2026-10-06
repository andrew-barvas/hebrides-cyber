// GET /api/account/partner-portal — E-39 server-side Agency gate.
// Previously PartnerPortalPanel.tsx fetched its data directly from the
// browser's Supabase client, relying on a client-side `plan === "agency"`
// check that any user could bypass by calling the component directly.
// This route enforces the Agency-tier gate server-side and returns the
// same stats the component needs, so the component no longer needs DB access.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { planGate } from "@/lib/planAccess";

type PartnerPortalStats = {
  brandName: string | null;
  brandLogoUrl: string | null;
  monitoredTargetCount: number;
  totalScans: number;
  latestScore: number | null;
  avgScore: number | null;
};

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Unauthorized" });

  // Server-side plan check — must be an active agency subscriber.
  const gate = await planGate(supabaseAdmin, caller.ownerId, "agency");
  if (gate === "error") return res.status(500).json({ error: "Could not verify subscription" });
  if (gate === "denied") {
    return res.status(403).json({ error: "Partner portal requires an Agency subscription" });
  }

  const { data: sub } = await supabaseAdmin
    .from("subscriptions")
    .select("brand_logo_url, brand_name")
    .eq("owner", caller.ownerId)
    .maybeSingle();
  const brandName = (sub?.brand_name as string | null) ?? null;
  const brandLogoUrl = (sub?.brand_logo_url as string | null) ?? null;

  const [targetsRes, scansRes] = await Promise.all([
    supabaseAdmin
      .from("monitored_targets")
      .select("id", { count: "exact", head: true })
      .eq("owner", caller.ownerId),
    supabaseAdmin
      .from("scans")
      .select("id", { count: "exact", head: true })
      .eq("owner", caller.ownerId)
      .eq("status", "completed"),
  ]);

  const monitoredTargetCount = targetsRes.count ?? 0;
  const totalScans = scansRes.count ?? 0;

  let latestScore: number | null = null;
  let avgScore: number | null = null;

  if (totalScans > 0) {
    const { data: scoreData } = await supabaseAdmin
      .from("scan_results")
      .select("score, scan_id, scans!inner(owner)")
      .eq("scans.owner", caller.ownerId)
      .order("created_at", { ascending: false })
      .limit(20);

    if (scoreData && scoreData.length > 0) {
      const scores = (scoreData as Array<{ score: number | null }>)
        .map((r) => r.score)
        .filter((s): s is number => s !== null);
      if (scores.length > 0) {
        latestScore = scores[0];
        avgScore = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
      }
    }
  }

  const stats: PartnerPortalStats = {
    brandName,
    brandLogoUrl,
    monitoredTargetCount,
    totalScans,
    latestScore,
    avgScore,
  };

  return res.status(200).json(stats);
}
