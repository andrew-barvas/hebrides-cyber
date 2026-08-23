import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin, supabaseAdmin } from "@/lib/adminAuth";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).end();
  const adminId = await requireAdmin(req);
  if (!adminId) return res.status(403).json({ error: "Admin access required" });

  const [
    { count: totalCustomers },
    { data: subscriptions },
    { data: scans },
    { data: recentSignups },
  ] = await Promise.all([
    supabaseAdmin.from("users").select("*", { count: "exact", head: true }),
    supabaseAdmin.from("subscriptions").select("plan, status"),
    supabaseAdmin.from("scans").select("status, created_at").order("created_at", { ascending: false }).limit(500),
    supabaseAdmin
      .from("users")
      .select("id, email, company_name, created_at")
      .order("created_at", { ascending: false })
      .limit(10),
  ]);

  const activeSubscriptions = (subscriptions ?? []).filter((s) => s.status === "active");
  const planBreakdown: Record<string, number> = {};
  for (const s of activeSubscriptions) {
    planBreakdown[s.plan] = (planBreakdown[s.plan] ?? 0) + 1;
  }

  const scansByStatus: Record<string, number> = {};
  const now = Date.now();
  let scansLast30d = 0;
  for (const s of scans ?? []) {
    scansByStatus[s.status] = (scansByStatus[s.status] ?? 0) + 1;
    if (new Date(s.created_at).getTime() > now - 30 * 86_400_000) scansLast30d++;
  }

  // Rough MRR estimate based on plan counts × hardcoded prices. Must match
  // the real prices in src/app/dashboard/page.tsx's PLAN_LABELS (and
  // /pricing) — these had drifted out of sync (19/49/99 here vs the real
  // 20/35/75), silently understating MRR on every load.
  const PLAN_PRICE: Record<string, number> = { basic: 20, pro: 35, agency: 75 };
  const mrr = activeSubscriptions.reduce((sum, s) => sum + (PLAN_PRICE[s.plan] ?? 0), 0);

  return res.status(200).json({
    totalCustomers: totalCustomers ?? 0,
    activeSubscriptions: activeSubscriptions.length,
    totalScans: (scans ?? []).length,
    scansLast30d,
    scansByStatus,
    planBreakdown: Object.entries(planBreakdown).map(([plan, count]) => ({ plan, count })),
    mrrUsd: mrr,
    recentSignups: recentSignups ?? [],
  });
}
