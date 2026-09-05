import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin, supabaseAdmin } from "@/lib/adminAuth";

// scans.status's check constraint (sql/migrations/001_init.sql) — used to
// get an exact per-status count via 4 small head queries instead of the
// former single .limit(500) fetch, which silently reported an incomplete
// breakdown (and a capped totalScans) once scan volume passed 500 rows.
const SCAN_STATUSES = ["pending", "running", "completed", "failed"] as const;

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).end();
  const adminId = await requireAdmin(req);
  if (!adminId) return res.status(403).json({ error: "Admin access required" });

  // E-17 (docs/ENHANCEMENTS.md): totalScans/scansByStatus used to be derived
  // from a single .limit(500) fetch — a correctness bug at scale (silently
  // wrong once past 500 lifetime scans), not just a performance one. Every
  // scan-derived number below now comes from an exact-count head query, so
  // none of them are capped regardless of how many scans exist.
  const thirtyDaysAgo = new Date(Date.now() - 30 * 86_400_000).toISOString();

  const [{ count: totalCustomers }, { data: subscriptions }, { data: recentSignups }] = await Promise.all([
    supabaseAdmin.from("users").select("*", { count: "exact", head: true }),
    supabaseAdmin.from("subscriptions").select("plan, status"),
    supabaseAdmin
      .from("users")
      .select("id, email, company_name, created_at")
      .order("created_at", { ascending: false })
      .limit(10),
  ]);

  // Sequential rather than Promise.all'd — all five hit the same "scans"
  // table, and running them one after another keeps each one's result
  // unambiguous (an admin dashboard load is not latency-sensitive enough to
  // trade that clarity for a handful of milliseconds of parallelism).
  const { count: totalScans } = await supabaseAdmin.from("scans").select("id", { count: "exact", head: true });
  const scanStatusCounts: Array<readonly [string, number]> = [];
  for (const status of SCAN_STATUSES) {
    const { count } = await supabaseAdmin.from("scans").select("id", { count: "exact", head: true }).eq("status", status);
    scanStatusCounts.push([status, count ?? 0]);
  }
  const { count: scansLast30d } = await supabaseAdmin
    .from("scans")
    .select("id", { count: "exact", head: true })
    .gte("created_at", thirtyDaysAgo);

  const activeSubscriptions = (subscriptions ?? []).filter((s) => s.status === "active");
  const planBreakdown: Record<string, number> = {};
  for (const s of activeSubscriptions) {
    planBreakdown[s.plan] = (planBreakdown[s.plan] ?? 0) + 1;
  }

  // Only include statuses that actually occur, matching the previous
  // behaviour of building this object incrementally from real rows.
  const scansByStatus = Object.fromEntries(scanStatusCounts.filter(([, count]) => count > 0));

  // Rough MRR estimate based on plan counts × hardcoded prices. Must match
  // the real prices in src/app/dashboard/page.tsx's PLAN_LABELS (and
  // /pricing) — these had drifted out of sync (19/49/99 here vs the real
  // 20/35/75), silently understating MRR on every load.
  const PLAN_PRICE: Record<string, number> = { basic: 20, pro: 35, agency: 75 };
  const mrr = activeSubscriptions.reduce((sum, s) => sum + (PLAN_PRICE[s.plan] ?? 0), 0);

  return res.status(200).json({
    totalCustomers: totalCustomers ?? 0,
    activeSubscriptions: activeSubscriptions.length,
    totalScans: totalScans ?? 0,
    scansLast30d: scansLast30d ?? 0,
    scansByStatus,
    planBreakdown: Object.entries(planBreakdown).map(([plan, count]) => ({ plan, count })),
    mrrUsd: mrr,
    recentSignups: recentSignups ?? [],
  });
}
