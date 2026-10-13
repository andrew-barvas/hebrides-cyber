import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin, supabaseAdmin } from "@/lib/adminAuth";
import { computeMrr, churnRatePct } from "@/lib/revenueMetrics";

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
    supabaseAdmin.from("subscriptions").select("plan, status, source"),
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

  const allSubs = subscriptions ?? [];
  const activeSubscriptions = allSubs.filter((s) => s.status === "active");
  const pastDueCount = allSubs.filter((s) => s.status === "past_due").length;
  const planBreakdown: Record<string, number> = {};
  for (const s of activeSubscriptions) {
    planBreakdown[s.plan] = (planBreakdown[s.plan] ?? 0) + 1;
  }

  // New subscriptions and cancellations over the window come from the
  // webhook-synced audit log (the Stripe webhook writes one row per lifecycle
  // event — see src/pages/api/stripe/webhook.ts), the only historical record
  // we keep: the subscriptions table is one upserted row per owner with no
  // history of its own.
  const { count: newSubs30d } = await supabaseAdmin
    .from("audit_logs")
    .select("id", { count: "exact", head: true })
    .eq("action", "stripe.checkout.completed")
    .gte("created_at", thirtyDaysAgo);
  const { count: cancellations30d } = await supabaseAdmin
    .from("audit_logs")
    .select("id", { count: "exact", head: true })
    .eq("action", "stripe.subscription.deleted")
    .gte("created_at", thirtyDaysAgo);

  // Only include statuses that actually occur, matching the previous
  // behaviour of building this object incrementally from real rows.
  const scansByStatus = Object.fromEntries(scanStatusCounts.filter(([, count]) => count > 0));

  // MRR from the real subscription rows and this product's own published
  // prices (revenueMetrics.ts) — paying Stripe subs only, so admin-granted
  // comps and bespoke Tier A no longer inflate the figure the way a flat
  // "every active sub × its plan price" sum did.
  const mrr = computeMrr(allSubs);

  // Churn over the window: cancellations / active at the window's start.
  // Approximate the starting base from the current active count adjusted by
  // the window's own gains and losses (no per-day history is kept).
  const newCount = newSubs30d ?? 0;
  const cancelCount = cancellations30d ?? 0;
  const activeAtWindowStart = activeSubscriptions.length - newCount + cancelCount;

  return res.status(200).json({
    totalCustomers: totalCustomers ?? 0,
    activeSubscriptions: activeSubscriptions.length,
    totalScans: totalScans ?? 0,
    scansLast30d: scansLast30d ?? 0,
    scansByStatus,
    planBreakdown: Object.entries(planBreakdown).map(([plan, count]) => ({ plan, count })),
    // mrrUsd is a legacy field name (the value is GBP) kept for the top-line
    // StatCard; it now carries real paying MRR, not the old inflated sum.
    mrrUsd: mrr.payingMrrGbp,
    revenue: {
      payingMrrGbp: mrr.payingMrrGbp,
      payingCount: mrr.payingCount,
      compedCount: mrr.compedCount,
      bespokeCount: mrr.bespokeCount,
      byPlan: mrr.byPlan,
      pastDueCount,
      newSubs30d: newCount,
      cancellations30d: cancelCount,
      churnRatePct: churnRatePct(cancelCount, activeAtWindowStart),
    },
    recentSignups: recentSignups ?? [],
  });
}
