// Revenue/MRR/churn maths for the admin dashboard, kept pure and fed real
// rows by the caller — same "pure fn, unit-testable without Supabase" model
// as scanCadence.ts's isScanDue(). No Stripe API call: the per-plan prices
// below are this product's own published prices (/pricing, GBP/month), the
// single source of truth the admin panel and the pricing page both describe.
// Calling Stripe's list-subscriptions API on every admin load would be heavy
// and isn't reachable in CI; the subscription rows are already kept in sync
// by the Stripe webhook, so MRR is computed from them.

/**
 * Published monthly price per plan, in GBP. `null` means the plan has no
 * fixed published price — Tier A is bespoke ("Contact us" on /pricing), so
 * its real amount isn't knowable from published data and it is counted
 * separately rather than guessed or treated as £0.
 */
export const PLAN_PRICE_GBP: Record<string, number | null> = {
  basic: 20,
  pro: 35,
  agency: 75,
  tier_a: null,
};

export type RevenueSubRow = { plan: string; status: string; source?: string | null };

export type MrrBreakdown = {
  payingMrrGbp: number;
  payingCount: number;
  /** Active subs granted by an admin (source = 'admin') — real cash is £0. */
  compedCount: number;
  /** Active subs on a known plan with no fixed price (Tier A) — excluded from MRR. */
  bespokeCount: number;
  byPlan: { plan: string; count: number; mrrGbp: number }[];
};

/**
 * MRR from real subscription rows. Only active subs count. A sub is "paying"
 * unless it was explicitly admin-granted (source = 'admin'); the DB default
 * for source is 'stripe', so a row with no source is treated as paying.
 * byPlan lists every active plan with its count and the recurring revenue it
 * contributes (0 for comped or bespoke plans).
 */
export function computeMrr(subs: RevenueSubRow[]): MrrBreakdown {
  const active = subs.filter((s) => s.status === "active");
  let payingMrrGbp = 0;
  let payingCount = 0;
  let compedCount = 0;
  let bespokeCount = 0;
  const byPlan = new Map<string, { count: number; mrrGbp: number }>();

  for (const sub of active) {
    const comped = sub.source === "admin";
    const price = PLAN_PRICE_GBP[sub.plan] ?? null;
    const contribution = !comped && price !== null ? price : 0;

    if (comped) compedCount += 1;
    else if (price === null) bespokeCount += 1;
    else {
      payingCount += 1;
      payingMrrGbp += price;
    }

    const entry = byPlan.get(sub.plan) ?? { count: 0, mrrGbp: 0 };
    entry.count += 1;
    entry.mrrGbp += contribution;
    byPlan.set(sub.plan, entry);
  }

  return {
    payingMrrGbp,
    payingCount,
    compedCount,
    bespokeCount,
    byPlan: [...byPlan.entries()].map(([plan, v]) => ({ plan, ...v })),
  };
}

/**
 * Monthly churn as a percentage: subscriptions cancelled in the window over
 * the number active at the window's start. Returns null when the starting
 * base is zero or negative (not enough data to express a rate), rather than
 * a misleading 0% or a divide-by-zero.
 */
export function churnRatePct(cancelledInWindow: number, activeAtWindowStart: number): number | null {
  if (activeAtWindowStart <= 0) return null;
  return (cancelledInWindow / activeAtWindowStart) * 100;
}
