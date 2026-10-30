// Plan-tier scan cadence: how long to wait since a target's last *completed*
// scan (see sql/migrations/001_init.sql's `scans.status`/`created_at`)
// before it's due to be scanned again by the scheduled queue
// (src/scripts/enqueue-scheduled-scans.ts). Keyed off `subscriptions.plan`
// — no new column/migration needed, this is computed against existing
// `scans` rows at enqueue time.
//
// Policy:
//   - Basic  = weekly (7 days) — matches the "Weekly automated scans"
//     pricing copy on /pricing, which was previously just aspirational
//     since the old enqueue script scanned every active subscription daily
//     regardless of plan.
//   - Pro    = daily (1 day)  — the existing cron already runs once a day
//     (`0 3 * * *` in .github/workflows/scheduled-scans.yml), so daily is
//     the fastest cadence available without standing up a second cron or
//     more infrastructure. Giving Pro a real frequency bump over Basic is
//     what actually justifies its price step; before this, Pro's pricing
//     copy didn't even mention frequency.
//   - Agency = daily (1 day)  — same cadence as Pro. Agency's differentiator
//     is multi-site monitoring and white-label reports, not scan speed, so
//     there's no need to invent a faster-than-daily tier that the current
//     once-a-day cron can't deliver anyway.
export type Plan = "basic" | "pro" | "agency" | "tier_a";

export const SCAN_INTERVAL_DAYS: Record<Plan, number> = {
  basic: 7,
  pro: 1,
  agency: 1,
  tier_a: 1,
};

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * True when a target on `plan` is due for another scheduled scan, given the
 * `created_at` timestamp of its most recent *completed* scan (`null` if it
 * has never completed one — always due in that case).
 *
 * Pure/sync on purpose: enqueue-scheduled-scans.ts does the Supabase query
 * for `lastCompletedScanAt` and just passes the result in, so this function
 * (and the interval policy above) can be unit-tested without touching
 * Supabase at all.
 */
export function isScanDue(plan: Plan, lastCompletedScanAt: string | null, now: Date): boolean {
  if (!lastCompletedScanAt) return true;
  const elapsedMs = now.getTime() - new Date(lastCompletedScanAt).getTime();
  return elapsedMs >= SCAN_INTERVAL_DAYS[plan] * DAY_MS;
}
