// Queue-wait metric: how long the oldest pending scan_jobs row has waited to
// be claimed. Depth alone can't tell a busy queue from a dead one — 40 jobs
// that started a minute ago are fine, one job that has sat for three hours
// means no worker is running. /api/health reports it, and once the alert is
// switched on a wait past the threshold turns health "degraded", which is the
// existing on-call path: UptimeRobot pages on the 503 and uptime.yml opens an
// incident issue.
//
// The alert is off unless SCAN_QUEUE_WAIT_ALERT=1. While scans still run only
// from the once-a-day GitHub Actions fallback (scheduled-scans.yml), a job
// left over from one run waits for the next by design, and the alert would
// fire daily. Switch it on once the always-on Container Apps workers
// (azure/terraform/scan-workers.tf) are live.
//
// Pure functions, no Supabase: the health route does the one query.

/** Two hours: the gap analysis's service level for "a queued scan starts". */
export const QUEUE_WAIT_ALERT_SECONDS = 2 * 60 * 60;

export type QueueWait = {
  /** Seconds the oldest pending job has waited; 0 when nothing is pending. */
  oldestWaitSeconds: number;
  /** True only when the alert is switched on and the wait passed the threshold. */
  waitExceeded: boolean;
};

/**
 * Age of the oldest pending job in whole seconds. No pending job is a wait of
 * 0. A timestamp that doesn't parse is reported as null rather than 0, so the
 * caller fails the check instead of reading a broken row as an empty queue.
 * A created_at slightly in the future (clock skew) counts as 0.
 */
export function queueWaitSeconds(oldestCreatedAt: string | null | undefined, now: Date): number | null {
  if (!oldestCreatedAt) return 0;
  const created = Date.parse(oldestCreatedAt);
  if (Number.isNaN(created)) return null;
  return Math.max(0, Math.floor((now.getTime() - created) / 1000));
}

/** SCAN_QUEUE_WAIT_ALERT=1 (or "true") switches the alert on; anything else leaves it off. */
export function queueWaitAlertEnabled(env: Record<string, string | undefined> = process.env): boolean {
  const value = env.SCAN_QUEUE_WAIT_ALERT?.trim().toLowerCase();
  return value === "1" || value === "true";
}

/** Strictly past the threshold: a job at exactly two hours has not breached it. */
export function decideQueueWait(
  oldestWaitSeconds: number,
  options: { alertEnabled: boolean; thresholdSeconds?: number }
): QueueWait {
  const threshold = options.thresholdSeconds ?? QUEUE_WAIT_ALERT_SECONDS;
  return { oldestWaitSeconds, waitExceeded: options.alertEnabled && oldestWaitSeconds > threshold };
}
