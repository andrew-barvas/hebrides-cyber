// Error tracking and correlation ids for the GitHub Actions scan worker
// (src/scripts/run-queued-scan-jobs.ts).
//
// The web app has Sentry via instrumentation.ts, but the worker is a plain
// Node script on an ephemeral runner, so none of that ever loaded there: a
// scan that crashed or failed on a runner left a line in an Actions log that
// disappears after 90 days and that nobody is watching. This gives the worker
// the same two properties the web app has: failures reach Sentry (when
// SENTRY_DSN is set; otherwise it is a no-op, like everywhere else), and one
// id ties together a scan's log lines, its scan_jobs row, its Sentry events
// and (for on-demand scans) the API request that created it.
//
// The correlation id is the scan id when the job has one, else the job id.
// Both are UUIDs already stored and shown in the app, so there is nothing new
// to look up. Tags carry the target's host only, never its full URL, and
// sentryScrub.ts redacts credential-looking fields before anything is sent.
import * as Sentry from "@sentry/node";
import { scrubSentryEvent } from "./sentryScrub";

export type JobContext = {
  workerId: string;
  jobId: string;
  scanId: string | null;
  targetUrl: string;
};

/** One id for a scan across logs, scan_jobs, Sentry and the API request. */
export function correlationId(job: { id: string; scan_id: string | null }): string {
  return job.scan_id ?? job.id;
}

/** `[scan 1234] ` style prefix for log lines, so one scan can be grepped out of a shared runner log. */
export function logPrefix(job: { id: string; scan_id: string | null }): string {
  return `[${job.scan_id ? "scan" : "job"} ${correlationId(job)}]`;
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return "invalid-url";
  }
}

let initialised = false;

/** Start Sentry for the worker. No-op, returning false, without a DSN. Safe to call more than once. */
export function initWorkerSentry(workerId: string, env: Record<string, string | undefined> = process.env): boolean {
  const dsn = env.SENTRY_DSN;
  if (!dsn) return false;
  if (initialised) return true;
  Sentry.init({
    dsn,
    environment: "worker",
    // Errors only: a worker has no latency problem this would help with.
    tracesSampleRate: 0,
    beforeSend: scrubSentryEvent,
  });
  Sentry.setTag("worker_id", workerId);
  initialised = true;
  return true;
}

/** Report an unexpected failure with the job's identifiers. Never throws, and does nothing without init. */
export function captureWorkerError(err: unknown, job: JobContext, stage: string): void {
  if (!initialised) return;
  try {
    Sentry.withScope((scope) => {
      scope.setTag("stage", stage);
      scope.setTag("worker_id", job.workerId);
      scope.setTag("job_id", job.jobId);
      if (job.scanId) scope.setTag("scan_id", job.scanId);
      scope.setTag("target_host", hostOf(job.targetUrl));
      scope.setTag("correlation_id", job.scanId ?? job.jobId);
      // One group per stage and message shape, not one per scan.
      scope.setFingerprint(["worker", stage, err instanceof Error ? err.name : "non-error"]);
      Sentry.captureException(err instanceof Error ? err : new Error(String(err)));
    });
  } catch {
    // Reporting must never be the thing that fails a scan.
  }
}

/** Report a worker-level failure with no job (claim RPC down, crash in main). */
export function captureWorkerFatal(err: unknown, workerId: string, stage: string): void {
  if (!initialised) return;
  try {
    Sentry.withScope((scope) => {
      scope.setTag("stage", stage);
      scope.setTag("worker_id", workerId);
      Sentry.captureException(err instanceof Error ? err : new Error(String(err)));
    });
  } catch {
    // see above
  }
}

/** Send queued events before the process exits; a runner is gone the moment it does. */
export async function flushWorkerSentry(timeoutMs = 3000): Promise<void> {
  if (!initialised) return;
  try {
    await Sentry.flush(timeoutMs);
  } catch {
    // best effort
  }
}

/** Test seam. */
export function resetWorkerSentryForTests(): void {
  initialised = false;
}
