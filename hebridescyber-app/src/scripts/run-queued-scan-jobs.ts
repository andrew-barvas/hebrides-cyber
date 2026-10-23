// The free-tier "worker": claims scan_jobs rows via the claim_scan_job()
// SKIP LOCKED RPC (sql/migrations/008_scan_jobs.sql) and runs each one to
// completion using the exact same executeScan() the dashboard's synchronous
// "Run scan" button uses (src/lib/scanExecution.ts) — just invoked directly
// in this ephemeral GitHub Actions runner instead of via the Azure Function.
//
// Multiple shards of this script can run concurrently (see
// .github/workflows/scheduled-scans.yml's matrix) — SKIP LOCKED guarantees
// no two shards ever claim the same job.
//
// Bounded on purpose: a fixed max job count and a wall-clock budget per run,
// so one Actions job can't run indefinitely. Whatever's left over gets
// picked up next time this workflow fires — matches the "fine at today's
// scale, revisit if it becomes a bottleneck" tone already used elsewhere in
// this codebase for its early-stage constraints.
//
// Run locally with:
//   SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... npx tsx src/scripts/run-queued-scan-jobs.ts

// Must be the first import so Sentry is initialised before any async code
// runs. Silent no-op when SENTRY_DSN is unset — see sentry.worker.config.ts.
import "../sentry.worker.config";
import * as Sentry from "@sentry/node";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import type { WebSocketLikeConstructor } from "@supabase/realtime-js";
import ws from "ws";
import { randomUUID } from "node:crypto";
import { pathToFileURL } from "node:url";
import { validateNoSsrf, isDomainVerified } from "../lib/ownership";
import { executeScan } from "../lib/scanExecution";
import { hasTierAAccess } from "../lib/planAccess";
import { hasActiveOffensiveAuthorization } from "../lib/offensiveAuthorization";
import { logAuditEvent } from "../lib/audit";
import { enablesOffensiveTools } from "../lib/scanProfiles";
import type { ScanProfile, ExtendedToolName } from "../lib/scanProfiles";

// With a "full"/"api"/"cms"/"osint" scan profile, a single job can take up to ~3.5 minutes
// (sqlmap's own 180s timeout is the long pole, run in parallel with the
// other tools) versus ~10-30s for passive-only checks — both budgets sized
// accordingly, well inside a single Actions job's own ~6 hour limit.
const MAX_JOBS_PER_RUN = 15;
const TIME_BUDGET_MS = 25 * 60 * 1000; // 25 minutes

async function main() {
  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !serviceRoleKey) {
    console.error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required.");
    process.exit(1);
  }

  const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey, {
    realtime: { transport: ws as unknown as WebSocketLikeConstructor },
  });

  const workerId = process.env.WORKER_ID ?? `local-${process.pid}`;
  const startedAt = Date.now();

  // Reset any scan_jobs rows stuck in 'running' past GitHub's job ceiling
  // (see 041_reset_stale_scan_jobs.sql for why it can't be shorter) — handles
  // runners killed mid-job (OOM, timeout, restart) so the job gets re-claimed
  // on this run rather than staying orphaned indefinitely.
  const { data: resetCount, error: resetError } = await supabaseAdmin.rpc("reset_stale_scan_jobs");
  if (resetError) {
    console.warn(`[${workerId}] reset_stale_scan_jobs: ${resetError.message}`);
    Sentry.captureException(new Error(resetError.message), { tags: { worker_id: workerId, rpc: "reset_stale_scan_jobs" } });
  } else if ((resetCount as number) > 0) {
    console.log(`[${workerId}] reset ${resetCount} stale job(s) to pending — they will be re-claimed now.`);
  }

  let processed = 0;
  let succeeded = 0;
  let failed = 0;

  while (processed < MAX_JOBS_PER_RUN && Date.now() - startedAt < TIME_BUDGET_MS) {
    const { data: claimed, error: claimError } = await supabaseAdmin.rpc("claim_scan_job", {
      worker_id: workerId,
    });

    if (claimError) {
      console.error(`[${workerId}] claim_scan_job RPC failed: ${claimError.message}`);
      Sentry.captureException(new Error(claimError.message), { tags: { worker_id: workerId, rpc: "claim_scan_job" } });
      break;
    }

    const job = claimed?.[0] as
      | { id: string; owner: string; target_url: string; scan_id: string | null; scan_profile: string | null }
      | undefined;
    if (!job) break; // queue is empty

    processed++;
    console.log(`[${workerId}] claimed job ${job.id} — ${job.target_url}`);

    const ok = await runOne(supabaseAdmin, job);
    if (ok) succeeded++;
    else failed++;
  }

  console.log(`[${workerId}] done — processed ${processed}, succeeded ${succeeded}, failed ${failed}.`);
  // Flush Sentry before the process exits — the runner is ephemeral (GitHub
  // Actions), so any buffered events would be lost if we don't drain first.
  // No-op when SENTRY_DSN is unset. Cap at 5 s to not delay clean exit.
  await Sentry.flush(5000).catch(() => {});
}

type ScanConfig = { profile: ScanProfile; toolOverrides?: Partial<Record<ExtendedToolName, boolean>> };

/**
 * Pure decision logic for "which scan profile/tool-overrides does this job
 * get" — kept separate from resolveScanConfig()'s Supabase fetches so it's
 * unit-testable without a mocked client, the same way ticketLinks.ts's
 * decideTicketAction() is. Precedence:
 *   1. An explicit per-job override (job.scan_profile) wins outright.
 *   2. An on-demand job (job.scan_id preset) always stays "safe" —
 *      unchanged from today's passive-only on-demand behaviour.
 *   3. A scheduled job's target's scan_bundle_id, if set, wins over its
 *      plain scan_profile column.
 *   4. Otherwise the target's plain scan_profile column, defaulting to
 *      "full" if there's no monitored_targets row at all (matches today's
 *      unconditional-extended-tools behaviour for a scheduled job with no
 *      target row, which shouldn't normally happen but is the safe default
 *      if it does).
 */
export function decideScanConfig(
  job: { scan_id: string | null; scan_profile: string | null },
  target: { scan_profile: string; scan_bundle_id: string | null } | null,
  bundle: { base_profile: string; tool_overrides: Record<string, boolean> } | null
): ScanConfig {
  if (job.scan_profile) return { profile: job.scan_profile as ScanProfile };
  if (job.scan_id) return { profile: "safe" };
  if (target?.scan_bundle_id && bundle) {
    return { profile: bundle.base_profile as ScanProfile, toolOverrides: bundle.tool_overrides };
  }
  return { profile: (target?.scan_profile as ScanProfile) ?? "full" };
}

async function resolveScanConfig(
  supabaseAdmin: SupabaseClient,
  job: { owner: string; target_url: string; scan_id: string | null; scan_profile: string | null }
): Promise<ScanConfig> {
  // Explicit override / on-demand cases never need a target lookup at all.
  if (job.scan_profile || job.scan_id) return decideScanConfig(job, null, null);

  const { data: target } = await supabaseAdmin
    .from("monitored_targets")
    .select("scan_profile, scan_bundle_id")
    .eq("owner", job.owner)
    .eq("target_url", job.target_url)
    .maybeSingle();

  if (!target?.scan_bundle_id) return decideScanConfig(job, target ?? null, null);

  const { data: bundle } = await supabaseAdmin
    .from("scan_bundles")
    .select("base_profile, tool_overrides")
    .eq("id", target.scan_bundle_id)
    .maybeSingle();

  return decideScanConfig(job, target, bundle ?? null);
}

async function runOne(
  supabaseAdmin: SupabaseClient,
  job: { id: string; owner: string; target_url: string; scan_id: string | null; scan_profile: string | null }
): Promise<boolean> {
  // Per-job correlation id: ties log lines and Sentry events together across
  // the worker process, scanExecution.ts, and any downstream logging. Only
  // the first 8 hex chars appear in log prefixes (enough to distinguish jobs
  // in a run); Sentry gets the full UUID as a tag for exact search.
  const correlationId = randomUUID();
  const tag = `[job ${job.id} corr:${correlationId.slice(0, 8)}]`;
  Sentry.setTag("correlation_id", correlationId);
  Sentry.setTag("job_id", job.id);

  async function failJob(message: string) {
    console.error(`${tag} failed: ${message}`);
    Sentry.captureException(new Error(message), {
      extra: { job_id: job.id, target_url: job.target_url, owner: job.owner, correlation_id: correlationId },
    });
    await supabaseAdmin.from("scan_jobs").update({ status: "failed", last_error: message }).eq("id", job.id);
    if (job.scan_id) {
      // Mirror the reason onto the scan the owner/admin see (migration 058).
      await supabaseAdmin.from("scans").update({ status: "failed", error_detail: message.slice(0, 2000) }).eq("id", job.scan_id);
    }
  }

  // Re-checked here even though enqueue-scheduled-scans.ts (and
  // src/pages/api/run-scan.ts, for on-demand jobs) already filtered on this —
  // a job can sit in the queue for a while, and defense in depth costs
  // nothing. Same reasoning as run-scan.ts's own SSRF re-check at execution
  // time, not just at scan-creation time.
  try {
    await validateNoSsrf(job.target_url);
  } catch (err) {
    await failJob(`SSRF check failed: ${(err as Error).message}`);
    return false;
  }

  if (!(await isDomainVerified(supabaseAdmin, job.owner, job.target_url))) {
    await failJob("Domain ownership verification is no longer on file for this target.");
    return false;
  }

  // job.scan_id distinguishes the two sources this queue now serves:
  //   - null: a scheduled job (enqueue-scheduled-scans.ts) — this worker owns
  //     the whole scans row lifecycle and resolves its scan profile from the
  //     target (or an explicit job-level override), since every scheduled
  //     target already has a verified, paying-subscription owner behind it.
  //   - set: an on-demand job (src/pages/api/run-scan.ts) — the scans row
  //     already exists (created when the customer clicked "Run scan"), so
  //     this worker reuses it and stays on the "safe" profile, matching what
  //     /what-we-check tells customers an on-demand scan does.
  let scanId = job.scan_id;

  // Idempotency guard: a second job for a scan that has already completed
  // (an older double-enqueue, or a stale-job reset racing a run that did
  // finish) must not run it again — that's how one scan ended up with two
  // scan_results rows. An admin retry is unaffected: it sets the scan back
  // to "queued" before re-enqueuing.
  if (scanId) {
    const { data: existing } = await supabaseAdmin.from("scans").select("status").eq("id", scanId).maybeSingle();
    if (existing?.status === "completed") {
      await supabaseAdmin.from("scan_jobs").update({ status: "completed" }).eq("id", job.id);
      console.log(`${tag} skipped — scan ${scanId} already completed`);
      return true;
    }
  }

  let scanConfig = await resolveScanConfig(supabaseAdmin, job);

  // Authoritative gate for any configuration that would run the offensive-only
  // tools (brute-force / real attack). The UI and the DB CHECK constraint let
  // the value be stored, but nothing until here decides whether it may actually
  // RUN. It runs only when the owner is on Tier A AND has a current per-scan
  // authorization for this target (offensive_scan_authorizations) — the
  // domain-ownership check above already ran. If either is missing we downgrade
  // to a passive "safe" scan rather than failing the job, and record why. This
  // is the only place the offensive suite is unlocked; a comment used to be the
  // sole "gate".
  //
  // The condition asks enablesOffensiveTools() rather than comparing the
  // profile to "offensive": that comparison missed `ai-pentest`, which enables
  // the same four tools, and would miss a scan bundle whose tool_overrides turn
  // one on over a tame base profile.
  if (enablesOffensiveTools(scanConfig.profile, scanConfig.toolOverrides)) {
    const requestedProfile = scanConfig.profile;
    const [tierOk, authorized] = await Promise.all([
      hasTierAAccess(supabaseAdmin, job.owner),
      hasActiveOffensiveAuthorization(supabaseAdmin, job.owner, job.target_url),
    ]);
    if (!tierOk || !authorized) {
      const reason = !tierOk ? "owner is not on Tier A" : "no current offensive-scan authorization for this target";
      console.warn(`${tag} offensive tools refused for profile "${requestedProfile}" (${reason}); downgrading to safe`);
      await logAuditEvent(supabaseAdmin, {
        actorId: job.owner,
        action: "offensive_scan.refused",
        resourceType: "scan_job",
        resourceId: job.id,
        metadata: { target_url: job.target_url, reason, profile: requestedProfile },
      });
      // Drops toolOverrides along with the profile — a "safe" profile carrying
      // an override that re-enabled an offensive tool would defeat the point.
      scanConfig = { profile: "safe" };
    } else {
      await logAuditEvent(supabaseAdmin, {
        actorId: job.owner,
        action: "offensive_scan.ran",
        resourceType: "scan_job",
        resourceId: job.id,
        metadata: { target_url: job.target_url, profile: requestedProfile },
      });
    }
  }

  if (!scanId) {
    const { data: scan, error: insertError } = await supabaseAdmin
      .from("scans")
      .insert({
        owner: job.owner,
        target_url: job.target_url,
        status: "running",
        owner_verified: true,
      })
      .select("id")
      .single();

    if (insertError || !scan) {
      await failJob(insertError?.message ?? "Failed to create scans row");
      return false;
    }

    scanId = scan.id;
    await supabaseAdmin.from("scan_jobs").update({ scan_id: scanId }).eq("id", job.id);
  }

  if (!scanId) {
    // Unreachable — either job.scan_id was already set, or the insert above
    // succeeded (guarded by the insertError/!scan check). Kept as an explicit
    // guard rather than a non-null assertion so a future change to that logic
    // fails loudly here instead of passing a bad id to executeScan.
    await failJob("Internal error: scanId was not resolved before running the scan.");
    return false;
  }

  // Transition the scan to "running" now that a worker has actually claimed
  // it — run-scan.ts only sets "queued" at enqueue time, since a queued scan
  // may sit for hours if the on-demand dispatch fails and the daily cron is
  // the fallback. The "running" status should mean "a worker is actively
  // scanning right now", not "a scan_jobs row exists somewhere".
  await supabaseAdmin.from("scans").update({ status: "running" }).eq("id", scanId);

  const outcome = await executeScan(supabaseAdmin, scanId, job.owner, job.target_url, {
    profile: scanConfig.profile,
    toolOverrides: scanConfig.toolOverrides,
    correlationId,
  });
  if (!outcome.ok) {
    await failJob(outcome.error);
    return false;
  }

  await supabaseAdmin.from("scan_jobs").update({ status: "completed" }).eq("id", job.id);
  console.log(`${tag} completed — score ${outcome.score}`);
  return true;
}

// Guarded so importing decideScanConfig() from a test doesn't also trigger
// a real run of main() (which would exit the process if SUPABASE_URL isn't
// set) — this is the first script in src/scripts/ that's imported rather
// than only ever executed directly via `tsx`, so no prior file needed this.
// pathToFileURL (not a raw `file://${process.argv[1]}` string) matters on
// Windows, where a naive concatenation gets the drive-letter path format
// and separators wrong.
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(async (err) => {
    Sentry.captureException(err);
    await Sentry.flush(5000).catch(() => {});
    console.error("run-queued-scan-jobs failed:", err);
    process.exit(1);
  });
}
