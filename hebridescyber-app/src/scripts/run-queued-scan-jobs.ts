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

import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import type { WebSocketLikeConstructor } from "@supabase/realtime-js";
import ws from "ws";
import { pathToFileURL } from "node:url";
import { validateNoSsrf, isDomainVerified } from "../lib/ownership";
import { executeScan } from "../lib/scanExecution";
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

  let processed = 0;
  let succeeded = 0;
  let failed = 0;

  while (processed < MAX_JOBS_PER_RUN && Date.now() - startedAt < TIME_BUDGET_MS) {
    const { data: claimed, error: claimError } = await supabaseAdmin.rpc("claim_scan_job", {
      worker_id: workerId,
    });

    if (claimError) {
      console.error("claim_scan_job RPC failed:", claimError.message);
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
  async function failJob(message: string) {
    console.error(`[job ${job.id}] failed: ${message}`);
    await supabaseAdmin.from("scan_jobs").update({ status: "failed", last_error: message }).eq("id", job.id);
    if (job.scan_id) {
      await supabaseAdmin.from("scans").update({ status: "failed" }).eq("id", job.scan_id);
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
  const scanConfig = await resolveScanConfig(supabaseAdmin, job);

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

  const outcome = await executeScan(supabaseAdmin, scanId, job.owner, job.target_url, {
    profile: scanConfig.profile,
    toolOverrides: scanConfig.toolOverrides,
  });
  if (!outcome.ok) {
    await failJob(outcome.error);
    return false;
  }

  await supabaseAdmin.from("scan_jobs").update({ status: "completed" }).eq("id", job.id);
  console.log(`[job ${job.id}] completed — score ${outcome.score}`);
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
  main().catch((err) => {
    console.error("run-queued-scan-jobs failed:", err);
    process.exit(1);
  });
}
