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
import { validateNoSsrf, isDomainVerified } from "../lib/ownership";
import { executeScan } from "../lib/scanExecution";

// With runExtendedTools enabled, a single job can take up to ~3.5 minutes
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

    const job = claimed?.[0] as { id: string; owner: string; target_url: string } | undefined;
    if (!job) break; // queue is empty

    processed++;
    console.log(`[${workerId}] claimed job ${job.id} — ${job.target_url}`);

    const ok = await runOne(supabaseAdmin, job);
    if (ok) succeeded++;
    else failed++;
  }

  console.log(`[${workerId}] done — processed ${processed}, succeeded ${succeeded}, failed ${failed}.`);
}

async function runOne(
  supabaseAdmin: SupabaseClient,
  job: { id: string; owner: string; target_url: string }
): Promise<boolean> {
  async function failJob(message: string) {
    console.error(`[job ${job.id}] failed: ${message}`);
    await supabaseAdmin.from("scan_jobs").update({ status: "failed", last_error: message }).eq("id", job.id);
  }

  // Re-checked here even though enqueue-scheduled-scans.ts already filtered
  // on this — a job can sit in the queue for a while, and defense in depth
  // costs nothing. Same reasoning as run-scan/index.ts's own SSRF re-check
  // at execution time, not just at scan-creation time.
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

  await supabaseAdmin.from("scan_jobs").update({ scan_id: scan.id }).eq("id", job.id);

  // Extended tools (nmap/nuclei/sqlmap/ZAP) only ever run here — this is the
  // one environment (a GitHub Actions runner, see scheduled-scans.yml) that
  // actually has the binaries/daemon installed. Safe to enable unconditionally:
  // every job reaching this point already passed isDomainVerified above, so
  // active scanning only ever targets a domain the owner has proven they
  // control.
  const outcome = await executeScan(supabaseAdmin, scan.id, job.owner, job.target_url, {
    runExtendedTools: true,
  });
  if (!outcome.ok) {
    await failJob(outcome.error);
    return false;
  }

  await supabaseAdmin.from("scan_jobs").update({ status: "completed" }).eq("id", job.id);
  console.log(`[job ${job.id}] completed — score ${outcome.score}`);
  return true;
}

main().catch((err) => {
  console.error("run-queued-scan-jobs failed:", err);
  process.exit(1);
});
