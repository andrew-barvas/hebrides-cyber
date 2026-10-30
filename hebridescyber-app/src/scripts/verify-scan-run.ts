// The `verify` job of .github/workflows/scheduled-scans.yml (SPRINT-PLAN H3):
// proves the run's shards actually scanned, rather than completing scans in
// which every extended tool was missing or broken.
//
// Reads the scan_jobs this run claimed (claimed_by = "gha-<RUN_ID>-<shard>",
// set from WORKER_ID in the `work` job) and the extended-tool block of each
// resulting scan_results row, then applies verifyScanRun()
// (src/lib/scanRunVerification.ts). Writes a JSON report (artifact) and a
// Markdown job summary, and exits 1 on a failing verdict or any read error. A
// read error is a failed verification, never a clean one.
//
// Run locally with:
//   SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... RUN_ID=<actions run id> npx tsx src/scripts/verify-scan-run.ts
import { appendFileSync, writeFileSync } from "node:fs";
import { createClient } from "@supabase/supabase-js";
import type { WebSocketLikeConstructor } from "@supabase/realtime-js";
import ws from "ws";
import { formatScanRunSummary, verifyScanRun, type ScanRunJob, type ScanRunResult } from "../lib/scanRunVerification";

async function main() {
  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const runId = process.env.RUN_ID;
  if (!supabaseUrl || !serviceRoleKey || !runId) {
    console.error("SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY and RUN_ID are required.");
    process.exit(1);
  }
  if (!/^\d+$/.test(runId)) {
    console.error(`RUN_ID must be a numeric Actions run id, got "${runId}".`);
    process.exit(1);
  }
  const db = createClient(supabaseUrl, serviceRoleKey, { realtime: { transport: ws as unknown as WebSocketLikeConstructor } });

  const { data: jobs, error: jobsError } = await db
    .from("scan_jobs")
    .select("id, status, scan_id, last_error")
    .like("claimed_by", `gha-${runId}-%`);
  if (jobsError) {
    console.error("Could not read this run's scan_jobs:", jobsError.message);
    process.exit(1);
  }

  const scanIds = (jobs ?? []).map((j) => j.scan_id).filter((id): id is string => typeof id === "string");
  let results: ScanRunResult[] = [];
  if (scanIds.length > 0) {
    const { data, error } = await db.from("scan_results").select("scan_id, extended:results->extended").in("scan_id", scanIds);
    if (error) {
      console.error("Could not read this run's scan_results:", error.message);
      process.exit(1);
    }
    results = (data ?? []) as ScanRunResult[];
  }

  const verification = verifyScanRun((jobs ?? []) as ScanRunJob[], results);
  const summary = formatScanRunSummary(verification);
  writeFileSync(process.env.VERIFY_OUTPUT ?? "scan-run-verification.json", JSON.stringify({ runId, ...verification }, null, 2));
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary + "\n");
  console.log(summary);

  if (verification.verdict === "fail") {
    console.error(`::error::Scheduled scan run ${runId} did not prove it scanned: ${verification.problems.join("; ")}`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("verify-scan-run failed:", err);
  process.exit(1);
});
