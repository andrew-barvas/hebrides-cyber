// SCALE-2: standalone EASM discovery sweep. Runs on its own schedule
// (.github/workflows/easm-discovery.yml), independent of the scan cadence, so
// a newly-certificated subdomain is discovered within hours rather than at the
// next full scan. All logic is in src/lib/easmPipeline.ts; this is the thin
// shell (same shape as check-emerging-threats.ts / enqueue-scheduled-scans.ts).
//
// Run locally with:
//   SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... npm run easm:discover [-- --dry-run]
import { createClient } from "@supabase/supabase-js";
import type { WebSocketLikeConstructor } from "@supabase/realtime-js";
import ws from "ws";
import { runEasmPipeline } from "../lib/easmPipeline";

async function main() {
  const dryRun = process.argv.includes("--dry-run");
  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!supabaseUrl || !serviceRoleKey) {
    console.error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required.");
    process.exit(1);
  }

  // Same Node-20-CI RealtimeClient workaround as the other scheduled scripts.
  const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey, {
    realtime: { transport: ws as unknown as WebSocketLikeConstructor },
  });

  console.log(dryRun ? "DRY RUN — enumerating targets, discovering nothing." : "Running EASM discovery sweep…");
  const r = await runEasmPipeline(supabaseAdmin, { dryRun });
  console.log(
    `EASM sweep: ${r.targetsSwept}/${r.targetsConsidered} target(s) swept, ` +
      `${r.newAssets} new asset(s), ${r.hostnamesReported} new hostname(s) reported, ` +
      `${r.skippedUnverified} unverified, ${r.skippedNoDomain} no-domain, ${r.errors} error(s).`,
  );
  if (r.ctFailed > 0) {
    // Not fatal: crt.sh is often briefly down and the next sweep tries again. But say so,
    // because those targets got no certificate evidence and so no alert decision this run.
    console.warn(`crt.sh could not be read for ${r.ctFailed} target(s); their pending hostnames were left for the next sweep.`);
  }
  // A sweep error on an individual target is tolerated (counted, not fatal);
  // only a top-level failure (bad DB) throws out of runEasmPipeline below.
  // An alert that was due but could not be delivered fails the run, the same as
  // the erasure-deadline reminder: otherwise a missing RESEND_API_KEY would let
  // customers go unwarned with every run still green. The hostnames are released
  // and retried on the next sweep.
  if (r.alertFailures > 0) {
    console.error(`${r.alertFailures} new-hostname alert(s) could not be delivered (is RESEND_API_KEY set?). They will be retried.`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("run-easm-discovery failed:", err);
  process.exit(1);
});
