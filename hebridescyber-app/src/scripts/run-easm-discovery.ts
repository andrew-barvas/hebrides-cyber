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
      `${r.newAssets} new asset(s), ${r.skippedUnverified} unverified, ` +
      `${r.skippedNoDomain} no-domain, ${r.errors} error(s).`,
  );
  // A sweep error on an individual target is tolerated (counted, not fatal);
  // only a top-level failure (bad DB) throws out of runEasmPipeline below.
}

main().catch((err) => {
  console.error("run-easm-discovery failed:", err);
  process.exit(1);
});
