// Used by .github/workflows/scheduled-scans.yml to build a dynamic build
// matrix of { owner, targetUrl } pairs to scan, instead of a hardcoded
// list. Queries Supabase directly with the service role key (this only
// ever runs in CI, never client-side).
//
// Output: prints a single line `matrix=<json>` suitable for
// `echo "matrix=$json" >> "$GITHUB_OUTPUT"` when GITHUB_OUTPUT is set,
// and always prints the JSON to stdout for local debugging too.
//
// Run locally with:
//   SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... npx tsx src/scripts/fetch-scheduled-targets.ts

import { createClient } from "@supabase/supabase-js";
import { appendFileSync } from "node:fs";

async function main() {
  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !serviceRoleKey) {
    console.error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required.");
    process.exit(1);
  }

  const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey);

  const { data: activeSubs, error: subsError } = await supabaseAdmin
    .from("subscriptions")
    .select("owner")
    .eq("status", "active");

  if (subsError) {
    console.error("Failed to fetch active subscriptions:", subsError.message);
    process.exit(1);
  }

  const activeOwners = (activeSubs ?? []).map((s) => s.owner);
  if (activeOwners.length === 0) {
    writeMatrix({ include: [] });
    return;
  }

  // TODO: paginate if a single customer could plausibly have hundreds of
  // monitored targets — fine for the expected scale of an early-stage
  // product, revisit if it becomes a bottleneck.
  const { data: targets, error: targetsError } = await supabaseAdmin
    .from("monitored_targets")
    .select("owner, target_url")
    .in("owner", activeOwners);

  if (targetsError) {
    console.error("Failed to fetch monitored targets:", targetsError.message);
    process.exit(1);
  }

  const include = (targets ?? []).map((t) => ({ owner: t.owner, targetUrl: t.target_url }));
  writeMatrix({ include });
}

function writeMatrix(matrix: { include: Array<{ owner: string; targetUrl: string }> }) {
  const json = JSON.stringify(matrix);
  console.log(json);
  const githubOutput = process.env.GITHUB_OUTPUT;
  if (githubOutput) {
    appendFileSync(githubOutput, `matrix=${json}\n`);
  }
}

main().catch((err) => {
  console.error("fetch-scheduled-targets failed:", err);
  process.exit(1);
});
