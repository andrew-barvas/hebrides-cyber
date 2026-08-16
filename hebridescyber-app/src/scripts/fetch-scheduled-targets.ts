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
import type { WebSocketLikeConstructor } from "@supabase/realtime-js";
import { appendFileSync } from "node:fs";
import ws from "ws";

async function main() {
  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !serviceRoleKey) {
    console.error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required.");
    process.exit(1);
  }

  // This script only does REST (.from().select()) calls and never subscribes
  // to a realtime channel — but createClient() constructs a RealtimeClient
  // unconditionally, which throws at construction time on Node 20 CI runners
  // that lack a native WebSocket global. Supplying the `ws` package as the
  // transport (Supabase's own documented workaround for Node < 22) avoids
  // the crash without changing the pinned Node version for the whole workflow.
  const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey, {
    // ws's bundled types don't structurally match WebSocketLikeConstructor
    // (its `address` param is typed wider than the interface expects) even
    // though it satisfies the interface at runtime — a known mismatch
    // between the two packages' type definitions, not a real incompatibility.
    realtime: { transport: ws as unknown as WebSocketLikeConstructor },
  });

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
