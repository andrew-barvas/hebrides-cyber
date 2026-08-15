// Local scanner test script — runs the same stub steps as run-scan
// (shared via src/lib/scanners.ts), directly from the CLI against a target
// you own, with no Azure dependency. Useful for iterating on scanner logic
// before wiring it into the Azure Function.
//
// Run with: npm run scan:local -- https://example.com
// (defaults to http://localhost:3000 if no URL is given)
//
// If SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, and SCAN_OWNER_ID are all set
// in the environment, results are also written to the scans/scan_results
// tables — handy for seeding test data without going through the dashboard
// or the Azure Function. Omit them to just print JSON to the console.

import { runAllChecks, summariseResults, scoreFromFindings } from "../lib/scanners";

async function main() {
  const targetUrl = process.argv[2] ?? "http://localhost:3000";
  console.log(`\nRunning local scan against: ${targetUrl}\n`);

  const results = await runAllChecks(targetUrl);
  const { summary, findings } = summariseResults(results);
  const score = scoreFromFindings(findings);

  console.log(JSON.stringify({ results, findings, summary, score }, null, 2));
  console.log(`\nScore: ${score}/100`);
  console.log("\nDone. This uses the same stub scanner functions as src/functions/run-scan/index.ts.\n");

  await maybeWriteToSupabase(targetUrl, results, findings, summary, score);
}

async function maybeWriteToSupabase(
  targetUrl: string,
  results: unknown,
  findings: unknown,
  summary: string,
  score: number
) {
  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const ownerId = process.env.SCAN_OWNER_ID;

  if (!supabaseUrl || !serviceRoleKey || !ownerId) {
    console.log(
      "Skipping Supabase write — set SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, and SCAN_OWNER_ID to persist this run."
    );
    return;
  }

  // Dynamic import so this dependency is only required when actually used.
  const { createClient } = await import("@supabase/supabase-js");
  const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey);

  const { data: scan, error: scanError } = await supabaseAdmin
    .from("scans")
    .insert({
      owner: ownerId,
      target_url: targetUrl,
      status: "completed",
      proof_token: "local-script", // TODO: not a real token — this bypass is only for local seeding.
      owner_verified: true,
    })
    .select("id")
    .single();

  if (scanError || !scan) {
    console.error("Failed to write scan row:", scanError?.message);
    return;
  }

  const { error: resultsError } = await supabaseAdmin.from("scan_results").insert({
    scan_id: scan.id,
    results: { ...(results as object), findings },
    summary,
    score,
  });

  if (resultsError) {
    console.error("Failed to write scan_results row:", resultsError.message);
    return;
  }

  console.log(`Wrote scan ${scan.id} to Supabase.`);
}

main().catch((err) => {
  console.error("scan-local failed:", err);
  process.exit(1);
});
