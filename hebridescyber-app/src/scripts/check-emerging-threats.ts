// Emerging-threat alerts: matches CVEs CISA newly added to its Known
// Exploited Vulnerabilities catalog against each paying customer's latest
// scans, records matches in emerging_threat_alerts and alerts the owner.
// Run every 6 hours by .github/workflows/emerging-threats.yml; the logic is
// src/lib/emergingThreatAlerts.ts (+ the pure matching in emergingThreats.ts).
//
//   SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... npx tsx src/scripts/check-emerging-threats.ts --dry-run
//
// --dry-run prints the matches and writes/sends nothing.
// Exit code 1 when the KEV feed can't be read, a write or send failed, or a
// lookup failed on a CVE's last day in the KEV window. A failed lookup is
// never treated as "not affected": earlier in the window it is a warning and
// the next run (6 hours later) checks the CVE again.
import { createScriptSupabase } from "../lib/scriptSupabase";
import { runEmergingThreatCheck } from "../lib/emergingThreatAlerts";

async function main() {
  const dryRun = process.argv.includes("--dry-run");
  const supabaseAdmin = createScriptSupabase();

  const summary = await runEmergingThreatCheck(supabaseAdmin, {
    dryRun,
    nvdApiKey: process.env.NVD_API_KEY || undefined,
    log: (line) => console.log(line),
  });

  console.log(
    `Emerging threats${dryRun ? " (dry run)" : ""}: ${summary.kevAdditions} KEV addition(s), ` +
      `${summary.cvesEvaluated.length} evaluated, ${summary.cvesPending.length} awaiting NVD analysis, ` +
      `${summary.ownersChecked} owner(s), ${summary.hostsChecked} site(s), ${summary.matches.length} match(es), ` +
      `${summary.notified} notified, ${summary.lookupsToRetry.length} lookup(s) to retry, ${summary.errors.length} error(s).`
  );
  for (const m of summary.matches) {
    console.log(
      `  ${m.match.tier.padEnd(17)} ${m.kev.cveId} ${m.host} ${m.match.product} ${m.match.detectedVersion ?? "(version unknown)"} [${m.match.reason}] owner=${m.ownerId}`
    );
  }
  if (summary.migrationPending) console.log("Migration 045 is not applied — nothing was recorded or sent.");
  for (const note of summary.lookupsToRetry) console.log(`::warning::${note} (checked again next run)`);
  for (const err of summary.errors) console.error(`  - ${err}`);
  if (summary.errors.length > 0) process.exit(1);
}

main().catch((err) => {
  console.error("check-emerging-threats failed:", (err as Error).message);
  process.exit(1);
});
