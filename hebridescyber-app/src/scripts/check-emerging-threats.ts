// Emerging-threat alerts: matches CVEs CISA newly added to its Known
// Exploited Vulnerabilities catalog against each paying customer's latest
// scans, records matches in emerging_threat_alerts and alerts the owner.
// Run every 6 hours by .github/workflows/emerging-threats.yml; the logic is
// src/lib/emergingThreatAlerts.ts (+ the pure matching in emergingThreats.ts).
//
//   SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... npx tsx src/scripts/check-emerging-threats.ts --dry-run
//
// --dry-run prints the matches and writes/sends nothing.
// Exit code 1 when the KEV feed can't be read or any lookup, write or send
// failed — a failed lookup is never treated as "not affected".
import { createClient } from "@supabase/supabase-js";
import type { WebSocketLikeConstructor } from "@supabase/realtime-js";
import ws from "ws";
import { runEmergingThreatCheck } from "../lib/emergingThreatAlerts";

async function main() {
  const dryRun = process.argv.includes("--dry-run");
  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!supabaseUrl || !serviceRoleKey) {
    console.error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required.");
    process.exit(1);
  }
  const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey, {
    realtime: { transport: ws as unknown as WebSocketLikeConstructor },
  });

  const summary = await runEmergingThreatCheck(supabaseAdmin, {
    dryRun,
    nvdApiKey: process.env.NVD_API_KEY || undefined,
    log: (line) => console.log(line),
  });

  console.log(
    `Emerging threats${dryRun ? " (dry run)" : ""}: ${summary.kevAdditions} KEV addition(s), ` +
      `${summary.cvesEvaluated.length} evaluated, ${summary.cvesPending.length} awaiting NVD analysis, ` +
      `${summary.ownersChecked} owner(s), ${summary.hostsChecked} site(s), ${summary.matches.length} match(es), ` +
      `${summary.notified} notified, ${summary.errors.length} error(s).`
  );
  for (const m of summary.matches) {
    console.log(
      `  ${m.match.tier.padEnd(17)} ${m.kev.cveId} ${m.host} ${m.match.product} ${m.match.detectedVersion ?? "(version unknown)"} [${m.match.reason}] owner=${m.ownerId}`
    );
  }
  if (summary.migrationPending) console.log("Migration 045 is not applied — nothing was recorded or sent.");
  for (const err of summary.errors) console.error(`  - ${err}`);
  if (summary.errors.length > 0) process.exit(1);
}

main().catch((err) => {
  console.error("check-emerging-threats failed:", (err as Error).message);
  process.exit(1);
});
