// Matches device agent reports to CVEs and end-of-life dates and re-checks
// the Cyber Essentials 14-day rule (src/lib/deviceAgent/matchJob.ts). Run
// hourly by .github/workflows/device-inventory-match.yml.
//
//   npx tsx src/scripts/match-device-inventories.ts [--dry-run] [--limit N]
import { createScriptSupabase } from "../lib/scriptSupabase";
import { runDeviceMatchJob } from "../lib/deviceAgent/matchJob";
import { createCveIndex } from "../lib/cveIndex";
import { objectCveIndexStore } from "../lib/cveIndexObjects";
import { cveIndexObjectStore } from "../lib/objectStore";
import { fetchOsvVulnDetails, queryOsvBatch } from "../lib/scanners/osv";
import { fetchEolProduct } from "../lib/scanners/endOfLife";

async function main() {
  const dryRun = process.argv.includes("--dry-run");
  const limitArg = process.argv.indexOf("--limit");
  const limit = limitArg >= 0 ? Number(process.argv[limitArg + 1]) : undefined;
  const db = createScriptSupabase();

  const result = await runDeviceMatchJob(
    db,
    async () => {
      const now = new Date();
      let cveIndex = null;
      try {
        cveIndex = createCveIndex(objectCveIndexStore(await cveIndexObjectStore(db)), { now });
      } catch (err) {
        console.error("CVE index store unavailable:", (err as Error).message);
      }
      return { cveIndex, queryOsvBatch, fetchOsvVulnDetails: (ids) => fetchOsvVulnDetails(ids), fetchEolProduct, now };
    },
    { dryRun, limit: Number.isInteger(limit) && limit! > 0 ? limit : undefined }
  );

  if (result.status === "unavailable") {
    console.log("Device matching: migration 086 not applied yet, nothing to do.");
    return;
  }
  console.log(`Device matching${dryRun ? " (dry run)" : ""}: matched ${result.matched}, skipped ${result.skipped}, ${result.errors.length} error(s).`);
  for (const err of result.errors) console.error(`  - ${err}`);
  if (result.errors.length > 0) process.exit(1);
}

main().catch((err) => {
  console.error("match-device-inventories failed:", err);
  process.exit(1);
});
