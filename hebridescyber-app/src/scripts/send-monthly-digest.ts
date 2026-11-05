// Sends the monthly Security Score digest (src/lib/monthlyDigest.ts's
// sendMonthlyDigest) directly against Supabase, run by
// .github/workflows/monthly-digest.yml as a plain script. See
// src/scripts/generate-daily-blog.ts's header and docs/ENHANCEMENTS.md E-11
// for why this moved off the former POST /api/send-monthly-digest route —
// same execution-ceiling failure mode already fixed twice elsewhere, applied
// here a third time.
//
// Run locally with:
//   SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... npx tsx src/scripts/send-monthly-digest.ts

import { createScriptSupabase } from "../lib/scriptSupabase";
import { sendMonthlyDigest } from "../lib/monthlyDigest";

async function main() {
  const supabaseAdmin = createScriptSupabase();

  const { sent, skipped, errors } = await sendMonthlyDigest(supabaseAdmin);

  console.log(`Monthly digest: sent ${sent}, skipped ${skipped}, ${errors.length} error(s).`);
  for (const err of errors) console.error(`  - ${err}`);

  if (errors.length > 0) process.exit(1);
}

main().catch((err) => {
  console.error("send-monthly-digest failed:", err);
  process.exit(1);
});
