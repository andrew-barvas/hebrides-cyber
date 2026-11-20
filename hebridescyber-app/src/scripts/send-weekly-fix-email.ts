// Sends the weekly "one thing to fix" email (src/lib/weeklyFixEmail.ts),
// run by .github/workflows/weekly-fix-email.yml as a plain script, like
// send-monthly-digest.ts.
//
// Run locally with:
//   SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... RESEND_API_KEY=... npx tsx src/scripts/send-weekly-fix-email.ts
import { createScriptSupabase } from "../lib/scriptSupabase";
import { sendWeeklyFixEmails } from "../lib/weeklyFixEmail";

async function main() {
  const { sent, skipped, errors } = await sendWeeklyFixEmails(createScriptSupabase());
  console.log(`Weekly fix email: sent ${sent}, skipped ${skipped}, ${errors.length} error(s).`);
  for (const err of errors) console.error(`  - ${err}`);
  if (errors.length > 0) process.exit(1);
}

main().catch((err) => {
  console.error("send-weekly-fix-email failed:", err);
  process.exit(1);
});
