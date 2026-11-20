// One-off (and safe to repeat) email to owners whose connected repositories
// aren't linked to a site (src/lib/repoLinkReminder.ts). Each connection is
// reminded once. Run by .github/workflows/repo-link-reminders.yml.
//
//   npx tsx src/scripts/send-repo-link-reminders.ts [--dry-run]
import { createScriptSupabase } from "../lib/scriptSupabase";
import { sendRepoLinkReminders } from "../lib/repoLinkReminder";

async function main() {
  const dryRun = process.argv.includes("--dry-run");
  const { sent, skipped, errors } = await sendRepoLinkReminders(createScriptSupabase(), { dryRun });
  console.log(`Repo link reminders${dryRun ? " (dry run)" : ""}: sent ${sent}, skipped ${skipped}, ${errors.length} error(s).`);
  for (const err of errors) console.error(`  - ${err}`);
  if (errors.length > 0) process.exit(1);
}

main().catch((err) => {
  console.error("send-repo-link-reminders failed:", err);
  process.exit(1);
});
