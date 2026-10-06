// Daily reminder for account deletion requests nearing the 30-day deadline
// /privacy promises. Run by .github/workflows/deletion-requests.yml; the logic
// is in src/lib/accountErasure.ts (runDeletionReminder).
//
// Exits 1 when a reminder was due but couldn't be sent, so the failed run is
// visible in GitHub Actions instead of the deadline passing silently.
//
// Run with:
//   SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... RESEND_API_KEY=... [CONTACT_EMAIL=...] npm run account:deletion-reminders

import { createClient } from "@supabase/supabase-js";
import type { WebSocketLikeConstructor } from "@supabase/realtime-js";
import ws from "ws";
import { runDeletionReminder } from "../lib/accountErasure";
import { sendEmail } from "../lib/email";

async function main() {
  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!supabaseUrl || !serviceRoleKey) {
    console.error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required.");
    process.exit(1);
  }
  const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey, {
    realtime: { transport: ws as unknown as WebSocketLikeConstructor },
  });
  const to = process.env.CONTACT_EMAIL || "hello@hebridescyber.co.uk";

  const outcome = await runDeletionReminder(supabaseAdmin, (subject, html) => sendEmail({ to, subject, html }));
  switch (outcome.status) {
    case "unavailable":
      console.log("deletion_requests doesn't exist yet (migration 048 not applied) — nothing to check.");
      return;
    case "nothing_due":
      console.log("No deletion requests due within the reminder window.");
      return;
    case "sent":
      console.log(`Reminder sent to ${to}: ${outcome.overdue} overdue, ${outcome.dueSoon} due soon.`);
      return;
    case "send_failed":
      console.error(`Deletion requests are due but the reminder could not be sent: ${outcome.error}`);
      process.exit(1);
  }
}

main().catch((err) => {
  console.error("check-deletion-requests failed:", err);
  process.exit(1);
});
