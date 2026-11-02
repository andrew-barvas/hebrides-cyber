// Sends due scheduled reports to their configured recipients.
// Run by .github/workflows/scheduled-reports.yml as a cron job.
// Same direct-Supabase pattern as send-monthly-digest.ts — no HTTP hop.
//
// `--pdf-due-check` only reports whether this hour's run will render a PDF
// (step output `pdf_due`), so the workflow installs Chromium only then.
//
// Run locally with:
//   SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... npx tsx src/scripts/send-scheduled-reports.ts

import { appendFileSync } from "node:fs";
import { createClient } from "@supabase/supabase-js";
import type { WebSocketLikeConstructor } from "@supabase/realtime-js";
import ws from "ws";
import {
  isReportDue,
  pdfReportDue,
  runDueReport,
  type PlanCheck,
  type ScheduledReport,
} from "../lib/scheduledReports";
import { sendEmail } from "../lib/email";
import { planGate } from "../lib/planAccess";
import { htmlToPdf } from "../lib/reportPdf";

function writeStepOutput(name: string, value: string) {
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`);
  console.log(`${name}=${value}`);
}

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

  const { data: reports, error: fetchErr } = await supabaseAdmin
    .from("scheduled_reports")
    .select("*")
    .eq("enabled", true);

  if (process.argv.includes("--pdf-due-check")) {
    // Fail open: on a failed read, install the browser and let the send step report the error.
    if (fetchErr) console.warn("Could not read scheduled reports for the PDF check:", fetchErr.message);
    writeStepOutput("pdf_due", String(fetchErr ? true : pdfReportDue((reports ?? []) as ScheduledReport[], new Date())));
    return;
  }

  if (fetchErr) {
    console.error("Failed to fetch scheduled reports:", fetchErr.message);
    process.exit(1);
  }

  const allReports = (reports ?? []) as ScheduledReport[];
  const now = new Date();
  const due = allReports.filter((r) => isReportDue(r.next_due, now));

  console.log(`Scheduled reports: ${allReports.length} total, ${due.length} due.`);

  let sent = 0;
  let skipped = 0;
  let lapsed = 0;
  const errors: string[] = [];
  const pdfFallbacks: string[] = [];

  // One plan lookup per owner per run, however many reports they have.
  const plans = new Map<string, Promise<PlanCheck>>();
  const planCheck = (ownerId: string) => {
    if (!plans.has(ownerId)) plans.set(ownerId, planGate(supabaseAdmin, ownerId, "basic"));
    return plans.get(ownerId)!;
  };
  const siteUrl = process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk";

  for (const report of due) {
    try {
      const outcome = await runDueReport(supabaseAdmin, report, { siteUrl, renderPdf: htmlToPdf, send: sendEmail, planCheck });
      switch (outcome.kind) {
        case "not_entitled":
          lapsed++;
          break;
        case "no_sites":
          skipped++;
          break;
        case "undelivered":
          // Not marked sent: the next run retries. Without this a missing
          // RESEND_API_KEY would mark every report sent while mailing none.
          errors.push(`Report ${report.id}: not delivered to anyone, will retry (${outcome.failed.map((f) => `${f.recipient}: ${f.error}`).join("; ")})`);
          break;
        case "sent":
          sent++;
          for (const f of outcome.failed) errors.push(`Report ${report.id}: not delivered to ${f.recipient} (${f.error})`);
          if (outcome.pdfError) pdfFallbacks.push(`Report ${report.id}: PDF could not be generated, sent as CSV instead (${outcome.pdfError})`);
          break;
      }
    } catch (err) {
      errors.push(`Report ${report.id}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  console.log(
    `Scheduled reports: sent ${sent}, skipped ${skipped} (no sites), ${lapsed} skipped (no active paid plan), ${errors.length} error(s), ${pdfFallbacks.length} PDF(s) sent as CSV.`,
  );
  for (const err of errors) console.error(`  - ${err}`);
  for (const fallback of pdfFallbacks) console.error(`  - ${fallback}`);

  // A PDF that fell back to CSV was still delivered, and its email says so, but
  // the run fails so a broken Chromium install is noticed rather than lasting.
  if (errors.length > 0 || pdfFallbacks.length > 0) process.exit(1);
}

main().catch((err) => {
  console.error("send-scheduled-reports failed:", err);
  process.exit(1);
});
