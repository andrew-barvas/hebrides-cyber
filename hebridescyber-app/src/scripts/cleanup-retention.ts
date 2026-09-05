// Scheduled data-retention cleanup (docs/ENHANCEMENTS.md E-10) — deletes
// data past the windows already published on /privacy: scan results (12
// months), report PDFs in Blob Storage (90 days), contact enquiries (12
// months). Confirmed against docs/security.md's own caveat that these
// figures were "never verified against any actual legal or business
// requirement" before being approved for automation.
//
// Run by .github/workflows/data-retention-cleanup.yml directly against
// Supabase, matching src/scripts/generate-weekly-newsletter.ts's pattern
// rather than an HTTP route — same execution-ceiling risk already fixed
// twice for daily-blog/weekly-newsletter (E-11 applies the same fix a third
// time, to the monthly digest).
//
// This job does NOT delete `scans` rows or touch account/subscription
// data — only the heavier payloads (`scan_results`, PDFs, enquiries) that
// /privacy actually promises a retention window for. Deleting a whole
// customer account is a separate, human-confirmed action — see
// src/scripts/erase-user-data.ts.
//
// Run locally with:
//   SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... [AZURE_STORAGE_CONNECTION_STRING=...] \
//     npx tsx src/scripts/cleanup-retention.ts

import { createClient } from "@supabase/supabase-js";
import type { WebSocketLikeConstructor } from "@supabase/realtime-js";
import ws from "ws";

export const SCAN_RESULTS_RETENTION_DAYS = 365;
export const CONTACT_ENQUIRIES_RETENTION_DAYS = 365;
export const REPORT_PDF_RETENTION_DAYS = 90;

function cutoffIso(days: number): string {
  return new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
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

  let hadError = false;

  const { data: deletedResults, error: resultsError } = await supabaseAdmin
    .from("scan_results")
    .delete()
    .lt("created_at", cutoffIso(SCAN_RESULTS_RETENTION_DAYS))
    .select("id");
  if (resultsError) {
    console.error("[retention] scan_results cleanup failed:", resultsError.message);
    hadError = true;
  } else {
    console.log(
      `[retention] deleted ${deletedResults?.length ?? 0} scan_results row(s) older than ${SCAN_RESULTS_RETENTION_DAYS} days.`
    );
  }

  const { data: deletedEnquiries, error: enquiriesError } = await supabaseAdmin
    .from("contact_enquiries")
    .delete()
    .lt("created_at", cutoffIso(CONTACT_ENQUIRIES_RETENTION_DAYS))
    .select("id");
  if (enquiriesError) {
    console.error("[retention] contact_enquiries cleanup failed:", enquiriesError.message);
    hadError = true;
  } else {
    console.log(
      `[retention] deleted ${deletedEnquiries?.length ?? 0} contact_enquiries row(s) older than ${CONTACT_ENQUIRIES_RETENTION_DAYS} days.`
    );
  }

  const blobResult = await cleanupOldReportBlobs(REPORT_PDF_RETENTION_DAYS);
  if (!blobResult.ok) hadError = true;

  if (hadError) process.exit(1);
}

/**
 * Deletes report PDFs in the "reports" Blob Storage container older than
 * `retentionDays`, using each blob's own createdOn/lastModified timestamp —
 * no DB join needed since generate-report.ts names blobs `report-{scanId}.pdf`
 * with no separate metadata table. Resolves { ok: true, deleted: 0 } rather
 * than failing when Blob Storage isn't configured or the container doesn't
 * exist yet, matching this codebase's convention of degrading gracefully on
 * an unset optional integration.
 */
export async function cleanupOldReportBlobs(retentionDays: number): Promise<{ ok: boolean; deleted: number }> {
  const connectionString = process.env.AZURE_STORAGE_CONNECTION_STRING;
  if (!connectionString) {
    console.log("[retention] AZURE_STORAGE_CONNECTION_STRING not set — skipping PDF report cleanup.");
    return { ok: true, deleted: 0 };
  }

  try {
    const { BlobServiceClient } = await import("@azure/storage-blob");
    const blobService = BlobServiceClient.fromConnectionString(connectionString);
    const container = blobService.getContainerClient("reports");

    if (!(await container.exists())) {
      console.log('[retention] "reports" container does not exist yet — nothing to clean up.');
      return { ok: true, deleted: 0 };
    }

    const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
    let deleted = 0;

    for await (const blob of container.listBlobsFlat()) {
      const createdOn = blob.properties.createdOn ?? blob.properties.lastModified;
      if (createdOn && createdOn.getTime() < cutoff) {
        await container.deleteBlob(blob.name);
        deleted += 1;
      }
    }

    console.log(`[retention] deleted ${deleted} report PDF(s) older than ${retentionDays} days.`);
    return { ok: true, deleted };
  } catch (err) {
    console.error("[retention] PDF report cleanup failed:", (err as Error).message);
    return { ok: false, deleted: 0 };
  }
}

main().catch((err) => {
  console.error("cleanup-retention failed:", err);
  process.exit(1);
});
