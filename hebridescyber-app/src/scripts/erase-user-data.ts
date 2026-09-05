// Erases one customer's account and all data derived from it — the
// admin-run half of E-10's GDPR erasure commitment (docs/ENHANCEMENTS.md,
// /privacy §7's 30-day response promise). The customer-facing half,
// src/pages/api/account/request-deletion.ts, only records the request and
// emails you — nothing is deleted until you run this script deliberately.
//
// Defaults to a DRY RUN: looks the account up, reports what would be
// deleted, and exits without touching anything. Pass --confirm to actually
// execute. This is irreversible — there is no undo once the auth user is
// deleted.
//
// Deletes, in this order:
//   1. Report PDFs in the "reports" Blob Storage container for every scan
//      this user owns. Must happen BEFORE step 2 — once the auth user row
//      is gone, the scan rows that name which blobs belong to them are gone
//      too (sql/migrations/001_init.sql's `on delete cascade`).
//   2. The auth.users row, via the Supabase Admin API. The cascade chain
//      already defined in the schema then removes, automatically:
//      public.users, scans (and scan_results via scans' own cascade),
//      monitored_targets, subscriptions, and every other table keyed to
//      auth.users(id) with `on delete cascade`.
//
// Does NOT touch Stripe. An active subscription is flagged as a warning,
// not cancelled — deleting billing state is a distinct, financially
// consequential action left to a human decision in the Stripe Dashboard.
//
// Run with:
//   SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... [AZURE_STORAGE_CONNECTION_STRING=...] \
//     npx tsx src/scripts/erase-user-data.ts <email> [--confirm]

import { createClient } from "@supabase/supabase-js";
import type { WebSocketLikeConstructor } from "@supabase/realtime-js";
import ws from "ws";

async function main() {
  const [, , emailArg, ...rest] = process.argv;
  const confirm = rest.includes("--confirm");

  if (!emailArg) {
    console.error("Usage: npx tsx src/scripts/erase-user-data.ts <email> [--confirm]");
    process.exit(1);
  }
  const email = emailArg.trim().toLowerCase();

  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!supabaseUrl || !serviceRoleKey) {
    console.error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required.");
    process.exit(1);
  }

  const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey, {
    realtime: { transport: ws as unknown as WebSocketLikeConstructor },
  });

  const { data: user, error: userError } = await supabaseAdmin
    .from("users")
    .select("id, email, full_name")
    .eq("email", email)
    .maybeSingle();

  if (userError) {
    console.error(`Failed to look up ${email}:`, userError.message);
    process.exit(1);
  }
  if (!user) {
    console.error(`No user found with email ${email}.`);
    process.exit(1);
  }

  const { data: subscription } = await supabaseAdmin
    .from("subscriptions")
    .select("plan, status, stripe_subscription_id")
    .eq("owner", user.id)
    .maybeSingle();

  const { data: scans } = await supabaseAdmin.from("scans").select("id").eq("owner", user.id);
  const scanIds: string[] = (scans ?? []).map((s) => s.id as string);

  console.log(`User: ${user.email} (${user.id})`);
  console.log(`Scans to remove: ${scanIds.length}`);
  if (subscription?.status === "active") {
    console.log(
      `WARNING: subscription is ACTIVE (${subscription.plan}, stripe_subscription_id=${
        subscription.stripe_subscription_id ?? "none on file"
      }) — cancel it in Stripe yourself; this script does not touch billing.`
    );
  }

  if (!confirm) {
    console.log("\nDry run only — nothing deleted. Re-run with --confirm to execute.");
    return;
  }

  const blobResult = await deleteReportBlobs(scanIds);
  console.log(
    `Deleted ${blobResult.deleted} report PDF(s)${blobResult.skipped ? " (Blob Storage not configured — skipped)" : ""}.`
  );

  const { error: deleteError } = await supabaseAdmin.auth.admin.deleteUser(user.id);
  if (deleteError) {
    console.error(`Failed to delete auth user ${user.id}:`, deleteError.message);
    process.exit(1);
  }

  console.log(`Deleted auth user ${user.id} — cascading deletes removed all related rows.`);
}

async function deleteReportBlobs(scanIds: string[]): Promise<{ deleted: number; skipped: boolean }> {
  const connectionString = process.env.AZURE_STORAGE_CONNECTION_STRING;
  if (!connectionString || scanIds.length === 0) return { deleted: 0, skipped: !connectionString };

  const { BlobServiceClient } = await import("@azure/storage-blob");
  const blobService = BlobServiceClient.fromConnectionString(connectionString);
  const container = blobService.getContainerClient("reports");
  if (!(await container.exists())) return { deleted: 0, skipped: false };

  let deleted = 0;
  for (const scanId of scanIds) {
    const blob = container.getBlockBlobClient(`report-${scanId}.pdf`);
    if (await blob.exists()) {
      await blob.delete();
      deleted += 1;
    }
  }
  return { deleted, skipped: false };
}

main().catch((err) => {
  console.error("erase-user-data failed:", err);
  process.exit(1);
});
