// Erases one customer's account and all data derived from it — the
// operator-run half of the GDPR erasure commitment (/privacy: actioned within
// 30 days). The customer-facing half, src/pages/api/account/request-deletion.ts,
// records the request in deletion_requests (migration 048) and emails you;
// src/scripts/check-deletion-requests.ts reminds you daily as the deadline
// nears. Nothing is deleted until you run this deliberately.
//
// Defaults to a DRY RUN: looks the account up, reports what would happen,
// and exits without touching anything. Pass --confirm to execute. This is
// irreversible — there is no undo once the auth user is deleted.
//
// What --confirm does, in order (see accountErasure.ts's eraseAccount):
//   1. Cancels the Stripe subscription, if one is still billing, so an
//      erased customer isn't charged again. Refunds stay a decision for the
//      Stripe Dashboard. Pass --keep-stripe-subscription to leave billing
//      untouched (for example when it was already handled by hand).
//   2. Deletes report PDFs from the "reports" Blob Storage container.
//   3. Deletes the auth user; ON DELETE CASCADE removes public.users, scans,
//      scan_results, monitored_targets, subscriptions and every other table
//      keyed to the user.
//   4. Marks the pending deletion request completed.
//
// Run with:
//   SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... [STRIPE_SECRET_KEY=...] [AZURE_STORAGE_CONNECTION_STRING=...] \
//     npm run account:erase -- <email or user id> [--confirm] [--keep-stripe-subscription]

import { createClient } from "@supabase/supabase-js";
import type { WebSocketLikeConstructor } from "@supabase/realtime-js";
import ws from "ws";
import { eraseAccount, findAccount, planErasure } from "../lib/accountErasure";
import { getStripe } from "../lib/stripeClient";

async function main() {
  const args = process.argv.slice(2);
  const target = args.find((a) => !a.startsWith("--"));
  const confirm = args.includes("--confirm");
  const keepStripe = args.includes("--keep-stripe-subscription");

  if (!target) {
    console.error("Usage: npm run account:erase -- <email or user id> [--confirm] [--keep-stripe-subscription]");
    process.exit(1);
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!supabaseUrl || !serviceRoleKey) {
    console.error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required.");
    process.exit(1);
  }

  const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey, {
    realtime: { transport: ws as unknown as WebSocketLikeConstructor },
  });

  const account = await findAccount(supabaseAdmin, target);
  if (!account) {
    console.error(`No user found for ${target}.`);
    process.exit(1);
  }

  const plan = await planErasure(supabaseAdmin, account);
  console.log(`User: ${account.email ?? "(no email)"} (${account.id})`);
  console.log(`Scans to remove: ${plan.scanIds.length}`);
  if (plan.pendingRequest) {
    console.log(`Deletion requested ${plan.pendingRequest.requestedAt}, due by ${plan.pendingRequest.dueAt}.`);
  }
  if (plan.stripeToCancel) {
    if (keepStripe) {
      console.log(`Stripe subscription ${plan.stripeToCancel} (${plan.subscription?.plan}, ${plan.subscription?.status}) will be LEFT RUNNING (--keep-stripe-subscription).`);
    } else {
      console.log(`Stripe subscription ${plan.stripeToCancel} (${plan.subscription?.plan}, ${plan.subscription?.status}) will be cancelled immediately. Decide any refund in the Stripe Dashboard.`);
      if (!process.env.STRIPE_SECRET_KEY) {
        console.error("STRIPE_SECRET_KEY is not set: set it, or pass --keep-stripe-subscription if billing is already dealt with.");
        process.exit(1);
      }
    }
  }

  if (!confirm) {
    console.log("\nDry run only — nothing deleted. Re-run with --confirm to execute.");
    return;
  }

  const result = await eraseAccount(supabaseAdmin, plan, {
    cancelStripeSubscription: keepStripe
      ? undefined
      : async (id) => {
          await getStripe().subscriptions.cancel(id);
        },
    deleteReportBlobs,
  });

  if (result.stripeCancelled) console.log(`Cancelled Stripe subscription ${plan.stripeToCancel}.`);
  console.log(`Deleted ${result.reportsDeleted} report PDF(s)${result.reportsSkipped ? " (Blob Storage not configured — skipped)" : ""}.`);
  console.log(`Deleted auth user ${account.id} — cascading deletes removed all related rows.`);
  if (result.ledgerWarning) {
    console.error(result.ledgerWarning);
    process.exit(1);
  }
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
