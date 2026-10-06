// Account erasure: the 30-day deadline ledger (deletion_requests, migration
// 048) and the erasure itself. /privacy promises an erasure request is
// actioned within 30 days. Erasure stays a deliberate operator step
// (src/scripts/erase-user-data.ts): an irreversible delete has no place
// behind one unconfirmed POST. What this adds is that the deadline can't be
// forgotten:
//   - POST /api/account/request-deletion records the request here;
//   - a daily job (src/scripts/check-deletion-requests.ts) emails the
//     operator about requests due within REMIND_WITHIN_DAYS or overdue;
//   - eraseAccount() marks the request completed once the account is gone.
// Before migration 048 every read degrades to "no ledger" and the old
// audit-log-plus-email behaviour carries on.
import type { SupabaseClient } from "@supabase/supabase-js";
import { isMissingSchemaError } from "./dbErrors";

export const REMIND_WITHIN_DAYS = 7;
/** The daily job runs every 24 h; a little less tolerates cron start jitter. */
const REMIND_EVERY_MS = 20 * 60 * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;

export type DeletionRequestRow = {
  id: string;
  owner: string;
  status: "pending" | "completed" | "withdrawn";
  requested_at: string;
  due_at: string;
  reminded_at: string | null;
};

export type RecordedRequest = { requestedAt: string; dueAt: string; alreadyPending: boolean };

/**
 * Record an erasure request, or return the one already pending (a repeated
 * click must not restart the 30-day clock). null before migration 048.
 */
export async function recordDeletionRequest(db: SupabaseClient, ownerId: string): Promise<RecordedRequest | null> {
  const pending = async () =>
    db.from("deletion_requests").select("requested_at, due_at").eq("owner", ownerId).eq("status", "pending").maybeSingle();

  const existing = await pending();
  if (existing.error) {
    if (isMissingSchemaError(existing.error)) return null;
    throw new Error(existing.error.message);
  }
  if (existing.data) return { requestedAt: existing.data.requested_at, dueAt: existing.data.due_at, alreadyPending: true };

  const inserted = await db.from("deletion_requests").insert({ owner: ownerId }).select("requested_at, due_at").single();
  if (!inserted.error && inserted.data) return { requestedAt: inserted.data.requested_at, dueAt: inserted.data.due_at, alreadyPending: false };
  // Two clicks at once: the unique pending index lets one through.
  if (inserted.error?.code === "23505") {
    const again = await pending();
    if (again.data) return { requestedAt: again.data.requested_at, dueAt: again.data.due_at, alreadyPending: true };
  }
  throw new Error(inserted.error?.message ?? "the request was not recorded");
}

/** Pure: the pending requests the operator should hear about now, overdue first. */
export function selectRequestsToRemind(rows: DeletionRequestRow[], now: Date): { overdue: DeletionRequestRow[]; dueSoon: DeletionRequestRow[] } {
  const t = now.getTime();
  const remind = rows
    .filter((r) => r.status === "pending")
    .filter((r) => Date.parse(r.due_at) - t <= REMIND_WITHIN_DAYS * DAY_MS)
    .filter((r) => !r.reminded_at || t - Date.parse(r.reminded_at) >= REMIND_EVERY_MS)
    .sort((a, b) => Date.parse(a.due_at) - Date.parse(b.due_at));
  return {
    overdue: remind.filter((r) => Date.parse(r.due_at) < t),
    dueSoon: remind.filter((r) => Date.parse(r.due_at) >= t),
  };
}

/** "5 days overdue", "due today", "due in 2 days": whole days, never rounded up. */
export function deadlineWording(dueAt: string, now: Date): string {
  const days = (Date.parse(dueAt) - now.getTime()) / DAY_MS;
  const n = (k: number) => `${k} day${k === 1 ? "" : "s"}`;
  if (days < 0) return `${n(Math.max(1, Math.floor(-days)))} overdue`;
  return days < 1 ? "due today" : `due in ${n(Math.floor(days))}`;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export type Account = { id: string; email: string | null; fullName: string | null };

/** By user id or by exact (lower-cased) email. Never a pattern match: this feeds an irreversible delete. */
export async function findAccount(db: SupabaseClient, emailOrId: string): Promise<Account | null> {
  const key = emailOrId.trim();
  const query = db.from("users").select("id, email, full_name");
  const { data, error } = await (UUID_RE.test(key) ? query.eq("id", key.toLowerCase()) : query.eq("email", key.toLowerCase())).maybeSingle();
  if (error) throw new Error(error.message);
  return data ? { id: data.id as string, email: (data.email as string | null) ?? null, fullName: (data.full_name as string | null) ?? null } : null;
}

export type ErasurePlan = {
  account: Account;
  scanIds: string[];
  subscription: { plan: string | null; status: string | null; stripeSubscriptionId: string | null } | null;
  /** True when there is a Stripe subscription that is still billing. */
  stripeToCancel: string | null;
  pendingRequest: { requestedAt: string; dueAt: string } | null;
};

export async function planErasure(db: SupabaseClient, account: Account): Promise<ErasurePlan> {
  const [sub, scans, request] = await Promise.all([
    db.from("subscriptions").select("plan, status, stripe_subscription_id").eq("owner", account.id).maybeSingle(),
    db.from("scans").select("id").eq("owner", account.id),
    db.from("deletion_requests").select("requested_at, due_at").eq("owner", account.id).eq("status", "pending").maybeSingle(),
  ]);
  if (sub.error) throw new Error(sub.error.message);
  if (scans.error) throw new Error(scans.error.message);
  if (request.error && !isMissingSchemaError(request.error)) throw new Error(request.error.message);

  const subscription = sub.data
    ? { plan: (sub.data.plan as string | null) ?? null, status: (sub.data.status as string | null) ?? null, stripeSubscriptionId: (sub.data.stripe_subscription_id as string | null) ?? null }
    : null;
  const billing = subscription?.stripeSubscriptionId && subscription.status !== "cancelled" ? subscription.stripeSubscriptionId : null;
  return {
    account,
    scanIds: ((scans.data ?? []) as { id: string }[]).map((s) => s.id),
    subscription,
    stripeToCancel: billing,
    pendingRequest: request.data ? { requestedAt: request.data.requested_at, dueAt: request.data.due_at } : null,
  };
}

export type ErasureDeps = {
  /** Cancels the Stripe subscription now. Omit to leave billing alone (the operator chose --keep-stripe-subscription). */
  cancelStripeSubscription?: (subscriptionId: string) => Promise<void>;
  deleteReportBlobs: (scanIds: string[]) => Promise<{ deleted: number; skipped: boolean }>;
  now?: Date;
};

export type ErasureResult = {
  stripeCancelled: boolean;
  reportsDeleted: number;
  reportsSkipped: boolean;
  /** Set when the account is gone but the request couldn't be marked completed. */
  ledgerWarning: string | null;
};

/**
 * Irreversible. In order, so a failure part-way leaves something retryable:
 *   1. cancel the Stripe subscription (an erased customer must not go on
 *      being billed); if that fails, nothing else has happened yet;
 *   2. delete report PDFs (the scan rows naming them go with the user);
 *   3. delete the auth user — the schema's ON DELETE CASCADE removes the rest;
 *   4. mark the pending request completed (the ledger has no foreign key,
 *      so the record survives the erasure).
 */
export async function eraseAccount(db: SupabaseClient, plan: ErasurePlan, deps: ErasureDeps): Promise<ErasureResult> {
  let stripeCancelled = false;
  if (plan.stripeToCancel && deps.cancelStripeSubscription) {
    await deps.cancelStripeSubscription(plan.stripeToCancel);
    stripeCancelled = true;
  }

  const blobs = await deps.deleteReportBlobs(plan.scanIds);

  const { error: deleteError } = await db.auth.admin.deleteUser(plan.account.id);
  if (deleteError) throw new Error(`Could not delete auth user ${plan.account.id}: ${deleteError.message}`);

  const completedAt = (deps.now ?? new Date()).toISOString();
  const { error: ledgerError } = await db
    .from("deletion_requests")
    .update({ status: "completed", completed_at: completedAt })
    .eq("owner", plan.account.id)
    .eq("status", "pending");
  const ledgerWarning = ledgerError && !isMissingSchemaError(ledgerError) ? `The account was erased, but its deletion request could not be marked completed: ${ledgerError.message}` : null;

  return { stripeCancelled, reportsDeleted: blobs.deleted, reportsSkipped: blobs.skipped, ledgerWarning };
}

export type ReminderOutcome =
  | { status: "unavailable" } // before migration 048
  | { status: "nothing_due" }
  | { status: "sent"; overdue: number; dueSoon: number }
  | { status: "send_failed"; error: string };

/**
 * The daily check: email the operator about pending requests due within
 * REMIND_WITHIN_DAYS or already overdue, then stamp reminded_at on exactly
 * those rows. A failed send stamps nothing, so tomorrow's run tries again.
 */
export async function runDeletionReminder(
  db: SupabaseClient,
  send: (subject: string, html: string) => Promise<{ ok: boolean; error?: string }>,
  now: Date = new Date()
): Promise<ReminderOutcome> {
  const horizon = new Date(now.getTime() + REMIND_WITHIN_DAYS * DAY_MS).toISOString();
  const { data, error } = await db
    .from("deletion_requests")
    .select("id, owner, status, requested_at, due_at, reminded_at")
    .eq("status", "pending")
    .lte("due_at", horizon);
  if (error) {
    if (isMissingSchemaError(error)) return { status: "unavailable" };
    throw new Error(error.message);
  }

  const { overdue, dueSoon } = selectRequestsToRemind((data ?? []) as DeletionRequestRow[], now);
  if (overdue.length + dueSoon.length === 0) return { status: "nothing_due" };

  const line = (r: DeletionRequestRow) => {
    const wording = deadlineWording(r.due_at, now);
    const when = Date.parse(r.due_at) < now.getTime() ? `<strong>${wording}</strong>` : wording;
    return `<li><code>${r.owner}</code>: requested ${r.requested_at.slice(0, 10)}, ${when} (${r.due_at.slice(0, 10)})<br>` +
      `<code>npm run account:erase -- ${r.owner} --confirm</code></li>`;
  };
  const subject = overdue.length
    ? `OVERDUE: ${overdue.length} account deletion request${overdue.length === 1 ? "" : "s"} past the 30-day deadline`
    : `${dueSoon.length} account deletion request${dueSoon.length === 1 ? "" : "s"} due within ${REMIND_WITHIN_DAYS} days`;
  const html = [
    "<p>/privacy promises erasure within 30 days of a request. These are still pending:</p>",
    `<ul>${[...overdue, ...dueSoon].map(line).join("")}</ul>`,
    "<p>Run the command without <code>--confirm</code> first to see what will be deleted.</p>",
  ].join("");

  const result = await send(subject, html);
  if (!result.ok) return { status: "send_failed", error: result.error ?? "unknown error" };

  const ids = [...overdue, ...dueSoon].map((r) => r.id);
  const { error: stampError } = await db.from("deletion_requests").update({ reminded_at: now.toISOString() }).in("id", ids);
  if (stampError) throw new Error(stampError.message);
  return { status: "sent", overdue: overdue.length, dueSoon: dueSoon.length };
}
