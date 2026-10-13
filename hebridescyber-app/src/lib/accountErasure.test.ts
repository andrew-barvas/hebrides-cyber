import { describe, it, expect, vi } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import {
  deadlineWording,
  eraseAccount,
  findAccount,
  planErasure,
  recordDeletionRequest,
  runDeletionReminder,
  selectRequestsToRemind,
  summarizeDeletionQueue,
  type DeletionRequestRow,
  type ErasurePlan,
} from "./accountErasure";

type Reply = { data?: unknown; error?: { code?: string; message: string } | null };
type Call = { table: string; op: string; args: unknown[] };

/** A Supabase stand-in: each table answers from its own queue, every call is recorded. */
function fakeDb(queues: Record<string, Reply[]>, deleteUserError: { message: string } | null = null) {
  const calls: Call[] = [];
  const order: string[] = [];
  const deleteUser = vi.fn(async (id: string) => {
    order.push(`deleteUser:${id}`);
    return { error: deleteUserError };
  });
  const from = (table: string) => {
    const reply = () => {
      const r = queues[table]?.shift() ?? {};
      return Promise.resolve({ data: r.data ?? null, error: r.error ?? null });
    };
    const builder: Record<string, unknown> = {};
    for (const op of ["select", "eq", "lte", "in", "insert", "update"]) {
      builder[op] = (...args: unknown[]) => {
        calls.push({ table, op, args });
        if (op === "update" || op === "insert") order.push(`${op}:${table}`);
        return builder;
      };
    }
    builder.maybeSingle = reply;
    builder.single = reply;
    builder.then = (resolve: (v: unknown) => void, reject: (e: unknown) => void) => reply().then(resolve, reject);
    return builder;
  };
  const db = { from, auth: { admin: { deleteUser } } } as unknown as SupabaseClient;
  return { db, calls, order, deleteUser };
}

const NOW = new Date("2026-10-20T12:00:00Z");
const row = (id: string, due: string, extra: Partial<DeletionRequestRow> = {}): DeletionRequestRow => ({
  id, owner: `owner-${id}`, status: "pending", requested_at: "2026-10-01T00:00:00Z", due_at: due, reminded_at: null, ...extra,
});

describe("selectRequestsToRemind", () => {
  it("picks pending requests due within 7 days or overdue, overdue first, soonest first", () => {
    const { overdue, dueSoon } = selectRequestsToRemind([
      row("later", "2026-11-10T00:00:00Z"),
      row("soon", "2026-10-25T00:00:00Z"),
      row("edge", "2026-10-27T12:00:00Z"),
      row("late2", "2026-10-19T00:00:00Z"),
      row("late1", "2026-10-10T00:00:00Z"),
      row("done", "2026-10-10T00:00:00Z", { status: "completed" }),
    ], NOW);
    expect(overdue.map((r) => r.id)).toEqual(["late1", "late2"]);
    expect(dueSoon.map((r) => r.id)).toEqual(["soon", "edge"]);
  });

  it("doesn't repeat a reminder within the same day, but does the next", () => {
    const remindedRecently = row("a", "2026-10-22T00:00:00Z", { reminded_at: "2026-10-20T06:00:00Z" });
    const remindedYesterday = row("b", "2026-10-22T00:00:00Z", { reminded_at: "2026-10-19T06:47:00Z" });
    const { dueSoon } = selectRequestsToRemind([remindedRecently, remindedYesterday], NOW);
    expect(dueSoon.map((r) => r.id)).toEqual(["b"]);
  });

  it("words the deadline in whole days, never rounding up", () => {
    expect(deadlineWording("2026-10-25T00:00:00Z", NOW)).toBe("due in 4 days");
    expect(deadlineWording("2026-10-21T13:00:00Z", NOW)).toBe("due in 1 day");
    expect(deadlineWording("2026-10-20T20:00:00Z", NOW)).toBe("due today");
    expect(deadlineWording("2026-10-20T06:00:00Z", NOW)).toBe("1 day overdue");
    expect(deadlineWording("2026-10-15T00:00:00Z", NOW)).toBe("5 days overdue");
  });
});

describe("recordDeletionRequest", () => {
  it("returns the pending request instead of starting a new clock", async () => {
    const { db, calls } = fakeDb({ deletion_requests: [{ data: { requested_at: "r", due_at: "d" } }] });
    expect(await recordDeletionRequest(db, "o")).toEqual({ requestedAt: "r", dueAt: "d", alreadyPending: true });
    expect(calls.some((c) => c.op === "insert")).toBe(false);
  });

  it("inserts a new request when none is pending", async () => {
    const { db, calls } = fakeDb({ deletion_requests: [{}, { data: { requested_at: "r", due_at: "d" } }] });
    expect(await recordDeletionRequest(db, "o")).toEqual({ requestedAt: "r", dueAt: "d", alreadyPending: false });
    expect(calls.find((c) => c.op === "insert")?.args[0]).toEqual({ owner: "o" });
  });

  it("settles a double click on the request that won", async () => {
    const { db } = fakeDb({ deletion_requests: [{}, { error: { code: "23505", message: "duplicate" } }, { data: { requested_at: "r", due_at: "d" } }] });
    expect(await recordDeletionRequest(db, "o")).toEqual({ requestedAt: "r", dueAt: "d", alreadyPending: true });
  });

  it("is null before migration 048 and throws on any other failure", async () => {
    expect(await recordDeletionRequest(fakeDb({ deletion_requests: [{ error: { code: "42P01", message: "missing" } }] }).db, "o")).toBeNull();
    await expect(recordDeletionRequest(fakeDb({ deletion_requests: [{ error: { code: "08006", message: "down" } }] }).db, "o")).rejects.toThrow("down");
    await expect(recordDeletionRequest(fakeDb({ deletion_requests: [{}, { error: { code: "23514", message: "check" } }] }).db, "o")).rejects.toThrow("check");
    await expect(recordDeletionRequest(fakeDb({ deletion_requests: [{}, {}] }).db, "o")).rejects.toThrow("not recorded");
  });
});

describe("findAccount", () => {
  it("looks a user id up by id and anything else by exact lower-cased email", async () => {
    const id = "33333333-3333-4333-8333-333333333333";
    const byId = fakeDb({ users: [{ data: { id, email: "jo@example.com", full_name: "Jo" } }] });
    expect(await findAccount(byId.db, ` ${id.toUpperCase()} `)).toEqual({ id, email: "jo@example.com", fullName: "Jo" });
    expect(byId.calls.find((c) => c.op === "eq")?.args).toEqual(["id", id]);

    const byEmail = fakeDb({ users: [{ data: { id, email: null, full_name: null } }] });
    expect(await findAccount(byEmail.db, "Jo@Example.com")).toEqual({ id, email: null, fullName: null });
    expect(byEmail.calls.find((c) => c.op === "eq")?.args).toEqual(["email", "jo@example.com"]);
  });

  it("is null for no match and throws on a lookup error", async () => {
    expect(await findAccount(fakeDb({ users: [{}] }).db, "nobody@example.com")).toBeNull();
    await expect(findAccount(fakeDb({ users: [{ error: { message: "down" } }] }).db, "x@example.com")).rejects.toThrow("down");
  });
});

const ACCOUNT = { id: "u1", email: "jo@example.com", fullName: null };

describe("planErasure", () => {
  it("lists scans, the subscription to cancel and the pending request", async () => {
    const { db } = fakeDb({
      subscriptions: [{ data: { plan: "pro", status: "past_due", stripe_subscription_id: "sub_1" } }],
      scans: [{ data: [{ id: "s1" }, { id: "s2" }] }],
      deletion_requests: [{ data: { requested_at: "r", due_at: "d" } }],
    });
    expect(await planErasure(db, ACCOUNT)).toEqual({
      account: ACCOUNT,
      scanIds: ["s1", "s2"],
      subscription: { plan: "pro", status: "past_due", stripeSubscriptionId: "sub_1" },
      stripeToCancel: "sub_1",
      pendingRequest: { requestedAt: "r", dueAt: "d" },
    });
  });

  it("has nothing to cancel for a cancelled or Stripe-less subscription, and tolerates no ledger", async () => {
    const cancelled = fakeDb({ subscriptions: [{ data: { plan: "pro", status: "cancelled", stripe_subscription_id: "sub_1" } }], scans: [{ data: [] }], deletion_requests: [{ error: { code: "PGRST205", message: "missing" } }] });
    expect(await planErasure(cancelled.db, ACCOUNT)).toMatchObject({ stripeToCancel: null, pendingRequest: null });
    const none = fakeDb({ subscriptions: [{}], scans: [{}], deletion_requests: [{}] });
    expect(await planErasure(none.db, ACCOUNT)).toMatchObject({ subscription: null, stripeToCancel: null, scanIds: [] });
  });

  it("throws rather than plan an erasure from a partial read", async () => {
    await expect(planErasure(fakeDb({ subscriptions: [{ error: { message: "sub down" } }], scans: [{}], deletion_requests: [{}] }).db, ACCOUNT)).rejects.toThrow("sub down");
    await expect(planErasure(fakeDb({ subscriptions: [{}], scans: [{ error: { message: "scans down" } }], deletion_requests: [{}] }).db, ACCOUNT)).rejects.toThrow("scans down");
    await expect(planErasure(fakeDb({ subscriptions: [{}], scans: [{}], deletion_requests: [{ error: { code: "08006", message: "ledger down" } }] }).db, ACCOUNT)).rejects.toThrow("ledger down");
  });
});

describe("eraseAccount", () => {
  const plan: ErasurePlan = { account: ACCOUNT, scanIds: ["s1"], subscription: null, stripeToCancel: "sub_1", pendingRequest: null };

  it("cancels billing, deletes reports, deletes the user, then marks the request completed — in that order", async () => {
    const { db, order, calls } = fakeDb({ deletion_requests: [{}] });
    const cancel = vi.fn(async () => {
      order.push("cancelStripe");
    });
    const blobs = vi.fn(async () => {
      order.push("deleteBlobs");
      return { deleted: 1, skipped: false };
    });
    const result = await eraseAccount(db, plan, { cancelStripeSubscription: cancel, deleteReportBlobs: blobs, now: NOW });
    expect(order).toEqual(["cancelStripe", "deleteBlobs", "deleteUser:u1", "update:deletion_requests"]);
    expect(cancel).toHaveBeenCalledWith("sub_1");
    expect(blobs).toHaveBeenCalledWith(["s1"]);
    expect(calls.find((c) => c.op === "update")?.args[0]).toEqual({ status: "completed", completed_at: NOW.toISOString() });
    expect(result).toEqual({ stripeCancelled: true, reportsDeleted: 1, reportsSkipped: false, ledgerWarning: null });
  });

  it("deletes nothing if cancelling the subscription fails", async () => {
    const { db, deleteUser } = fakeDb({});
    const blobs = vi.fn(async () => ({ deleted: 0, skipped: false }));
    await expect(eraseAccount(db, plan, { cancelStripeSubscription: async () => Promise.reject(new Error("stripe down")), deleteReportBlobs: blobs })).rejects.toThrow("stripe down");
    expect(blobs).not.toHaveBeenCalled();
    expect(deleteUser).not.toHaveBeenCalled();
  });

  it("leaves billing alone when told to, and doesn't mark the request done if the user wasn't deleted", async () => {
    const kept = fakeDb({ deletion_requests: [{}] });
    expect(await eraseAccount(kept.db, plan, { deleteReportBlobs: async () => ({ deleted: 0, skipped: true }) })).toMatchObject({ stripeCancelled: false, reportsSkipped: true });

    const failing = fakeDb({}, { message: "auth down" });
    await expect(eraseAccount(failing.db, { ...plan, stripeToCancel: null }, { deleteReportBlobs: async () => ({ deleted: 0, skipped: false }) })).rejects.toThrow("auth down");
    expect(failing.order).not.toContain("update:deletion_requests");
  });

  it("warns when the account is gone but the ledger can't be updated; silent before 048", async () => {
    const deps = { deleteReportBlobs: async () => ({ deleted: 0, skipped: false }) };
    const broken = fakeDb({ deletion_requests: [{ error: { code: "08006", message: "ledger down" } }] });
    expect((await eraseAccount(broken.db, { ...plan, stripeToCancel: null }, deps)).ledgerWarning).toContain("ledger down");
    const missing = fakeDb({ deletion_requests: [{ error: { code: "42P01", message: "missing" } }] });
    expect((await eraseAccount(missing.db, { ...plan, stripeToCancel: null }, deps)).ledgerWarning).toBeNull();
  });
});

describe("runDeletionReminder", () => {
  it("emails the operator about due and overdue requests, then stamps exactly those", async () => {
    const rows = [row("late", "2026-10-15T00:00:00Z"), row("soon", "2026-10-23T00:00:00Z"), row("recent", "2026-10-24T00:00:00Z", { reminded_at: "2026-10-20T08:00:00Z" })];
    const { db, calls } = fakeDb({ deletion_requests: [{ data: rows }, {}] });
    const send = vi.fn(async () => ({ ok: true }));
    expect(await runDeletionReminder(db, send, NOW)).toEqual({ status: "sent", overdue: 1, dueSoon: 1 });

    const [subject, html] = send.mock.calls[0] as unknown as [string, string];
    expect(subject).toMatch(/^OVERDUE: 1 account deletion request past/);
    expect(html).toContain("5 days overdue");
    expect(html).toContain("due in 2 days");
    expect(html).toContain("npm run account:erase -- owner-late --confirm");
    expect(html).not.toContain("owner-recent");
    expect(calls.find((c) => c.op === "lte")?.args).toEqual(["due_at", "2026-10-27T12:00:00.000Z"]);
    expect(calls.find((c) => c.op === "in")?.args).toEqual(["id", ["late", "soon"]]);
  });

  it("words a due-soon-only reminder without alarm", async () => {
    const send = vi.fn<(subject: string, html: string) => Promise<{ ok: boolean }>>(async () => ({ ok: true }));
    await runDeletionReminder(fakeDb({ deletion_requests: [{ data: [row("a", "2026-10-21T13:00:00Z")] }, {}] }).db, send, NOW);
    expect(send.mock.calls[0][0]).toBe("1 account deletion request due within 7 days");
    expect(send.mock.calls[0][1]).toContain("due in 1 day ");
  });

  it("stamps nothing when the email fails, so tomorrow retries", async () => {
    const { db, calls } = fakeDb({ deletion_requests: [{ data: [row("a", "2026-10-15T00:00:00Z")] }] });
    expect(await runDeletionReminder(db, async () => ({ ok: false, error: "smtp" }), NOW)).toEqual({ status: "send_failed", error: "smtp" });
    expect(calls.some((c) => c.op === "update")).toBe(false);
    expect(await runDeletionReminder(fakeDb({ deletion_requests: [{ data: [row("a", "2026-10-15T00:00:00Z")] }] }).db, async () => ({ ok: false }), NOW)).toEqual({ status: "send_failed", error: "unknown error" });
  });

  it("reports nothing due, no ledger yet, and throws on read or stamp failures", async () => {
    const send = vi.fn(async () => ({ ok: true }));
    expect(await runDeletionReminder(fakeDb({ deletion_requests: [{ data: [] }] }).db, send, NOW)).toEqual({ status: "nothing_due" });
    expect(await runDeletionReminder(fakeDb({ deletion_requests: [{ error: { code: "PGRST205", message: "missing" } }] }).db, send, NOW)).toEqual({ status: "unavailable" });
    await expect(runDeletionReminder(fakeDb({ deletion_requests: [{ error: { code: "08006", message: "down" } }] }).db, send, NOW)).rejects.toThrow("down");
    await expect(runDeletionReminder(fakeDb({ deletion_requests: [{ data: [row("a", "2026-10-15T00:00:00Z")] }, { error: { message: "stamp failed" } }] }).db, send, NOW)).rejects.toThrow("stamp failed");
    expect(send).toHaveBeenCalledTimes(1);
  });
});

describe("summarizeDeletionQueue", () => {
  const now = new Date("2026-06-15T12:00:00Z");
  const row = (over: Partial<DeletionRequestRow>): DeletionRequestRow => ({
    id: "r", owner: "o", status: "pending", requested_at: "2026-06-01T00:00:00Z",
    due_at: "2026-07-01T00:00:00Z", reminded_at: null, ...over,
  });

  it("returns only pending rows, soonest deadline first, with overdue flags and wording", () => {
    const { overdueCount, pending } = summarizeDeletionQueue(
      [
        row({ id: "future", due_at: "2026-06-20T00:00:00Z" }),
        row({ id: "overdue", due_at: "2026-06-10T00:00:00Z" }),
        row({ id: "done", status: "completed", due_at: "2026-06-05T00:00:00Z" }),
        row({ id: "gone", status: "withdrawn", due_at: "2026-06-01T00:00:00Z" }),
      ],
      now
    );
    expect(pending.map((p) => p.id)).toEqual(["overdue", "future"]);
    expect(pending[0]).toMatchObject({ overdue: true, wording: "5 days overdue" });
    expect(pending[1]).toMatchObject({ overdue: false, wording: "due in 4 days" });
    expect(overdueCount).toBe(1);
  });

  it("is empty with zero overdue when nothing is pending", () => {
    expect(summarizeDeletionQueue([row({ status: "completed" })], now)).toEqual({ overdueCount: 0, pending: [] });
  });
});
