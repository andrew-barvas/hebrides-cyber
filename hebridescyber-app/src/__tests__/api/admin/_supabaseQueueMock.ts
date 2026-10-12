// Shared call-order-consumed Supabase query-builder mock for admin route
// tests. Not a vi.mock() factory itself (those must stay in each test file
// for Vitest's hoisting to work) — just the reusable chain-building logic
// each file's factory delegates to.
//
// Each table has its own queue; every .from(table) call consumes the next
// entry off that table's queue, in call order. Every chain method both
// returns the builder (so further chaining works) and resolves via .then
// (so a call awaited without a .single()/.maybeSingle() terminal — e.g. a
// bare `.update().eq()` — still resolves to that queue entry).
export type QueueMap = Record<string, unknown[]>;

export function makeAdminSupabaseMock() {
  let queues: QueueMap = {};
  let rpcQueues: QueueMap = {};
  const inserted: Array<{ table: string; payload: unknown }> = [];
  const updated: Array<{ table: string; payload: unknown }> = [];
  const deleted: Array<{ table: string }> = [];
  const upserted: Array<{ table: string; payload: unknown; opts?: unknown }> = [];

  function makeBuilder(table: string) {
    const next = () => Promise.resolve(queues[table]?.shift() ?? { data: null, error: null });
    const builder: Record<string, unknown> = {
      select: () => builder,
      eq: () => builder,
      gte: () => builder,
      in: () => builder,
      or: () => builder,
      ilike: () => builder,
      order: () => builder,
      range: () => builder,
      limit: () => builder,
      insert: (payload: unknown) => {
        inserted.push({ table, payload });
        return builder;
      },
      update: (payload: unknown) => {
        updated.push({ table, payload });
        return builder;
      },
      upsert: (payload: unknown, opts?: unknown) => {
        upserted.push({ table, payload, opts });
        return builder;
      },
      delete: () => {
        deleted.push({ table });
        return builder;
      },
      single: next,
      maybeSingle: next,
      then: (resolve: (v: unknown) => void) => next().then(resolve),
    };
    return builder;
  }

  return {
    supabaseAdmin: {
      from: (table: string) => makeBuilder(table),
      rpc: (fn: string) => Promise.resolve(rpcQueues[fn]?.shift() ?? { data: null, error: null }),
    },
    setQueues: (next: QueueMap) => {
      queues = next;
    },
    setRpcQueues: (next: QueueMap) => {
      rpcQueues = next;
    },
    reset: () => {
      queues = {};
      rpcQueues = {};
      inserted.length = 0;
      updated.length = 0;
      deleted.length = 0;
      upserted.length = 0;
    },
    inserted,
    updated,
    deleted,
    upserted,
  };
}
