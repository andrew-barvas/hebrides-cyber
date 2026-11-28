// Test helper: a chainable stand-in for the Supabase query builder. Every
// call is recorded, and `resolve` decides what each finished query returns.
// Only tests import this.
import type { SupabaseClient } from "@supabase/supabase-js";

export type FakeQuery = {
  table: string;
  op: "select" | "insert" | "update" | "delete";
  columns: string | null;
  values: unknown;
  filters: Array<[string, string, unknown]>;
  options: Record<string, unknown> | undefined;
  terminal: "await" | "single" | "maybeSingle";
};

export type FakeResult = { data?: unknown; error?: { message: string; code?: string } | null; count?: number | null };

export function fakeSupabase(resolve: (q: FakeQuery) => FakeResult) {
  const calls: FakeQuery[] = [];
  const from = (table: string) => {
    const q: FakeQuery = { table, op: "select", columns: null, values: undefined, filters: [], options: undefined, terminal: "await" };
    const finish = (terminal: FakeQuery["terminal"]) => {
      q.terminal = terminal;
      calls.push(q);
      const r = resolve(q);
      return Promise.resolve({ data: r.data ?? null, error: r.error ?? null, count: r.count ?? null });
    };
    const b: Record<string, unknown> = {};
    const chain = (name: string) => (col: string, val: unknown) => {
      q.filters.push([name, col, val]);
      return b;
    };
    Object.assign(b, {
      select: (columns: string, options?: Record<string, unknown>) => {
        if (q.op === "select") q.columns = columns;
        q.options = options ?? q.options;
        return b;
      },
      insert: (values: unknown) => ((q.op = "insert"), (q.values = values), b),
      update: (values: unknown) => ((q.op = "update"), (q.values = values), b),
      delete: () => ((q.op = "delete"), b),
      eq: chain("eq"),
      neq: chain("neq"),
      is: chain("is"),
      in: chain("in"),
      order: () => b,
      limit: () => b,
      single: () => finish("single"),
      maybeSingle: () => finish("maybeSingle"),
      then: (ok: (v: unknown) => unknown, fail?: (e: unknown) => unknown) => finish("await").then(ok, fail),
    });
    return b;
  };
  return { client: { from } as unknown as SupabaseClient, calls };
}

/** The value of the first `eq`/`is`/`in` filter on `col`, if any. */
export const filterValue = (q: FakeQuery, col: string) => q.filters.find(([, c]) => c === col)?.[2];
