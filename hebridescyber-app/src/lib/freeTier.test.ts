import { describe, it, expect } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import { isFreeTierExhausted, FREE_SCANS_ALLOWED } from "./freeTier";

// Minimal chainable Supabase query-builder stub. Every chain method
// (select/eq/neq) returns itself; the chain resolves to `result` whether
// the caller ends with .maybeSingle() or just `await`s the chain directly
// (freeTier.ts's scan-count query does the latter, via its `{ count }`
// destructure with no .maybeSingle() call).
function makeQueryBuilder(result: unknown) {
  const builder: Record<string, unknown> = {
    select: () => builder,
    eq: () => builder,
    neq: () => builder,
    maybeSingle: () => Promise.resolve(result),
    then: (resolve: (value: unknown) => void) => Promise.resolve(result).then(resolve),
  };
  return builder;
}

function makeSupabaseMock(tables: Record<string, unknown>): SupabaseClient {
  return {
    from: (table: string) => makeQueryBuilder(tables[table]),
  } as unknown as SupabaseClient;
}

describe("isFreeTierExhausted", () => {
  it("is never exhausted for an admin, regardless of subscription or scan count", async () => {
    const supabase = makeSupabaseMock({
      users: { data: { is_admin: true } },
    });

    await expect(isFreeTierExhausted(supabase, "owner-1")).resolves.toBe(false);
  });

  it("is not exhausted when the owner has an active subscription", async () => {
    const supabase = makeSupabaseMock({
      users: { data: { is_admin: false } },
      subscriptions: { data: { status: "active" } },
    });

    await expect(isFreeTierExhausted(supabase, "owner-1")).resolves.toBe(false);
  });

  it("is not exhausted with no subscription and zero non-pending scans", async () => {
    const supabase = makeSupabaseMock({
      users: { data: null },
      subscriptions: { data: null },
      scans: { count: 0 },
    });

    await expect(isFreeTierExhausted(supabase, "owner-1")).resolves.toBe(false);
  });

  it(`is exhausted once the non-pending scan count reaches FREE_SCANS_ALLOWED (${FREE_SCANS_ALLOWED})`, async () => {
    const supabase = makeSupabaseMock({
      users: { data: { is_admin: false } },
      subscriptions: { data: { status: "past_due" } },
      scans: { count: FREE_SCANS_ALLOWED },
    });

    await expect(isFreeTierExhausted(supabase, "owner-1")).resolves.toBe(true);
  });

  it("is exhausted for an owner with a cancelled subscription who has already scanned", async () => {
    const supabase = makeSupabaseMock({
      users: { data: { is_admin: false } },
      subscriptions: { data: { status: "cancelled" } },
      scans: { count: 5 },
    });

    await expect(isFreeTierExhausted(supabase, "owner-1")).resolves.toBe(true);
  });

  it("treats a null scan count as zero rather than throwing", async () => {
    const supabase = makeSupabaseMock({
      users: { data: null },
      subscriptions: { data: null },
      scans: { count: null },
    });

    await expect(isFreeTierExhausted(supabase, "owner-1")).resolves.toBe(false);
  });
});
