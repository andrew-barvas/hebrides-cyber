import { describe, it, expect } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import { hasProAccess } from "./planAccess";

function client(sub: unknown, user: unknown): SupabaseClient {
  const table = (data: unknown) => ({ select: () => ({ eq: () => ({ maybeSingle: () => Promise.resolve({ data }) }) }) });
  return { from: (name: string) => (name === "subscriptions" ? table(sub) : table(user)) } as unknown as SupabaseClient;
}

describe("hasProAccess", () => {
  it("allows active Pro and Agency plans and admins", async () => {
    expect(await hasProAccess(client({ plan: "pro", status: "active" }, null), "o")).toBe(true);
    expect(await hasProAccess(client({ plan: "agency", status: "active" }, { is_admin: false }), "o")).toBe(true);
    expect(await hasProAccess(client(null, { is_admin: true }), "o")).toBe(true);
  });

  it("refuses Basic, inactive and absent subscriptions", async () => {
    expect(await hasProAccess(client({ plan: "basic", status: "active" }, null), "o")).toBe(false);
    expect(await hasProAccess(client({ plan: "pro", status: "past_due" }, null), "o")).toBe(false);
    expect(await hasProAccess(client(null, null), "o")).toBe(false);
  });
});
