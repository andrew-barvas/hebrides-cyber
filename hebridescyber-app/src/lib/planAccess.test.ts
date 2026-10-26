import { describe, it, expect } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import { hasAgencyAccess, hasPlanAccess, hasProAccess, hasTierAAccess, planGate, subscriptionGrants } from "./planAccess";

type Reply = { data: unknown; error?: { message: string } | null };

function client(sub: Reply | unknown, user: Reply | unknown): SupabaseClient {
  const asReply = (r: unknown): Reply => (r && typeof r === "object" && "data" in (r as object) ? (r as Reply) : { data: r, error: null });
  const table = (r: unknown) => ({ select: () => ({ eq: () => ({ maybeSingle: () => Promise.resolve(asReply(r)) }) }) });
  return { from: (name: string) => (name === "subscriptions" ? table(sub) : table(user)) } as unknown as SupabaseClient;
}

describe("subscriptionGrants", () => {
  it("needs an active subscription; Agency includes Pro", () => {
    expect(subscriptionGrants({ plan: "pro", status: "active" }, "pro")).toBe(true);
    expect(subscriptionGrants({ plan: "agency", status: "active" }, "pro")).toBe(true);
    expect(subscriptionGrants({ plan: "agency", status: "active" }, "agency")).toBe(true);
    expect(subscriptionGrants({ plan: "pro", status: "active" }, "agency")).toBe(false);
    expect(subscriptionGrants({ plan: "basic", status: "active" }, "pro")).toBe(false);
  });

  it("nests upward: Tier A grants agency and pro; agency/pro do not grant Tier A", () => {
    expect(subscriptionGrants({ plan: "tier_a", status: "active" }, "tier_a")).toBe(true);
    expect(subscriptionGrants({ plan: "tier_a", status: "active" }, "agency")).toBe(true);
    expect(subscriptionGrants({ plan: "tier_a", status: "active" }, "pro")).toBe(true);
    expect(subscriptionGrants({ plan: "agency", status: "active" }, "tier_a")).toBe(false);
    expect(subscriptionGrants({ plan: "pro", status: "active" }, "tier_a")).toBe(false);
    expect(subscriptionGrants({ plan: "tier_a", status: "cancelled" }, "tier_a")).toBe(false);
  });

  it("refuses a lapsed or cancelled subscription whose plan the webhook left unchanged", () => {
    for (const status of ["cancelled", "past_due", "incomplete", null, undefined]) {
      expect(subscriptionGrants({ plan: "agency", status }, "agency")).toBe(false);
    }
    expect(subscriptionGrants(null, "pro")).toBe(false);
    expect(subscriptionGrants(undefined, "pro")).toBe(false);
  });
});

describe("planGate", () => {
  it("is ok for an active plan or an admin, denied otherwise", async () => {
    expect(await planGate(client({ plan: "agency", status: "active" }, null), "o", "agency")).toBe("ok");
    expect(await planGate(client(null, { is_admin: true }), "o", "agency")).toBe("ok");
    expect(await planGate(client({ plan: "agency", status: "cancelled" }, { is_admin: false }), "o", "agency")).toBe("denied");
  });

  it("is an error, not a denial, when the plan can't be read; an admin is still let through", async () => {
    expect(await planGate(client({ data: null, error: { message: "down" } }, null), "o", "pro")).toBe("error");
    expect(await planGate(client({ plan: "pro", status: "active" }, { data: null, error: { message: "down" } }), "o", "pro")).toBe("error");
    expect(await planGate(client({ data: null, error: { message: "down" } }, { is_admin: true }), "o", "pro")).toBe("ok");
  });
});

describe("hasProAccess / hasAgencyAccess", () => {
  it("allows active Pro and Agency plans and admins", async () => {
    expect(await hasProAccess(client({ plan: "pro", status: "active" }, null), "o")).toBe(true);
    expect(await hasProAccess(client({ plan: "agency", status: "active" }, { is_admin: false }), "o")).toBe(true);
    expect(await hasProAccess(client(null, { is_admin: true }), "o")).toBe(true);
    expect(await hasAgencyAccess(client({ plan: "agency", status: "active" }, null), "o")).toBe(true);
  });

  it("refuses Basic, inactive, absent and unreadable subscriptions", async () => {
    expect(await hasProAccess(client({ plan: "basic", status: "active" }, null), "o")).toBe(false);
    expect(await hasProAccess(client({ plan: "pro", status: "past_due" }, null), "o")).toBe(false);
    expect(await hasProAccess(client(null, null), "o")).toBe(false);
    expect(await hasAgencyAccess(client({ plan: "pro", status: "active" }, null), "o")).toBe(false);
    expect(await hasPlanAccess(client({ data: null, error: { message: "down" } }, null), "o", "pro")).toBe(false);
  });
});

describe("hasTierAAccess", () => {
  it("allows only active Tier A and admins", async () => {
    expect(await hasTierAAccess(client({ plan: "tier_a", status: "active" }, null), "o")).toBe(true);
    expect(await hasTierAAccess(client(null, { is_admin: true }), "o")).toBe(true);
    expect(await hasTierAAccess(client({ plan: "agency", status: "active" }, { is_admin: false }), "o")).toBe(false);
    expect(await hasTierAAccess(client({ plan: "tier_a", status: "cancelled" }, null), "o")).toBe(false);
  });
});

// Billing safety contract: a basic-plan (or inactive) subscription MUST NOT
// grant access to paid tiers. This is the invariant the webhook's
// silent-downgrade fix (Sprint 1) is designed to protect — any regression here
// would mean a customer could access Pro/Agency features without paying.
describe("billing safety: basic does not grant paid tiers", () => {
  it("subscriptionGrants({plan:'basic',status:'active'}, 'pro') is false", () => {
    expect(subscriptionGrants({ plan: "basic", status: "active" }, "pro")).toBe(false);
  });

  it("subscriptionGrants({plan:'basic',status:'active'}, 'agency') is false", () => {
    expect(subscriptionGrants({ plan: "basic", status: "active" }, "agency")).toBe(false);
  });

  it("subscriptionGrants({plan:'basic',status:'active'}, 'tier_a') is false", () => {
    expect(subscriptionGrants({ plan: "basic", status: "active" }, "tier_a")).toBe(false);
  });

  it("an inactive pro subscription does not grant pro", () => {
    expect(subscriptionGrants({ plan: "pro", status: "past_due" }, "pro")).toBe(false);
    expect(subscriptionGrants({ plan: "pro", status: "cancelled" }, "pro")).toBe(false);
  });
});
