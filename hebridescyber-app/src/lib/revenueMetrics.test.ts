import { describe, it, expect } from "vitest";
import { computeMrr, churnRatePct, PLAN_PRICE_GBP } from "./revenueMetrics";

describe("computeMrr", () => {
  it("sums published prices for active paying subs only", () => {
    const r = computeMrr([
      { plan: "basic", status: "active", source: "stripe" },
      { plan: "pro", status: "active", source: "stripe" },
      { plan: "agency", status: "active", source: "stripe" },
    ]);
    expect(r.payingMrrGbp).toBe(20 + 35 + 75);
    expect(r.payingCount).toBe(3);
    expect(r.compedCount).toBe(0);
    expect(r.bespokeCount).toBe(0);
  });

  it("ignores non-active subscriptions entirely", () => {
    const r = computeMrr([
      { plan: "agency", status: "cancelled", source: "stripe" },
      { plan: "pro", status: "past_due", source: "stripe" },
      { plan: "basic", status: "active", source: "stripe" },
    ]);
    expect(r.payingMrrGbp).toBe(20);
    expect(r.payingCount).toBe(1);
  });

  it("treats a missing source as paying (the DB default is 'stripe')", () => {
    const r = computeMrr([{ plan: "pro", status: "active" }]);
    expect(r.payingMrrGbp).toBe(35);
    expect(r.payingCount).toBe(1);
  });

  it("counts admin-granted comps separately and adds £0 to MRR", () => {
    const r = computeMrr([
      { plan: "agency", status: "active", source: "admin" },
      { plan: "pro", status: "active", source: "stripe" },
    ]);
    expect(r.payingMrrGbp).toBe(35);
    expect(r.payingCount).toBe(1);
    expect(r.compedCount).toBe(1);
  });

  it("counts a bespoke (no fixed price) plan separately and excludes it from MRR", () => {
    expect(PLAN_PRICE_GBP.tier_a).toBeNull();
    const r = computeMrr([
      { plan: "tier_a", status: "active", source: "stripe" },
      { plan: "basic", status: "active", source: "stripe" },
    ]);
    expect(r.payingMrrGbp).toBe(20);
    expect(r.bespokeCount).toBe(1);
    expect(r.payingCount).toBe(1);
  });

  it("reports per-plan counts and revenue contributions", () => {
    const r = computeMrr([
      { plan: "basic", status: "active", source: "stripe" },
      { plan: "basic", status: "active", source: "stripe" },
      { plan: "agency", status: "active", source: "admin" },
    ]);
    const basic = r.byPlan.find((p) => p.plan === "basic");
    const agency = r.byPlan.find((p) => p.plan === "agency");
    expect(basic).toEqual({ plan: "basic", count: 2, mrrGbp: 40 });
    expect(agency).toEqual({ plan: "agency", count: 1, mrrGbp: 0 });
  });

  it("returns zeroed totals for no subscriptions", () => {
    expect(computeMrr([])).toEqual({
      payingMrrGbp: 0,
      payingCount: 0,
      compedCount: 0,
      bespokeCount: 0,
      byPlan: [],
    });
  });
});

describe("churnRatePct", () => {
  it("is cancelled over active-at-start as a percentage", () => {
    expect(churnRatePct(2, 40)).toBe(5);
  });

  it("is null when the starting base is zero (not enough data)", () => {
    expect(churnRatePct(0, 0)).toBeNull();
    expect(churnRatePct(3, 0)).toBeNull();
  });

  it("is null rather than negative when the starting base is implausibly negative", () => {
    expect(churnRatePct(1, -2)).toBeNull();
  });

  it("is 0 when nothing cancelled", () => {
    expect(churnRatePct(0, 10)).toBe(0);
  });
});
