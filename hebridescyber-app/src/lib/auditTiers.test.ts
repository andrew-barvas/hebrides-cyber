import { describe, it, expect } from "vitest";
import { AUDIT_TIERS, isAuditTierId, getAuditTier } from "./auditTiers";

describe("isAuditTierId", () => {
  it("accepts the three real tier ids", () => {
    for (const tier of AUDIT_TIERS) {
      expect(isAuditTierId(tier.id)).toBe(true);
    }
  });

  it("rejects anything else", () => {
    expect(isAuditTierId("enterprise")).toBe(false);
    expect(isAuditTierId("")).toBe(false);
    expect(isAuditTierId(undefined)).toBe(false);
    expect(isAuditTierId(42)).toBe(false);
  });
});

describe("getAuditTier", () => {
  it("returns the matching tier's name/price/budgetRange", () => {
    expect(getAuditTier("small")).toEqual(
      expect.objectContaining({ name: "Small Website Audit", price: "£300", budgetRange: "under_300" })
    );
    expect(getAuditTier("standard").budgetRange).toBe("300_800");
    expect(getAuditTier("full").budgetRange).toBe("800_1800");
  });
});
