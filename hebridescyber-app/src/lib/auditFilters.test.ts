import { describe, it, expect } from "vitest";
import { categoryLikePattern, dateRangeBounds, AUDIT_CATEGORIES } from "./auditFilters";

describe("categoryLikePattern", () => {
  it("returns a prefix LIKE pattern for a known category", () => {
    expect(categoryLikePattern("stripe")).toBe("stripe.%");
    expect(categoryLikePattern("admin")).toBe("admin.%");
  });

  it("trims surrounding whitespace", () => {
    expect(categoryLikePattern("  scan  ")).toBe("scan.%");
  });

  it("returns null for empty or unknown categories (no filter, not a no-match)", () => {
    expect(categoryLikePattern("")).toBeNull();
    expect(categoryLikePattern(undefined)).toBeNull();
    expect(categoryLikePattern(null)).toBeNull();
    expect(categoryLikePattern("not_a_category")).toBeNull();
  });

  it("every advertised category produces a usable pattern", () => {
    for (const c of AUDIT_CATEGORIES) {
      expect(categoryLikePattern(c.value)).toBe(`${c.value}.%`);
    }
  });
});

describe("dateRangeBounds", () => {
  it("maps from/to to inclusive start-of-day / end-of-day UTC bounds", () => {
    expect(dateRangeBounds("2026-06-15", "2026-06-16")).toEqual({
      gte: "2026-06-15T00:00:00.000Z",
      lte: "2026-06-16T23:59:59.999Z",
    });
  });

  it("returns a null bound for an empty or unparseable side", () => {
    expect(dateRangeBounds("", "2026-06-16")).toEqual({ gte: null, lte: "2026-06-16T23:59:59.999Z" });
    expect(dateRangeBounds("2026-06-15", "")).toEqual({ gte: "2026-06-15T00:00:00.000Z", lte: null });
    expect(dateRangeBounds("nonsense", undefined)).toEqual({ gte: null, lte: null });
  });

  it("returns both null for no inputs", () => {
    expect(dateRangeBounds(null, null)).toEqual({ gte: null, lte: null });
  });
});
