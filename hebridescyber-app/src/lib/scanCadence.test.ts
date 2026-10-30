import { describe, it, expect } from "vitest";
import { isScanDue, SCAN_INTERVAL_DAYS } from "./scanCadence";

describe("isScanDue", () => {
  it("is always due when there is no previous completed scan", () => {
    expect(isScanDue("basic", null, new Date("2026-01-01T00:00:00Z"))).toBe(true);
    expect(isScanDue("pro", null, new Date("2026-01-01T00:00:00Z"))).toBe(true);
    expect(isScanDue("agency", null, new Date("2026-01-01T00:00:00Z"))).toBe(true);
  });

  describe("basic plan (weekly cadence)", () => {
    const lastScan = "2026-01-01T00:00:00Z";

    it("is not due one day after the last scan", () => {
      const now = new Date("2026-01-02T00:00:00Z");
      expect(isScanDue("basic", lastScan, now)).toBe(false);
    });

    it("is not due one second before the 7-day boundary", () => {
      const now = new Date("2026-01-07T23:59:59Z");
      expect(isScanDue("basic", lastScan, now)).toBe(false);
    });

    it("is due exactly at the 7-day boundary", () => {
      const now = new Date("2026-01-08T00:00:00Z");
      expect(isScanDue("basic", lastScan, now)).toBe(true);
    });

    it("is due well past the 7-day boundary", () => {
      const now = new Date("2026-02-01T00:00:00Z");
      expect(isScanDue("basic", lastScan, now)).toBe(true);
    });
  });

  describe("pro, agency and tier_a plans (daily cadence)", () => {
    const lastScan = "2026-01-01T12:00:00Z";

    it.each(["pro", "agency", "tier_a"] as const)("%s is not due a few hours after the last scan", (plan) => {
      const now = new Date("2026-01-01T18:00:00Z");
      expect(isScanDue(plan, lastScan, now)).toBe(false);
    });

    it.each(["pro", "agency", "tier_a"] as const)("%s is due exactly at the 1-day boundary", (plan) => {
      const now = new Date("2026-01-02T12:00:00Z");
      expect(isScanDue(plan, lastScan, now)).toBe(true);
    });
  });

  it("SCAN_INTERVAL_DAYS encodes the documented pricing policy (basic weekly, pro/agency/tier_a daily)", () => {
    expect(SCAN_INTERVAL_DAYS).toEqual({ basic: 7, pro: 1, agency: 1, tier_a: 1 });
  });
});
