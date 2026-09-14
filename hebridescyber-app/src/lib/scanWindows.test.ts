import { describe, it, expect } from "vitest";
import { isWithinScanWindow, type ScanWindow } from "./scanWindows";

describe("isWithinScanWindow", () => {
  it("returns true when no window is set", () => {
    const window: ScanWindow = { startTime: null, endTime: null, timezone: "UTC" };
    expect(isWithinScanWindow(window, new Date("2026-09-14T14:00:00Z"))).toBe(true);
  });

  it("returns true when only start is set (incomplete window)", () => {
    const window: ScanWindow = { startTime: "02:00", endTime: null, timezone: "UTC" };
    expect(isWithinScanWindow(window, new Date("2026-09-14T14:00:00Z"))).toBe(true);
  });

  it("allows scans within a daytime window", () => {
    const window: ScanWindow = { startTime: "02:00", endTime: "06:00", timezone: "UTC" };
    expect(isWithinScanWindow(window, new Date("2026-09-14T03:00:00Z"))).toBe(true);
  });

  it("blocks scans outside a daytime window", () => {
    const window: ScanWindow = { startTime: "02:00", endTime: "06:00", timezone: "UTC" };
    expect(isWithinScanWindow(window, new Date("2026-09-14T14:00:00Z"))).toBe(false);
  });

  it("handles overnight windows (start > end)", () => {
    const window: ScanWindow = { startTime: "22:00", endTime: "06:00", timezone: "UTC" };
    expect(isWithinScanWindow(window, new Date("2026-09-14T23:00:00Z"))).toBe(true);
    expect(isWithinScanWindow(window, new Date("2026-09-14T03:00:00Z"))).toBe(true);
    expect(isWithinScanWindow(window, new Date("2026-09-14T12:00:00Z"))).toBe(false);
  });

  it("respects timezone conversion", () => {
    // 14:00 UTC = 15:00 Europe/London (BST, UTC+1 in summer)
    const window: ScanWindow = { startTime: "14:00", endTime: "16:00", timezone: "Europe/London" };
    // 14:00 UTC → 15:00 BST → within [14:00, 16:00) London time
    expect(isWithinScanWindow(window, new Date("2026-09-14T14:00:00Z"))).toBe(true);
  });

  it("returns true for invalid timezone (fail-open)", () => {
    const window: ScanWindow = { startTime: "02:00", endTime: "06:00", timezone: "Invalid/Zone" };
    expect(isWithinScanWindow(window, new Date("2026-09-14T14:00:00Z"))).toBe(true);
  });

  it("returns true for invalid time format (fail-open)", () => {
    const window: ScanWindow = { startTime: "25:00", endTime: "06:00", timezone: "UTC" };
    expect(isWithinScanWindow(window, new Date("2026-09-14T14:00:00Z"))).toBe(true);
  });

  it("boundary: exactly at start time is within window", () => {
    const window: ScanWindow = { startTime: "03:00", endTime: "06:00", timezone: "UTC" };
    expect(isWithinScanWindow(window, new Date("2026-09-14T03:00:00Z"))).toBe(true);
  });

  it("boundary: exactly at end time is outside window", () => {
    const window: ScanWindow = { startTime: "03:00", endTime: "06:00", timezone: "UTC" };
    expect(isWithinScanWindow(window, new Date("2026-09-14T06:00:00Z"))).toBe(false);
  });
});
