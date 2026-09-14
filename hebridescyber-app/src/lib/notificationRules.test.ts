import { describe, it, expect } from "vitest";
import { shouldNotify, severityRankOf, type NotificationPrefs } from "./notificationRules";

describe("severityRankOf", () => {
  it("ranks severities in ascending order", () => {
    expect(severityRankOf("info")).toBe(0);
    expect(severityRankOf("low")).toBe(1);
    expect(severityRankOf("medium")).toBe(2);
    expect(severityRankOf("high")).toBe(3);
    expect(severityRankOf("critical")).toBe(4);
  });

  it("returns -1 for unknown severity", () => {
    expect(severityRankOf("banana")).toBe(-1);
  });
});

describe("shouldNotify", () => {
  const noPrefs: NotificationPrefs = { scoreThreshold: null, severityMin: null };

  const makeReport = (opts: {
    score?: number | null;
    newCount?: number | null;
    findings?: { severity: string; status?: string }[];
  }) => ({
    score: opts.score !== undefined ? opts.score : 75,
    new_finding_count: opts.newCount ?? 0,
    findings: opts.findings ?? [],
  });

  it("always notifies when no preferences are set", () => {
    expect(shouldNotify(makeReport({ score: 95 }), noPrefs)).toBe(true);
    expect(shouldNotify(makeReport({ score: 10 }), noPrefs)).toBe(true);
  });

  describe("scoreThreshold", () => {
    const prefs: NotificationPrefs = { scoreThreshold: 70, severityMin: null };

    it("suppresses when score is at or above threshold", () => {
      expect(shouldNotify(makeReport({ score: 70 }), prefs)).toBe(false);
      expect(shouldNotify(makeReport({ score: 95 }), prefs)).toBe(false);
    });

    it("notifies when score is below threshold", () => {
      expect(shouldNotify(makeReport({ score: 69 }), prefs)).toBe(true);
      expect(shouldNotify(makeReport({ score: 0 }), prefs)).toBe(true);
    });

    it("notifies when score is null (no score yet)", () => {
      expect(shouldNotify(makeReport({ score: null }), prefs)).toBe(true);
    });
  });

  describe("severityMin", () => {
    const prefs: NotificationPrefs = { scoreThreshold: null, severityMin: "high" };

    it("suppresses when no new findings exist", () => {
      expect(shouldNotify(makeReport({ newCount: 0 }), prefs)).toBe(false);
      expect(shouldNotify(makeReport({ newCount: null }), prefs)).toBe(false);
    });

    it("suppresses when new findings exist but none meet severity minimum", () => {
      expect(
        shouldNotify(
          makeReport({
            newCount: 2,
            findings: [
              { severity: "medium", status: "new" },
              { severity: "low", status: "new" },
            ],
          }),
          prefs
        )
      ).toBe(false);
    });

    it("notifies when at least one new finding meets severity minimum", () => {
      expect(
        shouldNotify(
          makeReport({
            newCount: 2,
            findings: [
              { severity: "medium", status: "new" },
              { severity: "high", status: "new" },
            ],
          }),
          prefs
        )
      ).toBe(true);
    });

    it("ignores non-new findings", () => {
      expect(
        shouldNotify(
          makeReport({
            newCount: 1,
            findings: [
              { severity: "critical", status: "unchanged" },
              { severity: "low", status: "new" },
            ],
          }),
          prefs
        )
      ).toBe(false);
    });

    it("notifies with unknown severity min (does not suppress)", () => {
      const badPrefs: NotificationPrefs = { scoreThreshold: null, severityMin: "banana" };
      expect(shouldNotify(makeReport({ newCount: 1 }), badPrefs)).toBe(true);
    });
  });

  describe("combined thresholds", () => {
    const prefs: NotificationPrefs = { scoreThreshold: 80, severityMin: "critical" };

    it("suppresses when score is good AND no critical new findings", () => {
      expect(
        shouldNotify(
          makeReport({
            score: 90,
            newCount: 1,
            findings: [{ severity: "high", status: "new" }],
          }),
          prefs
        )
      ).toBe(false);
    });

    it("suppresses when score is bad but no qualifying new findings", () => {
      expect(
        shouldNotify(
          makeReport({
            score: 50,
            newCount: 1,
            findings: [{ severity: "high", status: "new" }],
          }),
          prefs
        )
      ).toBe(false);
    });

    it("notifies when score is bad AND a critical new finding exists", () => {
      expect(
        shouldNotify(
          makeReport({
            score: 50,
            newCount: 1,
            findings: [{ severity: "critical", status: "new" }],
          }),
          prefs
        )
      ).toBe(true);
    });
  });
});
