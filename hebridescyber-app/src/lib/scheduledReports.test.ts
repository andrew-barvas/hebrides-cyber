import { describe, it, expect } from "vitest";
import { isReportDue, formatReportCsv, formatReportJson, type FindingSummary } from "./scheduledReports";

describe("isReportDue", () => {
  it("returns true when next_due is null", () => {
    expect(isReportDue(null, new Date("2026-09-14T12:00:00Z"))).toBe(true);
  });

  it("returns true when now is past next_due", () => {
    expect(isReportDue("2026-09-14T00:00:00Z", new Date("2026-09-14T12:00:00Z"))).toBe(true);
  });

  it("returns false when now is before next_due", () => {
    expect(isReportDue("2026-09-15T00:00:00Z", new Date("2026-09-14T12:00:00Z"))).toBe(false);
  });

  it("returns true when now equals next_due exactly", () => {
    expect(isReportDue("2026-09-14T12:00:00Z", new Date("2026-09-14T12:00:00Z"))).toBe(true);
  });
});

describe("formatReportCsv", () => {
  const summaries: FindingSummary[] = [
    { targetUrl: "https://example.com", score: 85, totalFindings: 10, critical: 1, high: 2, medium: 3, low: 3, info: 1, lastScanDate: "2026-09-14T12:00:00Z" },
    { targetUrl: "https://test.com", score: null, totalFindings: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, lastScanDate: null },
  ];

  it("produces valid CSV with header", () => {
    const csv = formatReportCsv(summaries);
    const lines = csv.split("\r\n");
    expect(lines[0]).toBe("target_url,score,total_findings,critical,high,medium,low,info,last_scan_date");
    expect(lines[1]).toContain("https://example.com");
    expect(lines[1]).toContain("85");
    expect(lines[2]).toContain("https://test.com");
  });

  it("handles empty summaries", () => {
    const csv = formatReportCsv([]);
    expect(csv).toBe("target_url,score,total_findings,critical,high,medium,low,info,last_scan_date");
  });
});

describe("formatReportJson", () => {
  it("produces valid JSON with generated_at timestamp", () => {
    const json = formatReportJson([]);
    const parsed = JSON.parse(json);
    expect(parsed.generated_at).toBeDefined();
    expect(parsed.targets).toEqual([]);
  });
});
