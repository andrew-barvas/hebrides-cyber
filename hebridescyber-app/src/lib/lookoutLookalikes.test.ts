import { describe, expect, it } from "vitest";
import { lookalikeSummarySentence, lookalikesForPeriod } from "./lookoutLookalikes";
import { renderLookoutReportHtml } from "./lookoutReportPdf";

const row = (domain: string, notified: string | null, firstSeen = "2025-01-01T00:00:00Z") => ({
  candidate_domain: domain, target_domain: "example.com", technique: "omission", first_seen_at: firstSeen, notified_at: notified,
});

describe("lookalikesForPeriod", () => {
  const rows = [
    row("exmple.com", "2026-11-10T08:00:00Z"),
    row("examp1e.com", "2026-11-19T23:00:00Z"),
    row("eexample.com", "2026-09-01T00:00:00Z"),
    row("example.co", null, "2026-11-05T00:00:00Z"),
  ];

  it("lists those our sweep spotted in the period, newest first, by spotted date not certificate date", () => {
    const s = lookalikesForPeriod(rows, "2026-11-01", "2026-11-19");
    expect(s.newInPeriod.map((l) => l.domain)).toEqual(["examp1e.com", "exmple.com", "example.co"]);
    expect(s.newInPeriod[1]).toMatchObject({ how: "a character removed", targetDomain: "example.com", spottedAt: "2026-11-10T08:00:00Z", certificateSeenAt: "2025-01-01T00:00:00Z" });
    expect(s.totalKnown).toBe(4);
  });

  it("is empty outside the period", () => {
    expect(lookalikesForPeriod(rows, "2026-10-01", "2026-10-31").newInPeriod).toEqual([]);
  });
});

describe("lookalikeSummarySentence", () => {
  it("names up to three, or says nothing when there are none", () => {
    const s = lookalikesForPeriod([row("a.com", "2026-11-02T00:00:00Z"), row("b.com", "2026-11-03T00:00:00Z"), row("c.com", "2026-11-04T00:00:00Z"), row("d.com", "2026-11-05T00:00:00Z")], "2026-11-01", "2026-11-30");
    expect(lookalikeSummarySentence(s)).toBe("We spotted 4 new lookalike domains of yours (d.com, c.com, b.com and others), a common setup for phishing your customers or staff.");
    expect(lookalikeSummarySentence({ newInPeriod: [] })).toBe("");
  });
});

describe("the PDF's lookalike section", () => {
  const base = {
    report: { period_start: "2026-11-01", period_end: "2026-11-19", status: "published" as const, summary: "", published_at: null, acknowledged_at: null },
    items: [],
    gallery: [],
  };

  it("lists new lookalikes, says when there were none, and is absent when the data isn't available", () => {
    const section = { available: true, ...lookalikesForPeriod([row("exmple.com", "2026-11-10T08:00:00Z")], "2026-11-01", "2026-11-19") };
    const html = renderLookoutReportHtml({ ...base, lookalikes: section });
    expect(html).toContain("Lookalike domains");
    expect(html).toContain("exmple.com");
    expect(html).toContain("1 lookalike domain known in all");
    expect(renderLookoutReportHtml({ ...base, lookalikes: { available: true, newInPeriod: [], totalKnown: 2 } })).toContain("No new lookalike domains of yours were spotted this period (2 known from before)");
    expect(renderLookoutReportHtml({ ...base, lookalikes: { available: false, newInPeriod: [], totalKnown: 0 } })).not.toContain("Lookalike domains");
  });
});
