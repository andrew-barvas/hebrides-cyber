import { describe, expect, it } from "vitest";
import { lookoutPdfFileName, renderLookoutReportHtml, type LookoutPdfInput } from "./lookoutReportPdf";

const JPEG = "data:image/jpeg;base64,/9j/4AAQSkZJRg==";
const base: LookoutPdfInput = {
  report: { period_start: "2026-10-20", period_end: "2026-11-19", status: "published", summary: "One new issue.\n\nTwo were fixed.", published_at: "2026-11-19T10:00:00Z", acknowledged_at: null },
  items: [
    { host: "shop.example.com", severity: "medium", title: "Second", priority: 2, analyst_note: "", business_impact: "", fix_owner: null },
    { host: "www.example.com", severity: "high", title: "First <b>", priority: 1, analyst_note: "Renew it", business_impact: "Visitors see a warning", fix_owner: "it_supplier" },
  ],
  gallery: [{ host: "www.example.com", dataUri: JPEG }],
  now: new Date("2026-11-20T00:00:00Z"),
};

describe("renderLookoutReportHtml", () => {
  it("is dated, lists items in priority order and escapes text", () => {
    const html = renderLookoutReportHtml(base);
    expect(html).toContain("2026-10-20 to 2026-11-19");
    expect(html).toContain("published 2026-11-19");
    expect(html.indexOf("First &lt;b&gt;")).toBeLessThan(html.indexOf("Second"));
    expect(html).toContain("Your IT supplier");
    expect(html).toContain("<p>One new issue.</p><p>Two were fixed.</p>");
    expect(html).not.toContain("<b>First");
    expect(html).toContain("isn't acceptance of any risk");
  });

  it("embeds the estate gallery as JPEG data URIs only, so the render fetches nothing", () => {
    const html = renderLookoutReportHtml({ ...base, gallery: [...base.gallery, { host: "evil.example", dataUri: "https://evil.example/x.jpg" }] });
    expect(html).toContain("Your sites at a glance");
    expect(html).toContain(JPEG);
    expect(html).not.toContain("https://evil.example");
    expect(renderLookoutReportHtml({ ...base, gallery: [] })).not.toContain("Your sites at a glance");
  });

  it("marks a draft and shows when it was acknowledged", () => {
    expect(renderLookoutReportHtml({ ...base, report: { ...base.report, status: "draft" } })).toContain("DRAFT");
    expect(renderLookoutReportHtml({ ...base, report: { ...base.report, status: "acknowledged", acknowledged_at: "2026-11-21T09:00:00Z" } })).toContain("acknowledged 2026-11-21");
  });

  it("says what to do about new lookalike domains, and not when there are none", () => {
    const lookalikes = { available: true, newInPeriod: [{ domain: "examp1e.com", targetDomain: "example.com", how: "a character swapped for a lookalike", spottedAt: "2026-11-01T00:00:00Z", certificateSeenAt: "2026-10-30T00:00:00Z" }], totalKnown: 1 };
    const html = renderLookoutReportHtml({ ...base, lookalikes });
    expect(html).toContain("<b>What to do</b>");
    expect(html).toContain("report@phishing.gov.uk");
    expect(renderLookoutReportHtml({ ...base, lookalikes: { ...lookalikes, newInPeriod: [] } })).not.toContain("What to do");
  });

  it("shows the score over the period when there's history, and nothing otherwise", () => {
    const trends = { available: true, sites: [{ host: "shop.example.com", start: 50, end: 80, change: 30 }], average: [{ at: "2026-10-27", score: 50 }, { at: "2026-11-19", score: 80 }] };
    const html = renderLookoutReportHtml({ ...base, trends });
    expect(html).toContain("Your security score over this period");
    expect(html).toContain("<svg");
    expect(html).toContain("<td>+30</td>");
    expect(renderLookoutReportHtml(base)).not.toContain("over this period");
  });

  it("names the file by the period's end", () => {
    expect(lookoutPdfFileName(base.report)).toBe("lookout-report-2026-11-19.pdf");
  });
});
