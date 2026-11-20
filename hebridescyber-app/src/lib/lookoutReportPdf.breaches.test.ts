import { describe, expect, it } from "vitest";
import { renderLookoutReportHtml, type LookoutPdfInput } from "./lookoutReportPdf";

const base: LookoutPdfInput = {
  report: { period_start: "2026-10-20", period_end: "2026-11-19", status: "published", summary: "s", published_at: "2026-11-19T10:00:00Z", acknowledged_at: null },
  items: [],
  gallery: [],
  now: new Date("2026-11-20T00:00:00Z"),
};

describe("renderLookoutReportHtml: breached accounts", () => {
  it("lists breached accounts per site, and says when a domain isn't verified or had none", () => {
    const breaches = {
      available: true,
      sites: [
        { host: "a.example", status: "checked" as const, affectedAliasCount: 2, breaches: [{ name: "X", title: "X <Breach>", breachDate: "2024-01-01", dataClasses: ["Email addresses", "Passwords"], affectedAliasCount: 2 }] },
        { host: "b.example", status: "checked" as const, affectedAliasCount: 0, breaches: [] },
        { host: "c.example", status: "not_verified" as const },
      ],
    };
    const html = renderLookoutReportHtml({ ...base, breaches });
    expect(html).toContain("2 addresses found");
    expect(html).toContain("X &lt;Breach&gt;");
    expect(html).toContain("Email addresses, Passwords");
    expect(html).toContain("<b>b.example</b>: no addresses found in known breaches.");
    expect(html).toContain("not enabled yet");
    expect(renderLookoutReportHtml({ ...base, breaches: { available: false, sites: [] } })).not.toContain("not enabled yet");
  });
});
