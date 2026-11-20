import { describe, expect, it } from "vitest";
import { breachSummarySentence, breachesFromScans } from "./lookoutBreaches";
import { renderLookoutReportHtml } from "./lookoutReportPdf";
import type { HibpResult } from "./scanners/hibp";

const breach = (name: string, date: string, count: number) => ({
  name, title: name, breachDate: date, dataClasses: ["Email addresses", "Passwords"], description: "", isSensitive: false, isVerified: true, affectedAliasCount: count,
});
const scan = (url: string, at: string, hibp: HibpResult | null) => ({ target_url: url, created_at: at, scan_results: [{ hibp }] });

describe("breachesFromScans", () => {
  it("uses each site's latest scan, newest breach first, and never shows an older result as current", () => {
    const s = breachesFromScans([
      scan("https://www.example.com", "2026-11-19", { status: "checked", domain: "example.com", affectedAliasCount: 3, breaches: [breach("Old", "2019-01-01", 1), breach("New", "2024-05-01", 2)] }),
      scan("https://www.example.com", "2026-11-01", { status: "checked", domain: "example.com", affectedAliasCount: 9, breaches: [] }),
      scan("https://shop.example.org", "2026-11-18", { status: "not_verified", domain: "example.org", note: "" }),
      scan("https://blog.example.net", "2026-11-18", { status: "error", note: "timeout" }),
      scan("https://blog.example.net", "2026-11-10", { status: "checked", domain: "example.net", affectedAliasCount: 5, breaches: [breach("X", "2020-01-01", 5)] }),
    ]);
    expect(s.available).toBe(true);
    expect(s.sites.map((x) => x.host)).toEqual(["shop.example.org", "www.example.com"]);
    const www = s.sites.find((x) => x.host === "www.example.com");
    expect(www).toMatchObject({ status: "checked", affectedAliasCount: 3 });
    expect(www?.status === "checked" && www.breaches.map((b) => b.name)).toEqual(["New", "Old"]);
  });

  it("is unavailable (the section is left out) while HIBP isn't configured", () => {
    expect(breachesFromScans([scan("https://www.example.com", "2026-11-19", { status: "not_configured", note: "" })])).toEqual({ available: false, sites: [] });
    expect(breachesFromScans([scan("https://www.example.com", "2026-11-19", null)]).available).toBe(false);
  });
});

describe("breachSummarySentence", () => {
  it("sums addresses and names the most recent breach, or says nothing", () => {
    const s = breachesFromScans([scan("https://www.example.com", "2026-11-19", { status: "checked", domain: "example.com", affectedAliasCount: 3, breaches: [breach("Old", "2019-01-01", 1), breach("New", "2024-05-01", 2)] })]);
    expect(breachSummarySentence(s)).toBe("3 email addresses on your domain appear in known data breaches, most recently New (2024-05-01); those passwords should be changed and multi-factor sign-in turned on.");
    expect(breachSummarySentence({ available: true, sites: [{ host: "x", status: "not_verified" }] })).toBe("");
  });
});

describe("the PDF's breach section", () => {
  const base = {
    report: { period_start: "2026-11-01", period_end: "2026-11-19", status: "published" as const, summary: "", published_at: null, acknowledged_at: null },
    items: [],
    gallery: [],
  };

  it("lists breaches per site, explains an unverified domain, and is absent when dark", () => {
    const breaches = breachesFromScans([
      scan("https://www.example.com", "2026-11-19", { status: "checked", domain: "example.com", affectedAliasCount: 2, breaches: [breach("Canva <b>", "2019-05-24", 2)] }),
      scan("https://shop.example.org", "2026-11-18", { status: "not_verified", domain: "example.org", note: "" }),
    ]);
    const html = renderLookoutReportHtml({ ...base, breaches });
    expect(html).toContain("Email addresses in known data breaches");
    expect(html).toContain("Canva &lt;b&gt;");
    expect(html).toContain("2 addresses found");
    expect(html).toContain("not enabled yet");
    expect(renderLookoutReportHtml({ ...base, breaches: { available: false, sites: [] } })).not.toContain("known data breaches");
  });
});
