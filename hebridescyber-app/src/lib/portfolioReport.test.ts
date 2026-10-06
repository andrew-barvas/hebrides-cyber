import { describe, it, expect } from "vitest";
import type { Finding } from "./scanners";
import { buildTriageIndex } from "./findingTriage";
import { renderPortfolioReportHtml, summarisePortfolio, type PortfolioInput } from "./portfolioReport";

const NOW = new Date("2026-10-06T12:00:00Z");
const f = (checkId: string, severity: Finding["severity"], extra: Partial<Finding> = {}): Finding => ({
  checkId, severity, title: `Title ${checkId}`, detail: `Detail for ${checkId}`, ...extra,
});
const noTriage = buildTriageIndex([], NOW);
const site = (url: string, score: number | null, findings: Finding[], completedAt = "2026-10-05T00:00:00Z"): PortfolioInput["sites"][number] => ({
  targetUrl: url,
  scan: score === null && findings.length === 0 && completedAt === "none" ? null : { id: `scan-${url}`, completedAt, score, findings },
});

describe("summarisePortfolio", () => {
  it("lists the worst site first and sites with no scan last", () => {
    const { sites } = summarisePortfolio({
      sites: [
        site("https://good.example", 92, []),
        { targetUrl: "https://new.example", scan: null },
        site("https://bad.example", 41, [f("tls.expired", "critical")]),
        site("https://mid.example", 70, [f("headers.missing-critical", "high")]),
      ],
      triage: noTriage,
      now: NOW,
    });
    expect(sites.map((s) => s.host)).toEqual(["bad.example", "mid.example", "good.example", "new.example"]);
    expect(sites[3]).toMatchObject({ scanId: null, score: null, stale: true });
  });

  it("breaks score ties by critical and high counts", () => {
    const { sites } = summarisePortfolio({
      sites: [site("https://a.example", 60, [f("x", "low")]), site("https://b.example", 60, [f("y", "critical")])],
      triage: noTriage,
      now: NOW,
    });
    expect(sites.map((s) => s.host)).toEqual(["b.example", "a.example"]);
  });

  it("leaves false positives, accepted and snoozed findings out of the open counts", () => {
    const triage = buildTriageIndex(
      [
        { target_host: "shop.example", check_id: "a", state: "false_positive", reason: "not real", expires_at: null } as never,
        { target_host: "shop.example", check_id: "b", state: "accepted_risk", reason: "ok", expires_at: null } as never,
      ],
      NOW
    );
    const { sites, totals } = summarisePortfolio({
      sites: [site("https://shop.example", 50, [f("a", "critical"), f("b", "high"), f("c", "medium")])],
      triage,
      now: NOW,
    });
    expect(sites[0].counts).toMatchObject({ critical: 0, high: 0, medium: 1 });
    expect(totals).toMatchObject({ critical: 0, high: 0, medium: 1 });
  });

  it("finds issues shared by several sites, most widespread first, and counts known-exploited", () => {
    const hsts = () => f("headers.missing-critical", "high", { title: "Missing HSTS" });
    const summary = summarisePortfolio({
      sites: [
        site("https://a.example", 60, [hsts(), f("dns.dmarc-missing", "medium"), f("lib.old", "high", { threatIntel: { knownExploited: true } })]),
        site("https://b.example", 65, [hsts(), f("dns.dmarc-missing", "medium")]),
        site("https://c.example", 80, [hsts(), f("only.here", "critical"), f("info.thing", "info")]),
      ],
      triage: noTriage,
      now: NOW,
    });
    expect(summary.common.map((c) => [c.checkId, c.hosts.length])).toEqual([
      ["headers.missing-critical", 3],
      ["dns.dmarc-missing", 2],
    ]);
    expect(summary.common[0].title).toBe("Missing HSTS");
    expect(summary.exploited).toBe(1);
    expect(summary.averageScore).toBe(68);
    expect(summary.scanned).toBe(3);
    // Info findings never become a top priority.
    expect(summary.sites.find((s) => s.host === "c.example")?.top.map((t) => t.checkId)).toEqual(["only.here", "headers.missing-critical"]);
  });

  it("flags a site not rescanned for over two weeks", () => {
    const { sites } = summarisePortfolio({ sites: [site("https://old.example", 90, [], "2026-09-01T00:00:00Z")], triage: noTriage, now: NOW });
    expect(sites[0].stale).toBe(true);
  });
});

describe("renderPortfolioReportHtml", () => {
  const input: PortfolioInput = {
    sites: [
      site("https://a.example", 41, [f("tls.expired", "critical", { title: "Certificate <expired>" }), f("headers.missing-critical", "high", { threatIntel: { knownExploited: true } })]),
      site("https://b.example", 88, [f("headers.missing-critical", "high")]),
      { targetUrl: "https://new.example", scan: null },
    ],
    triage: noTriage,
    now: NOW,
  };

  it("summarises the portfolio, escapes every value, and is honest about unscanned sites", () => {
    const html = renderPortfolioReportHtml(input);
    expect(html).toContain("Security portfolio");
    expect(html).toContain("3 sites · generated 2026-10-06");
    expect(html).toContain("Certificate &lt;expired&gt;");
    expect(html).not.toContain("<expired>");
    expect(html).toContain("1 site has no completed scan yet");
    expect(html).toContain("no completed scan yet");
    expect(html).toContain("Issues on more than one site");
    expect(html).toContain("2 of 2: a.example, b.example");
    expect(html).toMatch(/1 open finding is on CISA's list/);
    expect(html.indexOf("a.example")).toBeLessThan(html.indexOf("b.example"));
  });

  it("white-labels completely: no Hebrides Cyber anywhere, and only an https logo", () => {
    const branded = renderPortfolioReportHtml({ ...input, branding: { name: "Acme Digital", logoUrl: "https://cdn.acme.example/logo.png" } });
    expect(branded).not.toMatch(/Hebrides/i);
    expect(branded).toContain("Acme Digital");
    expect(branded).toContain('src="https://cdn.acme.example/logo.png"');
    const unsafeLogo = renderPortfolioReportHtml({ ...input, branding: { name: "Acme", logoUrl: "javascript:alert(1)" } });
    expect(unsafeLogo).not.toContain("<img");
    expect(renderPortfolioReportHtml(input)).toContain("Hebrides Cyber");
  });

  it("words a clean, single-site portfolio correctly", () => {
    const html = renderPortfolioReportHtml({ sites: [site("https://one.example", 95, [])], triage: noTriage, now: NOW });
    expect(html).toContain("1 site · generated");
    expect(html).toContain("No open finding is on CISA's list");
    expect(html).not.toContain("Issues on more than one site");
    expect(html).not.toContain("Top priorities per site");
  });
});
