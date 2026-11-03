import { describe, it, expect, vi } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { FixFirstList, PrioritisedFinding } from "./estatePriority";
import {
  buildReportEmail,
  fixFirstJson,
  formatReportJson,
  renderFixFirstHtml,
  renderScheduledReportHtml,
  runDueReport,
  type FindingSummary,
  type ScheduledReport,
} from "./scheduledReports";

const NOW = new Date("2026-11-01T09:00:00Z");
const STYLE = { cell: "c", muted: "m" };

const item = (rank: number, over: Partial<PrioritisedFinding> = {}): PrioritisedFinding => ({
  key: `k${rank}`, host: "shop.example", checkId: "nuclei.cve-1", checkBase: "nuclei.cve-1", category: "nuclei", severity: "high",
  title: `Finding ${rank}`, detail: null, firstSeenAt: "2026-10-01T00:00:00Z", ageDays: 31, slaState: null, slaDueAt: null,
  knownExploited: true, ransomware: false, epss: null, cvssScore: null, cveIds: [], scanId: "s1", triage: null,
  priority: { rank, score: 33.8, base: 22.5, factors: [], reason: "High severity, KEV listed, on a high-criticality site" },
  ...over,
});

const LIST: FixFirstList = { items: [item(1), item(2)], total: 7, complete: true };
const SUMMARIES: FindingSummary[] = [
  { targetUrl: "https://shop.example", totalFindings: 7, critical: 0, high: 2, medium: 5, low: 0, info: 0, score: 70, lastScanDate: "2026-10-31T00:00:00Z" },
];

describe("renderFixFirstHtml", () => {
  it("lists rank, title, site and reason, and says how much is left", () => {
    const html = renderFixFirstHtml(LIST, STYLE);
    expect(html).toContain("<b>1</b>");
    expect(html).toContain("Finding 2");
    expect(html).toContain("shop.example · high");
    expect(html).toContain("Why here: High severity, KEV listed, on a high-criticality site");
    expect(html).toContain("Top 2 of 7 open findings.");
    expect(html).not.toContain("may be incomplete");
  });

  it("escapes text from scanned sites", () => {
    const html = renderFixFirstHtml({ items: [item(1, { title: `<img src=x onerror=alert(1)>`, host: `"><b>` })], total: 1, complete: true }, STYLE);
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img");
    expect(html).not.toContain("Top 1 of 1");
  });

  it("is honest about a partial, empty, failed or absent list", () => {
    expect(renderFixFirstHtml({ ...LIST, complete: false }, STYLE)).toContain("this ranking may be incomplete");
    expect(renderFixFirstHtml({ items: [], total: 0, complete: true }, STYLE)).toContain("Nothing open to fix");
    expect(renderFixFirstHtml(null, STYLE)).toContain("couldn't be read this time");
    expect(renderFixFirstHtml(undefined, STYLE)).toBe("");
  });
});

describe("fix-first in the report formats", () => {
  it("JSON carries the ranked items, an error marker when unreadable, and nothing when not requested", () => {
    expect(fixFirstJson(LIST)).toMatchObject({ complete: true, total_open: 7, items: [{ rank: 1, site: "shop.example", reason: expect.stringContaining("KEV") }, { rank: 2 }] });
    expect(JSON.parse(formatReportJson(SUMMARIES, LIST)).fix_first.items).toHaveLength(2);
    expect(JSON.parse(formatReportJson(SUMMARIES, null)).fix_first).toEqual({ error: "could not be read this time" });
    expect(JSON.parse(formatReportJson(SUMMARIES))).not.toHaveProperty("fix_first");
  });

  it("the PDF has a Fix this first section only when the list was loaded", () => {
    expect(renderScheduledReportHtml(SUMMARIES, { targetLabel: "all", frequency: "weekly", now: NOW, fixFirst: LIST })).toContain("<h2>Fix this first</h2>");
    expect(renderScheduledReportHtml(SUMMARIES, { targetLabel: "all", frequency: "weekly", now: NOW })).not.toContain("Fix this first");
  });

  it("the email body leads with the list", async () => {
    const email = await buildReportEmail({ format: "csv", target_url: null, frequency: "weekly" }, SUMMARIES, {
      siteUrl: "https://www.hebridescyber.co.uk",
      renderPdf: async () => Buffer.from(""),
      now: NOW,
      fixFirst: LIST,
    });
    expect(email.html).toContain("Fix this first");
    expect(email.html.indexOf("Finding 1")).toBeLessThan(email.html.indexOf("target_url,score"));
  });
});

describe("runDueReport with loadFixFirst", () => {
  // Enough of the Supabase builder for gatherReportData: one site, no scans.
  function db(): SupabaseClient {
    const responses: Record<string, unknown> = {
      monitored_targets: { data: [{ target_url: "https://shop.example" }], error: null },
      scans: { data: null, error: null },
      finding_triage: { data: [], error: null },
    };
    const builder = (table: string) => {
      const b: Record<string, unknown> = {};
      for (const m of ["select", "eq", "in", "order", "limit", "update", "is", "gt", "or"]) b[m] = () => b;
      b.maybeSingle = async () => responses[table] ?? { data: null, error: null };
      b.then = (resolve: (v: unknown) => void) => resolve(responses[table] ?? { data: null, error: null });
      return b;
    };
    return { from: vi.fn(builder) } as unknown as SupabaseClient;
  }
  const report: ScheduledReport = {
    id: "r1", owner: "o1", target_url: "https://Shop.Example/", frequency: "weekly", format: "csv", recipients: ["a@example.com"],
    enabled: true, last_sent: null, next_due: null,
  };
  const deps = (loadFixFirst: (ownerId: string, host: string | null) => Promise<FixFirstList | null>) => ({
    siteUrl: "https://www.hebridescyber.co.uk",
    renderPdf: async () => Buffer.from(""),
    send: vi.fn(async () => ({ ok: true })),
    planCheck: async () => "ok" as const,
    loadFixFirst,
    now: NOW,
  });

  it("asks for the list scoped to the report's site and puts it in the email", async () => {
    const load = vi.fn(async () => LIST);
    const d = deps(load);
    const outcome = await runDueReport(db(), report, d);
    expect(outcome.kind).toBe("sent");
    expect(load).toHaveBeenCalledWith("o1", "shop.example");
    expect((d.send.mock.calls[0] as unknown as [{ html: string }])[0].html).toContain("Why here:");
  });

  it("still sends the report when the list can't be read, and says so", async () => {
    const d = deps(async () => {
      throw new Error("boom");
    });
    const outcome = await runDueReport(db(), { ...report, target_url: null }, d);
    expect(outcome.kind).toBe("sent");
    expect((d.send.mock.calls[0] as unknown as [{ html: string }])[0].html).toContain("couldn't be read this time");
  });
});
