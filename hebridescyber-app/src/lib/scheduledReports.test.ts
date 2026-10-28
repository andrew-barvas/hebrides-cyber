import { describe, it, expect, vi } from "vitest";
import {
  isReportDue,
  pdfReportDue,
  formatReportCsv,
  formatReportJson,
  summariseReport,
  renderScheduledReportHtml,
  buildReportEmail,
  PDF_CHECK_LOOKAHEAD_MS,
  type FindingSummary,
  type ReportFormat,
} from "./scheduledReports";
import { REPORT_MUTED, REPORT_TEXT } from "./executiveReport";

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

const NOW = new Date("2026-10-27T00:15:00Z");
const SUMMARIES: FindingSummary[] = [
  { targetUrl: "https://good.example", score: 92, totalFindings: 2, critical: 0, high: 0, medium: 1, low: 1, info: 0, lastScanDate: "2026-10-26T03:00:00Z" },
  { targetUrl: "https://risky.example", score: 40, totalFindings: 7, critical: 1, high: 2, medium: 2, low: 1, info: 1, lastScanDate: "2026-09-01T03:00:00Z" },
  { targetUrl: "https://new.example", score: null, totalFindings: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, lastScanDate: null },
];
const PDF_BYTES = Buffer.from("%PDF-1.7 test");
type RenderPdf = (html: string) => Promise<Buffer>;

describe("pdfReportDue", () => {
  const report = (format: ReportFormat, next_due: string | null, enabled = true) => ({ format, next_due, enabled });

  it("is true only for an enabled pdf report that is due", () => {
    expect(pdfReportDue([report("pdf", "2026-10-27T00:00:00Z")], NOW)).toBe(true);
    expect(pdfReportDue([report("pdf", null)], NOW)).toBe(true);
    expect(pdfReportDue([report("csv", "2026-10-27T00:00:00Z"), report("json", null)], NOW)).toBe(false);
    expect(pdfReportDue([report("pdf", "2026-10-27T00:00:00Z", false)], NOW)).toBe(false);
    expect(pdfReportDue([], NOW)).toBe(false);
  });

  it("looks ahead, so a report falling due between the check and the send step still gets a browser", () => {
    const soon = new Date(NOW.getTime() + PDF_CHECK_LOOKAHEAD_MS - 1000).toISOString();
    const later = new Date(NOW.getTime() + PDF_CHECK_LOOKAHEAD_MS + 1000).toISOString();
    expect(pdfReportDue([report("pdf", soon)], NOW)).toBe(true);
    expect(pdfReportDue([report("pdf", later)], NOW)).toBe(false);
  });
});

describe("summariseReport", () => {
  it("totals findings and severities, and averages only the scored sites", () => {
    const s = summariseReport(SUMMARIES);
    expect(s.totalFindings).toBe(9);
    expect(s.avgScore).toBe(66);
    expect(s.totals).toEqual({ critical: 1, high: 2, medium: 3, low: 2, info: 1 });
  });

  it("has no average when nothing is scored", () => {
    expect(summariseReport([SUMMARIES[2]]).avgScore).toBeNull();
  });
});

describe("renderScheduledReportHtml", () => {
  const html = renderScheduledReportHtml(SUMMARIES, { targetLabel: "all monitored sites", frequency: "weekly", now: NOW });

  it("lists every site, worst score first, with a never-scanned site last and labelled as such", () => {
    const risky = html.indexOf("https://risky.example");
    const good = html.indexOf("https://good.example");
    const fresh = html.indexOf("https://new.example");
    expect(risky).toBeGreaterThan(-1);
    expect(risky).toBeLessThan(good);
    expect(good).toBeLessThan(fresh);
    expect(html).toContain("Not scanned yet: no results to report.");
  });

  it("flags a scan older than the staleness window, and only that one", () => {
    expect(html.match(/may be out of date/g)).toHaveLength(1);
    expect(html.indexOf("may be out of date")).toBeGreaterThan(html.indexOf("https://risky.example"));
    expect(html.indexOf("may be out of date")).toBeLessThan(html.indexOf("https://good.example"));
  });

  it("shows the headline figures and says the counts are untriaged", () => {
    expect(html).toContain("<b>66</b>");
    expect(html).toContain("average of 2 scanned sites");
    expect(html).toContain("Covers:</b> all monitored sites");
    expect(html).toContain("Frequency:</b> weekly");
    expect(html).toContain("Report date:</b> 2026-10-27");
    expect(html).toContain("before triage");
  });

  it("escapes every stored value", () => {
    const evil = renderScheduledReportHtml([{ ...SUMMARIES[0], targetUrl: `https://x.example/"><script>alert(1)</script>` }], {
      targetLabel: `<img src=x onerror=alert(1)>`,
      frequency: "daily",
      now: NOW,
    });
    expect(evil).not.toContain("<script>");
    expect(evil).not.toContain("<img");
    expect(evil).toContain("&lt;script&gt;");
  });

  it("prints text in the shared dark report colours, not the old hard-to-read grey", () => {
    expect(html).toContain(`color: ${REPORT_TEXT}`);
    expect(html).toContain(`color: ${REPORT_MUTED}`);
    expect(html).not.toMatch(/#64727f|#1f2933/i);
  });

  it("says so when there are no sites", () => {
    expect(renderScheduledReportHtml([], { targetLabel: "all monitored sites", frequency: "monthly", now: NOW })).toContain("No monitored sites.");
  });
});

describe("buildReportEmail", () => {
  const opts = (renderPdf = vi.fn<RenderPdf>(async () => PDF_BYTES)) => ({ siteUrl: "https://www.hebridescyber.co.uk", renderPdf, now: NOW });
  const report = (format: ReportFormat, target_url: string | null = null) => ({ format, target_url, frequency: "weekly" as const });

  it("pdf: attaches the rendered PDF, says so, and inlines no data block", async () => {
    const renderPdf = vi.fn<RenderPdf>(async () => PDF_BYTES);
    const email = await buildReportEmail(report("pdf"), SUMMARIES, opts(renderPdf));

    expect(renderPdf).toHaveBeenCalledTimes(1);
    expect(renderPdf.mock.calls[0][0]).toContain("Scheduled security report");
    expect(email.sentFormat).toBe("pdf");
    expect(email.pdfError).toBeUndefined();
    expect(email.attachments).toEqual([{ filename: "hebridescyber-report-2026-10-27.pdf", content: PDF_BYTES }]);
    expect(email.html).toContain("Format: PDF (attached)");
    expect(email.html).toContain("attached as a PDF");
    expect(email.html).not.toContain("<pre");
  });

  it("csv: inlines the CSV, attaches nothing, and never launches a browser", async () => {
    const renderPdf = vi.fn<RenderPdf>(async () => PDF_BYTES);
    const email = await buildReportEmail(report("csv"), SUMMARIES, opts(renderPdf));

    expect(renderPdf).not.toHaveBeenCalled();
    expect(email.sentFormat).toBe("csv");
    expect(email.attachments).toEqual([]);
    expect(email.html).toContain("Format: CSV");
    expect(email.html).toContain("target_url,score,total_findings");
  });

  it("json: inlines the JSON (escaped), attaches nothing, and never launches a browser", async () => {
    const renderPdf = vi.fn<RenderPdf>(async () => PDF_BYTES);
    const email = await buildReportEmail(report("json"), SUMMARIES, opts(renderPdf));

    expect(renderPdf).not.toHaveBeenCalled();
    expect(email.sentFormat).toBe("json");
    expect(email.attachments).toEqual([]);
    expect(email.html).toContain("Format: JSON");
    expect(email.html).toContain("&quot;targets&quot;");
    expect(email.html).not.toContain("target_url,score");
  });

  it("pdf that can't be rendered: sends CSV and says so, never JSON or a silent label", async () => {
    const failing = vi.fn<RenderPdf>(async () => {
      throw new Error("Executable doesn't exist");
    });
    const email = await buildReportEmail(report("pdf"), SUMMARIES, opts(failing));

    expect(email.sentFormat).toBe("csv");
    expect(email.pdfError).toBe("Executable doesn't exist");
    expect(email.attachments).toEqual([]);
    expect(email.html).toContain("Format: CSV (the PDF could not be generated)");
    expect(email.html).toContain("set to arrive as a PDF, but the PDF could not be generated");
    expect(email.html).toContain("target_url,score,total_findings");
    expect(email.html).not.toContain("Format: PDF");
  });

  it("names a single-site report's target and keeps the headline table", async () => {
    const email = await buildReportEmail(report("csv", "https://risky.example"), [SUMMARIES[1]], opts());

    expect(email.subject).toBe("Scheduled Security Report — https://risky.example");
    expect(email.html).toContain("Report for: <strong>https://risky.example</strong>");
    expect(email.html).toContain("40/100");
    expect(email.html).toContain("https://www.hebridescyber.co.uk/dashboard");
  });

  it("an all-sites report says so, and leaves out the average when nothing is scored", async () => {
    const email = await buildReportEmail(report("csv"), [SUMMARIES[2]], opts());

    expect(email.subject).toBe("Scheduled Security Report — all monitored sites");
    expect(email.html).not.toContain("Average score");
  });
});
