import { describe, it, expect, vi } from "vitest";
import { PDFDocument } from "pdf-lib";
import { decodeEntities, parseCss, parseHtml, renderHtmlPdf } from "./htmlPdf";
import { renderExecutiveReportHtml } from "./executiveReport";
import { renderPortfolioReportHtml } from "./portfolioReport";
import { renderLookoutReportHtml } from "./lookoutReportPdf";
import { EMPTY_TRIAGE_INDEX, buildTriageIndex } from "./findingTriage";
import type { Finding } from "./scanners";

// A real 8x5 JPEG.
const JPEG_B64 =
  "/9j/2wBDABQODxIPDRQSEBIXFRQYHjIhHhwcHj0sLiQySUBMS0dARkVQWnNiUFVtVkVGZIhlbXd7gYKBTmCNl4x9lnN+gXz/2wBDARUXFx4aHjshITt8U0ZTfHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHz/wAARCAAFAAgDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAX/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/8QAFAEBAAAAAAAAAAAAAAAAAAAABP/EABQRAQAAAAAAAAAAAAAAAAAAAAD/2gAMAwEAAhEDEQA/AJYBoT//2Q==";
const JPEG = `data:image/jpeg;base64,${JPEG_B64}`;

async function load(bytes: Buffer) {
  expect(bytes.subarray(0, 5).toString("latin1")).toBe("%PDF-");
  return PDFDocument.load(new Uint8Array(bytes));
}
const page = (body: string, css = "") => `<!doctype html><html><head><title>T</title><style>${css}</style></head><body>${body}</body></html>`;

describe("parsing", () => {
  it("decodes named and numeric entities", () => {
    expect(decodeEntities("a &amp; b &lt;c&gt; &quot;d&quot; &#39;e&#39; &rarr; &#x2014; &nbsp;&unknown;")).toBe("a & b <c> \"d\" 'e' → —  &unknown;");
  });

  it("builds a tree, keeps raw style text and tolerates void and self-closing tags", () => {
    const root = parseHtml('<html><head><style>p > b { color: red }</style></head><body><p class="x">Hi<br>there <img src="a.png"> <svg><line x1="0"/></svg></p></body></html>');
    const html = root.children[0] as { tag: string; children: unknown[] };
    expect(html.tag).toBe("html");
    const text = JSON.stringify(root, (k, v) => (k === "parent" ? undefined : v));
    expect(text).toContain("p > b { color: red }");
    expect(text).toContain('"tag":"line"');
  });

  it("reads tag, class and descendant selectors, most specific last, and skips the rest", () => {
    const rules = parseCss("@page { size: A4 } .a { color: #111 } p { color: #222 } .a b, td.num { color: #333 } a:hover { color: #444 } .x > div:first-child { color: #555 }");
    expect(rules.map((r) => r.decls.color)).toEqual(["#222", "#111", "#333", "#333"]);
    expect(rules[2].chain).toEqual([{ classes: ["a"] }, { tag: "b", classes: [] }]);
  });
});

describe("renderHtmlPdf", () => {
  it("draws a page with the document's title and nothing of ours in the metadata", async () => {
    const doc = await load(await renderHtmlPdf(page("<h1>Hello</h1><p>World</p>")));
    expect(doc.getTitle()).toBe("T");
    expect(`${doc.getCreator()} ${doc.getProducer()} ${doc.getAuthor() ?? ""}`).not.toMatch(/Hebrides/i);
    expect(doc.getPageCount()).toBe(1);
  });

  it("survives text the standard fonts can't encode and words wider than the page", async () => {
    const doc = await load(await renderHtmlPdf(page(`<p>Łódź 漢字 🚀 → ≥ ✓ ${"x".repeat(600)}</p><p><code>${"/a".repeat(300)}</code></p>`)));
    expect(doc.getPageCount()).toBeGreaterThanOrEqual(1);
  });

  it("runs a long table onto more pages and keeps going after it", async () => {
    const rows = Array.from({ length: 120 }, (_, i) => `<tr><td>Row ${i}</td><td>${"detail ".repeat(12)}</td><td class="num">${i}</td></tr>`).join("");
    const css = "table { width: 100%; border-collapse: collapse; } th, td { padding: 5px 6px; border-bottom: 1px solid #e4e9ee; } th { background: #f1f5f8; } td.num { text-align: center; }";
    const doc = await load(await renderHtmlPdf(page(`<table><thead><tr><th>A</th><th>B</th><th>C</th></tr></thead><tbody>${rows}<tr><td colspan="3">End</td></tr></tbody></table><p>After</p>`, css)));
    expect(doc.getPageCount()).toBeGreaterThan(2);
  });

  it("embeds JPEG data URIs, and fetches an https logo only through the hook", async () => {
    const fetchImage = vi.fn(async () => Uint8Array.from(Buffer.from(JPEG_B64, "base64")));
    const html = page(`<div class="head"><img src="https://cdn.example/logo.jpg" alt=""><div><h1>Acme</h1></div></div><div class="g"><figure><img src="${JPEG}"><figcaption>a.example</figcaption></figure></div>`, ".head { display: flex; gap: 12px } .head img { height: 40px; max-width: 160px } .g { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px } figure { margin: 0 } figure img { width: 100% }");
    const bytes = await renderHtmlPdf(html, { fetchImage });
    expect(fetchImage).toHaveBeenCalledWith("https://cdn.example/logo.jpg");
    expect(bytes.toString("latin1").match(/\/Subtype \/Image/g)).toHaveLength(2);
  });

  it("leaves out images it can't use instead of failing", async () => {
    const fetchImage = vi.fn(async () => null);
    const html = page('<img src="https://cdn.example/logo.svg"><img src="http://plain.example/x.jpg"><img src="data:image/jpeg;base64,/9j/4AAQ"><img src="data:image/webp;base64,AAAA"><p>Still here</p>');
    const bytes = await renderHtmlPdf(html, { fetchImage });
    expect(fetchImage).toHaveBeenCalledTimes(1);
    expect(bytes.toString("latin1")).not.toContain("/Subtype /Image");
    await load(bytes);
  });

  it("renders concurrent documents independently", async () => {
    const list = (n: number) => page(`<ol>${Array.from({ length: n }, (_, i) => `<li>Item ${i}</li>`).join("")}</ol><svg width="100" height="40"><polyline points="0,0 50,20 100,10" stroke="#0b3d5b" fill="none"/><circle cx="50" cy="20" r="2" fill="#0b3d5b"/><text x="10" y="35" font-size="9" fill="#64748b">2026-11-01</text></svg>`);
    const [a, b] = await Promise.all([renderHtmlPdf(list(200)), renderHtmlPdf(list(3))]);
    expect((await load(a)).getPageCount()).toBeGreaterThan(1);
    expect((await load(b)).getPageCount()).toBe(1);
  });
});

describe("the report templates", () => {
  const f = (checkId: string, severity: Finding["severity"], title: string, extra: Partial<Finding> = {}): Finding => ({ checkId, severity, title, detail: `${title}: seen during the scan.`, ...extra });
  const findings = [
    f("tls.cert-expired", "critical", "TLS certificate expired", { remediation: "Renew it.", fixDifficulty: "easy" }),
    f("headers.hsts-missing", "high", "HSTS header missing", { fixDifficulty: "trivial" }),
    f("dns.dmarc-missing", "medium", "DMARC record missing"),
  ];

  it("draws the executive scan report, white-labelled when branded", async () => {
    const html = renderExecutiveReportHtml({ targetUrl: "https://www.example.com/", scannedAt: "2026-11-19T09:00:00Z", score: 58, summary: "Fix the certificate.", findings, results: { zap: { status: "error" } }, triage: EMPTY_TRIAGE_INDEX, branding: { name: "Acme Security" }, now: new Date("2026-11-20T00:00:00Z") });
    const doc = await load(await renderHtmlPdf(html, { fetchImage: async () => null }));
    expect(doc.getTitle()).toBe("Acme Security — www.example.com");
    expect(doc.getPageCount()).toBeGreaterThanOrEqual(1);
  });

  it("draws the portfolio report", async () => {
    const html = renderPortfolioReportHtml({
      sites: [{ targetUrl: "https://a.example", scan: { id: "a", completedAt: "2026-11-18T00:00:00Z", score: 41, findings } }, { targetUrl: "https://b.example", scan: null }],
      triage: buildTriageIndex([], new Date("2026-11-20T00:00:00Z")),
      now: new Date("2026-11-20T00:00:00Z"),
    });
    expect((await load(await renderHtmlPdf(html))).getTitle()).toBe("Hebrides Cyber — security portfolio");
  });

  it("draws the Lookout report with its gallery and trend", async () => {
    const html = renderLookoutReportHtml({
      report: { period_start: "2026-10-20", period_end: "2026-11-19", status: "draft", summary: "One.\n\nTwo.", published_at: null, acknowledged_at: null },
      items: [{ host: "www.example.com", severity: "high", title: "Certificate expired", priority: 1, analyst_note: "Renew", business_impact: "Warnings", fix_owner: "it_supplier" }],
      gallery: [{ host: "www.example.com", dataUri: JPEG }],
      trends: { available: true, sites: [{ host: "www.example.com", start: 50, end: 80, change: 30 }], average: [{ at: "2026-10-27", score: 50 }, { at: "2026-11-19", score: 80 }] },
      now: new Date("2026-11-20T00:00:00Z"),
    });
    const bytes = await renderHtmlPdf(html);
    expect(bytes.toString("latin1")).toContain("/Subtype /Image");
    expect((await load(bytes)).getTitle()).toBe("Hebrides Cyber Lookout report 2026-10-20 to 2026-11-19");
  });
});
