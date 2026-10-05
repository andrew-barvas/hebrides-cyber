import { describe, it, expect } from "vitest";
import { escapeHtml, incompleteChecks, plainText, prioritise, ratingFor, renderExecutiveReportHtml, safeLogoUrl, type ExecutiveReportInput } from "./executiveReport";
import { buildTriageIndex, EMPTY_TRIAGE_INDEX, type TriageDbRow } from "./findingTriage";
import type { Finding } from "./scanners";

const f = (over: Partial<Finding> & { title: string }): Finding => ({ severity: "medium", detail: "Detail text.", checkId: `x.${over.title}`, ...over });
const NOW = new Date("2026-10-05T12:00:00Z");

function input(over: Partial<ExecutiveReportInput> = {}): ExecutiveReportInput {
  return {
    targetUrl: "https://www.example.com/",
    scannedAt: "2026-10-04T09:00:00Z",
    score: 72,
    summary: "Overall fair.",
    findings: [f({ title: "Low thing", severity: "low" }), f({ title: "Crit thing", severity: "critical", remediation: "**Patch** it: see [docs](https://x). ```code```" })],
    results: { tls: { status: "checked" } },
    triage: EMPTY_TRIAGE_INDEX,
    now: NOW,
    ...over,
  };
}

const triageRow = (checkId: string, state: TriageDbRow["state"]): TriageDbRow => ({
  id: "1", owner: "o", target_host: "www.example.com", check_id: checkId, state, reason: "internal note", expires_at: null, created_by: null, created_at: "", updated_at: "",
});

describe("helpers", () => {
  it("escapes quotes as well as angle brackets and ampersands", () => {
    expect(escapeHtml(`<a href="x" onclick='y'>&`)).toBe("&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;");
  });
  it("only accepts https logos", () => {
    expect(safeLogoUrl("https://cdn.test/a.png")).toBe("https://cdn.test/a.png");
    for (const bad of ["http://cdn.test/a.png", "javascript:alert(1)", "file:///etc/passwd", "not a url", "", undefined]) expect(safeLogoUrl(bad)).toBeNull();
  });
  it("flattens markdown and truncates", () => {
    expect(plainText("**Patch** it: see [docs](https://x). ```code``` now", 100)).toBe("Patch it: see docs. now");
    expect(plainText("a".repeat(50), 10)).toBe(`${"a".repeat(9)}…`);
  });
  it("rates scores", () => {
    expect([null, 95, 80, 60, 10].map((s) => ratingFor(s).label)).toEqual(["Not scored", "Strong", "Good", "Needs attention", "At risk"]);
  });
  it("orders by severity, then known-exploited, then EPSS, then easiest fix", () => {
    const list = [
      f({ title: "hard", severity: "high", fixDifficulty: "hard" }),
      f({ title: "easy", severity: "high", fixDifficulty: "easy" }),
      f({ title: "unrated", severity: "high" }),
      f({ title: "unrated2", severity: "high" }),
      f({ title: "epss", severity: "high", threatIntel: { knownExploited: false, epss: 0.9 } }),
      f({ title: "kev", severity: "high", threatIntel: { knownExploited: true } }),
      f({ title: "crit", severity: "critical" }),
    ];
    expect(prioritise(list).map((x) => x.title)).toEqual(["crit", "kev", "epss", "easy", "hard", "unrated", "unrated2"]);
  });
  it("lists only checks that did not finish", () => {
    expect(incompleteChecks({ tls: { status: "checked" }, dns: { status: "error" }, ports: { status: "partial" }, waf: { status: "not_configured" }, extended: { status: "error" }, n: null, s: "x" })).toEqual([
      { name: "dns", status: "error" },
      { name: "ports", status: "partial" },
      { name: "waf", status: "not_configured" },
    ]);
    expect(incompleteChecks(null)).toEqual([]);
  });
});

describe("renderExecutiveReportHtml", () => {
  it("shows the score, severity counts, ordered priorities and the default identity", () => {
    const html = renderExecutiveReportHtml(input());
    expect(html).toContain("Hebrides Cyber");
    expect(html).toContain(">72<");
    expect(html).toContain("Needs attention");
    expect(html.indexOf("Crit thing")).toBeLessThan(html.indexOf("Low thing"));
    expect(html).toContain("How to fix:</b> Patch it: see docs.");
    expect(html).not.toMatch(/"results"|\{\s*"tls"/); // no raw JSON appendix
    expect(html).toContain("Every automated check in this scan completed.");
    expect(html).toContain("Scanned:</b> 2026-10-04");
  });

  it("is white-labelled: no Hebrides Cyber anywhere, agency name in header and footer, https logo only", () => {
    const html = renderExecutiveReportHtml(input({ branding: { name: "Acme Secure", logoUrl: "https://cdn.test/logo.png" } }));
    expect(html).not.toMatch(/Hebrides/i);
    expect(html).toContain("<h1>Acme Secure</h1>");
    expect(html).toContain('src="https://cdn.test/logo.png"');
    expect(html).toContain("Prepared by Acme Secure.");
    const insecure = renderExecutiveReportHtml(input({ branding: { name: "Acme", logoUrl: "javascript:alert(1)" } }));
    expect(insecure).not.toContain("<img");
    expect(renderExecutiveReportHtml(input({ branding: { logoUrl: "https://cdn.test/l.png" } }))).toContain("<h1>Security Report</h1>");
  });

  it("escapes finding text and branding so a hostile value cannot inject markup", () => {
    const html = renderExecutiveReportHtml(input({ findings: [f({ title: `<img src=x onerror="alert(1)">`, severity: "high", detail: "<script>x</script>" })], branding: { name: `"><script>y</script>` } }));
    expect(html).not.toContain("<script>");
    expect(html).not.toContain('onerror="alert');
    expect(html).toContain("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;");
  });

  it("leaves out false positives, lists accepted risks separately and does not count them", () => {
    const triage = buildTriageIndex([triageRow("x.FP", "false_positive"), triageRow("x.Accepted", "accepted_risk")], NOW);
    const html = renderExecutiveReportHtml(input({ findings: [f({ title: "FP", severity: "high" }), f({ title: "Accepted", severity: "high" }), f({ title: "Real", severity: "high" })], triage }));
    expect(html).not.toContain(">FP<");
    expect(html).toContain("Accepted or snoozed risks");
    expect(html).toMatch(/<li>Accepted <span class="muted">— Accepted \/ authorised<\/span><\/li>/);
    expect(html).not.toContain("internal note");
    expect(html).toContain("All open findings (1)");
  });

  it("says which checks did not finish, singular and plural", () => {
    const one = renderExecutiveReportHtml(input({ results: { dns: { status: "error" } } }));
    expect(one).toContain("Checks that did not finish");
    expect(one).toContain("dns — could not complete");
    expect(one).toContain("it was not able");
    const two = renderExecutiveReportHtml(input({ results: { dns: { status: "error" }, ports: { status: "partial" }, waf: { status: "not_configured" } } }));
    expect(two).toContain("they were not able");
    expect(two).toContain("ports — completed only in part");
  });

  it("handles an unscored scan with no findings, no summary and no scan date", () => {
    const html = renderExecutiveReportHtml(input({ score: null, summary: null, findings: [], scannedAt: null, results: null }));
    expect(html).toContain("Not scored");
    expect(html).toContain("No summary was recorded");
    expect(html).toContain("No open findings above informational level");
    expect(html).toContain("No open findings.");
    expect(html).toContain("Scanned:</b> 2026-10-05");
  });

  it("ranks and flags findings a follow-up check confirmed as exploitable", () => {
    const proven = f({ title: "proven", severity: "high", metadata: { proofOfExploit: { confirmed: true, evidence: "e" } } });
    const other = f({ title: "other", severity: "high" });
    expect(prioritise([other, proven]).map((x) => x.title)).toEqual(["proven", "other"]);
    expect(renderExecutiveReportHtml(input({ findings: [proven] }))).toContain("confirmed exploitable");
  });

  it("marks actively exploited findings and shows fix effort", () => {
    const html = renderExecutiveReportHtml(input({ findings: [f({ title: "Old lib", severity: "high", threatIntel: { knownExploited: true }, fixDifficulty: "easy", remediation: "Upgrade." })] }));
    expect(html).toContain("actively exploited");
    expect(html).toContain("under an hour");
  });

  it("falls back to the raw target when it is not a URL", () => {
    expect(renderExecutiveReportHtml(input({ targetUrl: "unknown" }))).toContain("<b>Site:</b> unknown");
  });

  it("uses the default clock when none is given", () => {
    const html = renderExecutiveReportHtml({ ...input(), now: undefined });
    expect(html).toContain(`Report date:</b> ${new Date().toISOString().slice(0, 10)}`);
  });
});
