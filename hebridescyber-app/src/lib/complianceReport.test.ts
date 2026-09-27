import { describe, it, expect } from "vitest";
import {
  COMPLIANCE_REPORT_DISCLAIMER,
  CONTROL_RESULT,
  formatComplianceReportCsv,
  formatComplianceReportMarkdown,
  generateComplianceReport,
  generateFrameworkReport,
  toComplianceExportJson,
  withComplianceRefs,
} from "./complianceReport";
import { getComplianceRefs } from "./scanners/compliance";
import type { Finding } from "./scanners/index";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    severity: "high",
    title: "Test finding",
    detail: "detail",
    checkId: "tls.no-https",
    complianceRefs: [
      { framework: "cyber-essentials", control: "Secure configuration" },
      { framework: "iso-27001", control: "A.13 – Communications Security" },
    ],
    ...overrides,
  };
}

describe("generateFrameworkReport", () => {
  it("marks controls as passing when no findings hit them", () => {
    const report = generateFrameworkReport("cyber-essentials", "https://example.com", []);
    expect(report.passing).toBe(report.totalControls);
    expect(report.coveragePercent).toBe(100);
  });

  it("marks controls as failing when critical/high findings exist", () => {
    const findings = [makeFinding({ severity: "critical" })];
    const report = generateFrameworkReport("cyber-essentials", "https://example.com", findings);
    expect(report.failing).toBeGreaterThan(0);
    expect(report.coveragePercent).toBeLessThan(100);
  });

  it("marks controls as partial for medium-only findings", () => {
    const findings = [makeFinding({ severity: "medium" })];
    const report = generateFrameworkReport("cyber-essentials", "https://example.com", findings);
    const partialControls = report.controls.filter((c) => c.status === "partial");
    expect(partialControls.length).toBeGreaterThan(0);
  });
});

describe("generateComplianceReport", () => {
  it("generates reports for all frameworks", () => {
    const report = generateComplianceReport("https://example.com", []);
    expect(report.frameworks.length).toBeGreaterThanOrEqual(5);
    expect(report.overallScore).toBe(100);
  });

  it("lowers overall score with findings", () => {
    const findings = [
      makeFinding({ severity: "critical", checkId: "tls.no-https" }),
      makeFinding({ severity: "high", checkId: "headers.missing-critical", complianceRefs: [
        { framework: "cyber-essentials", control: "Secure configuration" },
        { framework: "owasp-top-10", control: "A05:2021 – Security Misconfiguration" },
      ]}),
    ];
    const report = generateComplianceReport("https://example.com", findings);
    expect(report.overallScore).toBeLessThan(100);
  });
});

describe("formatComplianceReportMarkdown", () => {
  it("produces readable markdown", () => {
    const report = generateComplianceReport("https://example.com", []);
    const md = formatComplianceReportMarkdown(report);
    expect(md).toContain("# Compliance Report");
    expect(md).toContain("ISO 27001");
  });

  // A clean external scan says nothing about policies, processes or physical
  // security — the export must never read as a certification.
  it("carries the disclaimer and never claims a pass or a compliance percentage", () => {
    const md = formatComplianceReportMarkdown(generateComplianceReport("https://example.com", []));
    expect(md).toContain(COMPLIANCE_REPORT_DISCLAIMER);
    expect(md).toContain("No issues found");
    expect(md).not.toMatch(/\bpass(ed|ing)?\b/i);
    expect(md).not.toMatch(/\d+%/);
  });

  it("lists each finding against its control and escapes table-breaking pipes", () => {
    const md = formatComplianceReportMarkdown(
      generateComplianceReport("https://example.com", [makeFinding({ title: "Weak | cipher\nsuite" })])
    );
    expect(md).toContain("Critical/high issues found");
    expect(md).toContain("[high] Weak \\| cipher suite");
  });
});

describe("formatComplianceReportCsv", () => {
  it("leads with the disclaimer, then one row per framework control", () => {
    const report = generateComplianceReport("https://example.com", [makeFinding({ severity: "medium" })]);
    const lines = formatComplianceReportCsv(report).split("\r\n");
    expect(lines[0].startsWith("Disclaimer,")).toBe(true);
    expect(lines[2]).toBe("framework,control,result,finding_count,findings");
    const totalControls = report.frameworks.reduce((n, fw) => n + fw.totalControls, 0);
    expect(lines).toHaveLength(3 + totalControls);
    const hit = lines.find((l) => l.includes("Secure configuration"));
    expect(hit).toContain("Issues found,1,[medium] Test finding (tls.no-https)");
  });

  it("neutralises formula-leading finding titles", () => {
    const csv = formatComplianceReportCsv(
      generateComplianceReport("https://example.com", [makeFinding({ title: "=cmd|' /C calc'!A0" })])
    );
    expect(csv).not.toMatch(/,=cmd/);
  });
});

describe("toComplianceExportJson", () => {
  it("uses result labels, not pass/fail, and includes the disclaimer", () => {
    const json = toComplianceExportJson(generateComplianceReport("https://example.com", [makeFinding()]));
    expect(json.disclaimer).toBe(COMPLIANCE_REPORT_DISCLAIMER);
    const results = new Set(json.frameworks.flatMap((fw) => fw.controls.map((c) => c.result)));
    expect([...results].every((r) => Object.values(CONTROL_RESULT).includes(r))).toBe(true);
    expect(results.has("high_severity_issues_found")).toBe(true);
    const ce = json.frameworks.find((fw) => fw.framework === "cyber-essentials")!;
    expect(ce.controls_with_issues + ce.controls_without_issues).toBe(ce.controls_mapped);
  });
});

describe("withComplianceRefs", () => {
  // Findings stored before per-finding refs existed must not export as
  // "no issues found" across the board.
  it("derives refs from checkId when a stored finding has none", () => {
    const [f] = withComplianceRefs([makeFinding({ complianceRefs: undefined })]);
    expect(f.complianceRefs).toEqual(getComplianceRefs("tls.no-https"));
    expect(f.complianceRefs!.length).toBeGreaterThan(0);
  });

  it("keeps refs that are already present", () => {
    const original = makeFinding();
    expect(withComplianceRefs([original])[0]).toBe(original);
  });
});
