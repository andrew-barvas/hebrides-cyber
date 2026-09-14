import { describe, it, expect } from "vitest";
import { generateFrameworkReport, generateComplianceReport, formatComplianceReportMarkdown } from "./complianceReport";
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
    expect(md).toContain("100%");
  });
});
