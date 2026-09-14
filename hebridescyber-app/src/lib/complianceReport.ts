// Compliance reporting — generates structured reports mapping scan findings
// to SOC 2, ISO 27001, and PCI DSS control frameworks. Builds on top of the
// per-finding complianceRefs already attached by compliance.ts, but aggregates
// them into a document-level view suitable for auditors and compliance teams.

import type { Finding } from "./scanners/index";
import type { ComplianceFramework, ComplianceRef } from "./scanners/compliance";
import { ALL_CONTROLS_BY_FRAMEWORK, COMPLIANCE_FRAMEWORK_LABELS } from "./scanners/compliance";

export type ControlStatus = "pass" | "fail" | "partial";

export type ControlResult = {
  control: string;
  status: ControlStatus;
  findings: Array<{ checkId: string; severity: Finding["severity"]; title: string }>;
};

export type FrameworkReport = {
  framework: ComplianceFramework;
  label: string;
  generatedAt: string;
  targetUrl: string;
  totalControls: number;
  passing: number;
  failing: number;
  coveragePercent: number;
  controls: ControlResult[];
};

export type ComplianceReportBundle = {
  generatedAt: string;
  targetUrl: string;
  frameworks: FrameworkReport[];
  overallScore: number;
};

function controlStatusFromFindings(findings: ControlResult["findings"]): ControlStatus {
  if (findings.length === 0) return "pass";
  const hasCriticalOrHigh = findings.some((f) => f.severity === "critical" || f.severity === "high");
  return hasCriticalOrHigh ? "fail" : "partial";
}

export function generateFrameworkReport(
  framework: ComplianceFramework,
  targetUrl: string,
  findings: Finding[],
): FrameworkReport {
  const allControls = ALL_CONTROLS_BY_FRAMEWORK[framework];
  const controlFindings = new Map<string, ControlResult["findings"]>();

  for (const controlName of allControls) {
    controlFindings.set(controlName, []);
  }

  for (const finding of findings) {
    if (!finding.complianceRefs) continue;
    for (const ref of finding.complianceRefs) {
      if (ref.framework !== framework) continue;
      const list = controlFindings.get(ref.control);
      if (list) {
        list.push({
          checkId: finding.checkId || "unknown",
          severity: finding.severity,
          title: finding.title,
        });
      }
    }
  }

  const controls: ControlResult[] = [];
  let passing = 0;
  let failing = 0;

  for (const [control, cFindings] of controlFindings) {
    const status = controlStatusFromFindings(cFindings);
    if (status === "pass") passing++;
    else if (status === "fail") failing++;
    controls.push({ control, status, findings: cFindings });
  }

  const totalControls = allControls.size;
  const coveragePercent = totalControls > 0 ? Math.round((passing / totalControls) * 100) : 100;

  return {
    framework,
    label: COMPLIANCE_FRAMEWORK_LABELS[framework],
    generatedAt: new Date().toISOString(),
    targetUrl,
    totalControls,
    passing,
    failing,
    coveragePercent,
    controls,
  };
}

const REPORT_FRAMEWORKS: ComplianceFramework[] = [
  "iso-27001",
  "pci-dss",
  "cyber-essentials",
  "owasp-top-10",
  "cis-controls-v8",
  "nis2",
  "dora",
];

export function generateComplianceReport(targetUrl: string, findings: Finding[]): ComplianceReportBundle {
  const frameworks = REPORT_FRAMEWORKS.map((fw) => generateFrameworkReport(fw, targetUrl, findings));
  const totalControls = frameworks.reduce((s, f) => s + f.totalControls, 0);
  const totalPassing = frameworks.reduce((s, f) => s + f.passing, 0);
  const overallScore = totalControls > 0 ? Math.round((totalPassing / totalControls) * 100) : 100;

  return {
    generatedAt: new Date().toISOString(),
    targetUrl,
    frameworks,
    overallScore,
  };
}

export function formatComplianceReportMarkdown(report: ComplianceReportBundle): string {
  const lines: string[] = [
    `# Compliance Report — ${report.targetUrl}`,
    `Generated: ${report.generatedAt}`,
    `Overall compliance score: **${report.overallScore}%**`,
    "",
  ];

  for (const fw of report.frameworks) {
    lines.push(`## ${fw.label}`);
    lines.push(`Coverage: ${fw.coveragePercent}% (${fw.passing}/${fw.totalControls} controls passing)`);
    lines.push("");
    lines.push("| Control | Status | Findings |");
    lines.push("|---------|--------|----------|");
    for (const c of fw.controls) {
      const icon = c.status === "pass" ? "✅" : c.status === "fail" ? "❌" : "⚠️";
      const findingList = c.findings.length > 0
        ? c.findings.map((f) => `[${f.severity}] ${f.title}`).join("; ")
        : "—";
      lines.push(`| ${c.control} | ${icon} ${c.status} | ${findingList} |`);
    }
    lines.push("");
  }

  return lines.join("\n");
}
