// Compliance reporting — aggregates the per-finding complianceRefs attached by
// scanners/compliance.ts into a per-framework, per-control view (ISO 27001,
// PCI DSS, Cyber Essentials, OWASP Top 10, CIS v8, NIS2, DORA) that a
// customer can hand to an auditor.
//
// Framing matters more than the maths here. The control list is only the
// controls our checks map to, so a control with no findings means "our
// external checks found nothing", never "this control is implemented". The
// export formatters below say exactly that, carry COMPLIANCE_REPORT_DISCLAIMER,
// and deliberately don't print overallScore — a single "compliance %" reads
// as a certification claim this product can't make (see CLAUDE.md's
// "automated indicator, never a certification" rule).

import type { Finding } from "./scanners/index";
import type { ComplianceFramework } from "./scanners/compliance";
import { ALL_CONTROLS_BY_FRAMEWORK, COMPLIANCE_FRAMEWORK_LABELS, getComplianceRefs } from "./scanners/compliance";
import { csvCell } from "./csv";

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
  "soc2",
  "hipaa",
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

// ---- Export ------------------------------------------------------------------

export const COMPLIANCE_REPORT_DISCLAIMER =
  "Automated indicator — not an audit, certification or attestation. Each finding from Hebrides Cyber's external scan is mapped to the framework controls it relates to. \"No issues found\" means none of our automated checks that map to that control detected a problem; it does not mean the control is implemented. Many controls in every framework (policies, internal processes, physical security) cannot be assessed by an external scan at all.";

/** Export-facing result names. Deliberately not "pass"/"fail". */
export type ControlResultLabel = "no_issues_found" | "issues_found" | "high_severity_issues_found";

export const CONTROL_RESULT: Record<ControlStatus, ControlResultLabel> = {
  pass: "no_issues_found",
  partial: "issues_found",
  fail: "high_severity_issues_found",
};

const CONTROL_RESULT_TEXT: Record<ControlResultLabel, string> = {
  no_issues_found: "No issues found",
  issues_found: "Issues found",
  high_severity_issues_found: "Critical/high issues found",
};

/**
 * Findings stored before per-finding compliance refs existed carry none, and
 * would export as "no issues found" everywhere. Derive them from checkId
 * (the same lookup the scan pipeline uses) wherever they're absent.
 */
export function withComplianceRefs(findings: Finding[]): Finding[] {
  return findings.map((f) => (f.complianceRefs?.length ? f : { ...f, complianceRefs: getComplianceRefs(f.checkId) }));
}

function mdCell(text: string): string {
  return text.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

export function formatComplianceReportMarkdown(report: ComplianceReportBundle): string {
  const lines: string[] = [
    `# Compliance Report — ${report.targetUrl}`,
    `Generated: ${report.generatedAt}`,
    "",
    `> ${COMPLIANCE_REPORT_DISCLAIMER}`,
    "",
  ];

  for (const fw of report.frameworks) {
    lines.push(`## ${fw.label}`);
    lines.push(
      `${fw.passing} of ${fw.totalControls} mapped controls: no issues found by automated checks. ${fw.totalControls - fw.passing} with issues.`
    );
    lines.push("");
    lines.push("| Control | Result | Findings |");
    lines.push("|---------|--------|----------|");
    for (const c of fw.controls) {
      const findingList = c.findings.length > 0 ? c.findings.map((f) => `[${f.severity}] ${mdCell(f.title)}`).join("; ") : "—";
      lines.push(`| ${mdCell(c.control)} | ${CONTROL_RESULT_TEXT[CONTROL_RESULT[c.status]]} | ${findingList} |`);
    }
    lines.push("");
  }

  return lines.join("\n");
}

/** One row per framework control. The disclaimer is the first row so it's
 *  the first thing anyone opening the file in a spreadsheet sees; use the JSON
 *  export for machine processing. */
export function formatComplianceReportCsv(report: ComplianceReportBundle): string {
  const rows: string[][] = [
    ["Disclaimer", COMPLIANCE_REPORT_DISCLAIMER],
    [],
    ["framework", "control", "result", "finding_count", "findings"],
  ];
  for (const fw of report.frameworks) {
    for (const c of fw.controls) {
      rows.push([
        fw.label,
        c.control,
        CONTROL_RESULT_TEXT[CONTROL_RESULT[c.status]],
        String(c.findings.length),
        c.findings.map((f) => `[${f.severity}] ${f.title} (${f.checkId})`).join("; "),
      ]);
    }
  }
  return rows.map((row) => row.map(csvCell).join(",")).join("\r\n");
}

export function toComplianceExportJson(report: ComplianceReportBundle) {
  return {
    disclaimer: COMPLIANCE_REPORT_DISCLAIMER,
    generated_at: report.generatedAt,
    target_url: report.targetUrl,
    frameworks: report.frameworks.map((fw) => ({
      framework: fw.framework,
      label: fw.label,
      controls_mapped: fw.totalControls,
      controls_without_issues: fw.passing,
      controls_with_issues: fw.totalControls - fw.passing,
      controls: fw.controls.map((c) => ({ control: c.control, result: CONTROL_RESULT[c.status], findings: c.findings })),
    })),
  };
}
