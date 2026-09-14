// Composite risk scoring — combines multiple signal dimensions into a single
// weighted risk score for a target. Goes beyond the simple severity-penalty
// model in scoreFromFindings() to incorporate temporal factors, asset context,
// and finding density.

import type { Finding } from "./scanners/index";

export type RiskFactor = {
  name: string;
  score: number; // 0-100
  weight: number;
  detail: string;
};

export type RiskAssessment = {
  overallScore: number; // 0-100, higher = more risk
  grade: "A" | "B" | "C" | "D" | "F";
  factors: RiskFactor[];
  generatedAt: string;
};

const SEVERITY_WEIGHTS: Record<Finding["severity"], number> = {
  critical: 40,
  high: 25,
  medium: 12,
  low: 4,
  info: 0,
};

function severityFactor(findings: Finding[]): RiskFactor {
  const maxPossible = 100;
  const rawPenalty = findings.reduce((sum, f) => sum + SEVERITY_WEIGHTS[f.severity], 0);
  const score = Math.min(maxPossible, rawPenalty);
  return {
    name: "Vulnerability severity",
    score,
    weight: 0.35,
    detail: `${findings.filter((f) => f.severity === "critical").length} critical, ${findings.filter((f) => f.severity === "high").length} high, ${findings.filter((f) => f.severity === "medium").length} medium findings`,
  };
}

function densityFactor(findings: Finding[], checkCount: number): RiskFactor {
  const actionable = findings.filter((f) => f.severity !== "info").length;
  const ratio = checkCount > 0 ? actionable / checkCount : 0;
  const score = Math.min(100, Math.round(ratio * 200));
  return {
    name: "Finding density",
    score,
    weight: 0.15,
    detail: `${actionable} actionable findings across ${checkCount} checks (${Math.round(ratio * 100)}% hit rate)`,
  };
}

function exploitabilityFactor(findings: Finding[]): RiskFactor {
  let score = 0;
  const provenExploits = findings.filter(
    (f) => f.metadata?.proofOfExploit && (f.metadata.proofOfExploit as { confirmed?: boolean }).confirmed,
  ).length;
  if (provenExploits > 0) score += Math.min(60, provenExploits * 20);

  const hasCvss = findings.filter((f) => f.cvssScore && f.cvssScore >= 9.0).length;
  score += Math.min(40, hasCvss * 15);

  return {
    name: "Exploitability",
    score: Math.min(100, score),
    weight: 0.25,
    detail: `${provenExploits} proven exploits, ${hasCvss} findings with CVSS ≥ 9.0`,
  };
}

function exposureFactor(findings: Finding[]): RiskFactor {
  let score = 0;
  const exposedFiles = findings.filter((f) => f.checkId?.startsWith("exposure.")).length;
  const openPorts = findings.filter((f) => f.checkId?.startsWith("ports.")).length;
  const publicBuckets = findings.filter((f) => f.checkId?.startsWith("cloud-misconfig.")).length;

  score += Math.min(40, exposedFiles * 10);
  score += Math.min(30, openPorts * 8);
  score += Math.min(30, publicBuckets * 15);

  return {
    name: "Attack surface",
    score: Math.min(100, score),
    weight: 0.15,
    detail: `${exposedFiles} exposed files, ${openPorts} risky ports, ${publicBuckets} public buckets`,
  };
}

function complianceFactor(findings: Finding[]): RiskFactor {
  const withRefs = findings.filter((f) => f.complianceRefs && f.complianceRefs.length > 0);
  const uniqueFrameworks = new Set(withRefs.flatMap((f) => f.complianceRefs!.map((r) => r.framework)));
  const score = Math.min(100, uniqueFrameworks.size * 15 + withRefs.length * 3);
  return {
    name: "Compliance impact",
    score,
    weight: 0.10,
    detail: `${withRefs.length} findings affect ${uniqueFrameworks.size} compliance frameworks`,
  };
}

function gradeFromScore(score: number): RiskAssessment["grade"] {
  if (score <= 15) return "A";
  if (score <= 35) return "B";
  if (score <= 55) return "C";
  if (score <= 75) return "D";
  return "F";
}

export function assessRisk(findings: Finding[], checkCount: number = 15): RiskAssessment {
  const factors = [
    severityFactor(findings),
    densityFactor(findings, checkCount),
    exploitabilityFactor(findings),
    exposureFactor(findings),
    complianceFactor(findings),
  ];

  const overallScore = Math.round(
    factors.reduce((sum, f) => sum + f.score * f.weight, 0),
  );

  return {
    overallScore: Math.min(100, overallScore),
    grade: gradeFromScore(overallScore),
    factors,
    generatedAt: new Date().toISOString(),
  };
}

export function compareRisk(current: RiskAssessment, previous: RiskAssessment): {
  direction: "improved" | "worsened" | "unchanged";
  delta: number;
} {
  const delta = current.overallScore - previous.overallScore;
  if (Math.abs(delta) < 3) return { direction: "unchanged", delta: 0 };
  return { direction: delta < 0 ? "improved" : "worsened", delta };
}
