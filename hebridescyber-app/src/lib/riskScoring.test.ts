import { describe, it, expect } from "vitest";
import { assessRisk, compareRisk, type RiskAssessment } from "./riskScoring";
import type { Finding } from "./scanners/index";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    severity: "medium",
    title: "Test",
    detail: "detail",
    ...overrides,
  };
}

describe("assessRisk", () => {
  it("returns grade A for no findings", () => {
    const result = assessRisk([]);
    expect(result.grade).toBe("A");
    expect(result.overallScore).toBe(0);
    expect(result.factors.length).toBe(5);
  });

  it("returns worse grade for critical findings", () => {
    const findings = [
      makeFinding({ severity: "critical", checkId: "tls.no-https" }),
      makeFinding({ severity: "critical", checkId: "headers.cors-wildcard" }),
      makeFinding({ severity: "high", checkId: "exposure.exposed-file:.env" }),
    ];
    const result = assessRisk(findings);
    expect(result.overallScore).toBeGreaterThan(30);
    expect(["C", "D", "F"]).toContain(result.grade);
  });

  it("includes exploitability factor for proven exploits", () => {
    const findings = [
      makeFinding({
        severity: "high",
        checkId: "webapp.cors-reflected",
        metadata: { proofOfExploit: { confirmed: true } },
      }),
    ];
    const result = assessRisk(findings);
    const exploitFactor = result.factors.find((f) => f.name === "Exploitability");
    expect(exploitFactor!.score).toBeGreaterThan(0);
  });

  it("factors in high CVSS scores", () => {
    const findings = [
      makeFinding({ severity: "critical", cvssScore: 9.8 }),
    ];
    const result = assessRisk(findings);
    const exploitFactor = result.factors.find((f) => f.name === "Exploitability");
    expect(exploitFactor!.score).toBeGreaterThan(0);
  });

  it("counts attack surface from exposure/ports/cloud findings", () => {
    const findings = [
      makeFinding({ severity: "high", checkId: "exposure.exposed-file:.env" }),
      makeFinding({ severity: "medium", checkId: "ports.risky-port:22" }),
      makeFinding({ severity: "high", checkId: "cloud-misconfig.public-bucket:s3:mybucket" }),
    ];
    const result = assessRisk(findings);
    const surfaceFactor = result.factors.find((f) => f.name === "Attack surface");
    expect(surfaceFactor!.score).toBeGreaterThan(0);
  });
});

describe("compareRisk", () => {
  it("detects improvement", () => {
    const current: RiskAssessment = { overallScore: 20, grade: "B", factors: [], generatedAt: "" };
    const previous: RiskAssessment = { overallScore: 50, grade: "C", factors: [], generatedAt: "" };
    expect(compareRisk(current, previous)).toEqual({ direction: "improved", delta: -30 });
  });

  it("detects worsening", () => {
    const current: RiskAssessment = { overallScore: 60, grade: "D", factors: [], generatedAt: "" };
    const previous: RiskAssessment = { overallScore: 30, grade: "B", factors: [], generatedAt: "" };
    expect(compareRisk(current, previous)).toEqual({ direction: "worsened", delta: 30 });
  });

  it("detects unchanged within threshold", () => {
    const current: RiskAssessment = { overallScore: 31, grade: "B", factors: [], generatedAt: "" };
    const previous: RiskAssessment = { overallScore: 30, grade: "B", factors: [], generatedAt: "" };
    expect(compareRisk(current, previous)).toEqual({ direction: "unchanged", delta: 0 });
  });
});
