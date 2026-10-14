import { describe, expect, it } from "vitest";
import { scoreFromFindings, type Finding } from "./index";
import { MAX_PENALTY_PER_FINDING, SEVERITY_PENALTY, findingPenalty } from "./riskScore";

function finding(severity: Finding["severity"], extra: Partial<Finding> = {}): Finding {
  return { severity, title: "t", detail: "d", ...extra };
}

describe("findingPenalty — findings with no CVSS or threat intel", () => {
  it.each(Object.entries(SEVERITY_PENALTY))("costs the flat %s penalty", (severity, penalty) => {
    expect(findingPenalty(finding(severity as Finding["severity"]))).toBe(penalty);
  });

  it("keeps the flat scores every existing report was produced with", () => {
    const findings = [finding("critical"), finding("high"), finding("medium"), finding("high"), finding("low"), finding("info")];
    expect(scoreFromFindings(findings)).toBe(100 - 30 - 15 - 7 - 15 - 2);
  });

  it("is 100 for no findings and never below 0", () => {
    expect(scoreFromFindings([])).toBe(100);
    expect(scoreFromFindings(Array.from({ length: 10 }, () => finding("critical")))).toBe(0);
  });
});

describe("findingPenalty — CVSS", () => {
  it("raises a finding rated below its CVSS band to that band's penalty", () => {
    expect(findingPenalty(finding("medium", { cvssScore: 9.8 }))).toBe(30);
    expect(findingPenalty(finding("low", { cvssScore: 7.5 }))).toBe(15);
    expect(findingPenalty(finding("low", { cvssScore: 5.0 }))).toBe(7);
  });

  it("never lowers a penalty: a high-severity finding with a modest CVSS stays at high", () => {
    expect(findingPenalty(finding("high", { cvssScore: 3.1 }))).toBe(15);
    expect(findingPenalty(finding("critical", { cvssScore: 7.2 }))).toBe(30);
  });

  it("ignores a non-numeric CVSS score", () => {
    expect(findingPenalty(finding("low", { cvssScore: Number.NaN }))).toBe(2);
  });
});

describe("findingPenalty — CISA KEV and EPSS", () => {
  it("charges a KEV-listed finding 1.5x, and 2x when used in ransomware campaigns", () => {
    expect(findingPenalty(finding("high", { threatIntel: { knownExploited: true } }))).toBe(22.5);
    expect(findingPenalty(finding("high", { threatIntel: { knownExploited: true, ransomware: true } }))).toBe(30);
  });

  it("caps a single finding so one CVE cannot blank the whole score", () => {
    const worst = finding("critical", { threatIntel: { knownExploited: true, ransomware: true } });
    expect(findingPenalty(worst)).toBe(MAX_PENALTY_PER_FINDING);
    expect(scoreFromFindings([worst])).toBe(55);
  });

  it("raises the penalty for a high or elevated EPSS", () => {
    expect(findingPenalty(finding("high", { threatIntel: { knownExploited: false, epss: 0.7 } }))).toBe(21);
    expect(findingPenalty(finding("high", { threatIntel: { knownExploited: false, epss: 0.2 } }))).toBe(18);
  });

  it("leaves the penalty alone for a middling EPSS", () => {
    expect(findingPenalty(finding("high", { threatIntel: { knownExploited: false, epss: 0.05 } }))).toBe(15);
  });

  it("lowers the penalty only for a measured, negligible EPSS on a finding not in KEV", () => {
    expect(findingPenalty(finding("high", { threatIntel: { knownExploited: false, epss: 0.002 } }))).toBe(11.25);
    expect(findingPenalty(finding("high", { threatIntel: { knownExploited: true, epss: 0.002 } }))).toBe(22.5);
  });

  it("treats absent intel as unknown: no change either way", () => {
    expect(findingPenalty(finding("high", { threatIntel: { knownExploited: false } }))).toBe(15);
    expect(findingPenalty(finding("high"))).toBe(15);
  });

  it("combines a CVSS floor with KEV", () => {
    expect(findingPenalty(finding("medium", { cvssScore: 9.8, threatIntel: { knownExploited: true } }))).toBe(45);
  });

  it("never charges an info finding, whatever it carries", () => {
    expect(findingPenalty(finding("info", { cvssScore: 9.8, threatIntel: { knownExploited: true } }))).toBe(0);
  });
});

describe("scoreFromFindings — rounding", () => {
  it("rounds the total once, not each finding", () => {
    const a = finding("high", { threatIntel: { knownExploited: false, epss: 0.002 } });
    expect(scoreFromFindings([a])).toBe(89);
    expect(scoreFromFindings([a, a])).toBe(78);
  });
});
