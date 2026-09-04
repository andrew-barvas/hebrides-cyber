import { describe, it, expect } from "vitest";
import { coverageForFindings } from "./clientScanHistory";
import { ALL_CONTROLS_BY_FRAMEWORK } from "./scanners/compliance";

describe("coverageForFindings", () => {
  it("reports 100% coverage for every framework when there are no findings", () => {
    const coverage = coverageForFindings([]);
    expect(coverage["cyber-essentials"]).toBe(1);
    expect(coverage["owasp-top-10"]).toBe(1);
    expect(coverage["cis-controls-v8"]).toBe(1);
  });

  it("ignores info-severity findings entirely", () => {
    const coverage = coverageForFindings([{ severity: "info", checkId: "sqlmap.sqli" }]);
    expect(coverage["owasp-top-10"]).toBe(1);
  });

  it("reduces coverage for the framework(s) a real finding's checkId maps to", () => {
    const coverage = coverageForFindings([{ severity: "critical", checkId: "sqlmap.sqli" }]);
    const total = ALL_CONTROLS_BY_FRAMEWORK["owasp-top-10"].size;
    expect(coverage["owasp-top-10"]).toBeCloseTo(1 - 1 / total);
  });

  it("does not double-count the same control cited by two different findings", () => {
    // sqlmap.sqli and commix.command-injection both cite OWASP A03 — one
    // finding of each should reduce coverage by exactly one control, not two.
    const withOne = coverageForFindings([{ severity: "critical", checkId: "sqlmap.sqli" }]);
    const withBoth = coverageForFindings([
      { severity: "critical", checkId: "sqlmap.sqli" },
      { severity: "high", checkId: "commix.command-injection" },
    ]);
    expect(withBoth["owasp-top-10"]).toBe(withOne["owasp-top-10"]);
  });

  it("returns coverage of exactly 0 (not negative) when every control in a framework is at risk", () => {
    // Not realistic with today's mapping, but the calculation shouldn't be
    // able to go negative if it ever were.
    const allCeChecks = ["tls.no-https", "headers.missing-critical", "ports.risky-port", "webapp.wp-xmlrpc"];
    const coverage = coverageForFindings(allCeChecks.map((checkId) => ({ severity: "high", checkId })));
    expect(coverage["cyber-essentials"]).toBeGreaterThanOrEqual(0);
  });

  it("leaves an unmapped checkId's finding with no effect on any framework's coverage", () => {
    const coverage = coverageForFindings([{ severity: "critical", checkId: "some-check-nobody-has-mapped-yet" }]);
    expect(coverage["cyber-essentials"]).toBe(1);
    expect(coverage["owasp-top-10"]).toBe(1);
    expect(coverage["cis-controls-v8"]).toBe(1);
  });
});
