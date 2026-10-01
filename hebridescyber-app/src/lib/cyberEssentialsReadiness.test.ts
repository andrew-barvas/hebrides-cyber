import { describe, it, expect } from "vitest";
import { assessCeReadiness } from "./cyberEssentialsReadiness";
import type { Finding } from "./scanners";

function finding(overrides: Partial<Finding> & Pick<Finding, "checkId" | "severity">): Finding {
  return {
    title: "test",
    detail: "test detail",
    ...overrides,
  };
}

describe("assessCeReadiness", () => {
  it("returns all pass with score 100 when no findings exist", () => {
    const report = assessCeReadiness([]);
    expect(report.overall_status).toBe("ready");
    expect(report.score).toBe(100);
    expect(report.controls).toHaveLength(5);
    report.controls.forEach((c) => {
      expect(c.status).toBe("pass");
      expect(c.gaps).toHaveLength(0);
    });
  });

  it("marks Firewalls as fail when dangerous ports are exposed", () => {
    const findings: Finding[] = [
      finding({ checkId: "nmap.dangerous-port:3306", severity: "high" }),
    ];
    const report = assessCeReadiness(findings);
    const fw = report.controls.find((c) => c.control === "Firewalls and internet gateways")!;
    expect(fw.status).toBe("fail");
    expect(fw.gaps.length).toBeGreaterThan(0);
    expect(fw.gaps.some((g) => g.includes("dangerous port"))).toBe(true);
  });

  it("marks Secure configuration as fail when no HTTPS", () => {
    const findings: Finding[] = [
      finding({ checkId: "tls.no-https", severity: "critical" }),
    ];
    const report = assessCeReadiness(findings);
    const sc = report.controls.find((c) => c.control === "Secure configuration")!;
    expect(sc.status).toBe("fail");
    expect(sc.gaps.some((g) => g.includes("HTTPS"))).toBe(true);
  });

  it("marks User access control as partial when CSRF is missing", () => {
    const findings: Finding[] = [
      finding({ checkId: "business-logic.missing-csrf", severity: "medium" }),
    ];
    const report = assessCeReadiness(findings);
    const uac = report.controls.find((c) => c.control === "User access control")!;
    expect(uac.status).toBe("partial");
    expect(uac.gaps.some((g) => g.includes("CSRF"))).toBe(true);
  });

  it("marks Malware protection as fail when Safe Browsing flags the site", () => {
    const findings: Finding[] = [
      finding({ checkId: "safeBrowsing.flagged", severity: "critical" }),
    ];
    const report = assessCeReadiness(findings);
    const mp = report.controls.find((c) => c.control === "Malware protection")!;
    expect(mp.status).toBe("fail");
    expect(mp.gaps.some((g) => g.includes("Safe Browsing"))).toBe(true);
  });

  it("marks Security update management as fail with vulnerable JS libs", () => {
    const findings: Finding[] = [
      finding({ checkId: "webapp.vulnerable-js-lib:jquery", severity: "high" }),
    ];
    const report = assessCeReadiness(findings);
    const sm = report.controls.find((c) => c.control === "Security update management")!;
    expect(sm.status).toBe("fail");
    expect(sm.gaps.some((g) => g.includes("JavaScript"))).toBe(true);
  });

  it("returns not-ready overall when any control fails", () => {
    const findings: Finding[] = [
      finding({ checkId: "tls.no-https", severity: "critical" }),
    ];
    const report = assessCeReadiness(findings);
    expect(report.overall_status).toBe("not-ready");
    expect(report.score).toBeLessThan(100);
    expect(report.recommendation).toContain("failed");
  });

  it("returns partial when some controls have non-critical gaps", () => {
    const findings: Finding[] = [
      finding({ checkId: "headers.csp-absent", severity: "medium" }),
    ];
    const report = assessCeReadiness(findings);
    expect(report.overall_status).toBe("partial");
    expect(report.recommendation).toContain("attention");
  });

  it("includes WAF evidence when detected", () => {
    const findings: Finding[] = [
      finding({ checkId: "whatwaf.waf-detected", severity: "info" }),
    ];
    const report = assessCeReadiness(findings);
    const fw = report.controls.find((c) => c.control === "Firewalls and internet gateways")!;
    expect(fw.evidence.some((e) => e.includes("WAF") || e.includes("Firewall"))).toBe(true);
  });

  it("flags directory listing under Secure configuration", () => {
    const findings: Finding[] = [
      finding({ checkId: "directoryListing.enabled", severity: "medium" }),
    ];
    const report = assessCeReadiness(findings);
    const sc = report.controls.find((c) => c.control === "Secure configuration")!;
    expect(sc.gaps.some((g) => g.includes("Directory listing"))).toBe(true);
  });

  it("flags rate limiting gaps under User access control", () => {
    const findings: Finding[] = [
      finding({ checkId: "business-logic.no-login-rate-limit", severity: "medium" }),
    ];
    const report = assessCeReadiness(findings);
    const uac = report.controls.find((c) => c.control === "User access control")!;
    expect(uac.gaps.some((g) => g.includes("rate limit"))).toBe(true);
  });

  it("handles multiple controls failing at once", () => {
    const findings: Finding[] = [
      finding({ checkId: "nmap.dangerous-port:3306", severity: "high" }),
      finding({ checkId: "tls.no-https", severity: "critical" }),
      finding({ checkId: "safeBrowsing.flagged", severity: "critical" }),
      finding({ checkId: "webapp.vulnerable-js-lib:lodash", severity: "high" }),
    ];
    const report = assessCeReadiness(findings);
    expect(report.overall_status).toBe("not-ready");
    const failed = report.controls.filter((c) => c.status === "fail");
    expect(failed.length).toBeGreaterThanOrEqual(3);
    expect(report.recommendation).toContain("failed");
  });

  it("score is 0 when all controls fail", () => {
    const findings: Finding[] = [
      finding({ checkId: "nmap.dangerous-port:22", severity: "high" }),
      finding({ checkId: "tls.no-https", severity: "critical" }),
      finding({ checkId: "sessionCheck.session-fixation", severity: "high" }),
      finding({ checkId: "safeBrowsing.flagged", severity: "critical" }),
      finding({ checkId: "webapp.vulnerable-js-lib:angular", severity: "high" }),
    ];
    const report = assessCeReadiness(findings);
    expect(report.score).toBe(0);
    expect(report.overall_status).toBe("not-ready");
  });
});

// Regression: three of this control's ids matched nothing any check produces.
describe("Security update management — real check ids", () => {
  const control = (findings: Finding[]) => assessCeReadiness(findings).controls.find((c) => c.control === "Security update management")!;

  it.each([
    ["eol.unsupported:php", "end-of-life software"],
    ["docker-base-image.outdated-base:node", "Docker base image"],
    ["trivy-image.vulnerable-package:openssl:CVE-2024-0001", "container image"],
    ["fingerprint.risky-library:PHP", "outdated server or CMS"],
  ])("counts %s against the control", (checkId, gap) => {
    const c = control([finding({ checkId, severity: "high" })]);
    expect(c.status).toBe("fail");
    expect(c.gaps.some((g) => g.includes(gap))).toBe(true);
    expect(c.evidence).not.toContain("Software components are up to date with no known vulnerabilities");
  });

  it("does not count an approaching end-of-life date as a gap", () => {
    expect(control([finding({ checkId: "eol.approaching:php", severity: "info" })]).status).toBe("pass");
  });
});
