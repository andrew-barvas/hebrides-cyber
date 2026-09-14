import { describe, it, expect } from "vitest";
import { validatePolicy, isCheckEnabled, isFindingExcluded, evaluatePolicyResult, getDefaultPolicy } from "./customScanPolicies";
import type { ScanPolicy } from "./customScanPolicies";

describe("validatePolicy", () => {
  it("accepts a valid policy", () => {
    const result = validatePolicy({ name: "CI Gate", orgId: "org-1", enabledChecks: ["tls", "headers"], severityThreshold: "high" });
    expect(result).toEqual({ valid: true });
  });

  it("rejects empty name", () => {
    const result = validatePolicy({ name: "", orgId: "org-1" });
    expect(result.valid).toBe(false);
  });

  it("rejects unknown check modules", () => {
    const result = validatePolicy({ name: "Test", orgId: "org-1", enabledChecks: ["tls", "bogus"] });
    expect(result.valid).toBe(false);
  });

  it("rejects empty enabledChecks", () => {
    const result = validatePolicy({ name: "Test", orgId: "org-1", enabledChecks: [] });
    expect(result.valid).toBe(false);
  });
});

describe("isCheckEnabled", () => {
  const policy: ScanPolicy = { orgId: "1", name: "T", enabledChecks: ["tls", "headers"], disabledCheckIds: [], severityThreshold: "high" };

  it("allows listed checks", () => {
    expect(isCheckEnabled(policy, "tls")).toBe(true);
  });

  it("blocks unlisted checks", () => {
    expect(isCheckEnabled(policy, "dns")).toBe(false);
  });
});

describe("isFindingExcluded", () => {
  const policy: ScanPolicy = { orgId: "1", name: "T", enabledChecks: [], disabledCheckIds: ["tls.hsts-missing", "exposure.exposed-file"], severityThreshold: "high" };

  it("excludes exact match", () => {
    expect(isFindingExcluded(policy, "tls.hsts-missing")).toBe(true);
  });

  it("excludes base match for keyed checkIds", () => {
    expect(isFindingExcluded(policy, "exposure.exposed-file:.env")).toBe(true);
  });

  it("allows non-excluded findings", () => {
    expect(isFindingExcluded(policy, "tls.no-https")).toBe(false);
  });
});

describe("evaluatePolicyResult", () => {
  const policy: ScanPolicy = { orgId: "1", name: "T", enabledChecks: [], disabledCheckIds: ["tls.hsts-short"], severityThreshold: "high", maxAllowedFindings: 2 };

  it("passes when under threshold", () => {
    const findings = [
      { severity: "medium", checkId: "headers.csp-weak" },
      { severity: "low", checkId: "tls.hsts-short" },
    ];
    const result = evaluatePolicyResult(policy, findings);
    expect(result.passed).toBe(true);
  });

  it("fails when too many findings above threshold", () => {
    const findings = [
      { severity: "high", checkId: "tls.no-https" },
      { severity: "high", checkId: "headers.cors-wildcard" },
      { severity: "critical", checkId: "webapp.cors-reflected-creds" },
    ];
    const result = evaluatePolicyResult(policy, findings);
    expect(result.passed).toBe(false);
  });

  it("excludes disabled checkIds from count", () => {
    const findings = [
      { severity: "high", checkId: "tls.hsts-short" },
      { severity: "high", checkId: "tls.no-https" },
    ];
    const result = evaluatePolicyResult(policy, findings);
    expect(result.passed).toBe(true);
  });
});

describe("getDefaultPolicy", () => {
  it("returns a valid default", () => {
    const p = getDefaultPolicy("org-1");
    expect(p.enabledChecks.length).toBeGreaterThan(0);
    expect(p.severityThreshold).toBe("high");
  });
});
