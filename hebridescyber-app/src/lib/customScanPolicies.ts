// Custom scan policies — lets organizations define which checks run, severity
// thresholds for pass/fail, and excluded checkIds. Pure validation and
// matching functions; the policy itself is stored in Supabase.

export type ScanPolicy = {
  id?: string;
  orgId: string;
  name: string;
  enabledChecks: string[];
  disabledCheckIds: string[];
  severityThreshold: "critical" | "high" | "medium" | "low";
  maxAllowedFindings?: number;
  createdAt?: string;
};

const ALL_CHECK_MODULES = [
  "tls", "headers", "dns", "exposure", "directoryListing", "cloudMisconfig",
  "fingerprint", "ports", "recon", "webapp", "safeBrowsing", "waybackDiscovery",
  "hibp", "wpVulnDb", "playwright", "zap",
] as const;

export type CheckModule = typeof ALL_CHECK_MODULES[number];

export function isValidCheckModule(name: string): name is CheckModule {
  return (ALL_CHECK_MODULES as readonly string[]).includes(name);
}

export function validatePolicy(policy: Partial<ScanPolicy>): { valid: true } | { valid: false; errors: string[] } {
  const errors: string[] = [];
  if (!policy.name?.trim()) errors.push("Policy name is required");
  if (!policy.orgId) errors.push("Organization ID is required");

  if (policy.enabledChecks) {
    for (const check of policy.enabledChecks) {
      if (!isValidCheckModule(check)) errors.push(`Unknown check module: ${check}`);
    }
    if (policy.enabledChecks.length === 0) errors.push("At least one check must be enabled");
  }

  if (policy.severityThreshold) {
    const valid = ["critical", "high", "medium", "low"];
    if (!valid.includes(policy.severityThreshold)) {
      errors.push(`Invalid severity threshold: ${policy.severityThreshold}`);
    }
  }

  if (policy.maxAllowedFindings !== undefined && policy.maxAllowedFindings < 0) {
    errors.push("maxAllowedFindings must be non-negative");
  }

  return errors.length === 0 ? { valid: true } : { valid: false, errors };
}

const SEVERITY_ORDER: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export function isCheckEnabled(policy: ScanPolicy, checkModule: string): boolean {
  if (policy.enabledChecks.length > 0 && !policy.enabledChecks.includes(checkModule)) return false;
  return true;
}

export function isFindingExcluded(policy: ScanPolicy, checkId: string): boolean {
  const base = checkId.includes(":") ? checkId.slice(0, checkId.indexOf(":")) : checkId;
  return policy.disabledCheckIds.includes(base) || policy.disabledCheckIds.includes(checkId);
}

export function evaluatePolicyResult(
  policy: ScanPolicy,
  findings: Array<{ severity: string; checkId?: string }>,
): { passed: boolean; reason: string } {
  const thresholdLevel = SEVERITY_ORDER[policy.severityThreshold] ?? 3;

  const actionable = findings.filter((f) => {
    if (f.checkId && isFindingExcluded(policy, f.checkId)) return false;
    return (SEVERITY_ORDER[f.severity] ?? 0) >= thresholdLevel;
  });

  if (policy.maxAllowedFindings !== undefined && actionable.length > policy.maxAllowedFindings) {
    return {
      passed: false,
      reason: `${actionable.length} findings at or above ${policy.severityThreshold} severity (max allowed: ${policy.maxAllowedFindings})`,
    };
  }

  if (actionable.length > 0 && policy.maxAllowedFindings === undefined) {
    return {
      passed: false,
      reason: `${actionable.length} findings at or above ${policy.severityThreshold} severity`,
    };
  }

  return { passed: true, reason: "All checks within policy thresholds" };
}

export function getDefaultPolicy(orgId: string): ScanPolicy {
  return {
    orgId,
    name: "Default",
    enabledChecks: [...ALL_CHECK_MODULES],
    disabledCheckIds: [],
    severityThreshold: "high",
  };
}
