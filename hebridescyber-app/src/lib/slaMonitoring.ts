// SLA monitoring — tracks whether vulnerability remediation meets defined
// service level agreements. Pure functions that operate on finding timestamps
// and SLA definitions.

export type SlaTier = {
  severity: "critical" | "high" | "medium" | "low";
  maxHours: number;
};

export type SlaPolicy = {
  name: string;
  tiers: SlaTier[];
};

export type SlaStatus = {
  checkId: string;
  severity: string;
  title: string;
  firstSeenAt: string;
  slaDeadline: string;
  hoursRemaining: number;
  breached: boolean;
  resolvedAt?: string;
};

export type SlaSummary = {
  totalTracked: number;
  withinSla: number;
  breached: number;
  compliancePercent: number;
  items: SlaStatus[];
};

const DEFAULT_SLA_TIERS: SlaTier[] = [
  { severity: "critical", maxHours: 24 },
  { severity: "high", maxHours: 72 },
  { severity: "medium", maxHours: 168 },
  { severity: "low", maxHours: 720 },
];

export function getDefaultSlaPolicy(): SlaPolicy {
  return { name: "Default", tiers: DEFAULT_SLA_TIERS };
}

function getMaxHours(policy: SlaPolicy, severity: string): number | null {
  const tier = policy.tiers.find((t) => t.severity === severity);
  return tier?.maxHours ?? null;
}

export function calculateSlaStatus(
  finding: { checkId: string; severity: string; title: string; firstSeenAt: string; resolvedAt?: string },
  policy: SlaPolicy,
  now: Date = new Date(),
): SlaStatus | null {
  const maxHours = getMaxHours(policy, finding.severity);
  if (maxHours === null) return null;

  const firstSeen = new Date(finding.firstSeenAt);
  if (isNaN(firstSeen.getTime())) return null;

  const deadline = new Date(firstSeen.getTime() + maxHours * 60 * 60 * 1000);
  const resolvedAt = finding.resolvedAt ? new Date(finding.resolvedAt) : null;

  const effectiveEnd = resolvedAt ?? now;
  const hoursRemaining = (deadline.getTime() - effectiveEnd.getTime()) / (60 * 60 * 1000);
  const breached = hoursRemaining < 0;

  return {
    checkId: finding.checkId,
    severity: finding.severity,
    title: finding.title,
    firstSeenAt: finding.firstSeenAt,
    slaDeadline: deadline.toISOString(),
    hoursRemaining: Math.round(hoursRemaining * 10) / 10,
    breached,
    resolvedAt: finding.resolvedAt,
  };
}

export function buildSlaSummary(
  findings: Array<{ checkId: string; severity: string; title: string; firstSeenAt: string; resolvedAt?: string }>,
  policy: SlaPolicy,
  now: Date = new Date(),
): SlaSummary {
  const items: SlaStatus[] = [];

  for (const finding of findings) {
    const status = calculateSlaStatus(finding, policy, now);
    if (status) items.push(status);
  }

  const breached = items.filter((i) => i.breached).length;
  const withinSla = items.length - breached;
  const compliancePercent = items.length > 0 ? Math.round((withinSla / items.length) * 100) : 100;

  return { totalTracked: items.length, withinSla, breached, compliancePercent, items };
}
