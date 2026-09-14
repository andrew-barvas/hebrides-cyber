// MSP multi-tenant portal — aggregates scan data across multiple client
// organizations for managed security service providers. Pure functions that
// operate on pre-fetched data; DB queries live in the API route.

export type ClientSummary = {
  orgId: string;
  orgName: string;
  targetCount: number;
  lastScanAt: string | null;
  averageScore: number | null;
  criticalFindings: number;
  highFindings: number;
  overallHealth: "healthy" | "warning" | "critical";
};

export type MspDashboard = {
  generatedAt: string;
  totalClients: number;
  totalTargets: number;
  clientsAtRisk: number;
  averageScore: number;
  clients: ClientSummary[];
};

function healthFromScore(score: number | null, criticals: number): ClientSummary["overallHealth"] {
  if (criticals > 0) return "critical";
  if (score === null) return "warning";
  if (score >= 70) return "healthy";
  if (score >= 40) return "warning";
  return "critical";
}

export function buildClientSummary(client: {
  orgId: string;
  orgName: string;
  targets: Array<{
    lastScore: number | null;
    lastScanAt: string | null;
    findings: Array<{ severity: string }>;
  }>;
}): ClientSummary {
  const targetCount = client.targets.length;
  const scannedTargets = client.targets.filter((t) => t.lastScore !== null);
  const averageScore = scannedTargets.length > 0
    ? Math.round(scannedTargets.reduce((s, t) => s + (t.lastScore ?? 0), 0) / scannedTargets.length)
    : null;

  const allFindings = client.targets.flatMap((t) => t.findings);
  const criticalFindings = allFindings.filter((f) => f.severity === "critical").length;
  const highFindings = allFindings.filter((f) => f.severity === "high").length;

  const lastScanAt = client.targets
    .map((t) => t.lastScanAt)
    .filter(Boolean)
    .sort()
    .pop() ?? null;

  return {
    orgId: client.orgId,
    orgName: client.orgName,
    targetCount,
    lastScanAt,
    averageScore,
    criticalFindings,
    highFindings,
    overallHealth: healthFromScore(averageScore, criticalFindings),
  };
}

export function buildMspDashboard(clients: ClientSummary[]): MspDashboard {
  const totalTargets = clients.reduce((s, c) => s + c.targetCount, 0);
  const clientsAtRisk = clients.filter((c) => c.overallHealth === "critical").length;
  const scoredClients = clients.filter((c) => c.averageScore !== null);
  const averageScore = scoredClients.length > 0
    ? Math.round(scoredClients.reduce((s, c) => s + (c.averageScore ?? 0), 0) / scoredClients.length)
    : 0;

  return {
    generatedAt: new Date().toISOString(),
    totalClients: clients.length,
    totalTargets,
    clientsAtRisk,
    averageScore,
    clients: clients.sort((a, b) => (a.averageScore ?? 0) - (b.averageScore ?? 0)),
  };
}
