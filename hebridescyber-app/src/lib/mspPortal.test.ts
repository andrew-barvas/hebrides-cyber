import { describe, it, expect } from "vitest";
import { buildClientSummary, buildMspDashboard } from "./mspPortal";

describe("buildClientSummary", () => {
  it("computes summary for a client with scanned targets", () => {
    const summary = buildClientSummary({
      orgId: "org-1",
      orgName: "Acme Corp",
      targets: [
        { lastScore: 85, lastScanAt: "2026-09-10T00:00:00Z", findings: [{ severity: "medium" }] },
        { lastScore: 60, lastScanAt: "2026-09-11T00:00:00Z", findings: [{ severity: "high" }, { severity: "critical" }] },
      ],
    });
    expect(summary.targetCount).toBe(2);
    expect(summary.averageScore).toBe(73);
    expect(summary.criticalFindings).toBe(1);
    expect(summary.overallHealth).toBe("critical");
  });

  it("handles no scans", () => {
    const summary = buildClientSummary({
      orgId: "org-2",
      orgName: "Empty Co",
      targets: [{ lastScore: null, lastScanAt: null, findings: [] }],
    });
    expect(summary.averageScore).toBeNull();
    expect(summary.overallHealth).toBe("warning");
  });

  it("returns healthy for high scores with no criticals", () => {
    const summary = buildClientSummary({
      orgId: "org-3",
      orgName: "Secure Inc",
      targets: [{ lastScore: 95, lastScanAt: "2026-09-01T00:00:00Z", findings: [] }],
    });
    expect(summary.overallHealth).toBe("healthy");
  });
});

describe("buildMspDashboard", () => {
  it("aggregates client summaries", () => {
    const clients = [
      { orgId: "1", orgName: "A", targetCount: 3, lastScanAt: "2026-09-10", averageScore: 80, criticalFindings: 0, highFindings: 1, overallHealth: "healthy" as const },
      { orgId: "2", orgName: "B", targetCount: 2, lastScanAt: "2026-09-11", averageScore: 40, criticalFindings: 2, highFindings: 3, overallHealth: "critical" as const },
    ];
    const dashboard = buildMspDashboard(clients);
    expect(dashboard.totalClients).toBe(2);
    expect(dashboard.totalTargets).toBe(5);
    expect(dashboard.clientsAtRisk).toBe(1);
    expect(dashboard.averageScore).toBe(60);
    expect(dashboard.clients[0].orgName).toBe("B");
  });
});
