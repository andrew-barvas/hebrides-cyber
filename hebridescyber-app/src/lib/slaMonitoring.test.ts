import { describe, it, expect } from "vitest";
import { calculateSlaStatus, buildSlaSummary, getDefaultSlaPolicy } from "./slaMonitoring";

const policy = getDefaultSlaPolicy();

describe("calculateSlaStatus", () => {
  it("returns within SLA for fresh critical finding", () => {
    const now = new Date("2026-09-14T12:00:00Z");
    const status = calculateSlaStatus(
      { checkId: "tls.no-https", severity: "critical", title: "No HTTPS", firstSeenAt: "2026-09-14T10:00:00Z" },
      policy,
      now,
    );
    expect(status).not.toBeNull();
    expect(status!.breached).toBe(false);
    expect(status!.hoursRemaining).toBe(22);
  });

  it("marks breach for expired SLA", () => {
    const now = new Date("2026-09-16T12:00:00Z");
    const status = calculateSlaStatus(
      { checkId: "tls.no-https", severity: "critical", title: "No HTTPS", firstSeenAt: "2026-09-14T00:00:00Z" },
      policy,
      now,
    );
    expect(status!.breached).toBe(true);
  });

  it("uses resolved time for resolved findings", () => {
    const now = new Date("2026-09-20T00:00:00Z");
    const status = calculateSlaStatus(
      {
        checkId: "tls.no-https",
        severity: "critical",
        title: "No HTTPS",
        firstSeenAt: "2026-09-14T00:00:00Z",
        resolvedAt: "2026-09-14T12:00:00Z",
      },
      policy,
      now,
    );
    expect(status!.breached).toBe(false);
  });

  it("returns null for info severity", () => {
    const status = calculateSlaStatus(
      { checkId: "test", severity: "info", title: "Info", firstSeenAt: "2026-09-14T00:00:00Z" },
      policy,
    );
    expect(status).toBeNull();
  });

  it("returns null for invalid dates", () => {
    const status = calculateSlaStatus(
      { checkId: "test", severity: "high", title: "Test", firstSeenAt: "not-a-date" },
      policy,
    );
    expect(status).toBeNull();
  });
});

describe("buildSlaSummary", () => {
  it("computes compliance percentage", () => {
    const now = new Date("2026-09-14T12:00:00Z");
    const findings = [
      { checkId: "tls.no-https", severity: "critical", title: "A", firstSeenAt: "2026-09-14T10:00:00Z" },
      { checkId: "headers.csp-absent", severity: "high", title: "B", firstSeenAt: "2026-09-10T00:00:00Z" },
    ];
    const summary = buildSlaSummary(findings, policy, now);
    expect(summary.totalTracked).toBe(2);
    expect(summary.breached).toBe(1);
    expect(summary.compliancePercent).toBe(50);
  });

  it("returns 100% compliance with no findings", () => {
    const summary = buildSlaSummary([], policy);
    expect(summary.compliancePercent).toBe(100);
  });
});
