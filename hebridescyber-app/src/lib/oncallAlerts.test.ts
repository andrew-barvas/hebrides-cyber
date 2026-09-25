import { describe, it, expect, vi, beforeEach } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { ScanReport } from "./scanReport";

const { createPagerDutyIncidentMock, resolvePagerDutyIncidentMock, createOpsgenieAlertMock, resolveOpsgenieAlertMock } = vi.hoisted(() => ({
  createPagerDutyIncidentMock: vi.fn(),
  resolvePagerDutyIncidentMock: vi.fn(),
  createOpsgenieAlertMock: vi.fn(),
  resolveOpsgenieAlertMock: vi.fn(),
}));

vi.mock("./oncallIntegrations", () => ({
  createPagerDutyIncident: createPagerDutyIncidentMock,
  resolvePagerDutyIncident: resolvePagerDutyIncidentMock,
  createOpsgenieAlert: createOpsgenieAlertMock,
  resolveOpsgenieAlert: resolveOpsgenieAlertMock,
}));

import { computeOncallDedupKey, triggerOncallAlerts, resolveOncallAlerts } from "./oncallAlerts";

let integrationRows: Array<Record<string, unknown>> = [];

function makeSupabase(): SupabaseClient {
  const builder: Record<string, unknown> = {
    select: () => builder,
    eq: () => builder,
    in: () => Promise.resolve({ data: integrationRows }),
  };
  return { from: () => builder } as unknown as SupabaseClient;
}

function report(overrides: Partial<ScanReport> = {}): ScanReport {
  return {
    scan_id: "scan-1",
    target_url: "https://example.com",
    status: "completed",
    created_at: "2026-03-01T00:00:00Z",
    score: 40,
    findings: [],
    fixed_findings: [],
    critical_paths: [],
    ...overrides,
  };
}

describe("computeOncallDedupKey", () => {
  it("is deterministic for the same inputs", () => {
    const a = computeOncallDedupKey("owner-1", "example.com", "tls.weak-protocol");
    const b = computeOncallDedupKey("owner-1", "example.com", "tls.weak-protocol");
    expect(a).toBe(b);
  });

  it("differs when any input differs", () => {
    const base = computeOncallDedupKey("owner-1", "example.com", "tls.weak-protocol");
    expect(computeOncallDedupKey("owner-2", "example.com", "tls.weak-protocol")).not.toBe(base);
    expect(computeOncallDedupKey("owner-1", "other.com", "tls.weak-protocol")).not.toBe(base);
    expect(computeOncallDedupKey("owner-1", "example.com", "headers.missing-csp")).not.toBe(base);
  });

  it("is prefixed with hc- and safe for PagerDuty/Opsgenie identifiers", () => {
    const key = computeOncallDedupKey("owner-1", "example.com", "tls.weak-protocol");
    expect(key).toMatch(/^hc-[0-9a-f]{40}$/);
  });
});

describe("triggerOncallAlerts", () => {
  beforeEach(() => {
    integrationRows = [];
    createPagerDutyIncidentMock.mockReset().mockResolvedValue({ ok: true, alertId: "dk", url: "https://app.pagerduty.com" });
    resolvePagerDutyIncidentMock.mockReset().mockResolvedValue(true);
    createOpsgenieAlertMock.mockReset().mockResolvedValue({ ok: true, alertId: "a", url: "https://app.opsgenie.com/alert/detail/a" });
    resolveOpsgenieAlertMock.mockReset().mockResolvedValue(true);
  });

  it("calls nothing when no oncall integration rows exist", async () => {
    const r = report({
      findings: [{ check_id: "tls.weak-protocol", severity: "critical", title: "Weak TLS", detail: "d", remediation: null, status: "new" }],
    });
    await triggerOncallAlerts(makeSupabase(), "owner-1", r);
    expect(createPagerDutyIncidentMock).not.toHaveBeenCalled();
    expect(createOpsgenieAlertMock).not.toHaveBeenCalled();
  });

  it("calls nothing when there are no new critical findings", async () => {
    integrationRows = [{ provider: "pagerduty", pagerduty_routing_key: "rk", opsgenie_api_key: null, region: null }];
    const r = report({
      findings: [
        { check_id: "tls.weak-protocol", severity: "high", title: "Weak TLS", detail: "d", remediation: null, status: "new" },
        { check_id: "headers.missing-csp", severity: "critical", title: "No CSP", detail: "d", remediation: null, status: "unchanged" },
      ],
    });
    await triggerOncallAlerts(makeSupabase(), "owner-1", r);
    expect(createPagerDutyIncidentMock).not.toHaveBeenCalled();
  });

  it("calls createPagerDutyIncident once with the deterministic dedup key for a new critical finding", async () => {
    integrationRows = [{ provider: "pagerduty", pagerduty_routing_key: "rk", opsgenie_api_key: null, region: null }];
    const r = report({
      findings: [{ check_id: "tls.weak-protocol", severity: "critical", title: "Weak TLS", detail: "d", remediation: null, status: "new" }],
    });

    await triggerOncallAlerts(makeSupabase(), "owner-1", r);

    const expectedKey = computeOncallDedupKey("owner-1", "example.com", "tls.weak-protocol");
    expect(createPagerDutyIncidentMock).toHaveBeenCalledTimes(1);
    expect(createPagerDutyIncidentMock).toHaveBeenCalledWith(
      "rk",
      expect.objectContaining({ dedupKey: expectedKey, summary: "Weak TLS", severity: "critical" })
    );
    expect(createOpsgenieAlertMock).not.toHaveBeenCalled();
  });

  it("fires to both providers when an owner has both configured", async () => {
    integrationRows = [
      { provider: "pagerduty", pagerduty_routing_key: "rk", opsgenie_api_key: null, region: null },
      { provider: "opsgenie", pagerduty_routing_key: null, opsgenie_api_key: "ok", region: "eu" },
    ];
    const r = report({
      findings: [{ check_id: "tls.weak-protocol", severity: "critical", title: "Weak TLS", detail: "d", remediation: null, status: "new" }],
    });

    await triggerOncallAlerts(makeSupabase(), "owner-1", r);

    expect(createPagerDutyIncidentMock).toHaveBeenCalledTimes(1);
    expect(createOpsgenieAlertMock).toHaveBeenCalledTimes(1);
    const expectedKey = computeOncallDedupKey("owner-1", "example.com", "tls.weak-protocol");
    expect(createOpsgenieAlertMock).toHaveBeenCalledWith("ok", "eu", expect.objectContaining({ alias: expectedKey }));
  });

  it("skips a finding with no check_id", async () => {
    integrationRows = [{ provider: "pagerduty", pagerduty_routing_key: "rk", opsgenie_api_key: null, region: null }];
    const r = report({
      findings: [{ check_id: null, severity: "critical", title: "Weak TLS", detail: "d", remediation: null, status: "new" }],
    });
    await triggerOncallAlerts(makeSupabase(), "owner-1", r);
    expect(createPagerDutyIncidentMock).not.toHaveBeenCalled();
  });

  it("swallows an unexpected error and never throws", async () => {
    integrationRows = [{ provider: "pagerduty", pagerduty_routing_key: "rk", opsgenie_api_key: null, region: null }];
    createPagerDutyIncidentMock.mockRejectedValue(new Error("network exploded"));
    const r = report({
      findings: [{ check_id: "tls.weak-protocol", severity: "critical", title: "Weak TLS", detail: "d", remediation: null, status: "new" }],
    });
    await expect(triggerOncallAlerts(makeSupabase(), "owner-1", r)).resolves.toBeUndefined();
  });
});

describe("resolveOncallAlerts", () => {
  beforeEach(() => {
    integrationRows = [];
    createPagerDutyIncidentMock.mockReset().mockResolvedValue({ ok: true, alertId: "dk", url: "https://app.pagerduty.com" });
    resolvePagerDutyIncidentMock.mockReset().mockResolvedValue(true);
    createOpsgenieAlertMock.mockReset().mockResolvedValue({ ok: true, alertId: "a", url: "https://app.opsgenie.com/alert/detail/a" });
    resolveOpsgenieAlertMock.mockReset().mockResolvedValue(true);
  });

  it("calls nothing when there are no fixed findings", async () => {
    integrationRows = [{ provider: "pagerduty", pagerduty_routing_key: "rk", opsgenie_api_key: null, region: null }];
    await resolveOncallAlerts(makeSupabase(), "owner-1", report({ fixed_findings: [] }));
    expect(resolvePagerDutyIncidentMock).not.toHaveBeenCalled();
  });

  it("calls nothing when no oncall integration rows exist", async () => {
    const r = report({ fixed_findings: [{ check_id: "tls.weak-protocol", severity: "critical", title: "Weak TLS" }] });
    await resolveOncallAlerts(makeSupabase(), "owner-1", r);
    expect(resolvePagerDutyIncidentMock).not.toHaveBeenCalled();
  });

  it("resolves with the SAME dedup key a corresponding trigger would have used, regardless of severity", async () => {
    integrationRows = [{ provider: "pagerduty", pagerduty_routing_key: "rk", opsgenie_api_key: null, region: null }];
    // Fixed finding severity is "medium" here — resolve fires anyway; we
    // don't know whether it was ever alerted on, and resolving an unknown
    // dedup_key is a harmless no-op per resolvePagerDutyIncident's contract.
    const r = report({ fixed_findings: [{ check_id: "tls.weak-protocol", severity: "medium", title: "Weak TLS" }] });

    await resolveOncallAlerts(makeSupabase(), "owner-1", r);

    const expectedKey = computeOncallDedupKey("owner-1", "example.com", "tls.weak-protocol");
    expect(resolvePagerDutyIncidentMock).toHaveBeenCalledWith("rk", expectedKey);
  });

  it("ignores fixed findings with no check_id", async () => {
    integrationRows = [{ provider: "pagerduty", pagerduty_routing_key: "rk", opsgenie_api_key: null, region: null }];
    const r = report({ fixed_findings: [{ check_id: null, severity: "critical", title: "Legacy" }] });
    await resolveOncallAlerts(makeSupabase(), "owner-1", r);
    expect(resolvePagerDutyIncidentMock).not.toHaveBeenCalled();
  });

  it("resolves on Opsgenie with region when configured", async () => {
    integrationRows = [{ provider: "opsgenie", pagerduty_routing_key: null, opsgenie_api_key: "ok", region: "eu" }];
    const r = report({ fixed_findings: [{ check_id: "tls.weak-protocol", severity: "high", title: "Weak TLS" }] });

    await resolveOncallAlerts(makeSupabase(), "owner-1", r);

    const expectedKey = computeOncallDedupKey("owner-1", "example.com", "tls.weak-protocol");
    expect(resolveOpsgenieAlertMock).toHaveBeenCalledWith("ok", "eu", expectedKey);
  });

  it("swallows an unexpected error and never throws", async () => {
    integrationRows = [{ provider: "pagerduty", pagerduty_routing_key: "rk", opsgenie_api_key: null, region: null }];
    resolvePagerDutyIncidentMock.mockRejectedValue(new Error("network exploded"));
    const r = report({ fixed_findings: [{ check_id: "tls.weak-protocol", severity: "critical", title: "Weak TLS" }] });
    await expect(resolveOncallAlerts(makeSupabase(), "owner-1", r)).resolves.toBeUndefined();
  });
});
