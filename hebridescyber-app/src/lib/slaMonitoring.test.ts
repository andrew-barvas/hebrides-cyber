import { describe, it, expect } from "vitest";
import {
  DEFAULT_SLA_POLICY,
  buildSlaSummary,
  policyFromRow,
  selectSlaAlerts,
  slaItem,
  type LifecycleRow,
  type SlaPolicy,
} from "./slaMonitoring";

const NOW = new Date("2026-09-27T12:00:00Z");
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();

function row(overrides: Partial<LifecycleRow> = {}): LifecycleRow {
  return {
    id: "r1",
    target_host: "shop.example",
    check_id: "headers.csp-absent",
    severity: "high",
    title: "CSP missing",
    first_seen_at: daysAgo(1),
    last_seen_at: daysAgo(0),
    resolved_at: null,
    ...overrides,
  };
}

describe("policyFromRow", () => {
  it("uses the defaults when the account has no policy row", () => {
    expect(policyFromRow(null)).toBe(DEFAULT_SLA_POLICY);
    expect(DEFAULT_SLA_POLICY.days).toEqual({ critical: 15, high: 30, medium: 90, low: 180 });
  });

  it("maps a stored row", () => {
    expect(
      policyFromRow({ critical_days: 7, high_days: 14, medium_days: 60, low_days: 120, warn_days: 5, alerts_enabled: false })
    ).toEqual({ days: { critical: 7, high: 14, medium: 60, low: 120 }, warnDays: 5, alertsEnabled: false });
  });
});

describe("slaItem", () => {
  it("is on track early in the window", () => {
    const item = slaItem(row({ first_seen_at: daysAgo(10) }), DEFAULT_SLA_POLICY, NOW)!;
    expect(item.state).toBe("on_track");
    expect(item.daysRemaining).toBeCloseTo(20);
    expect(item.dueAt).toBe(new Date(Date.parse(daysAgo(10)) + 30 * 86_400_000).toISOString());
  });

  it("is due soon inside the warning window, including the last moment", () => {
    expect(slaItem(row({ first_seen_at: daysAgo(28) }), DEFAULT_SLA_POLICY, NOW)!.state).toBe("due_soon");
    expect(slaItem(row({ first_seen_at: daysAgo(30) }), DEFAULT_SLA_POLICY, NOW)!.state).toBe("due_soon");
  });

  it("is breached past the deadline", () => {
    const item = slaItem(row({ first_seen_at: daysAgo(31) }), DEFAULT_SLA_POLICY, NOW)!;
    expect(item.state).toBe("breached");
    expect(item.daysRemaining).toBeCloseTo(-1);
  });

  it("uses each severity's own target", () => {
    expect(slaItem(row({ severity: "critical", first_seen_at: daysAgo(16) }), DEFAULT_SLA_POLICY, NOW)!.state).toBe("breached");
    expect(slaItem(row({ severity: "medium", first_seen_at: daysAgo(16) }), DEFAULT_SLA_POLICY, NOW)!.state).toBe("on_track");
  });

  it("ignores resolved rows, info findings and unparseable dates", () => {
    expect(slaItem(row({ resolved_at: daysAgo(0) }), DEFAULT_SLA_POLICY, NOW)).toBeNull();
    expect(slaItem(row({ severity: "info" }), DEFAULT_SLA_POLICY, NOW)).toBeNull();
    expect(slaItem(row({ first_seen_at: "not a date" }), DEFAULT_SLA_POLICY, NOW)).toBeNull();
  });
});

describe("buildSlaSummary", () => {
  const rows: LifecycleRow[] = [
    row({ id: "a", severity: "critical", first_seen_at: daysAgo(20), target_host: "a.example" }), // breached
    row({ id: "b", severity: "high", first_seen_at: daysAgo(28), target_host: "b.example" }), // due soon
    row({ id: "c", severity: "low", first_seen_at: daysAgo(5), target_host: "a.example" }), // on track
    row({ id: "d", severity: "info", first_seen_at: daysAgo(400) }), // no SLA
    row({ id: "e", severity: "high", first_seen_at: daysAgo(40), resolved_at: daysAgo(30) }), // fixed in 10d
    row({ id: "f", severity: "high", first_seen_at: daysAgo(80), resolved_at: daysAgo(30) }), // fixed in 50d, late
    row({ id: "g", severity: "high", first_seen_at: daysAgo(30), resolved_at: daysAgo(10) }), // fixed in 20d
  ];
  const summary = buildSlaSummary(rows, DEFAULT_SLA_POLICY, NOW);

  it("counts open items by state, skipping resolved and info", () => {
    expect(summary).toMatchObject({ open: 3, onTrack: 1, dueSoon: 1, breached: 1 });
  });

  it("orders items most urgent first", () => {
    expect(summary.items.map((i) => i.id)).toEqual(["a", "b", "c"]);
  });

  it("reports median time-to-fix and within-SLA count per severity", () => {
    expect(summary.resolved.high).toEqual({ count: 3, medianDaysToFix: 20, withinSla: 2 });
    expect(summary.resolved.critical).toEqual({ count: 0, medianDaysToFix: null, withinSla: 0 });
  });

  it("ranks sites by breaches, then due-soon", () => {
    expect(summary.hosts).toEqual([
      { host: "a.example", open: 2, dueSoon: 0, breached: 1 },
      { host: "b.example", open: 1, dueSoon: 1, breached: 0 },
    ]);
  });

  it("averages the middle pair for an even count", () => {
    const even = buildSlaSummary(
      [
        row({ id: "x", first_seen_at: daysAgo(12), resolved_at: daysAgo(2) }),
        row({ id: "y", first_seen_at: daysAgo(22), resolved_at: daysAgo(2) }),
      ],
      DEFAULT_SLA_POLICY,
      NOW
    );
    expect(even.resolved.high.medianDaysToFix).toBe(15);
  });
});

describe("selectSlaAlerts", () => {
  it("warns once when a finding becomes due soon", () => {
    const due = row({ first_seen_at: daysAgo(28) });
    expect(selectSlaAlerts([due], DEFAULT_SLA_POLICY, NOW).dueSoon).toHaveLength(1);
    expect(selectSlaAlerts([{ ...due, sla_warned_at: daysAgo(0) }], DEFAULT_SLA_POLICY, NOW).dueSoon).toHaveLength(0);
  });

  it("notifies once on breach, even if it was already warned", () => {
    const late = row({ first_seen_at: daysAgo(31), sla_warned_at: daysAgo(2) });
    expect(selectSlaAlerts([late], DEFAULT_SLA_POLICY, NOW).breached).toHaveLength(1);
    expect(selectSlaAlerts([{ ...late, sla_breach_notified_at: daysAgo(0) }], DEFAULT_SLA_POLICY, NOW).breached).toHaveLength(0);
  });

  it("sends only the breach alert when a finding skips straight past due-soon", () => {
    const result = selectSlaAlerts([row({ first_seen_at: daysAgo(45) })], DEFAULT_SLA_POLICY, NOW);
    expect(result).toMatchObject({ dueSoon: [], breached: [expect.objectContaining({ id: "r1" })] });
  });

  it("sends nothing when the account turned alerts off", () => {
    const off: SlaPolicy = { ...DEFAULT_SLA_POLICY, alertsEnabled: false };
    expect(selectSlaAlerts([row({ first_seen_at: daysAgo(45) })], off, NOW)).toEqual({ dueSoon: [], breached: [] });
  });
});
