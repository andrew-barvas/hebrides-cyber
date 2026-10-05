// Remediation SLAs — how long each severity may stay open before it counts
// as a breach, and where every open finding stands against that. Pure
// functions over finding_lifecycle rows (see findingLifecycle.ts for how
// first_seen/resolved are maintained), so the maths is testable without a
// database and the API, dashboard and alerts all agree by construction.
//
// Triage (findingTriage.ts): a finding with an active triage — accepted
// risk, false positive, or snoozed — is out of SLA tracking while the triage
// lasts: no open item, no due-soon/breach alert. When it ends (expiry, or
// Undo) the finding is tracked again against its original first-seen date;
// triage doesn't extend a deadline, so a finding snoozed past its deadline
// comes back breached. Every function here takes the index as an optional
// last argument, and behaves exactly as before without it.
import type { TriageIndex } from "./findingTriage";

export const SLA_SEVERITIES = ["critical", "high", "medium", "low"] as const;
export type SlaSeverity = (typeof SLA_SEVERITIES)[number];

export type SlaPolicy = {
  /** Days allowed to remediate, per severity. Info findings carry no SLA. */
  days: Record<SlaSeverity, number>;
  /** "Due soon" starts this many days before the deadline; alerts fire then. */
  warnDays: number;
  alertsEnabled: boolean;
};

// Critical/high follow CISA BOD 19-02 (15 and 30 days for internet-facing
// systems); medium/low are the common 90/180-day convention.
export const DEFAULT_SLA_POLICY: SlaPolicy = {
  days: { critical: 15, high: 30, medium: 90, low: 180 },
  warnDays: 3,
  alertsEnabled: true,
};

export type SlaPolicyRow = {
  critical_days: number;
  high_days: number;
  medium_days: number;
  low_days: number;
  warn_days: number;
  alerts_enabled: boolean;
};

export function policyFromRow(row: SlaPolicyRow | null | undefined): SlaPolicy {
  if (!row) return DEFAULT_SLA_POLICY;
  return {
    days: { critical: row.critical_days, high: row.high_days, medium: row.medium_days, low: row.low_days },
    warnDays: row.warn_days,
    alertsEnabled: row.alerts_enabled,
  };
}

export type LifecycleRow = {
  id: string;
  target_host: string;
  check_id: string;
  severity: string;
  title: string;
  first_seen_at: string;
  last_seen_at: string;
  resolved_at: string | null;
  sla_warned_at?: string | null;
  sla_breach_notified_at?: string | null;
};

export type SlaState = "on_track" | "due_soon" | "breached";

export type SlaItem = {
  id: string;
  host: string;
  checkId: string;
  severity: SlaSeverity;
  title: string;
  firstSeenAt: string;
  dueAt: string;
  /** Negative once breached. Fractional; round for display. */
  daysRemaining: number;
  state: SlaState;
};

const DAY_MS = 24 * 60 * 60 * 1000;

function isSlaSeverity(severity: string): severity is SlaSeverity {
  return (SLA_SEVERITIES as readonly string[]).includes(severity);
}

/** Open, with a severity that carries an SLA, but out of tracking because of
 *  an active triage. */
export function isTriagedOut(row: LifecycleRow, triage: TriageIndex | undefined): boolean {
  return Boolean(!row.resolved_at && isSlaSeverity(row.severity) && triage?.get(row.target_host, row.check_id));
}

/** Where one open finding stands. Null for resolved rows, for severities
 *  with no SLA (info, or anything unrecognised), and for findings with an
 *  active triage. */
export function slaItem(row: LifecycleRow, policy: SlaPolicy, now: Date, triage?: TriageIndex): SlaItem | null {
  if (row.resolved_at || !isSlaSeverity(row.severity)) return null;
  if (triage?.get(row.target_host, row.check_id)) return null;
  const firstSeen = Date.parse(row.first_seen_at);
  if (Number.isNaN(firstSeen)) return null;
  const due = firstSeen + policy.days[row.severity] * DAY_MS;
  const daysRemaining = (due - now.getTime()) / DAY_MS;
  const state: SlaState = daysRemaining < 0 ? "breached" : daysRemaining <= policy.warnDays ? "due_soon" : "on_track";
  return {
    id: row.id,
    host: row.target_host,
    checkId: row.check_id,
    severity: row.severity,
    title: row.title,
    firstSeenAt: row.first_seen_at,
    dueAt: new Date(due).toISOString(),
    daysRemaining,
    state,
  };
}

export type SlaSummary = {
  open: number;
  /** Open findings with an SLA severity left out of `open` (and everything
   *  below) because they're triaged — accepted, false positive or snoozed. */
  triaged: number;
  onTrack: number;
  dueSoon: number;
  breached: number;
  /** Open items, most urgent first (breached, then soonest due). */
  items: SlaItem[];
  /** Per severity, over findings resolved in the window: median days open,
   *  and how many were fixed inside their SLA. */
  resolved: Record<SlaSeverity, { count: number; medianDaysToFix: number | null; withinSla: number }>;
  hosts: Array<{ host: string; open: number; dueSoon: number; breached: number }>;
};

function median(values: number[]): number | null {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

/**
 * `rows` should hold the owner's open rows plus those resolved within the
 * reporting window — the caller decides the window, this just reports on
 * what it's given.
 */
export function buildSlaSummary(rows: LifecycleRow[], policy: SlaPolicy, now: Date = new Date(), triage?: TriageIndex): SlaSummary {
  const items = rows
    .map((row) => slaItem(row, policy, now, triage))
    .filter((item): item is SlaItem => item !== null)
    .sort((a, b) => a.daysRemaining - b.daysRemaining);

  const fixDays: Record<SlaSeverity, number[]> = { critical: [], high: [], medium: [], low: [] };
  for (const row of rows) {
    if (!row.resolved_at || !isSlaSeverity(row.severity)) continue;
    const days = (Date.parse(row.resolved_at) - Date.parse(row.first_seen_at)) / DAY_MS;
    if (Number.isFinite(days) && days >= 0) fixDays[row.severity].push(days);
  }
  const resolved = Object.fromEntries(
    SLA_SEVERITIES.map((s) => [
      s,
      {
        count: fixDays[s].length,
        medianDaysToFix: median(fixDays[s]),
        withinSla: fixDays[s].filter((d) => d <= policy.days[s]).length,
      },
    ])
  ) as SlaSummary["resolved"];

  const byHost = new Map<string, { host: string; open: number; dueSoon: number; breached: number }>();
  for (const item of items) {
    const entry = byHost.get(item.host) ?? { host: item.host, open: 0, dueSoon: 0, breached: 0 };
    entry.open++;
    if (item.state === "due_soon") entry.dueSoon++;
    if (item.state === "breached") entry.breached++;
    byHost.set(item.host, entry);
  }
  const hosts = [...byHost.values()].sort((a, b) => b.breached - a.breached || b.dueSoon - a.dueSoon || b.open - a.open);

  return {
    open: items.length,
    triaged: rows.filter((row) => isTriagedOut(row, triage)).length,
    onTrack: items.filter((i) => i.state === "on_track").length,
    dueSoon: items.filter((i) => i.state === "due_soon").length,
    breached: items.filter((i) => i.state === "breached").length,
    items,
    resolved,
    hosts,
  };
}

/**
 * Rows that should trigger an alert now: newly due-soon (not yet warned) and
 * newly breached (not yet notified). A row that jumps straight to breached
 * (e.g. a short SLA and a weekly scan) only produces the breach alert.
 */
export function selectSlaAlerts(
  rows: LifecycleRow[],
  policy: SlaPolicy,
  now: Date,
  triage?: TriageIndex
): { dueSoon: SlaItem[]; breached: SlaItem[] } {
  const dueSoon: SlaItem[] = [];
  const breached: SlaItem[] = [];
  if (!policy.alertsEnabled) return { dueSoon, breached };
  for (const row of rows) {
    const item = slaItem(row, policy, now, triage);
    if (!item) continue;
    if (item.state === "breached" && !row.sla_breach_notified_at) breached.push(item);
    else if (item.state === "due_soon" && !row.sla_warned_at) dueSoon.push(item);
  }
  return { dueSoon, breached };
}
