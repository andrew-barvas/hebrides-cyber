// Estate drift: what changed across every site an account monitors over a
// window (Lookout's "since your last report", usable on any plan). Built from
// finding_lifecycle (043) and asset_inventory (022), so it costs no scan.
//
//   opened    findings first seen in the window
//   fixed     findings resolved in the window (a later scan that could see
//             them no longer reported them; findingLifecycle.ts decides that)
//   openNow   findings open at the end of the window
//   newHosts  hostnames first seen in the window
//
// Honest about its limits, in the response itself:
//   - A finding that was fixed and then came back keeps its original
//     first_seen_at (043 reopens the same row), so a return is not counted as
//     "opened" again. It shows in openNow.
//   - Active false positives are left out everywhere: they are not real
//     issues. Accepted and snoozed findings still count, because they still
//     exist; the triage decision is about what to do, not whether it's there.
//   - Info findings are left out: nothing to fix.
//
// Everything except loadEstateDrift is pure.
import type { SupabaseClient } from "@supabase/supabase-js";
import { isMissingSchemaError } from "./dbErrors";
import { buildTriageIndex, loadTriageForOwner, type TriageIndex } from "./findingTriage";

export const DRIFT_WINDOWS = [7, 30, 90] as const;
export type DriftWindow = (typeof DRIFT_WINDOWS)[number];

const COUNTED = ["critical", "high", "medium", "low"] as const;
type CountedSeverity = (typeof COUNTED)[number];
export type SeverityCounts = Record<CountedSeverity, number> & { total: number };

export type DriftLifecycleRow = {
  target_host: string;
  check_id: string;
  severity: string;
  title: string;
  first_seen_at: string;
  resolved_at: string | null;
};
export type DriftAssetRow = { hostname: string; first_seen_at: string };

export type EstateDrift = {
  since: string;
  until: string;
  opened: SeverityCounts;
  fixed: SeverityCounts;
  openNow: SeverityCounts;
  newHosts: string[];
  /** Hosts with the most change, most first. */
  hosts: Array<{ host: string; opened: number; fixed: number }>;
  /** Critical and high findings first seen in the window, newest first. */
  notableOpened: Array<{ host: string; checkId: string; severity: CountedSeverity; title: string; firstSeenAt: string }>;
};

const MAX_HOSTS = 10;
const MAX_NOTABLE = 10;

function emptyCounts(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
}

function counted(severity: string): severity is CountedSeverity {
  return (COUNTED as readonly string[]).includes(severity);
}

function add(counts: SeverityCounts, severity: CountedSeverity): void {
  counts[severity]++;
  counts.total++;
}

export function parseDriftWindow(value: unknown): DriftWindow {
  const n = Number(Array.isArray(value) ? value[0] : value);
  return (DRIFT_WINDOWS as readonly number[]).includes(n) ? (n as DriftWindow) : 30;
}

export function buildEstateDrift(input: {
  lifecycle: DriftLifecycleRow[];
  assets: DriftAssetRow[];
  triage: TriageIndex;
  since: Date;
  until: Date;
}): EstateDrift {
  const since = input.since.getTime();
  const until = input.until.getTime();
  const inWindow = (iso: string | null) => {
    if (!iso) return false;
    const t = Date.parse(iso);
    return t >= since && t <= until;
  };

  const opened = emptyCounts();
  const fixed = emptyCounts();
  const openNow = emptyCounts();
  const perHost = new Map<string, { opened: number; fixed: number }>();
  const notable: EstateDrift["notableOpened"] = [];
  const seen = new Set<string>();

  for (const row of input.lifecycle) {
    const key = `${row.target_host} ${row.check_id}`;
    if (seen.has(key)) continue; // the open and resolved queries can overlap
    seen.add(key);
    if (!counted(row.severity)) continue;
    if (input.triage.get(row.target_host, row.check_id)?.state === "false_positive") continue;

    const host = perHost.get(row.target_host) ?? { opened: 0, fixed: 0 };
    if (inWindow(row.first_seen_at)) {
      add(opened, row.severity);
      host.opened++;
      if (row.severity === "critical" || row.severity === "high") {
        notable.push({ host: row.target_host, checkId: row.check_id, severity: row.severity, title: row.title, firstSeenAt: row.first_seen_at });
      }
    }
    if (inWindow(row.resolved_at)) {
      add(fixed, row.severity);
      host.fixed++;
    }
    const openAtEnd = Date.parse(row.first_seen_at) <= until && (!row.resolved_at || Date.parse(row.resolved_at) > until);
    if (openAtEnd) add(openNow, row.severity);
    if (host.opened > 0 || host.fixed > 0) perHost.set(row.target_host, host);
  }

  const newHosts = [...new Set(input.assets.filter((a) => inWindow(a.first_seen_at)).map((a) => a.hostname.toLowerCase()))].sort();
  const hosts = [...perHost.entries()]
    .map(([host, c]) => ({ host, ...c }))
    .sort((a, b) => b.opened + b.fixed - (a.opened + a.fixed) || a.host.localeCompare(b.host))
    .slice(0, MAX_HOSTS);
  notable.sort((a, b) => (a.severity === b.severity ? b.firstSeenAt.localeCompare(a.firstSeenAt) : a.severity === "critical" ? -1 : 1));

  return {
    since: input.since.toISOString(),
    until: input.until.toISOString(),
    opened,
    fixed,
    openNow,
    newHosts,
    hosts,
    notableOpened: notable.slice(0, MAX_NOTABLE),
  };
}

const LIFECYCLE_SELECT = "target_host, check_id, severity, title, first_seen_at, resolved_at";

export type DriftLoad = { ok: true; available: false } | { ok: true; available: true; drift: EstateDrift } | { ok: false; error: string };

export async function loadEstateDrift(supabaseAdmin: SupabaseClient, ownerId: string, days: DriftWindow, now: Date = new Date()): Promise<DriftLoad> {
  const since = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
  const sinceIso = since.toISOString();
  const [openRes, resolvedRes, assetsRes, triage] = await Promise.all([
    supabaseAdmin.from("finding_lifecycle").select(LIFECYCLE_SELECT).eq("owner", ownerId).is("resolved_at", null),
    supabaseAdmin.from("finding_lifecycle").select(LIFECYCLE_SELECT).eq("owner", ownerId).gte("resolved_at", sinceIso),
    supabaseAdmin.from("asset_inventory").select("hostname, first_seen_at").eq("owner", ownerId).gte("first_seen_at", sinceIso),
    loadTriageForOwner(supabaseAdmin, ownerId),
  ]);
  const lifecycleError = openRes.error ?? resolvedRes.error;
  if (lifecycleError) {
    if (isMissingSchemaError(lifecycleError)) return { ok: true, available: false };
    return { ok: false, error: "Could not load finding history" };
  }
  // A missing asset table only means no new-host list; any other failure is real.
  if (assetsRes.error && !isMissingSchemaError(assetsRes.error)) return { ok: false, error: "Could not load the asset inventory" };
  // Unlike a missing triage table, a failed read can't be shown as "nothing triaged".
  if (triage.error) return { ok: false, error: "Could not load triage" };

  return {
    ok: true,
    available: true,
    drift: buildEstateDrift({
      lifecycle: [...((openRes.data ?? []) as DriftLifecycleRow[]), ...((resolvedRes.data ?? []) as DriftLifecycleRow[])],
      assets: assetsRes.error ? [] : ((assetsRes.data ?? []) as DriftAssetRow[]),
      triage: buildTriageIndex(triage.rows, now),
      since,
      until: now,
    }),
  };
}
