// Cross-site findings view (E-74): every open finding across all of an
// owner's sites in one list, filterable and groupable by check, with the
// customer's triage decisions applied.
//
// Sources, joined per (host, checkId):
//   - finding_lifecycle (043): which findings are open (resolved_at null),
//     when first seen, severity and title. This is the authority on "open".
//   - the latest completed scan of that host: the finding's detail and its
//     threat intelligence (KEV / EPSS). Enrichment only — a finding the
//     latest scan doesn't carry (an on-demand passive scan after a full one
//     doesn't re-detect active-tool findings) stays listed from its lifecycle
//     row, just without detail.
//   - finding_triage (046) through findingTriage.ts, so only *active* triage
//     counts and an expired snooze puts the finding straight back in the list.
//
// Everything above the loader is pure and takes a fixed `now`, so one
// response can't disagree with itself and the logic is unit-testable without
// Supabase. The loader is the only I/O; before migration 043 it reports
// `available: false`, before 046 triage is simply absent (`triageAvailable:
// false`). A failed triage read is an error, never "nothing triaged" — that
// would show accepted findings as open (same rule as the SLA API).
import type { SupabaseClient } from "@supabase/supabase-js";
import { csvCell } from "./csv";
import { isMissingSchemaError } from "./dbErrors";
import { buildTriageIndex, loadTriageForOwner, TRIAGE_STATES, type TriageIndex, type TriageState } from "./findingTriage";
import { hostOf } from "./findingLifecycle";
import { hasSlaAccess } from "./slaAlerts";
import { DEFAULT_SLA_POLICY, policyFromRow, slaItem, type LifecycleRow, type SlaPolicy, type SlaPolicyRow, type SlaState } from "./slaMonitoring";

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type FindingSeverity = (typeof SEVERITIES)[number];

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const DAY_MS = 24 * 60 * 60 * 1000;

/** Most lifecycle rows one request will read — keeps a pathological account bounded. */
export const MAX_OPEN_ROWS = 5000;
export const DEFAULT_PAGE_SIZE = 50;
export const MAX_PAGE_SIZE = 100;
/** Detail text kept per finding in the response. */
const DETAIL_MAX = 500;

export type FindingRowTriage = { state: TriageState; reason: string; expiresAt: string | null };

export type FindingRow = {
  /** `${host} ${checkId}` — unique per finding, stable across requests. */
  key: string;
  host: string;
  checkId: string;
  /** checkId up to its first ":" — "headers.hsts-missing", "script-inventory.unreviewed". */
  checkBase: string;
  /** First dotted segment of the checkId: "headers", "dns", "sast"… */
  category: string;
  severity: FindingSeverity;
  title: string;
  detail: string | null;
  firstSeenAt: string;
  ageDays: number;
  slaState: SlaState | null;
  slaDueAt: string | null;
  knownExploited: boolean;
  ransomware: boolean;
  epss: number | null;
  cveIds: string[];
  /** The scan this finding was last seen in, for linking to its report. */
  scanId: string | null;
  triage: FindingRowTriage | null;
};

export type LifecycleOpenRow = LifecycleRow & { last_scan_id?: string | null };

export type ScanFinding = {
  checkId?: string;
  severity?: string;
  title?: string;
  detail?: string;
  cveIds?: string[];
  threatIntel?: { knownExploited?: boolean; ransomware?: boolean; epss?: number };
};

export type HostDetail = { scanId: string; findings: ScanFinding[] };

export function checkBaseOf(checkId: string): string {
  return checkId.split(":")[0];
}

export function categoryOfCheck(checkId: string): string {
  return checkBaseOf(checkId).split(".")[0] || "other";
}

function normaliseSeverity(value: string): FindingSeverity {
  return (SEVERITIES as readonly string[]).includes(value) ? (value as FindingSeverity) : "info";
}

/**
 * One row per open lifecycle row. `detailByHost` is the latest completed
 * scan's findings per host (may be missing for a host); `triage` is built
 * with the same `now`. `policy` null = SLA tracking not available to this
 * account, so no SLA state is attached.
 */
export function buildFindingRows(
  lifecycle: LifecycleOpenRow[],
  detailByHost: ReadonlyMap<string, HostDetail>,
  triage: TriageIndex,
  policy: SlaPolicy | null,
  now: Date
): FindingRow[] {
  const detailIndex = new Map<string, Map<string, ScanFinding>>();
  for (const [host, detail] of detailByHost) {
    const byId = new Map<string, ScanFinding>();
    for (const f of detail.findings) if (f.checkId && !byId.has(f.checkId)) byId.set(f.checkId, f);
    detailIndex.set(host, byId);
  }

  const rows: FindingRow[] = [];
  for (const row of lifecycle) {
    if (row.resolved_at) continue;
    const host = row.target_host.toLowerCase();
    const found = detailIndex.get(host)?.get(row.check_id);
    const active = triage.get(host, row.check_id);
    const sla = policy ? slaItem(row, policy, now) : null;
    const firstSeen = Date.parse(row.first_seen_at);
    const intel = found?.threatIntel;
    rows.push({
      key: `${host} ${row.check_id}`,
      host,
      checkId: row.check_id,
      checkBase: checkBaseOf(row.check_id),
      category: categoryOfCheck(row.check_id),
      severity: normaliseSeverity(row.severity),
      title: row.title,
      detail: found?.detail ? found.detail.slice(0, DETAIL_MAX) : null,
      firstSeenAt: row.first_seen_at,
      ageDays: Number.isNaN(firstSeen) ? 0 : Math.max(0, Math.floor((now.getTime() - firstSeen) / DAY_MS)),
      slaState: sla?.state ?? null,
      slaDueAt: sla?.dueAt ?? null,
      knownExploited: intel?.knownExploited === true,
      ransomware: intel?.ransomware === true,
      epss: typeof intel?.epss === "number" ? intel.epss : null,
      cveIds: Array.isArray(found?.cveIds) ? found.cveIds.filter((c) => typeof c === "string") : [],
      scanId: detailByHost.get(host)?.scanId ?? row.last_scan_id ?? null,
      triage: active ? { state: active.state, reason: active.reason, expiresAt: active.expires_at } : null,
    });
  }
  return rows;
}

// ---------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------

export type TriageFilter = "open" | "triaged" | "all" | TriageState;
export const TRIAGE_FILTERS: readonly TriageFilter[] = ["open", "triaged", "all", ...TRIAGE_STATES];

export type FindingFilters = {
  site: string | null;
  severities: FindingSeverity[];
  /** Only findings on a CISA-KEV-listed CVE. */
  kev: boolean;
  /** Only findings with an EPSS score at or above this (0–1). */
  epssMin: number | null;
  category: string | null;
  /** "open" (default) = no active triage. */
  triage: TriageFilter;
  sla: SlaState | null;
  minAgeDays: number | null;
};

export const DEFAULT_FILTERS: FindingFilters = {
  site: null,
  severities: [],
  kev: false,
  epssMin: null,
  category: null,
  triage: "open",
  sla: null,
  minAgeDays: null,
};

export function applyFilters(rows: FindingRow[], f: FindingFilters): FindingRow[] {
  return rows.filter((r) => {
    if (f.site && r.host !== f.site) return false;
    if (f.severities.length > 0 && !f.severities.includes(r.severity)) return false;
    if (f.kev && !r.knownExploited) return false;
    if (f.epssMin !== null && (r.epss === null || r.epss < f.epssMin)) return false;
    if (f.category && r.category !== f.category) return false;
    if (f.sla && r.slaState !== f.sla) return false;
    if (f.minAgeDays !== null && r.ageDays < f.minAgeDays) return false;
    switch (f.triage) {
      case "open":
        return r.triage === null;
      case "triaged":
        return r.triage !== null;
      case "all":
        return true;
      default:
        return r.triage?.state === f.triage;
    }
  });
}

type RawQuery = Record<string, string | string[] | undefined>;

function first(query: RawQuery, name: string): string | undefined {
  const v = query[name];
  const s = Array.isArray(v) ? v[0] : v;
  return s === undefined || s === "" ? undefined : s;
}

function positiveInt(value: string | undefined, max: number): number | null {
  if (value === undefined || !/^\d+$/.test(value)) return null;
  return Math.min(Number(value), max);
}

export type FindingsQuery = {
  filters: FindingFilters;
  view: "grouped" | "rows";
  page: number;
  pageSize: number;
  format: "json" | "csv";
};

/** Unknown or malformed values fall back to the default rather than erroring —
 *  a stale bookmark should still load a page. */
export function parseFindingsQuery(query: RawQuery): FindingsQuery {
  const severities = (first(query, "severity") ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter((s): s is FindingSeverity => (SEVERITIES as readonly string[]).includes(s));
  const epss = first(query, "epssMin");
  const epssNumber = epss !== undefined ? Number(epss) : NaN;
  const triage = first(query, "triage");
  const sla = first(query, "sla");
  const pageSize = positiveInt(first(query, "pageSize"), MAX_PAGE_SIZE);
  return {
    filters: {
      site: first(query, "site")?.trim().toLowerCase() ?? null,
      severities: [...new Set(severities)],
      kev: ["1", "true"].includes(first(query, "kev") ?? ""),
      epssMin: Number.isFinite(epssNumber) && epssNumber >= 0 && epssNumber <= 1 ? epssNumber : null,
      category: first(query, "category")?.trim().toLowerCase() ?? null,
      triage: TRIAGE_FILTERS.includes(triage as TriageFilter) ? (triage as TriageFilter) : "open",
      sla: sla === "breached" || sla === "due_soon" || sla === "on_track" ? sla : null,
      minAgeDays: positiveInt(first(query, "minAgeDays"), 3650),
    },
    view: first(query, "view") === "rows" ? "rows" : "grouped",
    page: Math.max(1, positiveInt(first(query, "page"), 1_000_000) ?? 1),
    pageSize: pageSize && pageSize > 0 ? pageSize : DEFAULT_PAGE_SIZE,
    format: first(query, "format") === "csv" ? "csv" : "json",
  };
}

// ---------------------------------------------------------------------------
// Sorting, grouping, paging
// ---------------------------------------------------------------------------

/** Most severe first, known-exploited and higher EPSS first within a severity,
 *  then longest open. Mirrors how the scan report orders findings. */
export function compareFindings(a: FindingRow, b: FindingRow): number {
  return (
    (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9) ||
    Number(b.knownExploited) - Number(a.knownExploited) ||
    (b.epss ?? -1) - (a.epss ?? -1) ||
    b.ageDays - a.ageDays ||
    a.host.localeCompare(b.host) ||
    a.checkId.localeCompare(b.checkId)
  );
}

export type FindingGroup = {
  /** The shared checkId base — the group's identity. */
  key: string;
  label: string;
  category: string;
  severity: FindingSeverity;
  count: number;
  siteCount: number;
  sites: string[];
  knownExploited: boolean;
  maxEpss: number | null;
  oldestFirstSeenAt: string;
  rows: FindingRow[];
};

/** "headers.hsts-missing" → "Headers hsts missing". */
export function humaniseCheckBase(base: string): string {
  const text = base.replace(/[._-]+/g, " ").trim();
  return text ? text.charAt(0).toUpperCase() + text.slice(1) : base;
}

function groupLabel(base: string, rows: FindingRow[]): string {
  const titles = new Set(rows.map((r) => r.title));
  // Titles often embed a count or key ("Missing recommended headers (3)"), so
  // a group whose rows disagree is named from its check id instead.
  return titles.size === 1 ? rows[0].title : humaniseCheckBase(base);
}

/** One group per checkId base ("missing HSTS on 7 sites"), most urgent first. */
export function groupFindings(rows: FindingRow[]): FindingGroup[] {
  const byBase = new Map<string, FindingRow[]>();
  for (const r of rows) {
    const list = byBase.get(r.checkBase);
    if (list) list.push(r);
    else byBase.set(r.checkBase, [r]);
  }
  const groups: FindingGroup[] = [];
  for (const [key, list] of byBase) {
    const sorted = [...list].sort(compareFindings);
    const sites = [...new Set(sorted.map((r) => r.host))].sort();
    const epss = sorted.map((r) => r.epss).filter((e): e is number => e !== null);
    groups.push({
      key,
      label: groupLabel(key, sorted),
      category: sorted[0].category,
      severity: sorted[0].severity,
      count: sorted.length,
      siteCount: sites.length,
      sites,
      knownExploited: sorted.some((r) => r.knownExploited),
      maxEpss: epss.length > 0 ? Math.max(...epss) : null,
      oldestFirstSeenAt: sorted.reduce((a, r) => (r.firstSeenAt < a ? r.firstSeenAt : a), sorted[0].firstSeenAt),
      rows: sorted,
    });
  }
  return groups.sort(
    (a, b) =>
      (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9) ||
      Number(b.knownExploited) - Number(a.knownExploited) ||
      b.siteCount - a.siteCount ||
      b.count - a.count ||
      a.key.localeCompare(b.key)
  );
}

export type Page<T> = { items: T[]; page: number; pageSize: number; total: number; pageCount: number };

/** A page past the end is clamped to the last page, so a filter that shrinks
 *  the list never leaves the caller on an empty one. */
export function paginate<T>(items: T[], page: number, pageSize: number): Page<T> {
  const size = Math.min(Math.max(1, Math.floor(pageSize)), MAX_PAGE_SIZE);
  const pageCount = Math.max(1, Math.ceil(items.length / size));
  const current = Math.min(Math.max(1, Math.floor(page)), pageCount);
  return { items: items.slice((current - 1) * size, current * size), page: current, pageSize: size, total: items.length, pageCount };
}

export type Facets = {
  sites: Array<{ value: string; count: number }>;
  categories: Array<{ value: string; count: number }>;
  severities: Record<FindingSeverity, number>;
  knownExploited: number;
};

/** What the filter bar offers, counted over the rows before any filter. */
export function buildFacets(rows: FindingRow[]): Facets {
  const sites = new Map<string, number>();
  const categories = new Map<string, number>();
  const severities: Record<FindingSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let knownExploited = 0;
  for (const r of rows) {
    if (r.triage) continue;
    sites.set(r.host, (sites.get(r.host) ?? 0) + 1);
    categories.set(r.category, (categories.get(r.category) ?? 0) + 1);
    severities[r.severity] += 1;
    if (r.knownExploited) knownExploited += 1;
  }
  const list = (m: Map<string, number>) =>
    [...m.entries()].map(([value, count]) => ({ value, count })).sort((a, b) => a.value.localeCompare(b.value));
  return { sites: list(sites), categories: list(categories), severities, knownExploited };
}

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

export const CSV_HEADER = [
  "site",
  "severity",
  "title",
  "check_id",
  "category",
  "first_seen",
  "age_days",
  "sla_state",
  "sla_due",
  "known_exploited",
  "epss",
  "cves",
  "triage_state",
  "triage_reason",
  "triage_expires",
] as const;

/** One CSV, header included. Every cell goes through csvCell, so text that
 *  came from a scanned site (titles quote headers, paths, hostnames) can't run
 *  as a spreadsheet formula. Lines end CRLF (RFC 4180). */
export function findingsToCsv(rows: FindingRow[]): string {
  const lines = [CSV_HEADER.join(",")];
  for (const r of rows) {
    lines.push(
      [
        r.host,
        r.severity,
        r.title,
        r.checkId,
        r.category,
        r.firstSeenAt,
        String(r.ageDays),
        r.slaState ?? "",
        r.slaDueAt ?? "",
        r.knownExploited ? "yes" : "no",
        r.epss === null ? "" : String(r.epss),
        r.cveIds.join(" "),
        r.triage?.state ?? "",
        r.triage?.reason ?? "",
        r.triage?.expiresAt ?? "",
      ]
        .map(csvCell)
        .join(",")
    );
  }
  return `${lines.join("\r\n")}\r\n`;
}

// ---------------------------------------------------------------------------
// Loader (the only I/O)
// ---------------------------------------------------------------------------

export type FindingsViewData = {
  /** False before migration 043 (no finding_lifecycle). */
  available: boolean;
  /** False before migration 046. */
  triageAvailable: boolean;
  slaEnabled: boolean;
  /** False if the latest scans' detail couldn't be read: rows then lack KEV/EPSS/detail. */
  detailComplete: boolean;
  truncated: boolean;
  rows: FindingRow[];
};

const LIFECYCLE_SELECT = "id, target_host, check_id, severity, title, first_seen_at, last_seen_at, resolved_at, last_scan_id";

/** The latest completed scan's findings per host (only for `hosts`). Null on
 *  any failure — detail is enrichment, so the caller degrades. */
async function loadLatestDetail(
  supabaseAdmin: SupabaseClient,
  ownerId: string,
  hosts: Set<string>
): Promise<Map<string, HostDetail> | null> {
  if (hosts.size === 0) return new Map();
  const { data: scans, error } = await supabaseAdmin
    .from("scans")
    .select("id, target_url, created_at")
    .eq("owner", ownerId)
    .eq("status", "completed")
    .order("created_at", { ascending: false })
    .limit(500);
  if (error) return null;

  const latest = new Map<string, string>();
  for (const s of (scans ?? []) as Array<{ id: string; target_url: string }>) {
    const host = hostOf(s.target_url);
    if (host && hosts.has(host) && !latest.has(host)) latest.set(host, s.id);
  }
  if (latest.size === 0) return new Map();

  const ids = [...latest.values()];
  const { data: results, error: resultsError } = await supabaseAdmin
    .from("scan_results")
    .select("scan_id, findings:results->findings")
    .in("scan_id", ids);
  if (resultsError) return null;

  const byScan = new Map<string, ScanFinding[]>();
  for (const r of (results ?? []) as Array<{ scan_id: string; findings: unknown }>) {
    byScan.set(r.scan_id, Array.isArray(r.findings) ? (r.findings as ScanFinding[]) : []);
  }
  const detail = new Map<string, HostDetail>();
  for (const [host, scanId] of latest) {
    const findings = byScan.get(scanId);
    if (findings) detail.set(host, { scanId, findings });
  }
  return detail;
}

export type FindingsViewResult = { ok: true; data: FindingsViewData } | { ok: false; error: string };

export async function loadFindingsView(supabaseAdmin: SupabaseClient, ownerId: string, now: Date = new Date()): Promise<FindingsViewResult> {
  const empty = (available: boolean): FindingsViewResult => ({
    ok: true,
    data: { available, triageAvailable: false, slaEnabled: false, detailComplete: true, truncated: false, rows: [] },
  });

  const [open, triage, slaAccess] = await Promise.all([
    supabaseAdmin
      .from("finding_lifecycle")
      .select(LIFECYCLE_SELECT)
      .eq("owner", ownerId)
      .is("resolved_at", null)
      .order("first_seen_at", { ascending: true })
      .limit(MAX_OPEN_ROWS + 1),
    loadTriageForOwner(supabaseAdmin, ownerId),
    hasSlaAccess(supabaseAdmin, ownerId).catch(() => false),
  ]);

  if (open.error) {
    if (isMissingSchemaError(open.error)) return empty(false);
    return { ok: false, error: "Could not load findings" };
  }
  if (triage.error) return { ok: false, error: "Could not load findings" };

  const all = (open.data ?? []) as LifecycleOpenRow[];
  const truncated = all.length > MAX_OPEN_ROWS;
  const lifecycle = truncated ? all.slice(0, MAX_OPEN_ROWS) : all;

  let policy: SlaPolicy | null = null;
  if (slaAccess) {
    const { data } = await supabaseAdmin
      .from("sla_policies")
      .select("critical_days, high_days, medium_days, low_days, warn_days, alerts_enabled")
      .eq("owner", ownerId)
      .maybeSingle();
    policy = data ? policyFromRow(data as SlaPolicyRow) : DEFAULT_SLA_POLICY;
  }

  const detail = await loadLatestDetail(supabaseAdmin, ownerId, new Set(lifecycle.map((r) => r.target_host.toLowerCase())));
  const rows = buildFindingRows(lifecycle, detail ?? new Map(), buildTriageIndex(triage.rows, now), policy, now);
  return {
    ok: true,
    data: { available: true, triageAvailable: triage.available, slaEnabled: slaAccess, detailComplete: detail !== null, truncated, rows },
  };
}
