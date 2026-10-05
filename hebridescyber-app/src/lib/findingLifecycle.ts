// Finding lifecycle — when each finding on each site was first seen, last
// seen and resolved (sql/migrations/043_finding_lifecycle_sla.sql), which is
// what remediation SLAs (slaMonitoring.ts) measure against. Synced after
// every completed scan by executeScan().
//
// The rule that matters: a scan can only resolve a finding it could have
// detected. On-demand scans are passive-only, so if one of them "didn't see"
// a nuclei or sqlmap finding from last night's full scan, that is not a fix —
// treating it as one would close the SLA clock, and the next full scan would
// reopen it with a fresh first_seen, understating how long it's been open.
// So each row records its `source` (the base suite, or the extended tool
// that produced it), and a scan resolves it only if that source ran to
// completion in the scan. The same rule bounds the history backfill.
//
// Identity is checkId, same as findingsDiff.ts; findings without one can't
// be tracked across scans and are skipped.
import type { SupabaseClient } from "@supabase/supabase-js";
import { isMissingSchemaError } from "./dbErrors";
import type { Finding } from "./scanners";
import { findingCheckIds } from "./findingConsolidation";

/** A finding resolved this recently that shows up again is the same
 *  occurrence (a flapping check, a transient scanner error), not a new one:
 *  it reopens with its original first_seen_at. */
export const REOPEN_WINDOW_DAYS = 7;

/** How far back the first sync of a site looks to date its open findings. */
export const BACKFILL_SCAN_LIMIT = 45;

const DAY_MS = 24 * 60 * 60 * 1000;

export type ScanCoverage = {
  /** Any extended tool completed. */
  extendedRan: boolean;
  /** Normalised keys of the extended tools that completed. */
  completedTools: Set<string>;
  /** Normalised keys of base checks that errored or had no credential this
   *  scan. The base suite always runs, but a TLS timeout or a rate-limited
   *  WPScan lookup saw nothing, and must not resolve what it saw last time. */
  failedBaseChecks: Set<string>;
};

export function normaliseToolKey(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, "");
}

// A base check in either state looked at nothing. "not_applicable" is
// different: the check ran and found its subject absent (no WordPress
// plugins detected), which can genuinely be a fix. "partial" saw only part
// of its subject (scriptInventory.ts without the headless browser lists the
// HTML's scripts but not runtime-injected ones), so its silence about a
// finding isn't a fix either.
const BASE_NOT_RUN = new Set(["error", "not_configured", "partial"]);

/**
 * From a scan's `extended` results object (absent for passive scans) and its
 * base results (the stored results object, or ScanResults; absent on rows
 * written before this was tracked, which then behave as before: every base
 * check counted as run).
 */
export function scanCoverage(
  extended: Record<string, unknown> | null | undefined,
  base?: Record<string, unknown> | null
): ScanCoverage {
  const completedTools = new Set<string>();
  for (const [key, value] of Object.entries(extended ?? {})) {
    const status = (value as { status?: unknown } | null)?.status;
    // "checked" is cloud posture's word for it.
    if (status === "completed" || status === "checked") completedTools.add(normaliseToolKey(key));
  }
  const failedBaseChecks = new Set<string>();
  for (const [key, value] of Object.entries(base ?? {})) {
    if (key === "extended" || !value || typeof value !== "object") continue;
    const status = (value as { status?: unknown }).status;
    if (typeof status === "string" && BASE_NOT_RUN.has(status)) failedBaseChecks.add(normaliseToolKey(key));
  }
  return { extendedRan: completedTools.size > 0, completedTools, failedBaseChecks };
}

// checkId namespaces that don't normalise to their tool's key in `extended`.
const TOOL_ALIASES: Record<string, string> = { apispec: "apispecinjection" };
// …and the same for base checks and their key in ScanResults.
const BASE_ALIASES: Record<string, string> = { wpvdb: "wpvulndb", domain: "domainregistration", eol: "endoflife" };

function baseCheckKey(checkId: string): string {
  const prefix = normaliseToolKey(checkId.split(/[.:]/)[0]);
  return BASE_ALIASES[prefix] ?? prefix;
}

/**
 * "base", the normalised key of the extended tool that produced the finding
 * (matched from the checkId's namespace — "deep-tls.x" → "deeptls"), or
 * "extended" when an extended finding's namespace matches no tool.
 */
export function findingSource(checkId: string, fromExtended: boolean, extendedToolKeys: string[]): string {
  if (!fromExtended) return "base";
  const prefix = normaliseToolKey(checkId.split(".")[0]);
  const key = TOOL_ALIASES[prefix] ?? prefix;
  return extendedToolKeys.some((k) => normaliseToolKey(k) === key) ? key : "extended";
}

/** Could a scan with this coverage have detected `checkId`, a finding from `source`? */
export function isCovered(source: string, coverage: ScanCoverage, checkId?: string): boolean {
  if (source === "base") return !checkId || !coverage.failedBaseChecks.has(baseCheckKey(checkId));
  if (source === "extended") return coverage.extendedRan;
  return coverage.completedTools.has(source);
}

export type LifecycleDbRow = {
  owner: string;
  target_host: string;
  check_id: string;
  severity: string;
  title: string;
  source: string;
  first_seen_at: string;
  last_seen_at: string;
  last_scan_id: string | null;
  resolved_at: string | null;
  sla_warned_at: string | null;
  sla_breach_notified_at: string | null;
};

export type CurrentFinding = { checkId: string; severity: string; title: string; source: string };

/**
 * Cross-tool consolidation (findingConsolidation.ts) drops a duplicate
 * extended-tool finding into a canonical one, so the duplicate's checkId no
 * longer appears in the scan. `merged` maps each such duplicate checkId to its
 * canonical's. Old rows are handled explicitly rather than left to look "fixed":
 *   - an open duplicate row is resolved, because the canonical row now carries
 *     the issue (no stale SLA item or alert). This is bookkeeping, not a fix,
 *     and happens once per pre-existing duplicate row (none are created after);
 *   - the canonical row inherits the earliest first-seen of the duplicates it
 *     absorbed, so consolidation can never restart an SLA clock.
 */
export type MergedInto = Map<string, string>;

export type HistoricalScan = { createdAt: string; checkIds: Set<string>; coverage: ScanCoverage };

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/** One entry per checkId (the most severe, if a scan reports one twice). */
export function dedupeFindings(findings: CurrentFinding[]): CurrentFinding[] {
  const byId = new Map<string, CurrentFinding>();
  for (const f of findings) {
    const seen = byId.get(f.checkId);
    if (!seen || (SEVERITY_RANK[f.severity] ?? 9) < (SEVERITY_RANK[seen.severity] ?? 9)) byId.set(f.checkId, f);
  }
  return [...byId.values()];
}

/**
 * First sync of a site: date each current finding by walking back through
 * earlier scans (newest first) while it keeps appearing. A scan that
 * couldn't have detected it is skipped rather than ending the run; one that
 * could, and didn't report it, ends it.
 */
export function backfillFirstSeen(current: CurrentFinding[], history: HistoricalScan[], scanAt: string): Map<string, string> {
  const firstSeen = new Map<string, string>();
  for (const f of current) {
    let earliest = scanAt;
    for (const scan of history) {
      if (scan.checkIds.has(f.checkId)) earliest = scan.createdAt;
      else if (isCovered(f.source, scan.coverage, f.checkId)) break;
    }
    firstSeen.set(f.checkId, earliest);
  }
  return firstSeen;
}

/**
 * The rows to upsert after one scan of one site: complete rows (never
 * partial — an upsert's missing columns would be nulled), and only rows that
 * actually change.
 */
export function planLifecycleSync(input: {
  owner: string;
  host: string;
  scanId: string;
  scanAt: string;
  existing: LifecycleDbRow[];
  current: CurrentFinding[];
  coverage: ScanCoverage;
  backfill?: Map<string, string>;
  merged?: MergedInto;
}): LifecycleDbRow[] {
  const { owner, host, scanId, scanAt, existing, coverage, backfill, merged } = input;
  const current = dedupeFindings(input.current);
  const existingById = new Map(existing.map((row) => [row.check_id, row]));
  const currentIds = new Set(current.map((f) => f.checkId));
  const scanTime = Date.parse(scanAt);
  const out: LifecycleDbRow[] = [];

  // Earliest first-seen among the still-open rows of duplicates folded into
  // each canonical (see MergedInto).
  const inheritedFirstSeen = new Map<string, string>();
  for (const [dupId, canonicalId] of merged ?? []) {
    const dupRow = existingById.get(dupId);
    if (!dupRow || dupRow.resolved_at) continue;
    const known = inheritedFirstSeen.get(canonicalId);
    if (!known || Date.parse(dupRow.first_seen_at) < Date.parse(known)) inheritedFirstSeen.set(canonicalId, dupRow.first_seen_at);
  }
  const earlier = (a: string, b: string | undefined) => (b && Date.parse(b) < Date.parse(a) ? b : a);

  for (const f of current) {
    const prior = existingById.get(f.checkId);
    const inherited = inheritedFirstSeen.get(f.checkId);
    const seen = { severity: f.severity, title: f.title, source: f.source, last_seen_at: scanAt, last_scan_id: scanId };

    if (!prior) {
      out.push({
        owner, target_host: host, check_id: f.checkId, ...seen,
        first_seen_at: earlier(backfill?.get(f.checkId) ?? scanAt, inherited),
        resolved_at: null, sla_warned_at: null, sla_breach_notified_at: null,
      });
      continue;
    }

    if (!prior.resolved_at) {
      // A severity change moves the deadline, so earlier alerts no longer
      // describe it — let the new stage alert afresh.
      const reset = prior.severity !== f.severity ? { sla_warned_at: null, sla_breach_notified_at: null } : {};
      out.push({ ...prior, ...seen, ...reset, first_seen_at: earlier(prior.first_seen_at, inherited) });
      continue;
    }

    const resolvedAgo = scanTime - Date.parse(prior.resolved_at);
    if (resolvedAgo <= REOPEN_WINDOW_DAYS * DAY_MS) {
      out.push({ ...prior, ...seen, resolved_at: null });
    } else {
      out.push({
        ...prior, ...seen,
        first_seen_at: scanAt, resolved_at: null, sla_warned_at: null, sla_breach_notified_at: null,
      });
    }
  }

  for (const prior of existing) {
    if (prior.resolved_at || currentIds.has(prior.check_id)) continue;
    const canonicalId = merged?.get(prior.check_id);
    if (canonicalId && currentIds.has(canonicalId)) {
      out.push({ ...prior, resolved_at: scanAt });
      continue;
    }
    if (isCovered(prior.source, coverage, prior.check_id)) out.push({ ...prior, resolved_at: scanAt });
  }

  return out;
}

export function hostOf(targetUrl: string): string | null {
  try {
    return new URL(targetUrl).hostname.toLowerCase();
  } catch {
    return null;
  }
}

const LIFECYCLE_COLUMNS =
  "owner, target_host, check_id, severity, title, source, first_seen_at, last_seen_at, last_scan_id, resolved_at, sla_warned_at, sla_breach_notified_at";

async function loadHistory(
  supabaseAdmin: SupabaseClient,
  ownerId: string,
  scanId: string,
  host: string,
  scanAt: string
): Promise<HistoricalScan[]> {
  const { data } = await supabaseAdmin
    .from("scans")
    .select("id, target_url, created_at, scan_results(results)")
    .eq("owner", ownerId)
    .eq("status", "completed")
    .neq("id", scanId)
    .lt("created_at", scanAt)
    .order("created_at", { ascending: false })
    .limit(BACKFILL_SCAN_LIMIT);

  const history: HistoricalScan[] = [];
  for (const scan of (data ?? []) as Array<{
    target_url: string;
    created_at: string;
    scan_results: { results: { findings?: Finding[]; extended?: Record<string, unknown> } }[] | null;
  }>) {
    if (hostOf(scan.target_url) !== host) continue;
    const results = scan.scan_results?.[0]?.results;
    if (!results) continue;
    history.push({
      createdAt: scan.created_at,
      checkIds: new Set((results.findings ?? []).flatMap(findingCheckIds)),
      coverage: scanCoverage(results.extended, results),
    });
  }
  return history;
}

/**
 * Records this scan's findings against the site's lifecycle rows. Never
 * throws, and does nothing before migration 043 — the scan has already
 * succeeded, and SLA bookkeeping must never be why it looks otherwise.
 * Returns the host synced, or null if nothing was.
 */
export async function syncFindingLifecycle(
  supabaseAdmin: SupabaseClient,
  input: {
    ownerId: string;
    scanId: string;
    targetUrl: string;
    scanAt: string;
    findings: Finding[];
    extendedCheckIds: Set<string>;
    extended: Record<string, unknown> | undefined;
    baseResults?: Record<string, unknown>;
  }
): Promise<string | null> {
  try {
    const host = hostOf(input.targetUrl);
    if (!host) return null;

    const { data: existing, error } = await supabaseAdmin
      .from("finding_lifecycle")
      .select(LIFECYCLE_COLUMNS)
      .eq("owner", input.ownerId)
      .eq("target_host", host);
    if (error) {
      if (!isMissingSchemaError(error)) console.error(`[findingLifecycle] load failed for ${host}:`, error.message);
      return null;
    }

    const toolKeys = Object.keys(input.extended ?? {});
    const current: CurrentFinding[] = input.findings
      .filter((f): f is Finding & { checkId: string } => Boolean(f.checkId))
      .map((f) => ({
        checkId: f.checkId,
        severity: f.severity,
        title: f.title.slice(0, 300),
        source: findingSource(f.checkId, input.extendedCheckIds.has(f.checkId), toolKeys),
      }));

    const merged: MergedInto = new Map();
    for (const f of input.findings) {
      for (const c of f.corroboratedBy ?? []) if (f.checkId) merged.set(c.checkId, f.checkId);
    }

    const rows = (existing ?? []) as LifecycleDbRow[];
    const backfill =
      rows.length === 0
        ? backfillFirstSeen(current, await loadHistory(supabaseAdmin, input.ownerId, input.scanId, host, input.scanAt), input.scanAt)
        : undefined;

    const upserts = planLifecycleSync({
      owner: input.ownerId,
      host,
      scanId: input.scanId,
      scanAt: input.scanAt,
      existing: rows,
      current,
      coverage: scanCoverage(input.extended, input.baseResults),
      backfill,
      merged,
    });

    for (let i = 0; i < upserts.length; i += 500) {
      const { error: upsertError } = await supabaseAdmin
        .from("finding_lifecycle")
        .upsert(upserts.slice(i, i + 500), { onConflict: "owner,target_host,check_id" });
      if (upsertError) {
        console.error(`[findingLifecycle] upsert failed for ${host}:`, upsertError.message);
        return null;
      }
    }
    return host;
  } catch (err) {
    console.error("[findingLifecycle] sync threw:", (err as Error).message);
    return null;
  }
}
