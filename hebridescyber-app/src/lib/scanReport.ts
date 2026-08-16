// Builds the scan report payload shared by GET /api/v1/scans/{id} and the
// webhook fired on scan completion — one contract, whether a caller polls or
// gets pushed to, rather than two JSON shapes that can drift apart.
import type { SupabaseClient } from "@supabase/supabase-js";
import { diffFindings } from "./findingsDiff";
import type { Finding } from "./scanners";

export type ScanRow = { id: string; owner: string; target_url: string; status: string; created_at: string };
export type ScanResultRow = { results: { findings?: Finding[] }; summary: string | null; score: number | null; created_at: string };

export type ScanReport = {
  scan_id: string;
  target_url: string;
  status: string;
  created_at: string;
  completed_at?: string;
  score: number | null;
  summary?: string | null;
  counts?: Record<string, number>;
  compared_to_previous_scan?: boolean;
  new_finding_count?: number | null;
  fixed_finding_count?: number | null;
  findings: Array<{
    check_id: string | null;
    severity: string;
    title: string;
    detail: string;
    remediation: string | null;
    status: "new" | "unchanged" | null;
    // Real CVE ids, when known — populated for vulnerable-JS-library findings
    // only today. [] means "checked, none known"; omitted entirely from a
    // finding type that was never checked (see Finding.cveIds in scanners).
    cve_ids?: string[];
  }>;
  fixed_findings?: Array<{ check_id: string | null; severity: string; title: string }>;
};

/**
 * Most recent completed scan of the same host, older than the given one.
 * Matches on hostname rather than exact target_url — target_url is stored raw
 * at scan-creation time, so protocol/trailing-slash/case differences would
 * otherwise hide a match between two scans of "the same" site.
 */
export async function findPreviousFindings(
  supabaseAdmin: SupabaseClient,
  ownerId: string,
  currentScanId: string,
  targetUrl: string,
  createdAt: string
): Promise<Finding[] | null> {
  let hostname: string;
  try {
    hostname = new URL(targetUrl).hostname.toLowerCase();
  } catch {
    return null;
  }

  const { data: candidates } = await supabaseAdmin
    .from("scans")
    .select("id, target_url, scan_results(results)")
    .eq("owner", ownerId)
    .eq("status", "completed")
    .neq("id", currentScanId)
    .lt("created_at", createdAt)
    .order("created_at", { ascending: false })
    .limit(100);

  for (const c of (candidates ?? []) as Array<{
    target_url: string;
    scan_results: { results: { findings?: Finding[] } }[];
  }>) {
    let host: string;
    try {
      host = new URL(c.target_url).hostname.toLowerCase();
    } catch {
      continue;
    }
    if (host !== hostname) continue;
    const prev = c.scan_results?.[0]?.results?.findings;
    if (prev) return prev;
  }

  return null;
}

/**
 * Assembles the full report for a scan that has results, tagging each
 * finding new/unchanged/null against `previousFindings` (null when there's no
 * earlier scan of this target to compare against — callers should treat that
 * as "can't tell what's new", not "nothing is new").
 */
export function buildScanReport(scan: ScanRow, result: ScanResultRow, previousFindings: Finding[] | null): ScanReport {
  const findings: Finding[] = result.results?.findings ?? [];
  const diff = previousFindings ? diffFindings(findings, previousFindings) : null;

  const statusByCheckId = new Map<string, "new" | "unchanged">();
  if (diff) {
    diff.added.forEach((f) => f.checkId && statusByCheckId.set(f.checkId, "new"));
    diff.unchanged.forEach((f) => f.checkId && statusByCheckId.set(f.checkId, "unchanged"));
  }

  const counts = findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});

  return {
    scan_id: scan.id,
    target_url: scan.target_url,
    status: scan.status,
    created_at: scan.created_at,
    completed_at: result.created_at,
    score: result.score,
    summary: result.summary,
    counts,
    compared_to_previous_scan: Boolean(diff),
    new_finding_count: diff ? diff.added.length : null,
    fixed_finding_count: diff ? diff.fixed.length : null,
    findings: findings.map((f) => ({
      check_id: f.checkId ?? null,
      severity: f.severity,
      title: f.title,
      detail: f.detail,
      remediation: f.remediation ?? null,
      status: f.checkId ? statusByCheckId.get(f.checkId) ?? null : null,
      cve_ids: f.cveIds,
    })),
    fixed_findings: diff
      ? diff.fixed.map((f) => ({ check_id: f.checkId ?? null, severity: f.severity, title: f.title }))
      : [],
  };
}

/** The minimal shape returned when a scan has no scan_results row yet. */
export function pendingScanReport(scan: ScanRow): ScanReport {
  return {
    scan_id: scan.id,
    target_url: scan.target_url,
    status: scan.status,
    created_at: scan.created_at,
    score: null,
    findings: [],
  };
}
