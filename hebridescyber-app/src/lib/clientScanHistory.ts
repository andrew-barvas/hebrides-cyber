// Client-side (RLS-scoped, anon key) helpers for building score trends and
// finding diffs for display in the dashboard. Distinct from
// src/lib/scanReport.ts's findPreviousFindings, which is the server-side
// (service-role) version used during scan execution to build the report
// that gets persisted/sent to webhooks — these run in the browser against
// the signed-in user's own RLS-scoped view, purely for rendering.
//
// Extracted from src/app/dashboard/scans/[id]/page.tsx (the first consumer)
// so the new dashboard overview (src/app/dashboard/page.tsx) can reuse the
// exact same hostname-matching logic rather than a second, drifting copy.
import { supabase } from "./supabaseClient";
import type { Finding } from "./scanners";
import type { ScorePoint } from "@/components/ScoreTrend";
import { getComplianceRefs, ALL_CONTROLS_BY_FRAMEWORK, type ComplianceFramework } from "./scanners/compliance";

/**
 * Finds the most recent completed scan of the same target that predates this
 * one, and returns its findings — or null if none exists (first scan of this
 * target) or the target's hostname can't be parsed.
 *
 * Matches by hostname rather than exact target_url: two scans of "the same"
 * site aren't guaranteed byte-identical strings (protocol, trailing slash,
 * case — target_url is stored raw, unnormalised, at scan-creation time).
 *
 * Fetches the 100 most recent completed scans across all of the user's
 * targets and filters client-side, since there's no indexed hostname column
 * to query against directly. Fine at today's scale; if a user regularly runs
 * 100+ scans of other targets between two scans of the same one, the match
 * will be missed and no previous scan can be found — worth revisiting with a
 * proper indexed hostname/target column if that starts happening in practice.
 */
export async function findPreviousFindingsClient(
  currentScanId: string,
  currentTargetUrl: string,
  currentCreatedAt: string
): Promise<Finding[] | null> {
  let hostname: string;
  try {
    hostname = new URL(currentTargetUrl).hostname.toLowerCase();
  } catch {
    return null;
  }

  const { data: candidates } = await supabase
    .from("scans")
    .select("id, target_url, created_at, scan_results(results)")
    .eq("status", "completed")
    .neq("id", currentScanId)
    .lt("created_at", currentCreatedAt)
    .order("created_at", { ascending: false })
    .limit(100);

  for (const c of (candidates ?? []) as Array<{
    id: string;
    target_url: string;
    scan_results: { results: { findings?: Finding[] } }[];
  }>) {
    let candidateHost: string;
    try {
      candidateHost = new URL(c.target_url).hostname.toLowerCase();
    } catch {
      continue;
    }
    if (candidateHost !== hostname) continue;
    const prevFindings = c.scan_results?.[0]?.results?.findings;
    if (prevFindings) return prevFindings;
  }

  return null;
}

/**
 * Score history for every completed scan of the same target (by hostname,
 * same reasoning as findPreviousFindingsClient above), oldest first,
 * including the current scan itself so the trend line ends at "now." Capped
 * at 20 points — a trend line, not a full audit log.
 */
export async function findScoreHistoryClient(
  currentScanId: string,
  currentTargetUrl: string,
  currentScore: number | null,
  currentCreatedAt: string
): Promise<ScorePoint[]> {
  let hostname: string;
  try {
    hostname = new URL(currentTargetUrl).hostname.toLowerCase();
  } catch {
    return [];
  }

  const { data: candidates } = await supabase
    .from("scans")
    .select("id, target_url, created_at, scan_results(score, created_at)")
    .eq("status", "completed")
    .neq("id", currentScanId)
    .order("created_at", { ascending: false })
    .limit(100);

  const points: ScorePoint[] = [];
  for (const c of (candidates ?? []) as Array<{
    target_url: string;
    scan_results: { score: number | null; created_at: string }[];
  }>) {
    let candidateHost: string;
    try {
      candidateHost = new URL(c.target_url).hostname.toLowerCase();
    } catch {
      continue;
    }
    if (candidateHost !== hostname) continue;
    const result = c.scan_results?.[0];
    if (result?.score == null) continue;
    points.push({ date: result.created_at, score: result.score });
    if (points.length >= 19) break; // + the current scan = 20
  }

  if (currentScore !== null) points.push({ date: currentCreatedAt, score: currentScore });

  return points.sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime());
}

// E-28 (docs/ENHANCEMENTS.md): per-framework compliance coverage over time,
// alongside the existing score trend above. "Coverage" for a given scan is
// the fraction of ALL_CONTROLS_BY_FRAMEWORK's controls that have zero open
// (non-info-severity) findings citing them in that scan -- a fixed
// denominator across scans, not just "however many controls this scan's
// findings happen to touch," so 100% genuinely means "every control this
// app checks for is currently clean," not "no findings mapped anything."
export type CompliancePoint = { date: string; coverage: Record<ComplianceFramework, number> };

// Structural, not the full Finding type — callers pass either Finding[]
// (server-shaped) or ScanReportView.tsx's ViewFinding[] (dashboard-shaped,
// what dashboard/page.tsx's overviewFindings actually is), and both already
// carry exactly this much.
type FindingLike = { severity: string; checkId?: string };

export function coverageForFindings(findings: FindingLike[]): Record<ComplianceFramework, number> {
  const atRisk: Record<ComplianceFramework, Set<string>> = {
    "cyber-essentials": new Set(),
    "owasp-top-10": new Set(),
    "cis-controls-v8": new Set(),
  };
  for (const f of findings) {
    if (f.severity === "info") continue;
    for (const ref of getComplianceRefs(f.checkId)) atRisk[ref.framework].add(ref.control);
  }

  const coverage = {} as Record<ComplianceFramework, number>;
  for (const framework of Object.keys(atRisk) as ComplianceFramework[]) {
    const total = ALL_CONTROLS_BY_FRAMEWORK[framework].size;
    coverage[framework] = total === 0 ? 1 : 1 - atRisk[framework].size / total;
  }
  return coverage;
}

/**
 * Compliance-coverage history for every completed scan of the same target
 * (by hostname, same convention as findScoreHistoryClient above), oldest
 * first, including the current scan. Capped at 10 points -- coverage moves
 * slower than score scan-to-scan, so a shorter window reads more clearly
 * than the 20-point score trend would.
 */
export async function findComplianceHistoryClient(
  currentScanId: string,
  currentTargetUrl: string,
  currentFindings: FindingLike[],
  currentCreatedAt: string
): Promise<CompliancePoint[]> {
  let hostname: string;
  try {
    hostname = new URL(currentTargetUrl).hostname.toLowerCase();
  } catch {
    return [];
  }

  const { data: candidates } = await supabase
    .from("scans")
    .select("id, target_url, created_at, scan_results(results, created_at)")
    .eq("status", "completed")
    .neq("id", currentScanId)
    .order("created_at", { ascending: false })
    .limit(100);

  const points: CompliancePoint[] = [];
  for (const c of (candidates ?? []) as Array<{
    target_url: string;
    scan_results: { results: { findings?: Finding[] } | null; created_at: string }[];
  }>) {
    let candidateHost: string;
    try {
      candidateHost = new URL(c.target_url).hostname.toLowerCase();
    } catch {
      continue;
    }
    if (candidateHost !== hostname) continue;
    const result = c.scan_results?.[0];
    const findings = result?.results?.findings;
    if (!result || !findings) continue;
    points.push({ date: result.created_at, coverage: coverageForFindings(findings) });
    if (points.length >= 9) break; // + the current scan = 10
  }

  points.push({ date: currentCreatedAt, coverage: coverageForFindings(currentFindings) });

  return points.sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime());
}
