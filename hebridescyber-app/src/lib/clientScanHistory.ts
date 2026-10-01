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
import { categoryOf } from "@/components/ComplianceTrend";

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
  // Derived from ALL_CONTROLS_BY_FRAMEWORK's own keys rather than a
  // hand-listed framework literal — a hand-listed Record here would fail
  // tsc the moment ComplianceFramework grows a new member (missing
  // properties), which is exactly what happened when ISO 27001/PCI DSS/
  // NIS2/DORA were added.
  const frameworks = Object.keys(ALL_CONTROLS_BY_FRAMEWORK) as ComplianceFramework[];
  const atRisk = Object.fromEntries(frameworks.map((f) => [f, new Set<string>()])) as Record<
    ComplianceFramework,
    Set<string>
  >;
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

/** One row for the Diff View's scan picker. */
export type ScanListEntry = { id: string; createdAt: string; score: number | null };

// Full-history variant of findScoreHistoryClient/findComplianceHistoryClient
// above, for src/app/dashboard/scans/history/page.tsx — that page starts
// from "pick a target" rather than "already viewing one scan," so it has no
// currentScanId/currentFindings to exclude or append the way the two
// scan-detail-page-driven functions above do. Capped at 500 scans (not the
// 20/10-point caps those two use) — a genuine "full history" view rather
// than a short trend line, but still bounded rather than truly unlimited.
const FULL_HISTORY_LIMIT = 500;

/**
 * Every completed scan of the same target (by hostname), newest first —
 * the source list for Diff View's "compare with" picker, which needs real
 * scan ids to fetch findings for, unlike findScoreHistoryClient's
 * ScorePoint[] (score + date only, no id).
 */
export async function listCompletedScansForTarget(targetUrl: string): Promise<ScanListEntry[]> {
  let hostname: string;
  try {
    hostname = new URL(targetUrl).hostname.toLowerCase();
  } catch {
    return [];
  }

  const { data: candidates } = await supabase
    .from("scans")
    .select("id, target_url, created_at, scan_results(score)")
    .eq("status", "completed")
    .order("created_at", { ascending: false })
    .limit(FULL_HISTORY_LIMIT);

  const entries: ScanListEntry[] = [];
  for (const c of (candidates ?? []) as Array<{ id: string; target_url: string; created_at: string; scan_results: { score: number | null }[] }>) {
    let candidateHost: string;
    try {
      candidateHost = new URL(c.target_url).hostname.toLowerCase();
    } catch {
      continue;
    }
    if (candidateHost !== hostname) continue;
    entries.push({ id: c.id, createdAt: c.created_at, score: c.scan_results?.[0]?.score ?? null });
  }

  return entries;
}

/** Findings for one specific scan, by id — Diff View fetches both sides of a comparison this way. */
export async function findFindingsForScan(scanId: string): Promise<Finding[] | null> {
  const { data } = await supabase.from("scan_results").select("results").eq("scan_id", scanId).order("created_at", { ascending: false }).limit(1).maybeSingle();
  return (data?.results as { findings?: Finding[] } | undefined)?.findings ?? null;
}

/** One scan's worth of category counts, for the history page's per-category sparklines. */
export type CategoryCountPoint = { date: string; counts: Record<string, number> };

export async function findFullScoreHistoryClient(targetUrl: string): Promise<ScorePoint[]> {
  let hostname: string;
  try {
    hostname = new URL(targetUrl).hostname.toLowerCase();
  } catch {
    return [];
  }

  const { data: candidates } = await supabase
    .from("scans")
    .select("target_url, created_at, scan_results(score, created_at)")
    .eq("status", "completed")
    .order("created_at", { ascending: false })
    .limit(FULL_HISTORY_LIMIT);

  const points: ScorePoint[] = [];
  for (const c of (candidates ?? []) as Array<{ target_url: string; scan_results: { score: number | null; created_at: string }[] }>) {
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
  }

  return points.sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime());
}

/**
 * Per-category open-finding counts across a target's full scan history —
 * same categoryOf() taxonomy ComplianceTrend.tsx's "Open findings by
 * category" bar list already uses, generalised into one point per scan
 * instead of only the latest.
 */
export async function findCategoryHistoryClient(targetUrl: string): Promise<CategoryCountPoint[]> {
  let hostname: string;
  try {
    hostname = new URL(targetUrl).hostname.toLowerCase();
  } catch {
    return [];
  }

  const { data: candidates } = await supabase
    .from("scans")
    .select("target_url, created_at, scan_results(results, created_at)")
    .eq("status", "completed")
    .order("created_at", { ascending: false })
    .limit(FULL_HISTORY_LIMIT);

  const points: CategoryCountPoint[] = [];
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

    const counts: Record<string, number> = {};
    for (const f of findings) {
      if (f.severity === "info") continue;
      const cat = categoryOf(f.checkId);
      counts[cat] = (counts[cat] ?? 0) + 1;
    }
    points.push({ date: result.created_at, counts });
  }

  return points.sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime());
}
